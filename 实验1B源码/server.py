"""Run the TLS file server with one bounded worker per connection."""
import argparse
import collections
import hashlib
import logging
import os
import socket
import ssl
import stat
import tempfile
import threading
import time
from contextlib import contextmanager, suppress
from pathlib import Path

from protocol import (
    MAX_FILE, TRANSFER_TIMEOUT, Kind, ProtocolError, deadline, enable_keepalive,
    measure, prefix_digest, recv_frame, send_frame, stream_receive, stream_send, valid_digest,
)
from storage import Storage, private_dir

HANDSHAKE_TIMEOUT = 5
IDLE_TIMEOUT = 60
MAX_CLIENTS = 16
MAX_PER_IP = 4
MAX_AUTH_ATTEMPTS = 3

class RateLimit:
    def __init__(self, bytes_per_second):
        self.bytes_per_second = bytes_per_second
        self.lock = threading.Lock()
        self.next_chunk = 0

    def wait(self, size, end):
        with self.lock:
            now = time.monotonic()
            ready = max(now, self.next_chunk) + size / self.bytes_per_second
            if ready >= end:
                raise TimeoutError("transfer deadline exceeded")
            self.next_chunk = ready
        time.sleep(ready - now)


class Transfers:
    def __init__(self, regular_rate, vip_rate):
        self.lock = threading.Lock()
        self.active = set()
        self.rates = {}
        self.regular_rate = regular_rate
        self.vip_rate = vip_rate

    def limits(self, user, vip):
        with self.lock:
            if user not in self.rates:
                rate = self.vip_rate if vip else self.regular_rate
                self.rates[user] = (RateLimit(rate), RateLimit(rate))
            return self.rates[user]

    @contextmanager
    def resumable(self, user):
        with self.lock:
            if user in self.active:
                raise ValueError("this account already has a resumable upload running")
            self.active.add(user)
        try:
            yield
        finally:
            with self.lock:
                self.active.remove(user)


class Session:
    def __init__(self, sock, storage, transfers, certificate_user=None):
        self.sock = sock
        self.storage = storage
        self.transfers = transfers
        self.certificate_user = certificate_user
        self.username = None
        self.failed_logins = 0
        self.last_request = 0

    def reply(self, kind, request_id, metadata=None, *, body=0, end=None):
        send_frame(self.sock, kind, request_id, metadata, body, end)

    def reject(self, request_id, code, message):
        self.reply(Kind.ERROR, request_id, {"code": code, "message": message})

    def run(self):
        while True:
            frame = recv_frame(self.sock, idle_timeout=IDLE_TIMEOUT)
            if frame is None:
                return
            kind, request_id, metadata, _ = frame
            if request_id <= self.last_request:
                raise ProtocolError("request IDs must increase")
            self.last_request = request_id
            if kind == Kind.QUIT:
                self.reply(Kind.OK, request_id, {"message": "bye"})
                return
            if kind == Kind.PING:
                self.reply(Kind.OK, request_id, {"message": "pong"})
                continue
            if kind == Kind.LOGIN:
                if not self.login(request_id, metadata):
                    return
                continue
            if kind not in (Kind.LIST, Kind.PUT, Kind.GET):
                raise ProtocolError("unexpected request type")
            if self.username is None:
                self.reject(request_id, "AUTH_REQUIRED", "log in first")
                continue
            try:
                if kind == Kind.LIST:
                    self.reply(Kind.OK, request_id, {"files": self.storage.entries(self.username)})
                elif kind == Kind.GET:
                    self.download(request_id, metadata)
                else:
                    self.upload(request_id, metadata)
            except ValueError as error:
                self.reject(request_id, "BAD_REQUEST", str(error))
            except FileNotFoundError:
                self.reject(request_id, "NOT_FOUND", "file not found")

    def login(self, request_id, metadata):
        if self.username is not None:
            self.reject(request_id, "ALREADY_LOGGED_IN", "session is already authenticated")
            return True
        username, password = metadata.get("username"), metadata.get("password")
        vip = self.storage.tier(username)
        if self.certificate_user is not None:
            accepted = vip is not None and self.certificate_user == username
        else:
            accepted = self.storage.authenticate(username, password)
        if accepted:
            self.username = username
            self.upload_rate, self.download_rate = self.transfers.limits(username, vip)
            self.reply(Kind.OK, request_id, {"message": "login successful", "tier": "VIP" if vip else "regular"})
            return True
        self.failed_logins += 1
        self.reject(request_id, "AUTH_FAILED", "invalid username or password")
        return self.failed_logins < MAX_AUTH_ATTEMPTS

    def upload(self, request_id, metadata):
        size, expected = metadata.get("size"), metadata.get("sha256")
        resume = metadata.get("resume", False)
        if type(size) is not int or not 0 <= size <= MAX_FILE or not valid_digest(expected):
            raise ValueError("invalid file size or SHA-256")
        if type(resume) is not bool:
            raise ValueError("invalid resume flag")
        target = self.storage.target(self.username, metadata.get("name"))
        with self.transfers.lock:
            self.storage.check_quota(self.username, target, size)
        if resume:
            with self.transfers.resumable(self.username):
                directory = private_dir(self.storage.partials / self.username)
                # The identity covers the name, full length and full digest.
                key = hashlib.sha256(f"{target.name}:{size}:{expected}".encode()).hexdigest()
                partial = directory / (".upload-" + key)
                for previous in directory.glob(".upload-*"):
                    if previous != partial:
                        previous.unlink()
                # The directory is private to the server account.
                with partial.open("a+b") as file:
                    if file.tell() > size:
                        file.truncate(0)
                    self.receive_upload(request_id, file, partial, target, size, expected, True)
        else:
            temporary = tempfile.NamedTemporaryFile(dir=target.parent, prefix=".part-", delete=False)
            path = Path(temporary.name)
            try:
                with temporary:
                    self.receive_upload(request_id, temporary, path, target, size, expected, False)
            finally:
                with suppress(FileNotFoundError):
                    path.unlink()

    def receive_upload(self, request_id, file, partial, target, size, expected, resume):
        offset = file.seek(0, os.SEEK_END)
        digest = prefix_digest(file, offset)
        end = deadline(TRANSFER_TIMEOUT)
        self.reply(Kind.READY, request_id, {"offset": offset} if resume else None, end=end)
        frame = recv_frame(self.sock, end=end)
        if frame != (Kind.DATA, request_id, {}, size - offset):
            raise ProtocolError("expected the declared DATA frame")
        actual = stream_receive(self.sock, file, size - offset, end, digest, self.upload_rate.wait)
        if actual != expected:
            partial.unlink()
            self.reject(request_id, "INTEGRITY", "SHA-256 mismatch")
            return
        file.flush()
        with self.transfers.lock:
            self.storage.check_quota(self.username, target, size)
            os.replace(partial, target)
        self.reply(Kind.OK, request_id, {"sha256": actual}, end=end)

    def download(self, request_id, metadata):
        target = self.storage.target(self.username, metadata.get("name"))
        if not stat.S_ISREG(target.lstat().st_mode):
            raise ValueError("requested item is not a regular file")
        with target.open("rb") as file:
            size, digest = measure(file)
            response = {"size": size, "sha256": digest}
            offset = 0
            if "offset" in metadata:
                proposed, prefix = metadata["offset"], metadata.get("prefix_sha256")
                if type(proposed) is not int or proposed < 0 or not valid_digest(prefix):
                    raise ValueError("invalid download offset or prefix digest")
                if proposed <= size and prefix_digest(file, proposed).hexdigest() == prefix:
                    offset = proposed
                response["offset"] = offset
            file.seek(offset)
            end = deadline(TRANSFER_TIMEOUT)
            self.reply(Kind.DATA, request_id, response, body=size - offset, end=end)
            stream_send(self.sock, file, size - offset, end, self.download_rate.wait)


class Server:
    def __init__(self, listener, tls, storage, transfers):
        self.listener = listener
        self.tls = tls
        self.storage = storage
        self.admission = threading.Lock()
        self.transfers = transfers
        self.addresses = collections.Counter()
        self.slots = threading.BoundedSemaphore(MAX_CLIENTS)

    def serve(self):
        while True:
            raw, address = self.listener.accept()
            ip = address[0]
            with self.admission:
                admitted = self.addresses[ip] < MAX_PER_IP and self.slots.acquire(blocking=False)
                if admitted:
                    self.addresses[ip] += 1
            if not admitted:
                raw.close()
                continue
            try:
                threading.Thread(target=self.worker, args=(raw, ip), daemon=True).start()
            except RuntimeError:
                raw.close()
                self.release(ip)

    def release(self, ip):
        with self.admission:
            self.addresses[ip] -= 1
            if not self.addresses[ip]:
                del self.addresses[ip]
            self.slots.release()

    def worker(self, raw, ip):
        try:
            with raw:
                raw.settimeout(HANDSHAKE_TIMEOUT)
                enable_keepalive(raw)
                with self.tls.wrap_socket(raw, server_side=True, suppress_ragged_eofs=False) as sock:
                    certificate_user = None
                    if self.tls.verify_mode == ssl.CERT_REQUIRED:
                        names = [value for group in sock.getpeercert()["subject"]
                                 for key, value in group if key == "commonName"]
                        if len(names) != 1:
                            raise ProtocolError("expected one certificate account name")
                        certificate_user = names[0]
                    Session(sock, self.storage, self.transfers, certificate_user).run()
        except (OSError, ProtocolError, TimeoutError) as error:
            logging.info("session closed (%s): %s", ip, error)
        finally:
            self.release(ip)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=Path("runtime"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--require-client-cert", action="store_true")
    parser.add_argument("--regular-kib", type=int, default=4096)
    parser.add_argument("--vip-kib", type=int, default=16384)
    options = parser.parse_args()
    if not 256 <= options.regular_kib <= options.vip_kib:
        parser.error("bandwidth must satisfy 256 <= regular <= VIP (KiB/s)")
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    os.umask(0o077)
    storage = Storage(options.runtime.resolve())
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(storage.root / "tls/server.pem"), str(storage.root / "tls/server-key.pem"))
    if options.require_client_cert:
        tls.load_verify_locations(cafile=str(storage.root / "client-ca/ca.pem"))
        tls.verify_mode = ssl.CERT_REQUIRED
    transfers = Transfers(options.regular_kib * 1024, options.vip_kib * 1024)
    try:
        with socket.create_server((options.host, options.port), backlog=32) as listener:
            host, port = listener.getsockname()[:2]
            print(f"Listening on {host}:{port} (TLS, keep-alive, up to {MAX_CLIENTS} sessions)", flush=True)
            Server(listener, tls, storage, transfers).serve()
    except KeyboardInterrupt:
        print("Server stopped")


if __name__ == "__main__":
    main()

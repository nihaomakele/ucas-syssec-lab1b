"""Run the TLS file server with one bounded worker per connection."""
import argparse
import collections
import logging
import os
import socket
import ssl
import stat
import tempfile
import threading
from contextlib import suppress
from pathlib import Path

from protocol import (
    MAX_FILE, Kind, ProtocolError, deadline, enable_keepalive,
    measure, recv_frame, send_frame, stream_receive, stream_send, valid_digest,
)
from storage import Storage

HANDSHAKE_TIMEOUT = 5
IDLE_TIMEOUT = 60
MAX_CLIENTS = 16
MAX_PER_IP = 4
MAX_AUTH_ATTEMPTS = 3


class Session:
    def __init__(self, sock, storage, commit_lock):
        self.sock = sock
        self.storage = storage
        self.commit_lock = commit_lock
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
        if self.storage.authenticate(username, password):
            self.username = username
            self.reply(Kind.OK, request_id, {"message": "login successful"})
            return True
        self.failed_logins += 1
        self.reject(request_id, "AUTH_FAILED", "invalid username or password")
        return self.failed_logins < MAX_AUTH_ATTEMPTS

    def upload(self, request_id, metadata):
        size, expected = metadata.get("size"), metadata.get("sha256")
        if type(size) is not int or not 0 <= size <= MAX_FILE or not valid_digest(expected):
            raise ValueError("invalid file size or SHA-256")
        target = self.storage.target(self.username, metadata.get("name"))
        with self.commit_lock:
            self.storage.check_quota(self.username, target, size)
        end = deadline()
        self.reply(Kind.READY, request_id, end=end)
        frame = recv_frame(self.sock, end=end)
        if frame != (Kind.DATA, request_id, {}, size):
            raise ProtocolError("expected the declared DATA frame")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".part-", delete=False) as file:
                temporary = Path(file.name)
                actual = stream_receive(self.sock, file, size, end)
            if actual != expected:
                self.reject(request_id, "INTEGRITY", "SHA-256 mismatch")
                return
            with self.commit_lock:
                self.storage.check_quota(self.username, target, size)
                os.replace(temporary, target)
            self.reply(Kind.OK, request_id, {"sha256": actual}, end=end)
        finally:
            if temporary is not None:
                with suppress(FileNotFoundError):
                    temporary.unlink()

    def download(self, request_id, metadata):
        target = self.storage.target(self.username, metadata.get("name"))
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("requested item is not a regular file")
        # Open descriptors keep reading the same version across atomic replacements.
        with target.open("rb") as file:
            size, digest = measure(file)
            end = deadline()
            self.reply(Kind.DATA, request_id, {"size": size, "sha256": digest}, body=size, end=end)
            stream_send(self.sock, file, size, end)


class Server:
    def __init__(self, listener, tls, storage):
        self.listener = listener
        self.tls = tls
        self.storage = storage
        self.admission = threading.Lock()
        self.commit_lock = threading.Lock()
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
                    Session(sock, self.storage, self.commit_lock).run()
        except (OSError, ProtocolError, TimeoutError) as error:
            logging.info("session closed (%s): %s", ip, error)
        finally:
            self.release(ip)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=Path("runtime"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18081)
    options = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    os.umask(0o077)
    storage = Storage(options.runtime.resolve())
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(storage.root / "tls/server.pem"), str(storage.root / "tls/server-key.pem"))
    try:
        with socket.create_server((options.host, options.port), backlog=32) as listener:
            host, port = listener.getsockname()[:2]
            print(f"Listening on {host}:{port} (TLS, keep-alive, up to {MAX_CLIENTS} sessions)", flush=True)
            Server(listener, tls, storage).serve()
    except KeyboardInterrupt:
        print("Server stopped")


if __name__ == "__main__":
    main()

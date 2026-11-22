"""Open one TLS session and run file commands until you quit."""
import argparse
import fcntl
import getpass
import hashlib
import os
import shlex
import socket
import ssl
import stat
import sys
import tempfile
import threading
from contextlib import contextmanager, suppress
from pathlib import Path

from protocol import (
    IO_TIMEOUT, MAX_FILE, TRANSFER_TIMEOUT, Kind, ProtocolError, deadline,
    enable_keepalive, measure, prefix_digest, recv_frame, send_frame,
    stream_receive, stream_send, valid_digest,
)

HEARTBEAT_INTERVAL = 15


class RequestError(Exception):
    """The server refused one command; the session can still be used."""


class Client:
    def __init__(self, host, port, ca, *, heartbeat=HEARTBEAT_INTERVAL, certificate=None, key=None):
        tls = ssl.create_default_context(cafile=str(ca))
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        if (certificate is None) != (key is None):
            raise ValueError("both client certificate and key are required")
        if certificate is not None:
            tls.load_cert_chain(str(certificate), str(key))
        self.certificate = certificate
        self.last_resume_offset = 0
        raw = socket.create_connection((host, port), timeout=IO_TIMEOUT)
        try:
            enable_keepalive(raw)
            self.sock = tls.wrap_socket(raw, server_hostname=host, suppress_ragged_eofs=False)
        except (OSError, ValueError):
            raw.close()
            raise
        self.lock = threading.Lock()
        self.finished = threading.Event()
        self.next_request = 0
        self.heartbeats = 0
        self.connection = self.sock.getsockname()
        self.tls_version = self.sock.version()
        self.heartbeat_thread = threading.Thread(target=self.keep_alive, args=(heartbeat,), daemon=True)
        self.heartbeat_thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        with self.lock:
            self._disconnect()
        self.heartbeat_thread.join()

    def _disconnect(self):
        self.finished.set()
        self.sock.close()

    @contextmanager
    def exchange(self):
        with self.lock:
            if self.finished.is_set():
                raise ProtocolError("session is closed")
            try:
                yield
            except (OSError, ProtocolError):
                self._disconnect()
                raise

    def request(self, kind, metadata=None):
        self.next_request += 1
        send_frame(self.sock, kind, self.next_request, metadata)
        return self.next_request

    def receive(self, request_id, expected, end=None):
        frame = recv_frame(self.sock, end=end)
        if frame is None or frame[1] != request_id:
            raise ProtocolError("missing response or invalid request ID")
        kind, _, metadata, size = frame
        if kind == Kind.ERROR:
            raise RequestError(f"{metadata.get('code', 'ERROR')}: {metadata.get('message', '')}")
        if kind != expected:
            raise ProtocolError("unexpected response type")
        return metadata, size

    def command(self, kind, metadata=None):
        with self.exchange():
            return self.receive(self.request(kind, metadata), Kind.OK)[0]

    def keep_alive(self, interval):
        while not self.finished.wait(interval):
            if not self.lock.acquire(blocking=False):
                continue  # The active transfer is already using the connection.
            try:
                if self.finished.is_set():
                    return
                self.receive(self.request(Kind.PING), Kind.OK)
                self.heartbeats += 1
            except (OSError, ProtocolError, RequestError):
                self._disconnect()
                return
            finally:
                self.lock.release()

    def login(self, username, password=None):
        metadata = {"username": username}
        if self.certificate is None:
            metadata["password"] = password
        return self.command(Kind.LOGIN, metadata)

    def put(self, local, name, *, resume=False):
        with local.open("rb") as file:
            size, digest = measure(file)
            with self.exchange():
                metadata = {"name": name, "size": size, "sha256": digest}
                if resume:
                    metadata["resume"] = True
                request_id = self.request(Kind.PUT, metadata)
                ready, _ = self.receive(request_id, Kind.READY)
                offset = ready.get("offset", 0) if resume else 0
                if type(offset) is not int or not 0 <= offset <= size:
                    raise ProtocolError("invalid upload offset")
                self.last_resume_offset = offset
                file.seek(offset)
                end = deadline(TRANSFER_TIMEOUT)
                send_frame(self.sock, Kind.DATA, request_id, body_len=size - offset, end=end)
                stream_send(self.sock, file, size - offset, end)
                reply, _ = self.receive(request_id, Kind.OK, end=end)
                if reply.get("sha256") != digest:
                    raise ProtocolError("server reported an unexpected digest")
        return digest

    def get(self, name, local, *, resume=False):
        if resume:
            key = hashlib.sha256(os.fsencode(local.name)).hexdigest()
            partial = local.parent / (".download-" + key + ".part")
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
            with os.fdopen(os.open(partial, flags, 0o600), "r+b") as file:
                if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                    raise ValueError("local partial file must be an ordinary file")
                try:
                    fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise ValueError("destination already has a resumable download running") from error
                digest = self.receive_download(name, file, True)
                file.flush()
                os.replace(partial, local)
                return digest

        with tempfile.NamedTemporaryFile(dir=local.parent, prefix=".download-", delete=False) as file:
            temporary = Path(file.name)
            try:
                digest = self.receive_download(name, file, False)
                file.flush()
                os.replace(temporary, local)
                return digest
            finally:
                with suppress(FileNotFoundError):
                    temporary.unlink()

    def receive_download(self, name, file, resume):
        with self.exchange():
            request = {"name": name}
            available = file.seek(0, os.SEEK_END) if resume else 0
            if available > MAX_FILE:
                available = 0
            digest = prefix_digest(file, available)
            if resume:
                request.update(offset=available, prefix_sha256=digest.hexdigest())
            request_id = self.request(Kind.GET, request)
            end = deadline(TRANSFER_TIMEOUT)
            metadata, body_size = self.receive(request_id, Kind.DATA, end=end)
            size, expected = metadata.get("size"), metadata.get("sha256")
            offset = metadata.get("offset", 0)
            if (type(size) is not int or not 0 <= size <= MAX_FILE
                    or type(offset) is not int or offset not in (0, available)
                    or offset + body_size != size or not valid_digest(expected)):
                raise ProtocolError("invalid download metadata")
            self.last_resume_offset = offset
            if offset == 0:
                file.seek(0)
                file.truncate()
                digest = hashlib.sha256()
            else:
                file.seek(offset)
            actual = stream_receive(self.sock, file, body_size, end, digest)
        if actual != expected:
            file.truncate(0)
            raise RequestError("local SHA-256 verification failed")
        return actual


def execute(client, line):
    words = shlex.split(line)
    if not words:
        return True
    command, *args = words
    if command == "help" and not args:
        print("list | put/rput LOCAL [REMOTE] | get/rget REMOTE [LOCAL] | ping | status | quit")
    elif command == "list" and not args:
        entries = client.command(Kind.LIST)["files"]
        for entry in entries:
            print(f"{entry['name']}\t{entry['size']} bytes")
        print(f"{len(entries)} file(s)")
    elif command in ("put", "rput") and 1 <= len(args) <= 2:
        source = Path(args[0])
        name = args[1] if len(args) == 2 else source.name
        digest = client.put(source, name, resume=command == "rput")
        print(f"Uploaded {name}  SHA-256 {digest}")
        if command == "rput":
            print(f"Resumed at byte {client.last_resume_offset}")
    elif command in ("get", "rget") and 1 <= len(args) <= 2:
        name = args[0]
        destination = Path(args[1] if len(args) == 2 else Path(name).name)
        digest = client.get(name, destination, resume=command == "rget")
        print(f"Downloaded {destination}  SHA-256 {digest}")
        if command == "rget":
            print(f"Resumed at byte {client.last_resume_offset}")
    elif command == "ping" and not args:
        print(client.command(Kind.PING)["message"])
    elif command == "status" and not args:
        print(f"{client.tls_version}; local port {client.connection[1]}; "
              f"background heartbeats {client.heartbeats}")
    elif command == "quit" and not args:
        client.command(Kind.QUIT)
        print("Session closed.")
        return False
    else:
        raise ValueError("invalid command; type help")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--ca", type=Path, default=Path("runtime/tls/ca.pem"))
    parser.add_argument("--user", required=True)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--password-stdin", action="store_true", help="read the password from the first stdin line")
    parser.add_argument("--batch", action="store_true", help="read commands until stdin EOF")
    options = parser.parse_args()
    if bool(options.cert) != bool(options.key):
        parser.error("--cert and --key must be used together")
    password = None
    if options.cert is None:
        password = (sys.stdin.readline().rstrip("\r\n") if options.password_stdin
                    else getpass.getpass("Password: "))
    try:
        with Client(options.host, options.port, options.ca, certificate=options.cert, key=options.key) as client:
            client.login(options.user, password)
            print(f"Logged in as {options.user} ({client.tls_version}). Type help for commands.", flush=True)
            while True:
                try:
                    line = sys.stdin.readline() if options.batch else input("sft> ")
                except (EOFError, KeyboardInterrupt):
                    print()
                    line = None
                if line is None or (options.batch and not line):
                    line = "quit"
                try:
                    if not execute(client, line):
                        return
                except (ValueError, RequestError, FileNotFoundError, PermissionError) as error:
                    if options.batch or client.finished.is_set():
                        raise
                    print(error, file=sys.stderr)
    except (OSError, ValueError, ProtocolError, RequestError) as error:
        parser.exit(1, f"Client error: {error}\n")


if __name__ == "__main__":
    main()

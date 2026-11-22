"""Open one TLS session and run file commands until you quit."""
import argparse
import getpass
import os
import shlex
import socket
import ssl
import sys
import tempfile
import threading
from contextlib import contextmanager, suppress
from pathlib import Path

from protocol import (
    IO_TIMEOUT, Kind, ProtocolError, deadline, enable_keepalive, measure,
    recv_frame, send_frame, stream_receive, stream_send, valid_digest,
)

HEARTBEAT_INTERVAL = 15


class RequestError(Exception):
    """The server refused one command; the session can still be used."""


class Client:
    def __init__(self, host, port, ca, *, heartbeat=HEARTBEAT_INTERVAL):
        tls = ssl.create_default_context(cafile=str(ca))
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
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

    def put(self, local, name):
        with local.open("rb") as file:
            size, digest = measure(file)
            with self.exchange():
                request_id = self.request(Kind.PUT, {"name": name, "size": size, "sha256": digest})
                self.receive(request_id, Kind.READY)
                end = deadline()
                send_frame(self.sock, Kind.DATA, request_id, body_len=size, end=end)
                stream_send(self.sock, file, size, end)
                reply, _ = self.receive(request_id, Kind.OK, end=end)
                if reply.get("sha256") != digest:
                    raise ProtocolError("server reported an unexpected digest")
        return digest

    def get(self, name, local):
        # Create the local temporary file before requesting any remote payload.
        with tempfile.NamedTemporaryFile(dir=local.parent, prefix=".download-", delete=False) as file:
            temporary = Path(file.name)
            try:
                with self.exchange():
                    request_id = self.request(Kind.GET, {"name": name})
                    end = deadline()
                    metadata, size = self.receive(request_id, Kind.DATA, end=end)
                    expected = metadata.get("sha256")
                    if type(metadata.get("size")) is not int or metadata["size"] != size or not valid_digest(expected):
                        raise ProtocolError("invalid download metadata")
                    actual = stream_receive(self.sock, file, size, end)
                if actual != expected:
                    raise RequestError("local SHA-256 verification failed")
                file.close()
                os.replace(temporary, local)
                return actual
            finally:
                with suppress(FileNotFoundError):
                    temporary.unlink()


def execute(client, line):
    words = shlex.split(line)
    if not words:
        return True
    command, *args = words
    if command == "help" and not args:
        print("list | put LOCAL [REMOTE] | get REMOTE [LOCAL] | ping | status | quit")
    elif command == "list" and not args:
        entries = client.command(Kind.LIST)["files"]
        for entry in entries:
            print(f"{entry['name']}\t{entry['size']} bytes")
        print(f"{len(entries)} file(s)")
    elif command == "put" and 1 <= len(args) <= 2:
        source = Path(args[0])
        name = args[1] if len(args) == 2 else source.name
        print(f"Uploaded {name}  SHA-256 {client.put(source, name)}")
    elif command == "get" and 1 <= len(args) <= 2:
        name = args[0]
        destination = Path(args[1] if len(args) == 2 else Path(name).name)
        print(f"Downloaded {destination}  SHA-256 {client.get(name, destination)}")
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
    parser.add_argument("--password-stdin", action="store_true", help="read the password from the first stdin line")
    parser.add_argument("--batch", action="store_true", help="read commands until stdin EOF")
    options = parser.parse_args()
    password = (sys.stdin.readline().rstrip("\r\n") if options.password_stdin
                else getpass.getpass("Password: "))
    try:
        with Client(options.host, options.port, options.ca) as client:
            client.command(Kind.LOGIN, {"username": options.user, "password": password})
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

"""Verify the file transfer on loopback using disposable storage and TLS keys."""
import concurrent.futures
import hashlib
import io
import selectors
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from client import Client, RequestError
from protocol import Kind, deadline, send_frame, stream_send

SOURCE = Path(__file__).resolve().parent
PASSWORD = "lab-test-only-7j92"


def run_tool(script, *args, typed=None):
    return subprocess.run(
        [sys.executable, str(SOURCE / script), *map(str, args)], input=typed,
        capture_output=True, text=True, check=True, timeout=15,
    ).stdout.strip()


def expect_error(action, code):
    try:
        action()
    except RequestError as error:
        assert str(error).startswith(code), str(error)
    else:
        raise AssertionError(f"expected {code}")


def verify(directory, port, ca):
    def open_client(user, heartbeat=15):
        client = Client("127.0.0.1", port, ca, heartbeat=heartbeat)
        try:
            client.command(Kind.LOGIN, {"username": user, "password": PASSWORD})
        except BaseException:
            client.close()
            raise
        return client

    with Client("127.0.0.1", port, ca) as client:
        expect_error(lambda: client.command(Kind.LIST), "AUTH_REQUIRED")
        expect_error(lambda: client.command(Kind.LOGIN, {"username": "alice", "password": "incorrect"}), "AUTH_FAILED")
    print("PASS authentication required; wrong credentials refused")

    try:
        with Client("127.0.0.1", port, directory / "untrusted/tls/ca.pem"):
            raise AssertionError("untrusted CA accepted")
    except ssl.SSLCertVerificationError:
        pass
    trust = ssl.create_default_context(cafile=str(ca))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with trust.wrap_socket(raw, server_hostname="wrong.example"):
                raise AssertionError("wrong certificate name accepted")
    except ssl.SSLCertVerificationError:
        pass
    print("PASS TLS rejects unknown CA and wrong certificate name")

    sample = directory / "sample.bin"
    data = bytes(range(256)) * 512 + b"end\x00"
    sample.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    with open_client("alice", heartbeat=0.25) as alice:
        local_port = alice.connection[1]
        assert alice.put(sample, "sample.bin") == expected
        assert alice.command(Kind.LIST)["files"] == [{"name": "sample.bin", "size": len(data)}]
        assert alice.get("sample.bin", directory / "download.bin") == expected
        assert (directory / "download.bin").read_bytes() == data
        print(f"PASS binary upload/download; {len(data)} bytes; SHA-256 {expected}")
        empty = directory / "empty.txt"
        empty.touch()
        assert alice.put(empty, "empty.txt") == hashlib.sha256(b"").hexdigest()
        alice.get("empty.txt", directory / "empty-copy.txt")
        assert (directory / "empty-copy.txt").stat().st_size == 0
        print("PASS zero-byte file round trip")

        limit = time.monotonic() + 3
        while alice.heartbeats == 0 and time.monotonic() < limit:
            time.sleep(0.05)
        assert alice.heartbeats > 0
        assert alice.sock.getsockname()[1] == local_port
        assert alice.command(Kind.PING)["message"] == "pong"
        print(f"PASS persistent connection; same client port {local_port}; background PING observed")

        with open_client("bob") as bob, concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            assert bob.command(Kind.LIST)["files"] == []
            expect_error(lambda: bob.get("sample.bin", directory / "forbidden.bin"), "NOT_FOUND")
            assert not (directory / "forbidden.bin").exists()
            expect_error(lambda: alice.put(sample, "invalid name.bin"), "BAD_REQUEST")
            first = pool.submit(alice.put, sample, "alice.bin")
            second = pool.submit(bob.put, sample, "bob.bin")
            assert first.result(timeout=5) == second.result(timeout=5) == expected
            assert [entry["name"] for entry in bob.command(Kind.LIST)["files"]] == ["bob.bin"]
            bob.command(Kind.QUIT)
        print("PASS two clients active; per-user directory isolation; invalid filename refused")

        with alice.exchange():
            request = alice.request(Kind.PUT, {"name": "sample.bin", "size": 3, "sha256": "0" * 64})
            alice.receive(request, Kind.READY)
            end = deadline()
            send_frame(alice.sock, Kind.DATA, request, body_len=3, end=end)
            stream_send(alice.sock, io.BytesIO(b"abc"), 3, end)
            expect_error(lambda: alice.receive(request, Kind.OK), "INTEGRITY")
        assert alice.get("sample.bin", directory / "unchanged.bin") == expected
        print("PASS digest mismatch refused; existing file preserved")
        with open_client("alice") as interrupted:
            with interrupted.exchange():
                request = interrupted.request(
                    Kind.PUT, {"name": "interrupted.bin", "size": 5, "sha256": expected}
                )
                interrupted.receive(request, Kind.READY)
                end = deadline()
                send_frame(interrupted.sock, Kind.DATA, request, body_len=5, end=end)
                interrupted.sock.sendall(b"ab")
        assert "interrupted.bin" not in [item["name"] for item in alice.command(Kind.LIST)["files"]]
        account_dir = directory / "runtime/files/alice"
        limit = time.monotonic() + 3
        while any(account_dir.glob(".part-*")) and time.monotonic() < limit:
            time.sleep(0.05)
        assert not list(account_dir.glob(".part-*"))
        assert stat.S_IMODE(account_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((account_dir / "sample.bin").stat().st_mode) == 0o600
        print("PASS interrupted upload cleaned up; directory 0700 and file 0600")
        alice.command(Kind.QUIT)


def main():
    with tempfile.TemporaryDirectory(prefix="lab1b-test-") as temporary:
        directory = Path(temporary)
        runtime = directory / "runtime"
        print(run_tool("setup.py", "--runtime", runtime, "init"))
        run_tool("setup.py", "--runtime", directory / "untrusted", "init")
        for username in ("alice", "bob"):
            print(run_tool("setup.py", "--runtime", runtime, "add-user", username,
                           "--password-stdin", typed=PASSWORD + "\n"))
        ca = runtime / "tls" / "ca.pem"
        with subprocess.Popen(
            [sys.executable, "-u", str(SOURCE / "server.py"), "--runtime", str(runtime), "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        ) as server:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(server.stdout, selectors.EVENT_READ)
                    if not selector.select(timeout=10):
                        raise RuntimeError("server startup timed out")
                first = server.stdout.readline().strip()
                if not first.startswith("Listening on 127.0.0.1:"):
                    raise RuntimeError(first + "\n" + server.stdout.read())
                print(first)
                port = int(first.split()[2].split(":")[1])
                verify(directory, port, ca)
            finally:
                if server.poll() is None:
                    server.terminate()
                server.communicate(timeout=5)
    print("All checks passed.")


if __name__ == "__main__":
    main()

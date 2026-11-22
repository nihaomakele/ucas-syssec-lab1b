"""Exercise resume, certificate login, account limits and the browser endpoints."""
import concurrent.futures
import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import client as client_module

from client import Client, RequestError
from protocol import CHUNK_SIZE, Kind, ProtocolError, deadline, send_frame
from verify import PASSWORD, SOURCE, expect_error, run_tool, running_server


def login(port, ca, user):
    client = Client("127.0.0.1", port, ca)
    try:
        result = client.login(user, PASSWORD)
        assert result["tier"] == ("VIP" if user == "bob" else "regular"), result
        return client
    except BaseException:
        client.close()
        raise


def verify_resume(directory, port, ca, source):
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    with login(port, ca, "alice") as interrupted:
        with interrupted.exchange():
            request = interrupted.request(
                Kind.PUT, {"name": "resumed.bin", "size": len(data), "sha256": digest, "resume": True}
            )
            assert interrupted.receive(request, Kind.READY)[0]["offset"] == 0
            send_frame(interrupted.sock, Kind.DATA, request, body_len=len(data), end=deadline())
            interrupted.sock.sendall(data[:CHUNK_SIZE])
            partial = directory / "runtime/partials/alice"
            end = time.monotonic() + 5
            while not any(path.stat().st_size == CHUNK_SIZE for path in partial.glob(".upload-*")):
                if time.monotonic() > end:
                    raise AssertionError("upload did not persist its complete first block")
                time.sleep(.03)
        # Context exit cuts the connection with data still outstanding.
    with login(port, ca, "alice") as client:
        for retry in range(20):
            try:
                result = client.put(source, "resumed.bin", resume=True)
                break
            except RequestError as error:
                if "already has a resumable upload" not in str(error) or retry == 19:
                    raise
                time.sleep(.05)
        assert result == digest and client.last_resume_offset == CHUNK_SIZE
        print(f"PASS upload resumed after disconnect at byte {client.last_resume_offset}", flush=True)
        destination = directory / "download.bin"
        key = hashlib.sha256(os.fsencode(destination.name)).hexdigest()
        part = directory / (".download-" + key + ".part")
        receive = client_module.stream_receive

        def interrupt_after_one_block(sock, file, size, end, previous):
            assert size > CHUNK_SIZE
            receive(sock, file, CHUNK_SIZE, end, previous)
            raise ConnectionError("simulated interruption after reading one full block")

        with login(port, ca, "alice") as interrupted:
            with patch.object(client_module, "stream_receive", interrupt_after_one_block):
                try:
                    interrupted.get("resumed.bin", destination, resume=True)
                except ConnectionError:
                    pass
                else:
                    raise AssertionError("expected the download to be interrupted")
        assert not destination.exists() and part.read_bytes() == data[:CHUNK_SIZE]
        assert client.get("resumed.bin", destination, resume=True) == digest
        assert destination.read_bytes() == data and not part.exists()
        assert client.last_resume_offset == CHUNK_SIZE
        print(f"PASS download resumed at byte {client.last_resume_offset}", flush=True)
        part.write_bytes(b"outdated prefix")
        assert client.get("resumed.bin", destination, resume=True) == digest
        assert client.last_resume_offset == 0 and destination.read_bytes() == data
        print("PASS outdated download prefix restarted at byte 0", flush=True)


def verify_rates(port, ca, source):
    with login(port, ca, "alice") as first, login(port, ca, "alice") as second:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            start = time.monotonic()
            uploads = [pool.submit(client.put, source, f"regular-{index}.bin")
                       for index, client in enumerate((first, second))]
            for upload in uploads:
                upload.result(timeout=10)
            elapsed = time.monotonic() - start
            start = time.monotonic()
            downloads = [pool.submit(client.get, f"regular-{index}.bin", source.parent / f"rate-{index}.bin")
                         for index, client in enumerate((first, second))]
            for download in downloads:
                download.result(timeout=10)
            download_elapsed = time.monotonic() - start
    with login(port, ca, "bob") as vip:
        start = time.monotonic()
        vip.put(source, "vip.bin")
        vip_elapsed = time.monotonic() - start
        start = time.monotonic()
        vip.get("vip.bin", source.parent / "vip-copy.bin")
        vip_download = time.monotonic() - start
    payload = source.stat().st_size
    assert min(elapsed, download_elapsed) >= 2 * payload / (256 * 1024) - .02
    assert min(vip_elapsed, vip_download) >= payload / (1024 * 1024) - .02
    assert max(vip_elapsed, vip_download) < min(elapsed, download_elapsed) / 2
    print(f"PASS shared regular rate: upload {elapsed:.2f}s, download {download_elapsed:.2f}s", flush=True)
    print(f"PASS VIP rate: upload {vip_elapsed:.2f}s, download {vip_download:.2f}s", flush=True)


def verify_browser(port, ca, source):
    args = [sys.executable, "-u", str(SOURCE / "gui.py"), "--no-browser"]
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          cwd=SOURCE, text=True) as gui:
        try:
            output = gui.stdout.readline().strip()
            base, token = output.split()[-1].split("#")
            with urllib.request.urlopen(base, timeout=5) as page:
                assert "安全文件传输".encode() in page.read()

            def request(path, data=None, token_value=token):
                operation = urllib.request.Request(base + path, data=data,
                                                   headers={"X-Lab-Token": token_value})
                with urllib.request.urlopen(operation, timeout=10) as response:
                    return response.read()

            try:
                request("api/files", token_value="invalid")
                raise AssertionError("bad browser token accepted")
            except urllib.error.HTTPError as error:
                assert error.code == 403
            result = request("api/connect", json.dumps({
                "host": "127.0.0.1", "port": port, "ca": str(ca), "username": "alice",
                "password": PASSWORD, "cert": "", "key": "",
            }).encode())
            assert json.loads(result)["tier"] == "regular"
            body = source.read_bytes()
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                start = time.monotonic()
                jobs = [pool.submit(request, "api/file/gui-one.bin", body),
                        pool.submit(request, "api/file/gui-two.bin", body),
                        pool.submit(request, "api/file/resumed.bin")]
                for job in jobs[:2]:
                    assert json.loads(job.result(timeout=10))["sha256"] == hashlib.sha256(body).hexdigest()
                assert jobs[2].result(timeout=10) == body
                elapsed = time.monotonic() - start
            files = json.loads(request("api/files"))["files"]
            assert {"gui-one.bin", "gui-two.bin"} <= {entry["name"] for entry in files}
            assert request("api/file/gui-one.bin") == body
            request("api/disconnect", b"")
            print(f"PASS browser endpoints: two uploads and one download in parallel ({elapsed:.2f}s)", flush=True)
        finally:
            gui.terminate()
            gui.communicate(timeout=5)


def verify_certificates(directory, runtime, ca):
    client_dir = runtime / "client-certs/alice"
    other = directory / "untrusted"
    run_tool("setup.py", "--runtime", other, "add-user", "alice", "--password-stdin", typed=PASSWORD + "\n")
    run_tool("setup.py", "--runtime", other, "issue-client", "alice")
    untrusted = other / "client-certs/alice"
    with running_server(runtime, "--require-client-cert") as port:
        for cert in (None, untrusted):
            try:
                with Client("127.0.0.1", port, ca, certificate=cert / "client.pem" if cert else None,
                            key=cert / "client-key.pem" if cert else None) as rejected:
                    rejected.login("alice", PASSWORD)
            except (ssl.SSLError, OSError, ProtocolError):
                pass
            else:
                raise AssertionError("untrusted or absent client certificate accepted")
        with Client("127.0.0.1", port, ca, certificate=client_dir / "client.pem",
                    key=client_dir / "client-key.pem") as trusted:
            expect_error(lambda: trusted.login("bob", PASSWORD), "AUTH_FAILED")
            assert trusted.login("alice")["tier"] == "regular"
            assert trusted.command(Kind.LIST)["files"]
        print("PASS mutual TLS accepts Alice and rejects missing, untrusted and wrong-account certificates", flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix="lab1b-bonus-test-") as temporary:
        directory = Path(temporary)
        runtime = directory / "runtime"
        run_tool("setup.py", "--runtime", runtime, "init")
        run_tool("setup.py", "--runtime", runtime, "add-user", "alice", "--password-stdin", typed=PASSWORD + "\n")
        run_tool("setup.py", "--runtime", runtime, "add-user", "bob", "--vip", "--password-stdin", typed=PASSWORD + "\n")
        run_tool("setup.py", "--runtime", runtime, "issue-client", "alice")
        source = directory / "payload.bin"
        source.write_bytes(bytes(range(256)) * 1024)
        ca = runtime / "tls/ca.pem"
        with running_server(runtime, "--regular-kib", "256", "--vip-kib", "1024") as port:
            verify_resume(directory, port, ca, source)
            verify_rates(port, ca, source)
            verify_browser(port, ca, source)
        verify_certificates(directory, runtime, ca)
    print("All bonus checks passed.")


if __name__ == "__main__":
    main()

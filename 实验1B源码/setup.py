"""Create laboratory TLS credentials and local user accounts."""
import argparse
import getpass
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from storage import Storage, private_dir

EXTENSIONS = """[root]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash

[server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[client]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[req]
distinguished_name=dn

[dn]
"""


def create_tls(root):
    tls_dir = root / "tls"
    if tls_dir.exists():
        raise ValueError("TLS directory already exists; use a different runtime for new credentials")
    if shutil.which("openssl") is None:
        raise ValueError("OpenSSL or LibreSSL is required for this deployment command")
    with tempfile.TemporaryDirectory(prefix=".tls-", dir=root) as staging:
        stage = Path(staging)
        (stage / "extensions.cnf").write_text(EXTENSIONS)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=stage, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-x509", "-sha256",
                "-days", "365", "-subj", "/CN=Lab 1B Local CA", "-config", "extensions.cnf",
                "-extensions", "root", "-out", "ca.pem", "-keyout", "ca-key.pem")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj",
                "/CN=localhost", "-config", "extensions.cnf", "-out", "server.csr",
                "-keyout", "server-key.pem")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca-key.pem",
                "-CAcreateserial", "-out", "server.pem", "-days", "90", "-sha256",
                "-extfile", "extensions.cnf", "-extensions", "server")
        openssl("verify", "-CAfile", "ca.pem", "server.pem")
        ready = private_dir(stage / "ready")
        for name in ("ca.pem", "server.pem", "server-key.pem"):
            (stage / name).rename(ready / name)
        (ready / "server-key.pem").chmod(0o600)
        ready.rename(tls_dir)


def issue_client(storage, username):
    if storage.tier(username) is None:
        raise ValueError("create the user before issuing a client certificate")
    root = storage.root
    ca = root / "client-ca"
    issued = private_dir(root / "client-certs")
    target = issued / username
    if target.exists():
        raise ValueError("a client certificate already exists for this user")
    with tempfile.TemporaryDirectory(prefix=".client-cert-", dir=root) as staging:
        stage = Path(staging)
        (stage / "extensions.cnf").write_text(EXTENSIONS)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=stage, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if not ca.exists():
            new_ca = private_dir(stage / "client-ca")
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-x509", "-sha256",
                    "-days", "365", "-subj", "/CN=Lab 1B Client CA", "-config", "extensions.cnf",
                    "-extensions", "root", "-out", str(new_ca / "ca.pem"),
                    "-keyout", str(new_ca / "ca-key.pem"))
            new_ca.rename(ca)
        ready = private_dir(stage / "issued")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj",
                f"/CN={username}", "-config", "extensions.cnf", "-out", "client.csr",
                "-keyout", str(ready / "client-key.pem"))
        openssl("x509", "-req", "-in", "client.csr", "-CA", str(ca / "ca.pem"),
                "-CAkey", str(ca / "ca-key.pem"), "-set_serial", str(int.from_bytes(os.urandom(16), "big") + 1),
                "-out", str(ready / "client.pem"), "-days", "90", "-sha256",
                "-extfile", "extensions.cnf", "-extensions", "client")
        openssl("verify", "-purpose", "sslclient", "-CAfile", str(ca / "ca.pem"),
                str(ready / "client.pem"))
        ready.rename(target)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=Path("runtime"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    user = commands.add_parser("add-user")
    user.add_argument("username")
    user.add_argument("--vip", action="store_true")
    certificate = commands.add_parser("issue-client")
    certificate.add_argument("username")
    user.add_argument("--password-stdin", action="store_true", help="read one line from standard input")
    options = parser.parse_args()
    os.umask(0o077)
    try:
        storage = Storage(options.runtime.resolve())
        if options.command == "init":
            create_tls(storage.root)
            print("TLS initialized. Only distribute runtime/tls/ca.pem to clients.")
        elif options.command == "issue-client":
            print(f"Client certificate: {issue_client(storage, options.username)}")
        else:
            password = (sys.stdin.readline().rstrip("\r\n") if options.password_stdin
                        else getpass.getpass("Password: "))
            if not options.password_stdin and password != getpass.getpass("Confirm password: "):
                raise ValueError("passwords differ")
            storage.add_user(options.username, password, options.vip)
            print(f"Account created: {options.username}")
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"OpenSSL failed: {error.stderr.strip()}\n")
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(1, f"Setup failed: {error}\n")


if __name__ == "__main__":
    main()

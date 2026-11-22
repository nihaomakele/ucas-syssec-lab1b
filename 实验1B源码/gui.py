"""Serve the browser client on loopback without third-party dependencies."""
import argparse
import hmac
import json
import secrets
import shutil
import tempfile
import threading
import webbrowser
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from client import Client, RequestError
from protocol import CHUNK_SIZE, MAX_FILE, Kind, ProtocolError
from storage import valid_filename

ASSETS = Path(__file__).resolve().parent
STATIC = {
    "/": ("gui.html", "text/html"),
    "/gui.css": ("gui.css", "text/css"),
    "/gui.js": ("gui.js", "text/javascript"),
}


class BrowserSession:
    def __init__(self):
        self.lock = threading.Lock()
        self.session = self.credentials = None
        self.transfers = threading.BoundedSemaphore(3)

    @staticmethod
    def open_session(host, port, ca, user, password, certificate, key):
        client = Client(host, port, ca, certificate=certificate, key=key)
        try:
            account = client.login(user, password)
        except BaseException:
            client.close()
            raise
        return client, account

    def connect(self, data):
        host, port, user = data.get("host"), data.get("port"), data.get("username")
        cert, key = data.get("cert"), data.get("key")
        if host not in ("127.0.0.1", "localhost") or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("请使用 127.0.0.1 或 localhost 和有效端口。")
        if not all(isinstance(data.get(name), str) for name in ("ca", "username", "password", "cert", "key")):
            raise ValueError("连接参数格式错误。")
        credentials = (host, port, data["ca"], user, data["password"], cert or None, key or None)
        with self.lock:
            session, account = self.open_session(*credentials)
            if self.session is not None:
                self.session.close()
            self.session = session
            self.credentials = credentials
            return {"tier": account.get("tier", "regular"), "tls": session.tls_version}

    def close(self):
        with self.lock:
            if self.session is not None:
                self.session.close()
            self.session = self.credentials = None

    def files(self):
        with self.lock:
            if self.session is None:
                raise ValueError("请先连接。")
            return self.session.command(Kind.LIST)

    def worker(self):
        with self.lock:
            credentials = self.credentials
        if credentials is None:
            raise ValueError("请先连接。")
        return self.open_session(*credentials)[0]


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_):
        pass

    def send_asset_headers(self, length, media_type):
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")

    def reply(self, value, status=200):
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_asset_headers(len(data), "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(data)

    def allowed(self, authenticated=True):
        host = f"127.0.0.1:{self.server.server_port}"
        origin = self.headers.get("Origin")
        if self.headers.get("Host") != host or origin not in (None, f"http://{host}"):
            return False
        if not authenticated:
            return True
        value = self.headers.get("X-Lab-Token", "")
        return value.isascii() and hmac.compare_digest(value, self.server.token)

    def content_length(self, maximum):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= maximum:
            raise ValueError("请求太大。")
        return length

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in STATIC:
            if not self.allowed(authenticated=False):
                self.reply({"error": "本机访问校验失败。"}, 403)
                return
            name, media = STATIC[path]
            data = (ASSETS / name).read_bytes()
            self.send_response(200)
            self.send_asset_headers(len(data), media + "; charset=utf-8")
            self.end_headers()
            self.wfile.write(data)
        else:
            self.dispatch(path)

    def do_POST(self):
        self.dispatch(urlsplit(self.path).path)

    def dispatch(self, path):
        if not self.allowed():
            self.reply({"error": "请用启动命令给出的完整链接打开界面。"}, 403)
            return
        bridge = self.server.bridge
        try:
            if path == "/api/connect" and self.command == "POST":
                data = json.loads(self.rfile.read(self.content_length(8192)))
                if not isinstance(data, dict):
                    raise ValueError("连接参数格式错误。")
                self.reply(bridge.connect(data))
            elif path == "/api/disconnect" and self.command == "POST":
                bridge.close()
                self.reply({})
            elif path == "/api/files" and self.command == "GET":
                self.reply(bridge.files())
            elif path.startswith("/api/file/"):
                self.transfer(bridge, unquote(path[len("/api/file/"):]))
            else:
                self.reply({"error": "找不到此操作。"}, 404)
        except (ValueError, OSError, RequestError, ProtocolError) as error:
            with suppress(OSError):
                self.reply({"error": str(error)}, 400)

    def transfer(self, bridge, name):
        if not valid_filename(name):
            raise ValueError("文件名只能包含字母、数字、点、横线和下划线，并以字母或数字开头。")
        if not bridge.transfers.acquire(blocking=False):
            self.reply({"error": "并行传输已满，请稍后重试。"}, 429)
            return
        try:
            with tempfile.TemporaryDirectory(prefix="lab1b-gui-") as directory, bridge.worker() as client:
                local = Path(directory) / name
                if self.command == "POST":
                    remaining = self.content_length(MAX_FILE)
                    with local.open("wb") as file:
                        while remaining:
                            block = self.rfile.read(min(CHUNK_SIZE, remaining))
                            if not block:
                                raise ValueError("上传在文件结束前中断。")
                            file.write(block)
                            remaining -= len(block)
                    self.reply({"sha256": client.put(local, name)})
                else:
                    client.get(name, local)
                    with local.open("rb") as file:
                        self.send_response(200)
                        self.send_asset_headers(local.stat().st_size, "application/octet-stream")
                        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(name)}")
                        self.end_headers()
                        with suppress(OSError):
                            shutil.copyfileobj(file, self.wfile)
        finally:
            bridge.transfers.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web-port", type=int, default=0)
    parser.add_argument("--no-browser", action="store_true")
    options = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", options.web_port), Handler) as server:
        server.bridge = BrowserSession()
        server.token = secrets.token_urlsafe(24)
        url = f"http://127.0.0.1:{server.server_port}/#{server.token}"
        print(f"图形界面 {url}", flush=True)
        if not options.no_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.bridge.close()


if __name__ == "__main__":
    main()

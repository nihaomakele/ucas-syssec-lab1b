"""Application frames carried inside one authenticated TLS connection."""
import hashlib
import json
import re
import socket
import struct
import time
from enum import IntEnum

MAGIC = b"SFT1"
VERSION = 1
HEADER = struct.Struct("!4sBBHIIQ")
MAX_METADATA = 32 * 1024
MAX_FILE = 32 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
IO_TIMEOUT = 15
FRAME_TIMEOUT = 90
TRANSFER_TIMEOUT = 180


class Kind(IntEnum):
    LOGIN = 1
    LIST = 2
    PUT = 3
    DATA = 4
    GET = 5
    PING = 6
    QUIT = 7
    OK = 128
    ERROR = 129
    READY = 130


class ProtocolError(Exception):
    """A malformed or incomplete frame requires closing the connection."""


def _reject_duplicate_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def deadline(seconds=FRAME_TIMEOUT):
    return time.monotonic() + seconds


def _set_timeout(sock, end, limit=IO_TIMEOUT):
    remaining = end - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("exchange deadline exceeded")
    sock.settimeout(min(limit, remaining))


def _read_exact(sock, size, end, allow_eof=False, first_timeout=IO_TIMEOUT):
    data = bytearray()
    while len(data) < size:
        _set_timeout(sock, end, first_timeout if not data else IO_TIMEOUT)
        block = sock.recv(size - len(data))
        if not block:
            if not data and allow_eof:
                return None
            raise ProtocolError("peer closed before the frame was complete")
        data.extend(block)
    return bytes(data)


def recv_frame(sock, end=None, idle_timeout=IO_TIMEOUT):
    # The first byte may wait during an idle session; the rest must arrive promptly.
    if end is None:
        end = time.monotonic() + idle_timeout + FRAME_TIMEOUT
    first = _read_exact(sock, 1, end, allow_eof=True, first_timeout=idle_timeout)
    if first is None:
        return None
    end = min(end, deadline())
    raw = first + _read_exact(sock, HEADER.size - 1, end)
    magic, version, kind, reserved, request_id, meta_len, body_len = HEADER.unpack(raw)
    if (magic != MAGIC or version != VERSION or reserved != 0 or request_id == 0
            or meta_len > MAX_METADATA or body_len > MAX_FILE):
        raise ProtocolError("invalid frame header")
    try:
        kind = Kind(kind)
        raw_meta = _read_exact(sock, meta_len, end) if meta_len else b"{}"
        metadata = json.loads(raw_meta.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, RecursionError) as error:
        raise ProtocolError("invalid message type or JSON metadata") from error
    if not isinstance(metadata, dict) or (body_len and kind != Kind.DATA):
        raise ProtocolError("invalid metadata or unexpected body")
    return kind, request_id, metadata, body_len


def send_frame(sock, kind, request_id, metadata=None, body_len=0, end=None):
    raw_meta = (json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                if metadata else b"")
    if len(raw_meta) > MAX_METADATA or not 0 <= body_len <= MAX_FILE:
        raise ProtocolError("outgoing frame exceeds size limits")
    if end is None:
        end = deadline()
    _set_timeout(sock, end)
    sock.sendall(HEADER.pack(MAGIC, VERSION, kind, 0, request_id, len(raw_meta), body_len) + raw_meta)


def stream_send(sock, source, size, end, throttle=None):
    while size:
        block = source.read(min(CHUNK_SIZE, size))
        if not block:
            raise ProtocolError("source became shorter during transfer")
        if throttle:
            throttle(len(block), end)
        _set_timeout(sock, end)
        sock.sendall(block)
        size -= len(block)


def stream_receive(sock, destination, size, end, digest=None, throttle=None):
    if digest is None:
        digest = hashlib.sha256()
    while size:
        amount = min(CHUNK_SIZE, size)
        if throttle:
            throttle(amount, end)
        block = _read_exact(sock, amount, end)
        destination.write(block)
        digest.update(block)
        size -= len(block)
    return digest.hexdigest()


def measure(source):
    digest = hashlib.sha256()
    size = 0
    while True:
        block = source.read(CHUNK_SIZE)
        if not block:
            break
        size += len(block)
        if size > MAX_FILE:
            raise ValueError("file exceeds 32 MiB")
        digest.update(block)
    source.seek(0)
    return size, digest.hexdigest()


def prefix_digest(file, length):
    """Hash the first length bytes and leave the stream at that offset."""
    file.seek(0)
    digest = hashlib.sha256()
    while length:
        data = file.read(min(CHUNK_SIZE, length))
        if not data:
            raise ValueError("file changed while reading its prefix")
        digest.update(data)
        length -= len(data)
    return digest


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def enable_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

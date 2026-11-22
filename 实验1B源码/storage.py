"""Private server storage and parameterized SQLite authentication."""
import hashlib
import hmac
import os
import re
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from protocol import MAX_FILE

ROUNDS = 600_000
MAX_FILES = 100
USER_QUOTA = 128 * 1024 * 1024
DUMMY_SALT = bytes(16)
DUMMY_DIGEST = bytes(32)


def valid_user(name):
    return isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]{2,23}", name) is not None


def valid_password(password):
    return isinstance(password, str) and len(password) <= 128 and all(
        32 <= ord(character) <= 126 for character in password
    )


def valid_filename(name):
    return (isinstance(name, str) and 0 < len(name) <= 64
            and name[0].isalnum()
            and all(character.isalnum() or character in "._-" for character in name))


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ROUNDS)


def private_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError(f"directory must be owned by the server user: {path}")
    path.chmod(0o700)
    return path


class Storage:
    def __init__(self, root):
        self.root = private_dir(Path(root))
        self.files = private_dir(self.root / "files")
        self.db = self.root / "accounts.sqlite3"
        with closing(self.connection()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS accounts (
                username TEXT PRIMARY KEY, salt BLOB NOT NULL, digest BLOB NOT NULL
            )""")
        self.db.chmod(0o600)

    def connection(self):
        if self.db.is_symlink():
            raise ValueError("the account database must not be a symbolic link")
        return sqlite3.connect(self.db, timeout=5)

    def add_user(self, username, password):
        if not valid_user(username):
            raise ValueError("username must start with a lowercase letter and have 3–24 letters, digits or underscores")
        if not valid_password(password) or len(password) < 12:
            raise ValueError("password must have 12–128 printable ASCII characters")
        salt = os.urandom(16)
        with closing(self.connection()) as db, db:
            db.execute("INSERT INTO accounts VALUES (?, ?, ?)",
                       (username, salt, password_digest(password, salt)))
            self.user_dir(username)

    def authenticate(self, username, password):
        if not valid_user(username) or not valid_password(password):
            return False
        with closing(self.connection()) as db:
            account = db.execute(
                "SELECT salt, digest FROM accounts WHERE username = ?", (username,)
            ).fetchone()
        salt, expected = account if account else (DUMMY_SALT, DUMMY_DIGEST)
        matches = hmac.compare_digest(password_digest(password, salt), expected)
        return account is not None and matches

    def user_dir(self, username):
        if not valid_user(username):
            raise ValueError("invalid username")
        return private_dir(self.files / username)

    def entries(self, username):
        results = []
        for path in self.user_dir(username).iterdir():
            if valid_filename(path.name):
                info = path.lstat()
                if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE:
                    results.append({"name": path.name, "size": info.st_size})
        return sorted(results, key=lambda entry: entry["name"])

    def target(self, username, name):
        if not valid_filename(name):
            raise ValueError("invalid filename")
        path = self.user_dir(username) / name
        if path.is_symlink():
            raise ValueError("symbolic links are not accessible")
        return path

    def check_quota(self, username, target, size):
        # Also handle filesystems that resolve an existing name case-insensitively.
        entries = self.entries(username)
        previous_size = target.stat().st_size if target.is_file() else None
        if previous_size is None and len(entries) >= MAX_FILES:
            raise ValueError("account file count limit reached")
        if sum(entry["size"] for entry in entries) - (previous_size or 0) + size > USER_QUOTA:
            raise ValueError("account storage quota exceeded")

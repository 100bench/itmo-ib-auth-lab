"""Локальный учебный стенд для работ №13–14; не запускать в открытой сети."""

from __future__ import annotations

import hashlib
import html
import secrets
import sqlite3
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs


@dataclass
class LoginResult:
    ok: bool
    message: str


class VulnerableAuth:
    """Преднамеренно уязвимая версия для изолированной лаборатории."""

    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE users (username TEXT, password TEXT)")
        self.db.execute("INSERT INTO users VALUES ('alice', 'correct-horse')")
        self.db.commit()

    def login(self, username: str, password: str) -> LoginResult:
        # V1: SQL-инъекция — конкатенация пользовательского ввода.
        query = (
            "SELECT username FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        # V2: пароль в базе хранится открытым текстом.
        # V3: длина и состав ввода не проверяются.
        # V4: число попыток не ограничено.
        row = self.db.execute(query).fetchone()
        if row:
            return LoginResult(True, "Вход выполнен")
        # V5: сообщение раскрывает существование учётной записи.
        exists = self.db.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        return LoginResult(False, "Неверный пароль" if exists else "Пользователь не найден")


class SecureAuth:
    """Исправленная версия: параметризация, scrypt, проверка и блокировка."""

    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE users (username TEXT, salt BLOB, digest BLOB)")
        salt = secrets.token_bytes(16)
        digest = self._hash("correct-horse", salt)
        self.db.execute(
            "INSERT INTO users VALUES (?, ?, ?)", ("alice", salt, digest)
        )
        self.db.commit()
        self.failures: dict[str, tuple[int, float]] = {}

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
        )

    def login(self, username: str, password: str) -> LoginResult:
        # S3: ограничение длины и допустимых символов.
        if not (1 <= len(username) <= 64 and username.replace("_", "").isalnum()):
            return LoginResult(False, "Неверные учётные данные")
        if not (1 <= len(password) <= 128):
            return LoginResult(False, "Неверные учётные данные")

        # S4: временное ограничение перебора в рамках лабораторного процесса.
        count, locked_until = self.failures.get(username, (0, 0.0))
        if locked_until > time.monotonic():
            return LoginResult(False, "Временно ограничены попытки входа")

        # S1: параметризованный запрос; данные не становятся SQL-кодом.
        row = self.db.execute(
            "SELECT salt, digest FROM users WHERE username = ?", (username,)
        ).fetchone()
        # S2: соль и scrypt; одинаковые сообщения для известных и неизвестных имён.
        salt, digest = row if row else (b"\x00" * 16, b"\x00" * 32)
        candidate = self._hash(password, salt)
        ok = row is not None and secrets.compare_digest(candidate, digest)
        if ok:
            self.failures.pop(username, None)
            return LoginResult(True, "Вход выполнен")
        count += 1
        self.failures[username] = (count, time.monotonic() + 60 if count >= 5 else 0.0)
        return LoginResult(False, "Неверные учётные данные")


VULNERABLE = VulnerableAuth()
SECURE = SecureAuth()


class Handler(BaseHTTPRequestHandler):
    def send_page(self, version: str, message: str = ""):
        body = (
            "<!doctype html><meta charset='utf-8'><title>Учебный вход</title>"
            f"<h1>Вход: {html.escape(version)}</h1>"
            f"<form method='post' action='/{version}'>"
            "<label>Логин <input name='username' required></label><br>"
            "<label>Пароль <input type='password' name='password' required></label><br>"
            "<button>Войти</button></form>"
            f"<p>{html.escape(message)}</p>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path not in ("/vulnerable", "/secure"):
            self.send_response(302)
            self.send_header("Location", "/vulnerable")
            self.end_headers()
            return
        self.send_page(self.path[1:])

    def do_POST(self):
        if self.path not in ("/vulnerable", "/secure"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 4096:
            self.send_error(413)
            return
        form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        target = VULNERABLE if self.path == "/vulnerable" else SECURE
        try:
            result = target.login(username, password)
            self.send_page(self.path[1:], result.message)
        except sqlite3.Error:
            self.send_page(self.path[1:], "Ошибка запроса SQL" if target is VULNERABLE else "Ошибка входа")


if __name__ == "__main__":
    print("Локальный стенд: http://127.0.0.1:8008/vulnerable и /secure")
    HTTPServer(("127.0.0.1", 8008), Handler).serve_forever()

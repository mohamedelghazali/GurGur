from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

TEST_KEY = "test-only-gurgur-key-0123456789abcdef"
os.environ.setdefault("LAB_API_KEY", TEST_KEY)
os.environ.setdefault("LAB_DATABASE_PATH", "/tmp/gurgur-test-import.sqlite3")

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


class QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"local-lab-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture
def api_key() -> str:
    return TEST_KEY


@pytest.fixture
def target_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def client(tmp_path, api_key):
    settings = Settings(api_key=api_key, database_path=tmp_path / "gurgur.sqlite3")
    application = create_app(settings)
    with TestClient(application) as test_client:
        yield test_client

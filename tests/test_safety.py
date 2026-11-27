from fastapi import HTTPException
import pytest

from app.safety import validate_private_target, validate_target_url
from app.config import Settings


@pytest.mark.parametrize("address", ["127.0.0.1", "127.12.1.2", "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.10.8"])
def test_accepts_only_private_or_loopback_ipv4(address):
    assert validate_private_target(address) == address


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "::1", "localhost"])
def test_rejects_non_private_or_non_ipv4_targets(address):
    with pytest.raises(HTTPException):
        validate_private_target(address)


def test_rejects_target_url_with_custom_path_or_query():
    with pytest.raises(HTTPException):
        validate_target_url("http://127.0.0.1:8081/admin?x=1")


def test_rejects_non_private_url_even_if_persisted():
    with pytest.raises(HTTPException):
        validate_target_url("http://203.0.113.10:8081/")


def test_configuration_requires_strong_api_key(monkeypatch):
    monkeypatch.setenv("LAB_API_KEY", "too-short")
    with pytest.raises(RuntimeError, match="LAB_API_KEY is required"):
        Settings.from_env()


def test_configuration_refuses_non_loopback_bind(monkeypatch):
    monkeypatch.setenv("LAB_API_KEY", "x" * 48)
    monkeypatch.setenv("LAB_BIND_HOST", "0.0.0.0")
    with pytest.raises(RuntimeError, match="Remote binding is disabled"):
        Settings.from_env()


def test_container_mode_requires_loopback_publish_ack(monkeypatch):
    monkeypatch.setenv("LAB_API_KEY", "x" * 48)
    monkeypatch.setenv("LAB_CONTAINER_MODE", "1")
    monkeypatch.delenv("LAB_CONTAINER_BIND_ACK", raising=False)
    with pytest.raises(RuntimeError, match="LAB_CONTAINER_BIND_ACK=127.0.0.1"):
        Settings.from_env()


def test_supported_launcher_uses_loopback_by_default(monkeypatch):
    from app import __main__ as launcher

    called = {}
    monkeypatch.setenv("LAB_API_KEY", "x" * 48)
    monkeypatch.setenv("LAB_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("LAB_BIND_PORT", "8000")
    monkeypatch.delenv("LAB_CONTAINER_MODE", raising=False)
    monkeypatch.setattr(launcher.uvicorn, "run", lambda *args, **kwargs: called.update(kwargs))

    launcher.main()

    assert called["host"] == "127.0.0.1"
    assert called["port"] == 8000
    assert called["reload"] is False

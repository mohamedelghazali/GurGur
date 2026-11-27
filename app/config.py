from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    api_key: str
    database_path: Path
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    max_rps: int = 10
    max_duration_seconds: int = 30
    max_concurrency: int = 5
    max_requests_per_run: int = 300
    request_timeout_seconds: float = 2.0
    max_response_bytes: int = 16_384

    @classmethod
    def from_env(cls) -> "Settings":
        api_key = os.getenv("LAB_API_KEY", "").strip()
        if len(api_key) < 32:
            raise RuntimeError(
                "LAB_API_KEY is required and must contain at least 32 characters. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )

        container_mode = os.getenv("LAB_CONTAINER_MODE", "0").strip() == "1"
        if container_mode:
            if os.getenv("LAB_CONTAINER_BIND_ACK", "") != "127.0.0.1":
                raise RuntimeError(
                    "Container mode requires LAB_CONTAINER_BIND_ACK=127.0.0.1. "
                    "The supplied Compose file publishes the host port on loopback only."
                )
            bind_host = "0.0.0.0"  # container interface; Compose publishes only on host loopback
        else:
            bind_host = os.getenv("LAB_BIND_HOST", "127.0.0.1").strip()
            if bind_host not in {"127.0.0.1", "localhost"}:
                raise RuntimeError(
                    "Remote binding is disabled in the local profile. Keep LAB_BIND_HOST=127.0.0.1; "
                    "a separately reviewed authenticated deployment profile is required for remote access."
                )

        bind_port = int(os.getenv("LAB_BIND_PORT", "8000"))
        if not 1024 <= bind_port <= 65535:
            raise RuntimeError("LAB_BIND_PORT must be between 1024 and 65535.")

        return cls(
            api_key=api_key,
            database_path=Path(os.getenv("LAB_DATABASE_PATH", "./data/gurgur.sqlite3")),
            bind_host=bind_host,
            bind_port=bind_port,
        )

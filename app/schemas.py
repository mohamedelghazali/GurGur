from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=60, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    ip: str = Field(min_length=7, max_length=15)
    port: int = Field(ge=1024, le=65535)
    scheme: Literal["http", "https"] = "http"


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=36, max_length=36)
    requests_per_second: int = Field(default=2, ge=1, le=10)
    duration_seconds: int = Field(default=5, ge=1, le=30)
    concurrency: int = Field(default=2, ge=1, le=5)


class StopResponse(BaseModel):
    run_id: str
    status: Literal["stopping", "already_finished"]


class AuditCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    algorithm: Literal["HMAC-SHA256"]
    key_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    created_at: str = Field(min_length=20, max_length=40)
    event_count: int = Field(ge=0)
    head_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

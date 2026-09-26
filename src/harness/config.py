"""User configuration management for security-agent-harness.

Stores persistent user preferences in ~/.config/security-agent-harness/config.json
so operators do not have to pass redundant flags on every run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field

CONFIG_DIR_NAME = "security-agent-harness"
CONFIG_FILE_NAME = "config.json"


def get_config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        p = Path(base) / CONFIG_DIR_NAME
    else:
        p = Path.home() / ".config" / CONFIG_DIR_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_config_path() -> Path:
    return get_config_dir() / CONFIG_FILE_NAME


class UserConfig(BaseModel):
    default_backend: str = Field(default="scripted", description="Default model backend")
    default_model: str = Field(default="scripted-planner", description="Default model id")
    default_endpoint: str | None = Field(default=None, description="Default endpoint URL")
    default_skill: str = Field(default="port_scan", description="Default skill")
    default_target: str | None = Field(default=None, description="Default scope target alias")
    default_scope: str | None = Field(default=None, description="Default scope.json path")
    default_public_key: str | None = Field(default=None, description="Default scope public key path")
    approval_mode: str = Field(default="deny", description="Default approval mode: deny | approve | scripted")
    enable_remote_egress: bool = Field(default=False, description="Whether remote egress is enabled by default")
    api_keys: dict[str, str] = Field(default_factory=dict, description="Backend API keys (backend -> key)")


def load_user_config() -> UserConfig:
    path = get_config_path()
    if not path.is_file():
        return UserConfig()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return UserConfig.model_validate(data)
    except Exception:
        return UserConfig()


def save_user_config(config: UserConfig) -> Path:
    path = get_config_path()
    from harness.util import atomic_write_json
    atomic_write_json(path, config.model_dump(mode="json"))
    return path


def resolve_api_key(backend: str) -> str | None:
    """Look up API key for a backend from environment variables or saved config."""
    clean_backend = backend.strip().lower()
    env_keys = [
        f"{clean_backend.upper()}_API_KEY",
        "HARNESS_API_KEY",
        "OPENAI_API_KEY",
    ]
    if clean_backend == "deepseek":
        env_keys = ["DEEPSEEK_API_KEY", "HARNESS_API_KEY", "OPENAI_API_KEY"]
    elif clean_backend == "openrouter":
        env_keys = ["OPENROUTER_API_KEY", "HARNESS_API_KEY"]
    elif clean_backend == "groq":
        env_keys = ["GROQ_API_KEY", "HARNESS_API_KEY"]
    elif clean_backend == "anthropic":
        env_keys = ["ANTHROPIC_API_KEY", "HARNESS_API_KEY"]

    for env_var in env_keys:
        val = os.environ.get(env_var)
        if val and val.strip():
            return val.strip()

    cfg = load_user_config()
    if clean_backend in cfg.api_keys:
        return cfg.api_keys[clean_backend]
    if "default" in cfg.api_keys:
        return cfg.api_keys["default"]
    return None

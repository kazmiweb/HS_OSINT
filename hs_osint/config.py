"""Configuration loading for providers and runtime settings."""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_ENABLED_PROVIDERS = [
    "github_repositories",
    "wayback",
    "social_profiles",
    "local_files",
    "generic_http",
    "breach_metadata",
]


@dataclass(frozen=True)
class GenericHttpService:
    name: str
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    json_path: str | None = None
    requires_lawful_use_ack: bool = False
    metadata_only: bool = True


@dataclass(frozen=True)
class AppConfig:
    enabled_providers: list[str] = field(default_factory=lambda: DEFAULT_ENABLED_PROVIDERS.copy())
    local_paths: list[str] = field(default_factory=lambda: ["data"])
    social_platforms: dict[str, str] = field(
        default_factory=lambda: {
            "github": "https://github.com/{username}",
            "reddit": "https://www.reddit.com/user/{username}",
            "x": "https://x.com/{username}",
            "instagram": "https://www.instagram.com/{username}/",
            "tiktok": "https://www.tiktok.com/@{username}",
        }
    )
    generic_services: list[GenericHttpService] = field(default_factory=list)
    breach_api_url: str | None = None
    breach_api_key_env: str | None = None
    openai_compatible_url: str | None = None
    openai_api_key_env: str | None = None
    openai_model: str = "gpt-4o-mini"


def load_config(path: str | None) -> AppConfig:
    if not path:
        return AppConfig()

    config_path = Path(path)
    data = _read_config(config_path)
    providers = data.get("providers", {})
    ai = data.get("ai", {})

    services = [
        GenericHttpService(
            name=item["name"],
            url=item["url"],
            method=item.get("method", "GET"),
            headers=_expand_env_mapping(item.get("headers", {})),
            params=item.get("params", {}),
            json_path=item.get("json_path"),
            requires_lawful_use_ack=item.get("requires_lawful_use_ack", False),
            metadata_only=item.get("metadata_only", True),
        )
        for item in providers.get("generic_http", {}).get("services", [])
    ]

    return AppConfig(
        enabled_providers=data.get("enabled_providers", DEFAULT_ENABLED_PROVIDERS.copy()),
        local_paths=providers.get("local_files", {}).get("paths", ["data"]),
        social_platforms=providers.get("social_profiles", {}).get(
            "platforms", AppConfig().social_platforms
        ),
        generic_services=services,
        breach_api_url=providers.get("breach_metadata", {}).get("api_url"),
        breach_api_key_env=providers.get("breach_metadata", {}).get("api_key_env"),
        openai_compatible_url=ai.get("openai_compatible_url"),
        openai_api_key_env=ai.get("api_key_env"),
        openai_model=ai.get("model", "gpt-4o-mini"),
    )


def _read_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        if path.suffix.lower() == ".json":
            return json.loads(fh.read().decode("utf-8"))
        if path.suffix.lower() == ".toml":
            return tomllib.load(fh)
    raise ValueError("Config must be JSON or TOML")


def _expand_env_mapping(mapping: dict[str, str]) -> dict[str, str]:
    expanded: dict[str, str] = {}
    for key, value in mapping.items():
        if value.startswith("env:"):
            expanded[key] = os.getenv(value.removeprefix("env:"), "")
        else:
            expanded[key] = value
    return expanded

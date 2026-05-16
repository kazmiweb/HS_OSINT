"""Shared models for query analysis, providers, and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class QueryType(str, Enum):
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    HASH = "hash"
    PERSON_NAME = "person_name"
    KEYWORD = "keyword"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class QueryAnalysis:
    """Normalized interpretation of the user's search query."""

    original: str
    normalized: str
    query_types: list[str]
    entities: dict[str, list[str]]
    intent: str
    risk_flags: list[str] = field(default_factory=list)
    suggested_providers: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProviderCapability:
    """Describes what a provider can search and what safeguards apply."""

    query_types: set[str]
    risk_level: RiskLevel = RiskLevel.LOW
    requires_lawful_use_ack: bool = False
    metadata_only: bool = True


@dataclass
class SearchResult:
    """A single normalized OSINT result."""

    provider: str
    title: str
    value: str
    url: str | None = None
    snippet: str | None = None
    score: float = 0.0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SearchContext:
    """Runtime options shared across providers."""

    max_results: int = 10
    timeout_seconds: float = 10.0
    lawful_use_acknowledged: bool = False
    include_raw: bool = False


@dataclass(frozen=True)
class ProviderDecision:
    """Decision made by the safety policy before running a provider."""

    allowed: bool
    reason: str | None = None

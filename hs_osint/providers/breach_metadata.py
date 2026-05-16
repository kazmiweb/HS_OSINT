"""Metadata-only breach exposure provider.

This provider is intentionally limited to breach/exposure metadata. It does not
retrieve, display, or store passwords, session tokens, or raw credential dumps.
"""

from __future__ import annotations

import os
from typing import Any

from hs_osint.models import ProviderCapability, QueryAnalysis, QueryType, RiskLevel, SearchContext, SearchResult
from hs_osint.providers.base import BaseProvider, ProviderError, http_json


class BreachMetadataProvider(BaseProvider):
    name = "breach_metadata"
    capability = ProviderCapability(
        query_types={QueryType.EMAIL.value, QueryType.DOMAIN.value, QueryType.USERNAME.value},
        risk_level=RiskLevel.HIGH,
        requires_lawful_use_ack=True,
        metadata_only=True,
    )

    def __init__(self, api_url: str | None = None, api_key_env: str | None = None) -> None:
        self.api_url = api_url
        self.api_key_env = api_key_env

    def search(self, analysis: QueryAnalysis, context: SearchContext) -> list[SearchResult]:
        if not self.api_url:
            return [
                SearchResult(
                    provider=self.name,
                    title="Breach metadata provider not configured",
                    value="Add a metadata-only breach API in config.toml to enable this connector.",
                    score=0.0,
                    tags=["setup_required"],
                )
            ]

        headers = {"User-Agent": "HS-OSINT/0.1"}
        if self.api_key_env:
            api_key = os.getenv(self.api_key_env)
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

        try:
            payload = http_json(
                self.api_url.format(query=analysis.normalized),
                headers=headers,
                timeout_seconds=context.timeout_seconds,
            )
        except (ProviderError, KeyError) as exc:
            return [
                SearchResult(
                    provider=self.name,
                    title="Breach metadata search unavailable",
                    value=str(exc),
                    score=0.0,
                    tags=["error"],
                )
            ]

        records = payload if isinstance(payload, list) else [payload]
        return [
            SearchResult(
                provider=self.name,
                title="Breach exposure metadata",
                value=_summary(record),
                snippet="Metadata-only exposure result; raw credentials are not collected.",
                score=1.0,
                tags=["breach_metadata", "metadata_only"],
                metadata={"record": _metadata_only(record)},
            )
            for record in records[: context.max_results]
        ]


def _summary(record: Any) -> str:
    if isinstance(record, dict):
        for key in ("name", "title", "breach", "source", "domain"):
            if key in record:
                return str(record[key])
    return str(record)[:120]


def _metadata_only(record: Any) -> Any:
    if not isinstance(record, dict):
        return record
    blocked = {"password", "passwords", "hash", "hashes", "token", "secret", "cookie"}
    return {key: value for key, value in record.items() if key.lower() not in blocked}

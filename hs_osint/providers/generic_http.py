"""Configurable HTTP JSON provider for user-owned APIs."""

from __future__ import annotations

from typing import Any

from hs_osint.config import GenericHttpService
from hs_osint.models import ProviderCapability, QueryAnalysis, QueryType, RiskLevel, SearchContext, SearchResult
from hs_osint.providers.base import BaseProvider, ProviderError, http_json


class GenericHttpProvider(BaseProvider):
    name = "generic_http"
    capability = ProviderCapability(
        query_types={item.value for item in QueryType},
        risk_level=RiskLevel.MEDIUM,
        requires_lawful_use_ack=False,
        metadata_only=True,
    )

    def __init__(self, services: list[GenericHttpService]) -> None:
        self.services = services

    def search(self, analysis: QueryAnalysis, context: SearchContext) -> list[SearchResult]:
        results: list[SearchResult] = []
        for service in self.services:
            if service.requires_lawful_use_ack and not context.lawful_use_acknowledged:
                continue
            try:
                payload = http_json(
                    service.url.format(query=analysis.normalized),
                    params={
                        key: value.format(query=analysis.normalized)
                        for key, value in service.params.items()
                    },
                    headers=service.headers,
                    timeout_seconds=context.timeout_seconds,
                )
            except (ProviderError, KeyError) as exc:
                results.append(
                    SearchResult(
                        provider=self.name,
                        title=f"{service.name} unavailable",
                        value=str(exc),
                        score=0.0,
                        tags=["error", service.name],
                    )
                )
                continue

            records = _select_json_path(payload, service.json_path)
            if not isinstance(records, list):
                records = [records]
            for record in records[: context.max_results]:
                results.append(
                    SearchResult(
                        provider=self.name,
                        title=f"{service.name} result",
                        value=_record_title(record),
                        snippet=_record_preview(record),
                        score=1.0,
                        tags=["api", service.name],
                        metadata={
                            "service": service.name,
                            "metadata_only": service.metadata_only,
                            "record": record if context.include_raw else _record_preview(record),
                        },
                    )
                )
                if len(results) >= context.max_results:
                    return results
        return results


def _select_json_path(payload: Any, json_path: str | None) -> Any:
    if not json_path:
        return payload
    current = payload
    for part in json_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
    return current


def _record_title(record: Any) -> str:
    if isinstance(record, dict):
        for key in ("title", "name", "username", "email", "domain", "url", "id"):
            if key in record:
                return str(record[key])
    return str(record)[:120]


def _record_preview(record: Any) -> str:
    text = str(record)
    return text[:300] + ("..." if len(text) > 300 else "")

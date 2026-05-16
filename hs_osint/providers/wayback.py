"""Internet Archive Wayback CDX provider."""

from __future__ import annotations

from urllib.parse import quote

from hs_osint.models import ProviderCapability, QueryAnalysis, QueryType, RiskLevel, SearchContext, SearchResult
from hs_osint.providers.base import BaseProvider, ProviderError, first_entity, http_json


class WaybackProvider(BaseProvider):
    name = "wayback"
    capability = ProviderCapability(
        query_types={QueryType.DOMAIN.value, QueryType.URL.value, QueryType.EMAIL.value},
        risk_level=RiskLevel.LOW,
        metadata_only=True,
    )

    def search(self, analysis: QueryAnalysis, context: SearchContext) -> list[SearchResult]:
        target = first_entity(
            analysis,
            QueryType.DOMAIN.value,
            QueryType.URL.value,
            QueryType.EMAIL.value,
        )
        if "@" in target:
            target = target.split("@", 1)[1]

        url = (
            "https://web.archive.org/cdx"
            f"?url={quote(target)}/*&output=json&fl=timestamp,original,statuscode,mimetype"
            f"&collapse=urlkey&limit={context.max_results}"
        )
        try:
            payload = http_json(url, timeout_seconds=context.timeout_seconds)
        except ProviderError as exc:
            return [
                SearchResult(
                    provider=self.name,
                    title="Wayback search unavailable",
                    value=str(exc),
                    score=0.0,
                    tags=["error"],
                )
            ]

        if not isinstance(payload, list) or len(payload) <= 1:
            return []

        rows = payload[1:]
        results: list[SearchResult] = []
        for timestamp, original, status, mimetype in rows[: context.max_results]:
            archive_url = f"https://web.archive.org/web/{timestamp}/{original}"
            results.append(
                SearchResult(
                    provider=self.name,
                    title=f"Archived URL {status}",
                    value=original,
                    url=archive_url,
                    snippet=f"{mimetype or 'unknown'} captured at {timestamp}",
                    score=1.0,
                    tags=["archive", "wayback"],
                    metadata={"timestamp": timestamp, "status": status, "mimetype": mimetype},
                )
            )
        return results

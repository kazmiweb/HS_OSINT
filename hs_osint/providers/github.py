"""Public GitHub search provider."""

from __future__ import annotations

from urllib.parse import quote_plus

from hs_osint.models import ProviderCapability, QueryAnalysis, QueryType, RiskLevel, SearchContext, SearchResult
from hs_osint.providers.base import BaseProvider, ProviderError, http_json


class GitHubRepositoriesProvider(BaseProvider):
    name = "github_repositories"
    capability = ProviderCapability(
        query_types={
            QueryType.KEYWORD.value,
            QueryType.USERNAME.value,
            QueryType.DOMAIN.value,
            QueryType.EMAIL.value,
            QueryType.URL.value,
        },
        risk_level=RiskLevel.LOW,
        metadata_only=True,
    )

    def search(self, analysis: QueryAnalysis, context: SearchContext) -> list[SearchResult]:
        query = analysis.normalized
        url = f"https://api.github.com/search/repositories?q={quote_plus(query)}"
        try:
            payload = http_json(url, timeout_seconds=context.timeout_seconds)
        except ProviderError as exc:
            return [
                SearchResult(
                    provider=self.name,
                    title="GitHub search unavailable",
                    value=str(exc),
                    score=0.0,
                    tags=["error"],
                )
            ]

        results: list[SearchResult] = []
        for item in payload.get("items", [])[: context.max_results]:
            results.append(
                SearchResult(
                    provider=self.name,
                    title=item.get("full_name", "repository"),
                    value=item.get("description") or item.get("html_url") or "",
                    url=item.get("html_url"),
                    snippet=item.get("description"),
                    score=float(item.get("stargazers_count", 0)),
                    tags=["repository", item.get("language") or "unknown"],
                    metadata={
                        "stars": item.get("stargazers_count", 0),
                        "forks": item.get("forks_count", 0),
                        "updated_at": item.get("updated_at"),
                    },
                )
            )
        return results

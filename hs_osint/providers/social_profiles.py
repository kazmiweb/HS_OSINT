"""Public social-profile URL checker."""

from __future__ import annotations

import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from hs_osint.models import ProviderCapability, QueryAnalysis, QueryType, RiskLevel, SearchContext, SearchResult
from hs_osint.providers.base import BaseProvider, first_entity


class SocialProfilesProvider(BaseProvider):
    name = "social_profiles"
    capability = ProviderCapability(
        query_types={QueryType.USERNAME.value, QueryType.KEYWORD.value},
        risk_level=RiskLevel.MEDIUM,
        requires_lawful_use_ack=False,
        metadata_only=True,
    )

    def __init__(self, platforms: dict[str, str]) -> None:
        self.platforms = platforms

    def search(self, analysis: QueryAnalysis, context: SearchContext) -> list[SearchResult]:
        username = first_entity(analysis, QueryType.USERNAME.value, QueryType.KEYWORD.value)
        username = username.lstrip("@").split()[0]
        results: list[SearchResult] = []

        for platform, template in list(self.platforms.items())[: context.max_results]:
            url = template.format(username=username)
            status = self._status(url, context.timeout_seconds)
            if status is None:
                continue
            if 200 <= status < 400:
                results.append(
                    SearchResult(
                        provider=self.name,
                        title=f"Possible {platform} profile",
                        value=username,
                        url=url,
                        snippet=f"Public profile URL returned HTTP {status}",
                        score=1.0,
                        tags=["social", platform],
                        metadata={"status": status, "platform": platform},
                    )
                )
        return results

    @staticmethod
    def _status(url: str, timeout_seconds: float) -> int | None:
        request = Request(url, method="HEAD", headers={"User-Agent": "HS-OSINT/0.1"})
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return response.status
        except HTTPError as exc:
            return exc.code
        except (URLError, TimeoutError, socket.timeout):
            return None

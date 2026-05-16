"""Search orchestration."""

from __future__ import annotations

from hs_osint.agent import AnalysisAgent
from hs_osint.analyzer import QueryAnalyzer
from hs_osint.config import AppConfig
from hs_osint.models import QueryAnalysis, SearchContext, SearchResult
from hs_osint.policy import SafetyPolicy
from hs_osint.providers.base import BaseProvider
from hs_osint.providers.breach_metadata import BreachMetadataProvider
from hs_osint.providers.generic_http import GenericHttpProvider
from hs_osint.providers.github import GitHubRepositoriesProvider
from hs_osint.providers.local_files import LocalFilesProvider
from hs_osint.providers.social_profiles import SocialProfilesProvider
from hs_osint.providers.wayback import WaybackProvider


class SearchEngine:
    """Coordinates query analysis, providers, policy, and result analysis."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.analyzer = QueryAnalyzer()
        self.policy = SafetyPolicy()
        self.agent = AnalysisAgent(
            openai_compatible_url=config.openai_compatible_url,
            api_key_env=config.openai_api_key_env,
            model=config.openai_model,
        )
        self.providers = self._build_providers(config)

    def search(
        self,
        query: str,
        context: SearchContext,
        provider_names: list[str] | None = None,
    ) -> dict[str, object]:
        analysis = self.analyzer.analyze(query)
        selected = provider_names or self.config.enabled_providers
        results: list[SearchResult] = []
        skipped: dict[str, str] = {}

        for name in selected:
            provider = self.providers.get(name)
            if not provider:
                skipped[name] = "provider not registered"
                continue
            if not set(analysis.query_types) & provider.capability.query_types:
                skipped[name] = "provider does not support this query type"
                continue

            decision = self.policy.decide_provider(
                analysis,
                provider.capability,
                context.lawful_use_acknowledged,
            )
            if not decision.allowed:
                skipped[name] = decision.reason or "blocked by safety policy"
                continue

            provider_results = provider.search(analysis, context)
            results.extend(self.policy.sanitize_result(result) for result in provider_results)

        results = sorted(results, key=lambda item: item.score, reverse=True)[: context.max_results]
        return {
            "analysis": analysis.to_dict(),
            "results": [result.to_dict() for result in results],
            "skipped": skipped,
            "agent": self.agent.summarize(analysis, results),
        }

    @staticmethod
    def _build_providers(config: AppConfig) -> dict[str, BaseProvider]:
        providers: list[BaseProvider] = [
            GitHubRepositoriesProvider(),
            WaybackProvider(),
            SocialProfilesProvider(config.social_platforms),
            LocalFilesProvider(config.local_paths),
            GenericHttpProvider(config.generic_services),
            BreachMetadataProvider(config.breach_api_url, config.breach_api_key_env),
        ]
        return {provider.name: provider for provider in providers}

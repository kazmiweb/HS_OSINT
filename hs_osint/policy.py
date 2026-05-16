"""Safety policy for lawful, privacy-preserving OSINT workflows."""

from __future__ import annotations

import re
from typing import Any

from hs_osint.models import ProviderCapability, ProviderDecision, QueryAnalysis, SearchResult


SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "session",
    "cookie",
    "hash",
}


class SafetyPolicy:
    """Applies guardrails before provider execution and before output."""

    def __init__(self, redact_sensitive_values: bool = True) -> None:
        self.redact_sensitive_values = redact_sensitive_values

    def decide_provider(
        self,
        analysis: QueryAnalysis,
        capability: ProviderCapability,
        lawful_use_acknowledged: bool,
    ) -> ProviderDecision:
        if capability.requires_lawful_use_ack and not lawful_use_acknowledged:
            return ProviderDecision(
                allowed=False,
                reason="requires --acknowledge-lawful-use for personal-data sources",
            )

        if "credential_terms" in analysis.risk_flags and not capability.metadata_only:
            return ProviderDecision(
                allowed=False,
                reason="raw credential retrieval is not supported; metadata-only checks are allowed",
            )

        return ProviderDecision(allowed=True)

    def sanitize_result(self, result: SearchResult) -> SearchResult:
        if not self.redact_sensitive_values:
            return result

        result.value = self._redact_text(result.value)
        if result.snippet:
            result.snippet = self._redact_text(result.snippet)
        result.metadata = self._redact_mapping(result.metadata)
        return result

    def _redact_mapping(self, data: dict[str, Any]) -> dict[str, Any]:
        cleaned: dict[str, Any] = {}
        for key, value in data.items():
            if key.lower() in SENSITIVE_KEYS:
                cleaned[key] = "[REDACTED]"
            elif isinstance(value, dict):
                cleaned[key] = self._redact_mapping(value)
            elif isinstance(value, list):
                cleaned[key] = [self._redact_value(item) for item in value]
            else:
                cleaned[key] = self._redact_value(value)
        return cleaned

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return self._redact_mapping(value)
        if isinstance(value, str):
            return self._redact_text(value)
        return value

    @staticmethod
    def _redact_text(text: str) -> str:
        text = re.sub(
            r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*\S+",
            r"\1=[REDACTED]",
            text,
        )
        return text

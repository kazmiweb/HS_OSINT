"""Query understanding and lightweight analysis."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from hs_osint.models import QueryAnalysis, QueryType


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)
USERNAME_RE = re.compile(r"(?<!\w)@([A-Za-z0-9_.-]{2,40})\b")

UNSAFE_INTENT_TERMS = {
    "password",
    "passwords",
    "passwd",
    "credential",
    "credentials",
    "combo",
    "combolist",
    "dump",
    "dumps",
    "stealer",
    "logs",
}


class QueryAnalyzer:
    """Classifies a query into OSINT-friendly entity types and intent."""

    def analyze(self, query: str) -> QueryAnalysis:
        normalized = " ".join(query.strip().split())
        lowered = normalized.lower()
        entities: dict[str, list[str]] = {}
        query_types: list[str] = []

        self._add_matches(entities, query_types, QueryType.EMAIL, EMAIL_RE, normalized)
        self._add_matches(entities, query_types, QueryType.PHONE, PHONE_RE, normalized)
        self._add_matches(entities, query_types, QueryType.IP_ADDRESS, IP_RE, normalized)
        self._add_matches(entities, query_types, QueryType.HASH, HASH_RE, normalized)
        self._add_matches(entities, query_types, QueryType.USERNAME, USERNAME_RE, normalized)

        url_type = self._extract_url(normalized)
        if url_type:
            entities.setdefault(QueryType.URL.value, []).append(url_type)
            query_types.append(QueryType.URL.value)

        domains = [
            item
            for item in DOMAIN_RE.findall(normalized)
            if item.lower() not in {d.lower() for d in entities.get(QueryType.EMAIL.value, [])}
        ]
        if domains:
            entities[QueryType.DOMAIN.value] = sorted(set(domains))
            query_types.append(QueryType.DOMAIN.value)

        if not query_types:
            if self._looks_like_person_name(normalized):
                query_types.append(QueryType.PERSON_NAME.value)
                entities[QueryType.PERSON_NAME.value] = [normalized]
            else:
                query_types.append(QueryType.KEYWORD.value)
                entities[QueryType.KEYWORD.value] = [normalized]

        risk_flags = self._risk_flags(lowered, query_types)
        intent = "credential_exposure_metadata" if "credential_terms" in risk_flags else "discovery"
        suggested = self._suggest_providers(query_types, risk_flags)

        return QueryAnalysis(
            original=query,
            normalized=normalized,
            query_types=sorted(set(query_types)),
            entities=entities,
            intent=intent,
            risk_flags=risk_flags,
            suggested_providers=suggested,
        )

    @staticmethod
    def _add_matches(
        entities: dict[str, list[str]],
        query_types: list[str],
        query_type: QueryType,
        pattern: re.Pattern[str],
        text: str,
    ) -> None:
        matches = sorted({match.group(0) for match in pattern.finditer(text)})
        if matches:
            entities[query_type.value] = matches
            query_types.append(query_type.value)

    @staticmethod
    def _extract_url(text: str) -> str | None:
        if not text.startswith(("http://", "https://")):
            return None
        parsed = urlparse(text)
        if parsed.scheme and parsed.netloc:
            return text
        return None

    @staticmethod
    def _looks_like_person_name(text: str) -> bool:
        words = text.split()
        return 2 <= len(words) <= 4 and all(
            word.replace("-", "").replace("'", "").isalpha() for word in words
        )

    @staticmethod
    def _risk_flags(lowered: str, query_types: list[str]) -> list[str]:
        flags: list[str] = []
        tokens = set(re.findall(r"[a-z0-9_+-]+", lowered))
        if UNSAFE_INTENT_TERMS & tokens:
            flags.append("credential_terms")
        if QueryType.PHONE.value in query_types or QueryType.PERSON_NAME.value in query_types:
            flags.append("personal_data")
        if "darkweb" in tokens or {"dark", "web"} <= tokens:
            flags.append("dark_web_context")
        return flags

    @staticmethod
    def _suggest_providers(query_types: list[str], risk_flags: list[str]) -> list[str]:
        suggestions = ["local_files", "generic_http"]
        types = set(query_types)
        if types & {QueryType.USERNAME.value, QueryType.KEYWORD.value}:
            suggestions.extend(["github_repositories", "social_profiles"])
        if types & {QueryType.DOMAIN.value, QueryType.URL.value, QueryType.EMAIL.value}:
            suggestions.extend(["wayback", "github_repositories"])
        if "credential_terms" in risk_flags:
            suggestions.append("breach_metadata")
        return sorted(set(suggestions))

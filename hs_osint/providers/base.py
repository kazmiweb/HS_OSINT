"""Base classes and helpers for OSINT providers."""

from __future__ import annotations

import json
import socket
from abc import ABC, abstractmethod
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from hs_osint.models import ProviderCapability, QueryAnalysis, SearchContext, SearchResult


class ProviderError(RuntimeError):
    """Raised when a provider cannot complete a query."""


class BaseProvider(ABC):
    name: str
    capability: ProviderCapability

    @abstractmethod
    def search(self, analysis: QueryAnalysis, context: SearchContext) -> list[SearchResult]:
        """Return normalized results for a query analysis."""


def http_json(
    url: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 10.0,
) -> Any:
    if params:
        delimiter = "&" if "?" in url else "?"
        url = f"{url}{delimiter}{urlencode(params)}"
    request = Request(url, headers=headers or {"User-Agent": "HS-OSINT/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, socket.timeout) as exc:
        raise ProviderError(str(exc)) from exc
    return json.loads(body)


def http_text(
    url: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = 10.0,
) -> str:
    if params:
        delimiter = "&" if "?" in url else "?"
        url = f"{url}{delimiter}{urlencode(params)}"
    request = Request(url, headers=headers or {"User-Agent": "HS-OSINT/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, socket.timeout) as exc:
        raise ProviderError(str(exc)) from exc


def first_entity(analysis: QueryAnalysis, *query_types: str) -> str:
    for query_type in query_types:
        values = analysis.entities.get(query_type, [])
        if values:
            return values[0]
    return analysis.normalized

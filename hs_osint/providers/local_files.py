"""Local dataset provider for user-supplied OSINT databases."""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from hs_osint.models import ProviderCapability, QueryAnalysis, QueryType, RiskLevel, SearchContext, SearchResult
from hs_osint.providers.base import BaseProvider


SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson", ".txt", ".sqlite", ".sqlite3", ".db"}


class LocalFilesProvider(BaseProvider):
    name = "local_files"
    capability = ProviderCapability(
        query_types={item.value for item in QueryType},
        risk_level=RiskLevel.MEDIUM,
        requires_lawful_use_ack=True,
        metadata_only=True,
    )

    def __init__(self, paths: list[str]) -> None:
        self.paths = [Path(path) for path in paths]

    def search(self, analysis: QueryAnalysis, context: SearchContext) -> list[SearchResult]:
        needle = analysis.normalized.lower()
        results: list[SearchResult] = []
        for file_path in self._iter_files():
            if len(results) >= context.max_results:
                break
            try:
                rows = self._read_rows(file_path)
                for row_number, row in rows:
                    if needle in json.dumps(row, sort_keys=True, default=str).lower():
                        results.append(
                            SearchResult(
                                provider=self.name,
                                title=f"Local match in {file_path.name}",
                                value=str(file_path),
                                snippet=self._preview(row),
                                score=1.0,
                                tags=["local", file_path.suffix.lower().lstrip(".")],
                                metadata={"path": str(file_path), "row": row_number, "record": row},
                            )
                        )
                    if len(results) >= context.max_results:
                        break
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, sqlite3.DatabaseError) as exc:
                results.append(
                    SearchResult(
                        provider=self.name,
                        title=f"Could not read {file_path.name}",
                        value=str(exc),
                        score=0.0,
                        tags=["error", "local"],
                    )
                )
        return results

    def _iter_files(self) -> Iterable[Path]:
        for path in self.paths:
            if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
                yield path
            elif path.is_dir():
                for child in path.rglob("*"):
                    if child.is_file() and child.suffix.lower() in SUPPORTED_SUFFIXES:
                        yield child

    def _read_rows(self, path: Path) -> Iterable[tuple[int, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            with path.open("r", encoding="utf-8", newline="") as fh:
                for index, row in enumerate(csv.DictReader(fh), start=1):
                    yield index, row
        elif suffix in {".jsonl", ".ndjson"}:
            with path.open("r", encoding="utf-8") as fh:
                for index, line in enumerate(fh, start=1):
                    if line.strip():
                        yield index, json.loads(line)
        elif suffix == ".json":
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if isinstance(payload, list):
                for index, row in enumerate(payload, start=1):
                    yield index, row
            else:
                yield 1, payload
        elif suffix == ".txt":
            with path.open("r", encoding="utf-8") as fh:
                for index, line in enumerate(fh, start=1):
                    yield index, {"line": line.strip()}
        elif suffix in {".sqlite", ".sqlite3", ".db"}:
            yield from self._read_sqlite(path)

    def _read_sqlite(self, path: Path) -> Iterable[tuple[int, Any]]:
        with sqlite3.connect(path) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            row_number = 0
            for (table_name,) in tables:
                quoted_table = self._quote_identifier(table_name)
                columns = [
                    item[1]
                    for item in connection.execute(f"PRAGMA table_info({quoted_table})").fetchall()
                ]
                if not columns:
                    continue
                query = f"SELECT * FROM {quoted_table} LIMIT 5000"
                for row in connection.execute(query):
                    row_number += 1
                    yield row_number, {"table": table_name, **dict(zip(columns, row, strict=False))}

    @staticmethod
    def _preview(row: Any) -> str:
        preview = json.dumps(row, sort_keys=True, default=str)
        return preview[:300] + ("..." if len(preview) > 300 else "")

    @staticmethod
    def _quote_identifier(identifier: str) -> str:
        return '"' + identifier.replace('"', '""') + '"'

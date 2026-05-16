import tempfile
import unittest
from pathlib import Path

from hs_osint.config import AppConfig
from hs_osint.engine import SearchEngine
from hs_osint.models import SearchContext


class EngineTest(unittest.TestCase):
    def test_local_files_are_skipped_without_acknowledgement(self) -> None:
        engine = SearchEngine(AppConfig(enabled_providers=["local_files"]))

        payload = engine.search("example", SearchContext(), provider_names=["local_files"])

        self.assertEqual([], payload["results"])
        self.assertIn("local_files", payload["skipped"])

    def test_local_file_search_with_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            path.write_text('{"username": "alice", "note": "example"}\n', encoding="utf-8")
            engine = SearchEngine(
                AppConfig(enabled_providers=["local_files"], local_paths=[str(path)])
            )

            payload = engine.search(
                "alice",
                SearchContext(lawful_use_acknowledged=True),
                provider_names=["local_files"],
            )

            self.assertEqual(1, len(payload["results"]))
            self.assertEqual("local_files", payload["results"][0]["provider"])


if __name__ == "__main__":
    unittest.main()

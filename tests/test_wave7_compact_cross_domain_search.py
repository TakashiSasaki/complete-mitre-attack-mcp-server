"""Wave 7 regression tests for compact vs full cross-domain `search_techniques(domain='all')`.

Covers:
1. Dominant fixed-overhead baseline and token-efficiency benchmark for
   `search_techniques(query='Screen Capture', domain='all', limit=10, include_description=False, include_formatted=False)`:
   - `detail_level='full'` (default) reproduces exact legacy 2736 compact JSON bytes (2884 default `json.dumps` bytes)
     and preserves the legacy `domain='all'` schema byte-for-byte.
   - `detail_level='compact'` achieves >= 25% byte/character reduction while preserving all 5 distinct hits
     (enterprise=2, mobile=2, ics=1).
2. Semantic equivalence between `detail_level='compact'` and `detail_level='full'`:
   - Identical technique ordering, `domain`, `attack_id`, `name`, `stix_id`, `description`,
     pagination fields (`count`, `total_count`, `offset`, `limit`, `has_more`, `next_offset`),
     `domains_searched`, `formatted`, and `message`.
   - Shared provenance retained in `metadata` (`attack_version`, `stix_spec_version`, `source_repository`,
     `source_index_url`, `source_url_template`, `source_release_date`, `source_release_date_known`,
     `freshness_status`, `complete`, `partial`, `unavailable_domains`).
   - Exact per-domain `source_url` derivable without fabricating from `metadata['source_url_template']`
     for every available domain and matching `detail_level='full'` `domain_status[dom]['source_url']`.
3. Fail-closed domain availability and differentiation of missing vs load-failed vs unknown release dates
   in both `compact` and `full` modes (no partial failure masking, `match_count=None` on failed domains).
4. Single-domain (`enterprise`, `mobile`, `ics`) byte-for-byte non-regression regardless of `detail_level`,
   and validation of invalid `detail_level`.
5. Tool count invariance (67 tools) and MCP `tools/list` schema exposing `detail_level` with default `'full'`.
"""

import asyncio
import json
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from mitreattack import release_info
import mitre_mcp_server.server as srv


class TestWave7CompactCrossDomainSearch(unittest.TestCase):
    """Regression and size-benchmark tests for Wave 7 `search_techniques` compact cross-domain response."""

    def test_mcp_schema_exposes_detail_level_default_full_and_67_tools(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        self.assertEqual(len(tools), 67)
        self.assertIn("search_techniques", tools)
        tool = tools["search_techniques"]
        props = tool.inputSchema.get("properties", {})
        self.assertIn("detail_level", props)
        dl_prop = props["detail_level"]
        self.assertEqual(dl_prop.get("default"), "full")
        self.assertEqual(set(dl_prop.get("enum", [])), {"compact", "full"})
        desc = (dl_prop.get("description") or "") + " " + (tool.description or "")
        self.assertIn("compact", desc)
        self.assertIn("full", desc)

    def test_screen_capture_size_benchmark_and_legacy_full_preservation(self) -> None:
        # Baseline single-domain calls: 489 + 485 + 353 = 1327 minified JSON bytes
        single_min_sizes = {}
        for dom in ("enterprise", "mobile", "ics"):
            r_dom = asyncio.run(
                srv.search_techniques(
                    query="Screen Capture",
                    domain=dom,
                    limit=10,
                    include_description=False,
                    include_formatted=False,
                )
            )
            single_min_sizes[dom] = len(json.dumps(r_dom, separators=(",", ":")))
        self.assertEqual(single_min_sizes, {"enterprise": 489, "mobile": 485, "ics": 353})
        self.assertEqual(sum(single_min_sizes.values()), 1327)

        # Default call (omitting detail_level) and explicit detail_level="full" must match legacy byte-for-byte
        res_default = asyncio.run(
            srv.search_techniques(
                query="Screen Capture",
                domain="all",
                limit=10,
                include_description=False,
                include_formatted=False,
            )
        )
        res_full = asyncio.run(
            srv.search_techniques(
                query="Screen Capture",
                domain="all",
                limit=10,
                include_description=False,
                include_formatted=False,
                detail_level="full",
            )
        )
        self.assertEqual(res_default, res_full)
        self.assertNotIn("detail_level", res_default)

        full_min_bytes = len(json.dumps(res_full, separators=(",", ":")).encode("ascii"))
        full_default_bytes = len(json.dumps(res_full).encode("ascii"))
        full_indent_bytes = len(json.dumps(res_full, indent=2).encode("ascii"))
        self.assertEqual(full_min_bytes, 2736)
        self.assertEqual(full_default_bytes, 2884)
        self.assertEqual(full_indent_bytes, 3376)

        # Compact cross-domain call under identical parameters
        res_compact = asyncio.run(
            srv.search_techniques(
                query="Screen Capture",
                domain="all",
                limit=10,
                include_description=False,
                include_formatted=False,
                detail_level="compact",
            )
        )
        self.assertEqual(res_compact["detail_level"], "compact")

        compact_min_bytes = len(json.dumps(res_compact, separators=(",", ":")).encode("ascii"))
        compact_default_bytes = len(json.dumps(res_compact).encode("ascii"))
        compact_indent_bytes = len(json.dumps(res_compact, indent=2).encode("ascii"))

        self.assertEqual(compact_min_bytes, 1852)
        self.assertEqual(compact_default_bytes, 1973)
        self.assertEqual(compact_indent_bytes, 2363)

        # Target meaningful reduction >= 25% across all standard JSON serializations
        self.assertLessEqual(
            compact_min_bytes,
            int(full_min_bytes * 0.75),
            f"Expected >=25% reduction in minified JSON bytes: got {compact_min_bytes} vs {full_min_bytes}",
        )
        self.assertLessEqual(
            compact_default_bytes,
            int(full_default_bytes * 0.75),
            f"Expected >=25% reduction in default JSON bytes: got {compact_default_bytes} vs {full_default_bytes}",
        )
        self.assertLessEqual(
            compact_indent_bytes,
            int(full_indent_bytes * 0.75),
            f"Expected >=25% reduction in indent=2 JSON bytes: got {compact_indent_bytes} vs {full_indent_bytes}",
        )

    def test_semantic_equivalence_and_derivable_provenance(self) -> None:
        res_full = asyncio.run(
            srv.search_techniques(
                query="Screen Capture",
                domain="all",
                limit=10,
                offset=0,
                include_description=False,
                include_formatted=False,
                detail_level="full",
            )
        )
        res_compact = asyncio.run(
            srv.search_techniques(
                query="Screen Capture",
                domain="all",
                limit=10,
                offset=0,
                include_description=False,
                include_formatted=False,
                detail_level="compact",
            )
        )

        # Pagination, records, rank sorting, and message are identical
        for key in (
            "domain",
            "domains_searched",
            "count",
            "total_count",
            "offset",
            "limit",
            "has_more",
            "next_offset",
            "techniques",
            "formatted",
            "message",
        ):
            self.assertEqual(res_compact[key], res_full[key], f"Mismatch on key {key!r}")

        self.assertEqual(res_compact["count"], 5)
        self.assertEqual(
            [(t["domain"], t["attack_id"], t["name"]) for t in res_compact["techniques"]],
            [
                ("enterprise", "T1113", "Screen Capture"),
                ("mobile", "T1513", "Screen Capture"),
                ("ics", "T0852", "Screen Capture"),
                ("enterprise", "T1125", "Video Capture"),
                ("mobile", "T1512", "Video Capture"),
            ],
        )

        # Shared provenance retained in metadata
        meta_c = res_compact["metadata"]
        meta_f = res_full["metadata"]
        self.assertEqual(meta_c["detail_level"], "compact")
        for k in (
            "attack_version",
            "stix_spec_version",
            "source_repository",
            "source_index_url",
            "source_release_date",
            "source_release_date_known",
            "freshness_status",
            "complete",
            "partial",
            "unavailable_domains",
        ):
            self.assertEqual(meta_c[k], meta_f[k], f"Metadata mismatch on {k!r}")

        # Source URL derivable WITHOUT fabricating for every available domain
        self.assertIn("source_url_template", meta_c)
        template = meta_c["source_url_template"]
        self.assertIn("{domain}", template)
        for dom in ("enterprise", "mobile", "ics"):
            ds_c = res_compact["domain_status"][dom]
            ds_f = res_full["domain_status"][dom]
            self.assertEqual(ds_c["status"], "OK")
            self.assertTrue(ds_c["available"])
            self.assertEqual(ds_c["match_count"], ds_f["match_count"])
            # Redundant shared fields omitted from per-domain entry when matching shared metadata
            for omitted_key in (
                "loaded_version",
                "stix_spec_version",
                "source_url",
                "source_release_date",
                "freshness_status",
            ):
                self.assertNotIn(omitted_key, ds_c)
            derived_url = template.format(domain=dom)
            self.assertEqual(derived_url, ds_f["source_url"])

    def test_failure_modes_and_unknown_release_differentiation_in_compact_and_full(self) -> None:
        # 1. Missing domain bundle on disk (freshness_status='missing_local_bundle')
        real_get_stix_path = srv.get_stix_path

        def _missing_ics_path(domain: str) -> Path:
            if domain == "ics":
                return Path("/nonexistent/v20.1/ics-attack.json")
            return real_get_stix_path(domain)

        with patch.object(srv, "get_stix_path", side_effect=_missing_ics_path):
            miss_compact = asyncio.run(
                srv.search_techniques(
                    query="Screen Capture",
                    domain="all",
                    limit=10,
                    include_description=False,
                    include_formatted=False,
                    detail_level="compact",
                )
            )
            miss_full = asyncio.run(
                srv.search_techniques(
                    query="Screen Capture",
                    domain="all",
                    limit=10,
                    include_description=False,
                    include_formatted=False,
                    detail_level="full",
                )
            )

        for res in (miss_compact, miss_full):
            self.assertFalse(res["found"])
            self.assertEqual(res["error_code"], "DOMAIN_UNAVAILABLE")
            self.assertEqual(res["count"], 0)
            self.assertEqual(res["total_count"], 0)
            self.assertEqual(res["techniques"], [])
            self.assertFalse(res["metadata"]["complete"])
            self.assertTrue(res["metadata"]["partial"])
            self.assertEqual(res["metadata"]["unavailable_domains"], ["ics"])
            self.assertEqual(res["domain_status"]["ics"]["status"], "UNAVAILABLE")
            self.assertFalse(res["domain_status"]["ics"]["available"])
            self.assertIsNone(res["domain_status"]["ics"]["match_count"])
            self.assertIsNone(res["domain_status"]["ics"]["loaded_version"])
            self.assertIsNone(res["domain_status"]["ics"]["source_url"])
            self.assertEqual(
                res["domain_status"]["ics"]["freshness_status"], "missing_local_bundle"
            )
            self.assertIn("error", res["domain_status"]["ics"])
            self.assertEqual(res["domain_status"]["enterprise"]["status"], "OK")
            self.assertEqual(res["domain_status"]["mobile"]["status"], "OK")

        # 2. Runtime load failure (freshness_status='domain_load_failed') differentiated from missing bundle
        real_get_attack_data = srv.get_attack_data

        def _failing_mobile_load(domain: str = "enterprise") -> Any:
            if domain == "mobile":
                raise RuntimeError("Corrupted mobile STIX bundle")
            return real_get_attack_data(domain)

        with patch.object(srv, "get_attack_data", side_effect=_failing_mobile_load):
            err_compact = asyncio.run(
                srv.search_techniques(
                    query="Screen Capture",
                    domain="all",
                    limit=10,
                    include_description=False,
                    include_formatted=False,
                    detail_level="compact",
                )
            )

        self.assertFalse(err_compact["found"])
        self.assertEqual(err_compact["error_code"], "DOMAIN_UNAVAILABLE")
        self.assertEqual(err_compact["metadata"]["unavailable_domains"], ["mobile"])
        mob_ds = err_compact["domain_status"]["mobile"]
        self.assertEqual(mob_ds["status"], "UNAVAILABLE")
        self.assertFalse(mob_ds["available"])
        self.assertIsNone(mob_ds["match_count"])
        self.assertIsNone(mob_ds["loaded_version"])
        self.assertIsNone(mob_ds["source_url"])
        self.assertEqual(mob_ds["freshness_status"], "domain_load_failed")
        self.assertIn("Corrupted mobile STIX bundle", mob_ds["error"])

        # 3. Unknown release date for an unmapped version is never fabricated
        with patch.dict(srv._KNOWN_SOURCE_RELEASE_DATES, {}, clear=True):
            unk_compact = asyncio.run(
                srv.search_techniques(
                    query="Screen Capture",
                    domain="all",
                    limit=5,
                    include_description=False,
                    include_formatted=False,
                    detail_level="compact",
                )
            )
        self.assertIsNone(unk_compact["metadata"]["source_release_date"])
        self.assertFalse(unk_compact["metadata"]["source_release_date_known"])

    def test_single_domain_unchanged_and_invalid_detail_level_rejected(self) -> None:
        # Single domain ignores detail_level and preserves exact legacy keys
        for dom in ("enterprise", "mobile", "ics"):
            r_default = asyncio.run(
                srv.search_techniques(
                    query="Screen Capture",
                    domain=dom,
                    limit=5,
                    include_description=False,
                    include_formatted=False,
                )
            )
            r_compact = asyncio.run(
                srv.search_techniques(
                    query="Screen Capture",
                    domain=dom,
                    limit=5,
                    include_description=False,
                    include_formatted=False,
                    detail_level="compact",
                )
            )
            self.assertEqual(r_default, r_compact)
            self.assertNotIn("detail_level", r_compact)

        # Invalid detail_level raises ValueError
        for bad_level in ("bogus", "minimal", "verbose", ""):
            with self.assertRaises(ValueError):
                asyncio.run(
                    srv.search_techniques(
                        query="Screen Capture",
                        domain="all",
                        detail_level=bad_level,  # type: ignore[arg-type]
                    )
                )


if __name__ == "__main__":
    unittest.main()

"""Wave 6 regression tests for cross-domain `search_techniques(domain='all')`.

Covers:
1. Cross-domain retrieval (`domain='all'`) across Enterprise, Mobile, and ICS v20.1 bundles
   as well as deterministic mock fixtures.
2. Per-hit domain disambiguation (including synthetic duplicate ATT&CK IDs / STIX IDs across domains).
3. Deterministic global sorting and pagination (`offset`, `limit`, `total_count`, `count`,
   `has_more`, `next_offset`) across domain boundaries and offset-beyond-end / empty results.
4. Domain availability and provenance metadata (`domain_status`, `metadata`) without inventing
   retrieval timestamps or confidence scores, and fail-closed `DOMAIN_UNAVAILABLE` behavior
   when one or more domain bundles fail to load or are missing (never mistaken for zero matches).
5. Byte-for-byte preservation of single-domain `search_techniques` contract for
   `enterprise`, `mobile`, and `ics`, plus invalid domain rejection.
6. Token-efficiency / long-response size gate (`include_formatted=False` emits `formatted == ""`,
   stays well under ceiling, and single `domain='all'` call vs 3 single-domain calls benchmark).
7. Tool count invariance (67 tools) and MCP `tools/list` schema verification for `search_techniques`.
"""

import asyncio
import json
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from mitreattack import release_info
import mitre_mcp_server.server as srv


class _MockTechnique:
    def __init__(self, stix_id: str, name: str, description: str, attack_id: str) -> None:
        self.id = stix_id
        self.name = name
        self.description = description
        self._attack_id = attack_id


class _MockAttackData:
    def __init__(self, techniques: List[_MockTechnique]) -> None:
        self._techniques = techniques
        self._aid_by_id = {t.id: t._attack_id for t in techniques}

    def get_techniques(self, remove_revoked_deprecated: bool = True) -> List[_MockTechnique]:
        return list(self._techniques)

    def get_attack_id(self, stix_id: Any) -> Optional[str]:
        if isinstance(stix_id, str):
            return self._aid_by_id.get(stix_id)
        sid = getattr(stix_id, "id", None)
        return self._aid_by_id.get(sid) if isinstance(sid, str) else None


class TestWave6CrossDomainSearchTechniques(unittest.TestCase):
    """Comprehensive unit and live v20.1 tests for `search_techniques(domain='all')`."""

    def test_tool_count_67_and_mcp_schema_exposes_domain_all(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        self.assertEqual(len(tools), 67)
        self.assertIn("search_techniques", tools)
        tool = tools["search_techniques"]
        props = tool.inputSchema.get("properties", {})
        self.assertIn("domain", props)
        self.assertEqual(props["domain"].get("default"), "enterprise")
        # Schema exposes 'all' via enum and/or description
        dom_prop = props["domain"]
        dom_enum = set(dom_prop.get("enum", []))
        dom_desc = (dom_prop.get("description") or "") + " " + (tool.description or "")
        self.assertTrue(
            "all" in dom_enum or '"all"' in dom_desc or "'all'" in dom_desc,
            f"Expected 'all' exposed in search_techniques domain schema or description: {dom_prop}",
        )
        if dom_enum:
            self.assertEqual(dom_enum, {"enterprise", "mobile", "ics", "all"})

    def test_live_confirmed_defect_command_domain_all_page_and_total(self) -> None:
        # Confirmed live scenario from user prompt:
        # search_techniques(query='Command', domain='all', limit=3, include_description=False, include_formatted=False)
        res_all = asyncio.run(
            srv.search_techniques(
                query="Command",
                domain="all",
                limit=3,
                offset=0,
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(res_all["domain"], "all")
        self.assertEqual(res_all["domains_searched"], ["enterprise", "mobile", "ics"])
        self.assertEqual(res_all["total_count"], 312)  # 260 enterprise + 22 mobile + 30 ics
        self.assertEqual(res_all["count"], 3)
        self.assertEqual(res_all["offset"], 0)
        self.assertEqual(res_all["limit"], 3)
        self.assertTrue(res_all["has_more"])
        self.assertEqual(res_all["next_offset"], 3)
        self.assertEqual(res_all["formatted"], "")
        self.assertEqual(len(res_all["techniques"]), 3)
        for item in res_all["techniques"]:
            self.assertIn(item["domain"], {"enterprise", "mobile", "ics"})
            self.assertIsNotNone(item["attack_id"])
            self.assertIsNotNone(item["name"])
            self.assertIsNotNone(item["stix_id"])
            self.assertIsNone(item["description"])

        # Provenance & domain_status checks
        self.assertIn("domain_status", res_all)
        self.assertIn("metadata", res_all)
        for dom, expected_cnt in (("enterprise", 260), ("mobile", 22), ("ics", 30)):
            ds = res_all["domain_status"][dom]
            self.assertEqual(ds["status"], "OK")
            self.assertTrue(ds["available"])
            self.assertEqual(ds["match_count"], expected_cnt)
            self.assertEqual(ds["loaded_version"], str(release_info.LATEST_VERSION))
            self.assertEqual(ds["source_release_date"], "2026-11-05")
            self.assertEqual(
                ds["freshness_status"], "pinned_local_release_upstream_unchecked"
            )
            self.assertTrue(ds["source_url"].endswith(f"{dom}-attack-20.1.json"))
            # Must not invent retrieval timestamps or confidence scores
            self.assertNotIn("retrieved_at", ds)
            self.assertNotIn("confidence", ds)

        meta = res_all["metadata"]
        self.assertEqual(meta["attack_version"], "20.1")
        self.assertEqual(meta["stix_spec_version"], "2.1")
        self.assertEqual(meta["source_release_date"], "2026-11-05")
        self.assertTrue(meta["complete"])
        self.assertFalse(meta["partial"])
        self.assertEqual(meta["unavailable_domains"], [])
        self.assertNotIn("retrieved_at", meta)
        self.assertNotIn("confidence", meta)

    def test_cross_domain_disambiguation_same_name_and_same_attack_id_mock(self) -> None:
        # Verify same technique name AND even same attack_id across domains are never collapsed
        mock_ent = _MockAttackData(
            [
                _MockTechnique(
                    "attack-pattern--11111111-1111-1111-1111-111111111111",
                    "Shared Technique Alpha",
                    "Command execution on enterprise host",
                    "T9001",
                ),
                _MockTechnique(
                    "attack-pattern--22222222-2222-2222-2222-222222222222",
                    "Zeta Command",
                    "Enterprise zeta",
                    "T9002",
                ),
            ]
        )
        mock_mob = _MockAttackData(
            [
                _MockTechnique(
                    "attack-pattern--11111111-1111-1111-1111-111111111111",
                    "Shared Technique Alpha",
                    "Command execution on mobile device",
                    "T9001",
                ),
            ]
        )
        mock_ics = _MockAttackData(
            [
                _MockTechnique(
                    "attack-pattern--33333333-3333-3333-3333-333333333333",
                    "Shared Technique Alpha",
                    "Command execution on ICS controller",
                    "T9001",
                ),
                _MockTechnique(
                    "attack-pattern--00000000-0000-0000-0000-000000000001",
                    "Alpha Early Command",
                    "ICS early",
                    "T0800",
                ),
            ]
        )
        mock_map = {"enterprise": mock_ent, "mobile": mock_mob, "ics": mock_ics}

        with (
            patch.object(srv, "get_attack_data", side_effect=lambda d="enterprise": mock_map[d]),
            patch.object(srv, "get_stix_path", side_effect=lambda d: Path(__file__)),
        ):
            p0 = asyncio.run(
                srv.search_techniques(
                    query="Command",
                    domain="all",
                    limit=2,
                    offset=0,
                    include_description=False,
                    include_formatted=False,
                )
            )
            p1 = asyncio.run(
                srv.search_techniques(
                    query="Command",
                    domain="all",
                    limit=2,
                    offset=2,
                    include_description=False,
                    include_formatted=False,
                )
            )
            p2 = asyncio.run(
                srv.search_techniques(
                    query="Command",
                    domain="all",
                    limit=2,
                    offset=4,
                    include_description=False,
                    include_formatted=False,
                )
            )

        self.assertEqual(p0["total_count"], 5)
        self.assertEqual(p0["count"], 2)
        self.assertTrue(p0["has_more"])
        self.assertEqual(p0["next_offset"], 2)

        self.assertEqual(p1["total_count"], 5)
        self.assertEqual(p1["count"], 2)
        self.assertTrue(p1["has_more"])
        self.assertEqual(p1["next_offset"], 4)

        self.assertEqual(p2["total_count"], 5)
        self.assertEqual(p2["count"], 1)
        self.assertFalse(p2["has_more"])
        self.assertIsNone(p2["next_offset"])

        combined = p0["techniques"] + p1["techniques"] + p2["techniques"]
        self.assertEqual(len(combined), 5)
        # All 3 "Shared Technique Alpha" with attack_id T9001 across enterprise, mobile, ics are preserved
        shared_hits = [t for t in combined if t["name"] == "Shared Technique Alpha"]
        self.assertEqual(len(shared_hits), 3)
        self.assertEqual([t["domain"] for t in shared_hits], ["enterprise", "mobile", "ics"])

    def test_global_pagination_and_live_disambiguation_screen_capture(self) -> None:
        # In v20.1, "Screen Capture" exists in Enterprise (T1113), Mobile (T1513), and ICS (T0852)
        res = asyncio.run(
            srv.search_techniques(
                query="Screen Capture",
                domain="all",
                include_description=False,
                include_formatted=False,
            )
        )
        exact_hits = [
            t for t in res["techniques"] if t["name"] == "Screen Capture"
        ]
        self.assertEqual(len(exact_hits), 3)
        self.assertEqual(
            [(t["domain"], t["attack_id"]) for t in exact_hits],
            [("enterprise", "T1113"), ("mobile", "T1513"), ("ics", "T0852")],
        )

        # Walk all pages for query="Command" across domain="all" and verify union equals sum of single domains
        single_items = []
        for dom in ("enterprise", "mobile", "ics"):
            off = 0
            while True:
                page = asyncio.run(
                    srv.search_techniques(
                        query="Command",
                        domain=dom,
                        limit=200,
                        offset=off,
                        include_description=False,
                        include_formatted=False,
                    )
                )
                for item in page["techniques"]:
                    single_items.append((dom, item["attack_id"], item["name"], item["stix_id"]))
                if not page["has_more"]:
                    break
                off = page["next_offset"]

        all_items = []
        off = 0
        while True:
            page = asyncio.run(
                srv.search_techniques(
                    query="Command",
                    domain="all",
                    limit=100,
                    offset=off,
                    include_description=False,
                    include_formatted=False,
                )
            )
            self.assertEqual(page["total_count"], len(single_items))
            for item in page["techniques"]:
                all_items.append((item["domain"], item["attack_id"], item["name"], item["stix_id"]))
            if not page["has_more"]:
                self.assertIsNone(page["next_offset"])
                break
            self.assertEqual(page["next_offset"], off + page["count"])
            off = page["next_offset"]

        self.assertEqual(len(all_items), len(single_items))
        self.assertEqual(set(all_items), set(single_items))

    def test_missing_or_unavailable_domain_fails_closed_not_mistaken_for_zero(self) -> None:
        # Simulate ICS STIX bundle missing on disk
        real_get_stix_path = srv.get_stix_path

        def _patched_stix_path(domain: str) -> Path:
            if domain == "ics":
                return Path("/nonexistent/v20.1/ics-attack.json")
            return real_get_stix_path(domain)

        with patch.object(srv, "get_stix_path", side_effect=_patched_stix_path):
            res_missing = asyncio.run(
                srv.search_techniques(
                    query="Command",
                    domain="all",
                    limit=5,
                    offset=0,
                    include_description=False,
                    include_formatted=False,
                )
            )

        self.assertFalse(res_missing["found"])
        self.assertEqual(res_missing["error_code"], "DOMAIN_UNAVAILABLE")
        self.assertEqual(res_missing["count"], 0)
        self.assertEqual(res_missing["total_count"], 0)
        self.assertEqual(res_missing["techniques"], [])
        self.assertIn("ics", res_missing["metadata"]["unavailable_domains"])
        self.assertFalse(res_missing["metadata"]["complete"])
        self.assertEqual(res_missing["domain_status"]["ics"]["status"], "UNAVAILABLE")
        self.assertFalse(res_missing["domain_status"]["ics"]["available"])
        self.assertIsNone(res_missing["domain_status"]["ics"]["match_count"])
        self.assertEqual(
            res_missing["domain_status"]["ics"]["freshness_status"], "missing_local_bundle"
        )
        self.assertEqual(res_missing["domain_status"]["enterprise"]["status"], "OK")
        self.assertEqual(res_missing["domain_status"]["mobile"]["status"], "OK")

        # Also test runtime load failure in get_attack_data for mobile
        real_get_attack_data = srv.get_attack_data

        def _patched_get_attack_data(domain: str = "enterprise") -> Any:
            if domain == "mobile":
                raise RuntimeError("Simulated corrupted mobile STIX bundle")
            return real_get_attack_data(domain)

        with patch.object(srv, "get_attack_data", side_effect=_patched_get_attack_data):
            res_load_err = asyncio.run(
                srv.search_techniques(
                    query="Command",
                    domain="all",
                    limit=5,
                    offset=0,
                    include_description=False,
                    include_formatted=False,
                )
            )

        self.assertFalse(res_load_err["found"])
        self.assertEqual(res_load_err["error_code"], "DOMAIN_UNAVAILABLE")
        self.assertIn("mobile", res_load_err["metadata"]["unavailable_domains"])
        self.assertEqual(res_load_err["domain_status"]["mobile"]["status"], "UNAVAILABLE")
        self.assertIsNone(res_load_err["domain_status"]["mobile"]["match_count"])

    def test_empty_results_offset_beyond_end_invalid_domain_and_stable_ordering(self) -> None:
        # 1. Empty query / whitespace query
        blank = asyncio.run(
            srv.search_techniques(
                query="   ",
                domain="all",
                limit=10,
                offset=0,
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(blank["count"], 0)
        self.assertEqual(blank["total_count"], 0)
        self.assertFalse(blank["has_more"])
        self.assertIsNone(blank["next_offset"])
        self.assertEqual(blank["techniques"], [])
        self.assertEqual(blank["formatted"], "")
        self.assertTrue(blank["metadata"]["complete"])
        for dom in ("enterprise", "mobile", "ics"):
            self.assertEqual(blank["domain_status"][dom]["status"], "OK")
            self.assertEqual(blank["domain_status"][dom]["match_count"], 0)

        # 2. Non-matching query
        nomatch = asyncio.run(
            srv.search_techniques(
                query="xyznonexistenttechnique987654321",
                domain="all",
                limit=10,
                offset=0,
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(nomatch["count"], 0)
        self.assertEqual(nomatch["total_count"], 0)
        self.assertFalse(nomatch["has_more"])
        self.assertIsNone(nomatch["next_offset"])
        self.assertTrue(nomatch["metadata"]["complete"])
        for dom in ("enterprise", "mobile", "ics"):
            self.assertEqual(nomatch["domain_status"][dom]["status"], "OK")
            self.assertEqual(nomatch["domain_status"][dom]["match_count"], 0)

        # 3. Offset beyond end
        past_end = asyncio.run(
            srv.search_techniques(
                query="Command",
                domain="all",
                limit=10,
                offset=500,
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(past_end["total_count"], 312)
        self.assertEqual(past_end["count"], 0)
        self.assertEqual(past_end["offset"], 500)
        self.assertEqual(past_end["limit"], 10)
        self.assertFalse(past_end["has_more"])
        self.assertIsNone(past_end["next_offset"])
        self.assertEqual(past_end["techniques"], [])
        self.assertEqual(past_end["formatted"], "")

        # 4. Invalid domain rejected with ValueError
        for bad_dom in ("bogus", "all-domains", "enterprise,mobile", "none"):
            with self.assertRaises(ValueError):
                asyncio.run(srv.search_techniques(query="Command", domain=bad_dom))

        # 5. Stable repeated ordering
        runs = [
            asyncio.run(
                srv.search_techniques(
                    query="Command",
                    domain="all",
                    limit=25,
                    offset=250,
                    include_description=False,
                    include_formatted=False,
                )
            )
            for _ in range(3)
        ]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])

    def test_single_domain_compatibility_and_size_gate(self) -> None:
        # Single domain contract preserved byte-for-byte (same top-level keys and technique item keys)
        for dom, expected_total in (("enterprise", 260), ("mobile", 22), ("ics", 30)):
            res = asyncio.run(
                srv.search_techniques(
                    query="Command",
                    domain=dom,
                    limit=3,
                    offset=0,
                    include_description=False,
                    include_formatted=False,
                )
            )
            self.assertEqual(
                set(res.keys()),
                {
                    "count",
                    "total_count",
                    "offset",
                    "limit",
                    "has_more",
                    "next_offset",
                    "techniques",
                    "formatted",
                    "message",
                },
            )
            self.assertEqual(res["total_count"], expected_total)
            self.assertEqual(res["count"], 3)
            self.assertEqual(res["formatted"], "")
            for item in res["techniques"]:
                self.assertEqual(
                    set(item.keys()),
                    {"attack_id", "name", "stix_id", "description"},
                )

        # Long response size gate: max page limit (200) on domain='all' with include_formatted=False
        max_page_compact = asyncio.run(
            srv.search_techniques(
                query="Command",
                domain="all",
                limit=srv.MAX_PAGE_LIMIT,
                offset=0,
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(max_page_compact["formatted"], "")
        self.assertLess(len(json.dumps(max_page_compact)), 50_000)

        max_page_desc = asyncio.run(
            srv.search_techniques(
                query="Command",
                domain="all",
                limit=srv.MAX_PAGE_LIMIT,
                offset=0,
                include_description=True,
                include_formatted=False,
            )
        )
        self.assertEqual(max_page_desc["formatted"], "")
        self.assertLess(len(json.dumps(max_page_desc)), 1_000_000)

        # include_formatted=True on domain='all' includes Domain label in formatted block
        fmt_all = asyncio.run(
            srv.search_techniques(
                query="Screen Capture",
                domain="all",
                limit=5,
                offset=0,
                include_description=False,
                include_formatted=True,
            )
        )
        self.assertIn("Domain: enterprise", fmt_all["formatted"])
        self.assertIn("Domain: mobile", fmt_all["formatted"])
        self.assertIn("Domain: ics", fmt_all["formatted"])


if __name__ == "__main__":
    unittest.main()

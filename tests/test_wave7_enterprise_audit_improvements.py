"""Regression tests for Wave 7 polish improvements:
1. `get_procedure_examples_by_technique` pagination, `include_formatted`,
   deterministic sorting by source `attack_id` (then name/stix_id), and
   case-insensitive `query` substring filter across description and source name/ID.
2. Consistent `suggested_platforms` guidance when `platforms` filter yields 0 hits
   in `get_detection_strategies_for_technique` (single & batch compact/full),
   `get_techniques_by_tactic`, and `search_techniques` (single & cross-domain).
"""

import asyncio
import unittest

import mitre_mcp_server.server as srv


class TestWave7EnterpriseAuditImprovements(unittest.TestCase):
    """Verify Wave 7 procedure example filtering/sorting and consistent platform suggestions."""

    def test_mcp_schemas_expose_wave7_parameters(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}

        proc_props = tools["get_procedure_examples_by_technique"].inputSchema.get("properties", {})
        self.assertIn("limit", proc_props)
        self.assertEqual(proc_props["limit"].get("default"), 100)
        self.assertIn("offset", proc_props)
        self.assertEqual(proc_props["offset"].get("default"), 0)
        self.assertIn("include_formatted", proc_props)
        self.assertEqual(proc_props["include_formatted"].get("default"), True)
        self.assertIn("query", proc_props)
        self.assertEqual(proc_props["query"].get("default"), "")

    def test_get_procedure_examples_by_technique_sorting_pagination_and_query(self) -> None:
        full_res = asyncio.run(
            srv.get_procedure_examples_by_technique(
                "T1190",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
                offset=0,
            )
        )
        self.assertTrue(full_res["found"])
        self.assertGreater(full_res["total_count"], 50)
        self.assertEqual(full_res["formatted"], "")
        self.assertEqual(full_res["limit"], 200)
        self.assertEqual(full_res["offset"], 0)

        # Verify deterministic sorting by source attack_id (then name, source stix_id, rel_id)
        sort_keys = [
            (
                srv._attack_id_sort_key(
                    e["source"]["attack_id"],
                    e["source"]["name"],
                    e["source"]["stix_id"],
                ),
                str(e["relationship_id"] or ""),
            )
            for e in full_res["examples"]
        ]
        self.assertEqual(sort_keys, sorted(sort_keys))

        # Verify pagination consistency & include_formatted toggle
        page0 = asyncio.run(
            srv.get_procedure_examples_by_technique(
                "T1190",
                domain="enterprise",
                include_description=False,
                include_formatted=True,
                limit=5,
                offset=0,
            )
        )
        self.assertEqual(page0["count"], 5)
        self.assertEqual(page0["total_count"], full_res["total_count"])
        self.assertTrue(page0["has_more"])
        self.assertEqual(page0["next_offset"], 5)
        self.assertTrue(len(page0["formatted"]) > 0)
        self.assertEqual(
            [e["relationship_id"] for e in page0["examples"]],
            [e["relationship_id"] for e in full_res["examples"][:5]],
        )

        page1 = asyncio.run(
            srv.get_procedure_examples_by_technique(
                "T1190",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=5,
                offset=5,
            )
        )
        self.assertEqual(page1["count"], 5)
        self.assertEqual(page1["offset"], 5)
        self.assertEqual(page1["formatted"], "")
        self.assertEqual(
            [e["relationship_id"] for e in page1["examples"]],
            [e["relationship_id"] for e in full_res["examples"][5:10]],
        )

        # Case-insensitive query filter across description (e.g. "CVE-")
        cve_upper = asyncio.run(
            srv.get_procedure_examples_by_technique(
                "T1190",
                domain="enterprise",
                include_description=True,
                include_formatted=False,
                limit=200,
                query="CVE-",
            )
        )
        cve_lower = asyncio.run(
            srv.get_procedure_examples_by_technique(
                "T1190",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
                query="cve-",
            )
        )
        self.assertGreater(cve_upper["total_count"], 0)
        self.assertLess(cve_upper["total_count"], full_res["total_count"])
        # Query matches description even when include_description=False
        self.assertEqual(cve_lower["total_count"], cve_upper["total_count"])
        self.assertEqual(
            [e["relationship_id"] for e in cve_lower["examples"]],
            [e["relationship_id"] for e in cve_upper["examples"]],
        )
        self.assertIn("matching query 'CVE-'", cve_upper["message"])
        for e in cve_upper["examples"]:
            haystack = (
                f"{e['description'] or ''}\n"
                f"{e['source']['name'] or ''}\n"
                f"{e['source']['attack_id'] or ''}\n"
                f"{e['source']['stix_id'] or ''}"
            ).lower()
            self.assertIn("cve-", haystack)

        # Query by source ATT&CK ID (case-insensitive)
        first_src = full_res["examples"][0]["source"]
        if first_src.get("attack_id"):
            by_src_id = asyncio.run(
                srv.get_procedure_examples_by_technique(
                    "T1190",
                    domain="enterprise",
                    include_description=False,
                    include_formatted=False,
                    query=first_src["attack_id"].lower(),
                )
            )
            self.assertGreaterEqual(by_src_id["total_count"], 1)
            self.assertTrue(
                any(
                    e["source"]["attack_id"] == first_src["attack_id"]
                    for e in by_src_id["examples"]
                )
            )

        # Non-matching query returns 0 cleanly
        none_res = asyncio.run(
            srv.get_procedure_examples_by_technique(
                "T1190",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                query="ZZZ_NONEXISTENT_PROCEDURE_999",
            )
        )
        self.assertTrue(none_res["found"])
        self.assertEqual(none_res["count"], 0)
        self.assertEqual(none_res["total_count"], 0)
        self.assertFalse(none_res["has_more"])
        self.assertIsNone(none_res["next_offset"])
        self.assertEqual(none_res["examples"], [])
        self.assertEqual(none_res["formatted"], "")
        self.assertIn("ZZZ_NONEXISTENT_PROCEDURE_999", none_res["message"])

    def test_detection_strategies_suggested_platforms_single_and_batch(self) -> None:
        cases = [
            (["QNAP"], ["Linux", "Network Devices"]),
            (["Ubuntu"], ["Linux"]),
            (["Router"], ["Network Devices"]),
            (["Ubuntu", "Router"], ["Network Devices", "Linux"]),
        ]

        # Single mode
        for raw_plats, expected_suggested in cases:
            res = asyncio.run(
                srv.get_detection_strategies_for_technique(
                    technique_stix_id="T1190",
                    domain="enterprise",
                    include_description=False,
                    platforms=raw_plats,
                )
            )
            self.assertTrue(res["found"])
            self.assertEqual(res["count"], 0)
            self.assertEqual(res["detection_strategies"], [])
            self.assertEqual(res.get("suggested_platforms"), expected_suggested)
            self.assertIn("Suggested ATT&CK platform(s)", res["message"])
            for plat in expected_suggested:
                self.assertIn(plat, res["message"])

        # Single mode unknown platform has no suggested_platforms noise
        unknown_single = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
                platforms=["NonExistentOS"],
            )
        )
        self.assertNotIn("suggested_platforms", unknown_single)
        self.assertNotIn("Suggested ATT&CK platform(s)", unknown_single["message"])

        # Batch mode (both compact and full)
        for detail_level in ("compact", "full"):
            batch_res = asyncio.run(
                srv.get_detection_strategies_for_technique(
                    technique_ids=["T1190", "T1003"],
                    domain="enterprise",
                    include_description=False,
                    detail_level=detail_level,
                    platforms=["QNAP"],
                )
            )
            self.assertEqual(batch_res["counts"]["analytics"], 0)
            self.assertEqual(
                batch_res.get("suggested_platforms"),
                ["Linux", "Network Devices"],
            )
            self.assertEqual(
                batch_res["metadata"].get("suggested_platforms"),
                ["Linux", "Network Devices"],
            )
            self.assertIn("Suggested ATT&CK platform(s)", batch_res["message"])
            self.assertIn("Linux", batch_res["message"])
            self.assertIn("Network Devices", batch_res["message"])

    def test_get_techniques_by_tactic_suggested_platforms(self) -> None:
        cases = [
            (["QNAP"], ["Linux", "Network Devices"]),
            (["Ubuntu"], ["Linux"]),
            (["Router"], ["Network Devices"]),
        ]
        for raw_plats, expected_suggested in cases:
            res = asyncio.run(
                srv.get_techniques_by_tactic(
                    "Persistence",
                    domain="enterprise",
                    include_description=False,
                    include_formatted=False,
                    platforms=raw_plats,
                )
            )
            self.assertEqual(res["count"], 0)
            self.assertEqual(res["total_count"], 0)
            self.assertEqual(res.get("suggested_platforms"), expected_suggested)
            self.assertIn("Suggested ATT&CK platform(s)", res["message"])
            for plat in expected_suggested:
                self.assertIn(plat, res["message"])

        # Domain-scoped check: Ubuntu on mobile should not suggest Linux
        mob_res = asyncio.run(
            srv.get_techniques_by_tactic(
                "Initial Access",
                domain="mobile",
                include_description=False,
                include_formatted=False,
                platforms=["Ubuntu"],
            )
        )
        self.assertEqual(mob_res["count"], 0)
        self.assertNotIn("suggested_platforms", mob_res)
        self.assertNotIn("Suggested ATT&CK platform(s)", mob_res["message"])

    def test_search_techniques_suggested_platforms_single_and_cross_domain(self) -> None:
        cases = [
            (["QNAP"], ["Linux", "Network Devices"]),
            (["Ubuntu"], ["Linux"]),
            (["Router"], ["Network Devices"]),
        ]
        # Single-domain enterprise
        for raw_plats, expected_suggested in cases:
            res = asyncio.run(
                srv.search_techniques(
                    "Command",
                    domain="enterprise",
                    include_description=False,
                    include_formatted=False,
                    platforms=raw_plats,
                )
            )
            self.assertEqual(res["count"], 0)
            self.assertEqual(res["total_count"], 0)
            self.assertEqual(res.get("suggested_platforms"), expected_suggested)
            self.assertIn("Suggested ATT&CK platform(s)", res["message"])
            for plat in expected_suggested:
                self.assertIn(plat, res["message"])

        # Cross-domain (both full and compact)
        for detail_level in ("full", "compact"):
            all_res = asyncio.run(
                srv.search_techniques(
                    "Command",
                    domain="all",
                    include_description=False,
                    include_formatted=False,
                    detail_level=detail_level,
                    platforms=["QNAP"],
                )
            )
            self.assertEqual(all_res["count"], 0)
            self.assertEqual(all_res["total_count"], 0)
            self.assertEqual(
                all_res.get("suggested_platforms"),
                ["Linux", "Network Devices"],
            )
            self.assertIn("Suggested ATT&CK platform(s)", all_res["message"])
            self.assertIn("Linux", all_res["message"])
            self.assertIn("Network Devices", all_res["message"])


if __name__ == "__main__":
    unittest.main()

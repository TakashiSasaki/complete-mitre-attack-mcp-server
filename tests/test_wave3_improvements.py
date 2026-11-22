"""Unit tests for Wave 3 improvements:
1. generate_layer support for Technique IDs (Txxxx / Txxxx.xxx), multiple ATT&CK IDs
   (via comma-separated attack_id or attack_ids list), strict validation, and deterministic sorting.
2. Compact relationship payload controls (include_relationships) and attribution provenance
   filtering (attribution_filter: 'all' | 'direct' | 'campaign') on group-technique tools
   (get_techniques_used_by_group, get_group_techniques) plus include_relationships on
   get_techniques_used_by_group_software.
"""

import asyncio
import json
import unittest

from mitreattack import release_info
import mitre_mcp_server.server as srv


class TestWave3GenerateLayerTechniquesAndMultiIDs(unittest.TestCase):
    """Verify generate_layer supports Txxxx/Txxxx.xxx, multi-IDs, deterministic sort, and strict validation."""

    def test_mcp_schema_exposes_attack_ids_and_technique_support(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        tool = tools["generate_layer"]
        props = tool.inputSchema.get("properties", {})
        self.assertIn("attack_id", props)
        self.assertIn("attack_ids", props)
        self.assertIn("score", props)
        self.assertIn("domain", props)
        desc = tool.description or ""
        self.assertIn("Txxxx", desc)
        self.assertIn("attack_ids", desc)

    def test_generate_layer_single_technique_and_subtechnique(self) -> None:
        # T1190: Exploit Public-Facing Application (https://attack.mitre.org/techniques/T1190/)
        res = asyncio.run(srv.generate_layer(attack_id="T1190", score=5, domain="enterprise"))
        self.assertTrue(res["success"], f"Expected success for T1190: {res}")
        self.assertEqual(res["attack_id"], "T1190")
        self.assertEqual(res["attack_ids"], ["T1190"])
        self.assertEqual(res["domain"], "enterprise")
        self.assertEqual(res["count"], 1)
        layer = res["layer"]
        self.assertIsNotNone(layer)
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["versions"]["attack"], str(release_info.LATEST_VERSION))
        self.assertEqual(layer["versions"]["navigator"], "5.1.0")
        self.assertEqual(layer["versions"]["layer"], "4.5")
        self.assertEqual(len(layer["techniques"]), 1)
        entry = layer["techniques"][0]
        self.assertEqual(entry["techniqueID"], "T1190")
        self.assertEqual(entry["score"], 5)
        self.assertTrue(entry["enabled"])
        self.assertIn("T1190", entry["comment"])

        # Sub-technique T1059.001 (PowerShell) with lowercase/whitespace normalization
        sub = asyncio.run(srv.generate_layer(attack_id="  t1059.001  ", score=3, domain="enterprise"))
        self.assertTrue(sub["success"], f"Expected success for T1059.001: {sub}")
        self.assertEqual(sub["attack_id"], "T1059.001")
        self.assertEqual(sub["count"], 1)
        self.assertEqual(sub["layer"]["techniques"][0]["techniqueID"], "T1059.001")
        self.assertEqual(sub["layer"]["techniques"][0]["score"], 3)

    def test_generate_layer_multiple_ids_and_deterministic_sort(self) -> None:
        # Order A vs Order B via attack_ids list must yield identical deterministic technique ordering
        res_a = asyncio.run(
            srv.generate_layer(
                attack_ids=["T1190", "T1059.001", "T1003", "T1190"],
                score=10,
                domain="enterprise",
            )
        )
        res_b = asyncio.run(
            srv.generate_layer(
                attack_ids=["T1003", "T1059.001", "T1190"],
                score=10,
                domain="enterprise",
            )
        )
        self.assertTrue(res_a["success"])
        self.assertTrue(res_b["success"])
        self.assertEqual(res_a["count"], 3)
        self.assertEqual(res_b["count"], 3)
        ids_a = [t["techniqueID"] for t in res_a["layer"]["techniques"]]
        ids_b = [t["techniqueID"] for t in res_b["layer"]["techniques"]]
        self.assertEqual(ids_a, ["T1003", "T1059.001", "T1190"])
        self.assertEqual(ids_a, ids_b)

        # Comma-separated attack_id string produces identical technique list
        res_csv = asyncio.run(
            srv.generate_layer(
                attack_id="T1190, t1059.001, T1003",
                score=10,
                domain="enterprise",
            )
        )
        self.assertTrue(res_csv["success"])
        self.assertEqual(
            [t["techniqueID"] for t in res_csv["layer"]["techniques"]],
            ["T1003", "T1059.001", "T1190"],
        )

        # Mixed group + technique IDs (G0016 + T1190) and deterministic sorting on single G0016
        g0016 = asyncio.run(srv.generate_layer(attack_id="G0016", domain="enterprise"))
        self.assertTrue(g0016["success"])
        g0016_ids = [t["techniqueID"] for t in g0016["layer"]["techniques"]]
        self.assertEqual(
            g0016_ids,
            sorted(g0016_ids, key=lambda tid: srv._attack_id_sort_key(tid, "", "")),
        )

        mixed = asyncio.run(
            srv.generate_layer(attack_ids=["G0016", "T1190"], score=2, domain="enterprise")
        )
        self.assertTrue(mixed["success"])
        mixed_ids = [t["techniqueID"] for t in mixed["layer"]["techniques"]]
        self.assertIn("T1190", mixed_ids)
        self.assertEqual(len(mixed_ids), len(set(mixed_ids)))
        self.assertEqual(
            mixed_ids,
            sorted(mixed_ids, key=lambda tid: srv._attack_id_sort_key(tid, "", "")),
        )

    def test_generate_layer_rejects_bad_and_missing_ids(self) -> None:
        bad_cases = [
            {"attack_id": ""},
            {"attack_id": "   "},
            {"attack_id": "INVALID"},
            {"attack_id": "X9999"},
            {"attack_id": "TA0001"},
            {"attack_id": "T1190.abc"},
            {"attack_ids": ["T1190", "BADID"]},
            {"attack_id": "T999999"},
            {"attack_ids": ["T1190", "T999999"]},
            {"attack_id": "T1190", "domain": "invalid-domain"},
        ]
        for kwargs in bad_cases:
            with self.subTest(kwargs=kwargs):
                res = asyncio.run(srv.generate_layer(**kwargs))
                self.assertFalse(res["success"], f"Expected failure for {kwargs}, got {res}")
                self.assertIsNone(res["layer"])
                self.assertEqual(res["count"], 0)


class TestWave3GroupRelationshipCompactAndAttributionFilter(unittest.TestCase):
    """Verify include_relationships and attribution_filter on group technique tools."""

    def test_mcp_schemas_expose_new_options(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        for name in ("get_techniques_used_by_group", "get_group_techniques"):
            props = tools[name].inputSchema.get("properties", {})
            self.assertIn("include_relationships", props, f"{name} missing include_relationships")
            self.assertEqual(props["include_relationships"].get("default"), True)
            self.assertIn("attribution_filter", props, f"{name} missing attribution_filter")
            self.assertEqual(props["attribution_filter"].get("default"), "all")
            self.assertEqual(
                set(props["attribution_filter"].get("enum", [])),
                {"all", "direct", "campaign"},
            )

        sw_props = tools["get_techniques_used_by_group_software"].inputSchema.get("properties", {})
        self.assertIn("include_relationships", sw_props)
        self.assertEqual(sw_props["include_relationships"].get("default"), True)

    def test_include_relationships_false_reduces_payload_and_preserves_attribution(self) -> None:
        full = asyncio.run(
            srv.get_techniques_used_by_group(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=200,
                offset=0,
                include_formatted=False,
                include_relationships=True,
            )
        )
        compact = asyncio.run(
            srv.get_techniques_used_by_group(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=200,
                offset=0,
                include_formatted=False,
                include_relationships=False,
            )
        )
        self.assertTrue(full["found"])
        self.assertTrue(compact["found"])
        self.assertEqual(compact["total_count"], full["total_count"])
        self.assertEqual(compact["count"], full["count"])
        self.assertEqual(
            [(t["attack_id"], t["attribution_source"]) for t in compact["techniques"]],
            [(t["attack_id"], t["attribution_source"]) for t in full["techniques"]],
        )
        self.assertTrue(all(t["relationships"] == [] for t in compact["techniques"]))
        self.assertTrue(any(len(t["relationships"]) > 0 for t in full["techniques"]))

        full_bytes = len(json.dumps(full))
        compact_bytes = len(json.dumps(compact))
        self.assertLess(compact_bytes, full_bytes * 0.6, f"Expected >40% payload reduction: {compact_bytes} vs {full_bytes}")

        # Also verify get_techniques_used_by_group_software compact payload reduction
        sw_full = asyncio.run(
            srv.get_techniques_used_by_group_software(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=50,
                offset=0,
                include_formatted=False,
                include_relationships=True,
            )
        )
        sw_compact = asyncio.run(
            srv.get_techniques_used_by_group_software(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=50,
                offset=0,
                include_formatted=False,
                include_relationships=False,
            )
        )
        self.assertEqual(sw_compact["total_count"], sw_full["total_count"])
        self.assertTrue(all(t["relationships"] == [] and t["provenance_paths"] == [] for t in sw_compact["techniques"]))
        self.assertLess(len(json.dumps(sw_compact)), len(json.dumps(sw_full)) * 0.5)

    def test_attribution_filter_direct_campaign_all_and_parity(self) -> None:
        all_res = asyncio.run(
            srv.get_techniques_used_by_group(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=200,
                offset=0,
                include_formatted=False,
                include_relationships=False,
                attribution_filter="all",
            )
        )
        direct_res = asyncio.run(
            srv.get_techniques_used_by_group(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=200,
                offset=0,
                include_formatted=False,
                include_relationships=False,
                attribution_filter="direct",
            )
        )
        camp_res = asyncio.run(
            srv.get_techniques_used_by_group(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=200,
                offset=0,
                include_formatted=False,
                include_relationships=False,
                attribution_filter="campaign",
            )
        )

        expected_direct = [
            t["attack_id"] for t in all_res["techniques"] if t["attribution_source"] in ("direct", "both")
        ]
        expected_camp = [
            t["attack_id"] for t in all_res["techniques"] if t["attribution_source"] in ("campaign", "both")
        ]

        self.assertEqual([t["attack_id"] for t in direct_res["techniques"]], expected_direct)
        self.assertEqual(direct_res["total_count"], len(expected_direct))
        self.assertTrue(all(t["attribution_source"] in ("direct", "both") for t in direct_res["techniques"]))

        self.assertEqual([t["attack_id"] for t in camp_res["techniques"]], expected_camp)
        self.assertEqual(camp_res["total_count"], len(expected_camp))
        self.assertTrue(all(t["attribution_source"] in ("campaign", "both") for t in camp_res["techniques"]))

        self.assertLess(direct_res["total_count"], all_res["total_count"])
        self.assertLess(camp_res["total_count"], all_res["total_count"])

        # Pagination accuracy under attribution_filter
        page0 = asyncio.run(
            srv.get_techniques_used_by_group(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=5,
                offset=0,
                include_formatted=False,
                include_relationships=False,
                attribution_filter="direct",
            )
        )
        self.assertEqual(page0["total_count"], len(expected_direct))
        self.assertEqual(page0["count"], 5)
        self.assertTrue(page0["has_more"])
        self.assertEqual(page0["next_offset"], 5)

        # Parity with get_group_techniques("APT29")
        apt29_direct = asyncio.run(
            srv.get_group_techniques(
                "APT29",
                domain="enterprise",
                include_description=False,
                limit=200,
                offset=0,
                include_formatted=False,
                include_relationships=False,
                attribution_filter="direct",
            )
        )
        self.assertEqual(
            [(t["attack_id"], t["attribution_source"]) for t in apt29_direct["techniques"]],
            [(t["attack_id"], t["attribution_source"]) for t in direct_res["techniques"]],
        )
        self.assertTrue(all(t["relationships"] == [] for t in apt29_direct["techniques"]))

        # Invalid attribution_filter raises ValueError
        with self.assertRaises(ValueError):
            asyncio.run(srv.get_techniques_used_by_group("G0016", attribution_filter="bogus"))  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            asyncio.run(srv.get_group_techniques("APT29", attribution_filter="bogus"))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

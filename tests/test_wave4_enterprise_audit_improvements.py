"""Regression tests for Wave 4 enterprise server / IT asset audit improvements:
1. Platform-filtered detection strategies on `get_detection_strategies_for_technique`
   (single mode, batch compact mode, and batch full mode).
2. `get_techniques_by_platform` case-insensitive normalization and `available_platforms`
   discovery when 0 techniques match.
3. `get_all_assets` `include_formatted` parameter consistency.
"""

import asyncio
import unittest

import mitre_mcp_server.server as srv


class TestWave4EnterpriseAuditImprovements(unittest.TestCase):
    """Verify platform-filtered detections, platform discovery, and get_all_assets formatting."""

    def test_mcp_schemas_expose_wave4_parameters(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}

        det_props = tools["get_detection_strategies_for_technique"].inputSchema.get("properties", {})
        self.assertIn("platforms", det_props)

        assets_props = tools["get_all_assets"].inputSchema.get("properties", {})
        self.assertIn("include_formatted", assets_props)
        self.assertEqual(assets_props["include_formatted"].get("default"), True)

    def test_detection_strategies_single_mode_platform_filtering(self) -> None:
        unfiltered = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertNotIn("applied_platforms", unfiltered)
        unfiltered_an_count = sum(
            len(ds["analytics"]) for ds in unfiltered["detection_strategies"]
        )
        self.assertGreater(unfiltered_an_count, 1)

        # Empty list preserves unfiltered backward-compatible behavior
        empty_filter = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
                platforms=[],
            )
        )
        self.assertNotIn("applied_platforms", empty_filter)
        self.assertEqual(
            sum(len(ds["analytics"]) for ds in empty_filter["detection_strategies"]),
            unfiltered_an_count,
        )

        # Case-insensitive single-platform filtering
        linux_res = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
                platforms=["linux"],
            )
        )
        self.assertTrue(linux_res["found"])
        self.assertEqual(linux_res["applied_platforms"], ["Linux"])
        self.assertIn("Linux", linux_res["message"])
        linux_analytics = [
            an for ds in linux_res["detection_strategies"] for an in ds["analytics"]
        ]
        self.assertGreater(len(linux_analytics), 0)
        self.assertLess(len(linux_analytics), unfiltered_an_count)
        for an in linux_analytics:
            self.assertIn("Linux", an["platforms"])

        # Multi-platform filtering
        multi_res = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
                platforms=["windows", "linux"],
            )
        )
        self.assertEqual(multi_res["applied_platforms"], ["Linux", "Windows"])
        multi_analytics = [
            an for ds in multi_res["detection_strategies"] for an in ds["analytics"]
        ]
        self.assertGreaterEqual(len(multi_analytics), len(linux_analytics))
        for an in multi_analytics:
            self.assertTrue(
                any(p in ("Linux", "Windows") for p in an["platforms"]),
                f"Unexpected analytic platforms: {an['platforms']}",
            )

        # Non-matching platform filters out strategies with 0 matching analytics
        none_res = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
                platforms=["NonExistentOS"],
            )
        )
        self.assertTrue(none_res["found"])
        self.assertEqual(none_res["count"], 0)
        self.assertEqual(none_res["detection_strategies"], [])
        self.assertEqual(none_res["applied_platforms"], ["NonExistentOS"])

    def test_detection_strategies_batch_mode_platform_filtering(self) -> None:
        unfiltered = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1190", "T1059.001", "T1003"],
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertNotIn("applied_platforms", unfiltered)
        self.assertNotIn("applied_platforms", unfiltered["metadata"])

        # Compact batch mode filtered to Linux
        compact_linux = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1190", "T1059.001", "T1003"],
                domain="enterprise",
                include_description=False,
                detail_level="compact",
                platforms=["linux"],
            )
        )
        self.assertTrue(compact_linux["batch"])
        self.assertEqual(compact_linux["applied_platforms"], ["Linux"])
        self.assertEqual(compact_linux["metadata"]["applied_platforms"], ["Linux"])
        self.assertIn("Linux", compact_linux["message"])

        an_map = compact_linux["coverage"]["analytics"]
        dc_map = compact_linux["coverage"]["data_components"]
        an_to_dc = compact_linux["coverage"]["edges"]["analytic_to_data_component"]
        ds_to_an = compact_linux["coverage"]["edges"]["detection_strategy_to_analytic"]

        self.assertGreater(len(an_map), 0)
        self.assertLess(len(an_map), unfiltered["counts"]["analytics"])
        self.assertLessEqual(len(dc_map), unfiltered["counts"]["data_components"])

        # Every returned analytic must match Linux
        for an_id, an_obj in an_map.items():
            self.assertIn("Linux", an_obj["platforms"], f"{an_id} missing Linux platform")

        # Edges and data_components must be strictly consistent with filtered analytics
        self.assertTrue(set(an_to_dc.keys()).issubset(set(an_map.keys())))
        referenced_dcs = {dc for dcs in an_to_dc.values() for dc in dcs}
        self.assertEqual(set(dc_map.keys()), referenced_dcs)
        for ds_id, an_ids in ds_to_an.items():
            self.assertTrue(set(an_ids).issubset(set(an_map.keys())))

        # PowerShell (T1059.001) has Windows-only analytics or no Linux analytics -> verify parity with full mode
        full_linux = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1190", "T1059.001", "T1003"],
                domain="enterprise",
                include_description=False,
                detail_level="full",
                platforms=["Linux"],
            )
        )
        self.assertEqual(full_linux["applied_platforms"], ["Linux"])
        self.assertEqual(full_linux["metadata"]["applied_platforms"], ["Linux"])
        self.assertEqual(full_linux["counts"], compact_linux["counts"])
        full_an_ids = {a["attack_id"] for a in full_linux["coverage"]["analytics"]}
        full_dc_ids = {d["attack_id"] for d in full_linux["coverage"]["data_components"]}
        self.assertEqual(full_an_ids, set(an_map.keys()))
        self.assertEqual(full_dc_ids, set(dc_map.keys()))

        # Non-matching platform leaves all valid techniques as VALID_NO_DETECTION
        none_batch = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1190", "T1003"],
                domain="enterprise",
                platforms=["NonExistentOS"],
            )
        )
        self.assertEqual(none_batch["counts"]["detection_strategies"], 0)
        self.assertEqual(none_batch["counts"]["analytics"], 0)
        self.assertEqual(none_batch["counts"]["data_components"], 0)
        self.assertEqual(none_batch["counts"]["valid_no_detection"], 2)
        self.assertEqual(none_batch["metadata"]["applied_platforms"], ["NonExistentOS"])

    def test_get_techniques_by_platform_normalization_and_discovery(self) -> None:
        # Case-insensitive matching ("linux" -> "Linux", "esxi" -> "ESXi")
        linux_lower = asyncio.run(
            srv.get_techniques_by_platform("linux", domain="enterprise", include_description=False, limit=5)
        )
        linux_canon = asyncio.run(
            srv.get_techniques_by_platform("Linux", domain="enterprise", include_description=False, limit=5)
        )
        self.assertEqual(linux_lower["platform"], "Linux")
        self.assertGreater(linux_lower["total_count"], 0)
        self.assertEqual(linux_lower["total_count"], linux_canon["total_count"])

        esxi_lower = asyncio.run(
            srv.get_techniques_by_platform("esxi", domain="enterprise", include_description=False, limit=5)
        )
        self.assertEqual(esxi_lower["platform"], "ESXi")
        self.assertGreater(esxi_lower["total_count"], 0)

        # Unrecognized platforms ("Cloud", "Ubuntu", blank) return available_platforms + guidance
        for bad_plat in ("Cloud", "Ubuntu", "   "):
            res = asyncio.run(
                srv.get_techniques_by_platform(bad_plat, domain="enterprise", include_description=False)
            )
            self.assertEqual(res["count"], 0)
            self.assertEqual(res["total_count"], 0)
            self.assertIn("available_platforms", res)
            avail = res["available_platforms"]
            self.assertIsInstance(avail, list)
            for expected in ("Windows", "Linux", "macOS", "Containers", "IaaS", "SaaS", "ESXi"):
                self.assertIn(expected, avail)
            self.assertIn("Valid platforms for domain 'enterprise':", res["message"])
            self.assertIn("Linux", res["message"])

        # Mobile domain also returns its own valid platforms when 0 match
        mob_bad = asyncio.run(
            srv.get_techniques_by_platform("Linux", domain="mobile", include_description=False)
        )
        self.assertEqual(mob_bad["count"], 0)
        self.assertIn("Android", mob_bad["available_platforms"])
        self.assertIn("iOS", mob_bad["available_platforms"])
        self.assertIn("Android", mob_bad["message"])

    def test_get_all_assets_include_formatted(self) -> None:
        with_fmt = asyncio.run(
            srv.get_all_assets(domain="ics", include_description=False, include_formatted=True)
        )
        without_fmt = asyncio.run(
            srv.get_all_assets(domain="ics", include_description=False, include_formatted=False)
        )
        self.assertGreater(with_fmt["count"], 0)
        self.assertTrue(len(with_fmt["formatted"]) > 0)
        self.assertEqual(without_fmt["count"], with_fmt["count"])
        self.assertEqual(without_fmt["assets"], with_fmt["assets"])
        self.assertEqual(without_fmt["formatted"], "")


if __name__ == "__main__":
    unittest.main()

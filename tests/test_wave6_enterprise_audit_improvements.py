"""Regression tests for Wave 6 token efficiency and real-world IT asset mapping:
1. `get_all_datacomponents` token efficiency (`include_log_sources`, `log_source_count`,
   and `log_source_filter`).
2. `get_techniques_by_platform` real-world IT asset `suggested_platforms` guidance
   while preserving strict exact ATT&CK platform matching.
"""

import asyncio
import json
import unittest

import mitre_mcp_server.server as srv


class TestWave6EnterpriseAuditImprovements(unittest.TestCase):
    """Verify Wave 6 datacomponent token efficiency and real-world IT asset platform hints."""

    def test_mcp_schemas_expose_wave6_parameters(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}

        dc_props = tools["get_all_datacomponents"].inputSchema.get("properties", {})
        self.assertIn("include_log_sources", dc_props)
        self.assertEqual(dc_props["include_log_sources"].get("default"), True)
        self.assertIn("log_source_filter", dc_props)
        self.assertEqual(dc_props["log_source_filter"].get("default"), "")

    def test_get_all_datacomponents_include_log_sources_false_saves_tokens(self) -> None:
        full_res = asyncio.run(
            srv.get_all_datacomponents(
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
            )
        )
        compact_res = asyncio.run(
            srv.get_all_datacomponents(
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                include_log_sources=False,
                limit=200,
            )
        )

        self.assertEqual(full_res["total_count"], 106)
        self.assertEqual(compact_res["total_count"], 106)
        self.assertEqual(compact_res["count"], 106)
        self.assertIn("include_log_sources=False", compact_res["message"])

        # Verify significant payload size reduction when include_log_sources=False
        full_bytes = len(json.dumps(full_res["datacomponents"]))
        compact_bytes = len(json.dumps(compact_res["datacomponents"]))
        self.assertLess(compact_bytes * 2, full_bytes)

        # Verify DC0002 (User Account Authentication) retains high log_source_count while omitting array
        full_by_id = {dc["attack_id"]: dc for dc in full_res["datacomponents"]}
        compact_by_id = {dc["attack_id"]: dc for dc in compact_res["datacomponents"]}

        dc0002_full = full_by_id["DC0002"]
        dc0002_compact = compact_by_id["DC0002"]
        self.assertGreater(dc0002_full["log_source_count"], 50)
        self.assertEqual(dc0002_full["log_source_count"], len(dc0002_full["log_sources"]))
        self.assertEqual(dc0002_compact["log_source_count"], dc0002_full["log_source_count"])
        self.assertEqual(dc0002_compact["log_sources"], [])

        for aid, dc in compact_by_id.items():
            self.assertEqual(dc["log_sources"], [])
            self.assertEqual(dc["log_source_count"], full_by_id[aid]["log_source_count"])

        # Query matching still works across log_sources even when include_log_sources=False
        query_compact = asyncio.run(
            srv.get_all_datacomponents(
                domain="enterprise",
                query="auditd",
                include_description=False,
                include_formatted=False,
                include_log_sources=False,
                limit=200,
            )
        )
        self.assertGreater(query_compact["total_count"], 0)
        for dc in query_compact["datacomponents"]:
            self.assertEqual(dc["log_sources"], [])
            self.assertGreater(dc["log_source_count"], 0)

    def test_get_all_datacomponents_log_source_filter(self) -> None:
        # Drill into DC0002 without filter vs with platform-specific log_source_filter
        unfiltered = asyncio.run(
            srv.get_all_datacomponents(
                domain="enterprise",
                query="DC0002",
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(unfiltered["total_count"], 1)
        dc_full = unfiltered["datacomponents"][0]
        total_ls = dc_full["log_source_count"]
        self.assertGreater(total_ls, 50)

        for ls_filter in ("linux", "WinEventLog", "networkdevice"):
            filtered = asyncio.run(
                srv.get_all_datacomponents(
                    domain="enterprise",
                    query="DC0002",
                    include_description=False,
                    include_formatted=False,
                    include_log_sources=True,
                    log_source_filter=ls_filter,
                )
            )
            self.assertEqual(filtered["total_count"], 1)
            self.assertIn(f"log_source_filter='{ls_filter}'", filtered["message"])
            dc_filt = filtered["datacomponents"][0]
            # log_source_count preserves total count on the DC
            self.assertEqual(dc_filt["log_source_count"], total_ls)
            # Filtered log_sources is strictly smaller than full list
            self.assertLess(len(dc_filt["log_sources"]), total_ls)
            # Every returned log_source matches case-insensitively on name or channel
            f_low = ls_filter.lower()
            for ls in dc_filt["log_sources"]:
                self.assertTrue(
                    f_low in ls["name"].lower() or f_low in ls["channel"].lower(),
                    f"Log source {ls} did not match filter '{ls_filter}'",
                )
            if ls_filter in ("linux", "WinEventLog"):
                self.assertGreater(
                    len(dc_filt["log_sources"]),
                    0,
                    f"Expected at least one '{ls_filter}' log source on DC0002",
                )

    def test_get_techniques_by_platform_real_world_asset_suggestions(self) -> None:
        expected_mappings = {
            "NAS": ["Linux", "Network Devices"],
            "QNAP": ["Linux", "Network Devices"],
            "Synology": ["Linux", "Network Devices"],
            "QNAP TS-453D": ["Linux", "Network Devices"],
            "Router": ["Network Devices"],
            "Wi-Fi": ["Network Devices"],
            "Firewall": ["Network Devices"],
            "Legacy Wi-Fi Router": ["Network Devices"],
            "Ubuntu": ["Linux"],
            "Ubuntu 22.04": ["Linux"],
            "Debian": ["Linux"],
            "RHEL": ["Linux"],
            "Windows 10": ["Windows"],
            "Windows Server": ["Windows"],
            "Docker": ["Containers"],
            "Kubernetes": ["Containers"],
            "AWS": ["IaaS", "SaaS", "Identity Provider"],
            "Azure": ["IaaS", "SaaS", "Identity Provider"],
            "GCP": ["IaaS", "SaaS", "Identity Provider"],
            "Cloud": ["IaaS", "SaaS", "Identity Provider"],
        }

        for asset_label, expected_plats in expected_mappings.items():
            res = asyncio.run(
                srv.get_techniques_by_platform(
                    asset_label,
                    domain="enterprise",
                    include_description=False,
                    include_formatted=False,
                )
            )
            # Strict exact matching preserved: never silently guesses and returns techniques
            self.assertEqual(res["count"], 0, f"Expected strict 0 match for '{asset_label}'")
            self.assertEqual(res["total_count"], 0)
            self.assertEqual(res["techniques"], [])
            # Suggested platforms + clear guidance in message
            self.assertEqual(
                res["suggested_platforms"],
                expected_plats,
                f"Unexpected suggested_platforms for '{asset_label}'",
            )
            self.assertIn("Suggested ATT&CK platform(s)", res["message"])
            for plat in expected_plats:
                self.assertIn(plat, res["available_platforms"])
                self.assertIn(plat, res["message"])
            self.assertIn("Valid platforms for domain 'enterprise':", res["message"])

        # Completely unknown platform returns empty suggested_platforms
        unknown = asyncio.run(
            srv.get_techniques_by_platform(
                "ZZZ_UNKNOWN_OS_999",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(unknown["count"], 0)
        self.assertEqual(unknown["suggested_platforms"], [])
        self.assertNotIn("Suggested ATT&CK platform(s)", unknown["message"])
        self.assertIn("Valid platforms for domain 'enterprise':", unknown["message"])

        # Domain-scoped filtering: "Ubuntu" on mobile domain should NOT suggest "Linux"
        mobile_res = asyncio.run(
            srv.get_techniques_by_platform(
                "Ubuntu",
                domain="mobile",
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(mobile_res["count"], 0)
        self.assertEqual(mobile_res["suggested_platforms"], [])
        self.assertIn("Android", mobile_res["available_platforms"])


if __name__ == "__main__":
    unittest.main()

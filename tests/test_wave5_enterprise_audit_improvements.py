"""Regression tests for Wave 5 enterprise server vulnerability/detection assessment
and ATT&CK v20.1 log-source usability improvements:
1. `get_all_datacomponents` ATT&CK v20.1 `log_sources` exposure & `query` filter.
2. Platform-filtered `get_techniques_by_tactic` & `search_techniques` (single-domain & cross-domain).
3. `get_techniques_by_tactic` self-correcting `available_tactics` on unknown tactic.
"""

import asyncio
import unittest

import mitre_mcp_server.server as srv


class TestWave5EnterpriseAuditImprovements(unittest.TestCase):
    """Verify Wave 5 datacomponent log_sources/query, platform filtering, and tactic discovery."""

    def test_mcp_schemas_expose_wave5_parameters(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}

        dc_props = tools["get_all_datacomponents"].inputSchema.get("properties", {})
        self.assertIn("query", dc_props)
        self.assertEqual(dc_props["query"].get("default"), "")

        tactic_props = tools["get_techniques_by_tactic"].inputSchema.get("properties", {})
        self.assertIn("platforms", tactic_props)

        search_props = tools["search_techniques"].inputSchema.get("properties", {})
        self.assertIn("platforms", search_props)

    def test_get_all_datacomponents_log_sources_and_query_filter(self) -> None:
        all_dcs = asyncio.run(
            srv.get_all_datacomponents(
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
            )
        )
        self.assertEqual(all_dcs["total_count"], 106)
        self.assertEqual(all_dcs["count"], 106)

        with_log_sources = 0
        for dc in all_dcs["datacomponents"]:
            # Legacy keys preserved for backward compatibility
            self.assertIn("data_source_stix_id", dc)
            self.assertIn("data_source_name", dc)
            self.assertIn("data_source_attack_id", dc)
            # New v20.1 log_sources key present as a list of {name, channel}
            self.assertIn("log_sources", dc)
            self.assertIsInstance(dc["log_sources"], list)
            if dc["log_sources"]:
                with_log_sources += 1
                for ls in dc["log_sources"]:
                    self.assertIn("name", ls)
                    self.assertIn("channel", ls)
        self.assertGreater(with_log_sources, 90)

        # Filter by ATT&CK DC ID (case-insensitive)
        by_id = asyncio.run(
            srv.get_all_datacomponents(
                domain="enterprise",
                query="dc0032",
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(by_id["total_count"], 1)
        self.assertEqual(by_id["datacomponents"][0]["attack_id"], "DC0032")
        self.assertGreater(len(by_id["datacomponents"][0]["log_sources"]), 0)
        self.assertIn("dc0032", by_id["message"])

        # Filter by log_sources name ("auditd" and "Sysmon")
        for log_query in ("auditd", "Sysmon"):
            res = asyncio.run(
                srv.get_all_datacomponents(
                    domain="enterprise",
                    query=log_query,
                    include_description=False,
                    include_formatted=False,
                    limit=200,
                )
            )
            self.assertGreater(res["total_count"], 0, f"Expected matches for {log_query}")
            self.assertLess(res["total_count"], all_dcs["total_count"])
            self.assertIn(log_query, res["message"])
            q_low = log_query.lower()
            for dc in res["datacomponents"]:
                matched_in_fields = (
                    q_low in (dc["attack_id"] or "").lower()
                    or q_low in (dc["name"] or "").lower()
                    or any(
                        q_low in ls["name"].lower() or q_low in ls["channel"].lower()
                        for ls in dc["log_sources"]
                    )
                )
                # Note: description may also match even when include_description=False
                if not matched_in_fields:
                    ad = srv.get_attack_data("enterprise")
                    obj = ad.get_object_by_stix_id(dc["stix_id"])
                    self.assertIn(q_low, (srv._stix_get(obj, "description") or "").lower())

        # Non-matching query returns 0 cleanly
        none_res = asyncio.run(
            srv.get_all_datacomponents(
                domain="enterprise",
                query="ZZZ_NO_SUCH_LOG_CHANNEL_999",
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(none_res["count"], 0)
        self.assertEqual(none_res["total_count"], 0)
        self.assertEqual(none_res["datacomponents"], [])
        self.assertIn("ZZZ_NO_SUCH_LOG_CHANNEL_999", none_res["message"])

    def test_get_techniques_by_tactic_platform_filtering(self) -> None:
        unfiltered = asyncio.run(
            srv.get_techniques_by_tactic(
                "Persistence",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
            )
        )
        self.assertNotIn("applied_platforms", unfiltered)
        self.assertGreater(unfiltered["total_count"], 10)

        # Empty list preserves unfiltered backward-compatible behavior
        empty_filter = asyncio.run(
            srv.get_techniques_by_tactic(
                "Persistence",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
                platforms=[],
            )
        )
        self.assertNotIn("applied_platforms", empty_filter)
        self.assertEqual(empty_filter["total_count"], unfiltered["total_count"])

        # Case-insensitive single-platform filter
        linux_res = asyncio.run(
            srv.get_techniques_by_tactic(
                "Persistence",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
                platforms=["linux"],
            )
        )
        self.assertEqual(linux_res["applied_platforms"], ["Linux"])
        self.assertIn("Linux", linux_res["message"])
        self.assertGreater(linux_res["total_count"], 0)
        self.assertLess(linux_res["total_count"], unfiltered["total_count"])

        ad = srv.get_attack_data("enterprise")
        for tech in linux_res["techniques"]:
            obj = ad.get_object_by_stix_id(tech["stix_id"])
            plats = srv._stix_get(obj, "x_mitre_platforms", []) or []
            self.assertIn("Linux", plats, f"{tech['attack_id']} missing Linux platform")

        # Multi-platform filter
        multi_res = asyncio.run(
            srv.get_techniques_by_tactic(
                "Persistence",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
                platforms=["esxi", "linux"],
            )
        )
        self.assertEqual(multi_res["applied_platforms"], ["ESXi", "Linux"])
        self.assertGreaterEqual(multi_res["total_count"], linux_res["total_count"])
        for tech in multi_res["techniques"]:
            obj = ad.get_object_by_stix_id(tech["stix_id"])
            plats = srv._stix_get(obj, "x_mitre_platforms", []) or []
            self.assertTrue(
                any(p in ("Linux", "ESXi") for p in plats),
                f"{tech['attack_id']} has unexpected platforms: {plats}",
            )

        # Non-matching platform on valid tactic returns 0 without unknown-tactic error
        none_res = asyncio.run(
            srv.get_techniques_by_tactic(
                "Persistence",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                platforms=["NonExistentOS"],
            )
        )
        self.assertEqual(none_res["count"], 0)
        self.assertEqual(none_res["total_count"], 0)
        self.assertEqual(none_res["applied_platforms"], ["NonExistentOS"])
        self.assertIn("NonExistentOS", none_res["message"])
        self.assertNotIn("available_tactics", none_res)

    def test_search_techniques_platform_filtering_single_and_cross_domain(self) -> None:
        # Single-domain unfiltered
        unfiltered = asyncio.run(
            srv.search_techniques(
                "Command",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
            )
        )
        self.assertNotIn("applied_platforms", unfiltered)
        self.assertGreater(unfiltered["total_count"], 10)

        # Empty list preserves unfiltered behavior
        empty_filter = asyncio.run(
            srv.search_techniques(
                "Command",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
                platforms=[],
            )
        )
        self.assertNotIn("applied_platforms", empty_filter)
        self.assertEqual(empty_filter["total_count"], unfiltered["total_count"])

        # Single-domain Linux filter
        linux_res = asyncio.run(
            srv.search_techniques(
                "Command",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                limit=200,
                platforms=["linux"],
            )
        )
        self.assertEqual(linux_res["applied_platforms"], ["Linux"])
        self.assertIn("Linux", linux_res["message"])
        self.assertGreater(linux_res["total_count"], 0)
        self.assertLess(linux_res["total_count"], unfiltered["total_count"])

        ad = srv.get_attack_data("enterprise")
        for tech in linux_res["techniques"]:
            obj = ad.get_object_by_stix_id(tech["stix_id"])
            plats = srv._stix_get(obj, "x_mitre_platforms", []) or []
            self.assertIn("Linux", plats)

        # Single-domain non-matching platform
        none_res = asyncio.run(
            srv.search_techniques(
                "Command",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
                platforms=["NonExistentOS"],
            )
        )
        self.assertEqual(none_res["count"], 0)
        self.assertEqual(none_res["applied_platforms"], ["NonExistentOS"])
        self.assertIn("NonExistentOS", none_res["message"])

        # Cross-domain platform filtering (compact & full)
        all_linux = asyncio.run(
            srv.search_techniques(
                "Command",
                domain="all",
                include_description=False,
                include_formatted=False,
                detail_level="compact",
                limit=20,
                platforms=["linux"],
            )
        )
        self.assertEqual(all_linux["applied_platforms"], ["Linux"])
        self.assertIn("Linux", all_linux["message"])
        self.assertGreater(all_linux["domain_status"]["enterprise"]["match_count"], 0)
        self.assertEqual(all_linux["domain_status"]["mobile"]["match_count"], 0)
        self.assertEqual(
            all_linux["total_count"],
            sum(all_linux["domain_status"][d]["match_count"] for d in srv.DOMAINS),
        )
        for tech in all_linux["techniques"]:
            dom_ad = srv.get_attack_data(tech["domain"])
            obj = dom_ad.get_object_by_stix_id(tech["stix_id"])
            plats = srv._stix_get(obj, "x_mitre_platforms", []) or []
            self.assertIn("Linux", plats, f"{tech['domain']}:{tech['attack_id']} missing Linux")

    def test_get_techniques_by_tactic_available_tactics_self_correction(self) -> None:
        # Unrecognized tactics return sorted available_tactics + guidance in message
        for bad_tactic in ("Recon", "UnknownTactic", "   "):
            res = asyncio.run(
                srv.get_techniques_by_tactic(
                    bad_tactic,
                    domain="enterprise",
                    include_description=False,
                    include_formatted=False,
                )
            )
            self.assertEqual(res["count"], 0)
            self.assertEqual(res["total_count"], 0)
            self.assertIn("available_tactics", res)
            avail = res["available_tactics"]
            self.assertEqual(avail, sorted(avail))
            for expected in ("Initial Access", "Persistence", "Stealth", "Defense Impairment", "Reconnaissance"):
                self.assertIn(expected, avail)
            self.assertIn("Valid tactics for domain 'enterprise':", res["message"])
            self.assertIn("Initial Access", res["message"])

        # Legacy "Defense Evasion" keeps suggested_tactics AND includes available_tactics
        legacy_res = asyncio.run(
            srv.get_techniques_by_tactic(
                "Defense Evasion",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(legacy_res["count"], 0)
        self.assertEqual(legacy_res["suggested_tactics"], ["Stealth", "Defense Impairment"])
        self.assertIn("available_tactics", legacy_res)
        self.assertIn("Stealth", legacy_res["available_tactics"])
        self.assertIn("Defense Impairment", legacy_res["available_tactics"])
        self.assertIn("Valid tactics for domain 'enterprise':", legacy_res["message"])

        # Mobile domain returns its own valid tactics
        mob_res = asyncio.run(
            srv.get_techniques_by_tactic(
                "UnknownTactic",
                domain="mobile",
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(mob_res["count"], 0)
        self.assertIn("available_tactics", mob_res)
        self.assertIn("Initial Access", mob_res["available_tactics"])
        self.assertIn("Valid tactics for domain 'mobile':", mob_res["message"])


if __name__ == "__main__":
    unittest.main()

"""Regression tests for unified STIX/ATT&CK ID resolution, aliases, metadata, filtering, pagination, and UX fixes."""

import asyncio
import unittest

import mitre_mcp_server.server as srv


class TestUnifiedIdentifierResolution(unittest.TestCase):
    """Verify resolve_stix_id and all 25 *_stix_id tools accept ATT&CK IDs and handle invalid IDs safely."""

    def test_resolve_stix_id_helper(self) -> None:
        self.assertEqual(
            srv.resolve_stix_id("T1190", "enterprise", "attack-pattern"),
            "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
        )
        self.assertIsNotNone(srv.resolve_stix_id("t1566.002", "enterprise", "attack-pattern"))
        self.assertEqual(
            srv.resolve_stix_id("G0016", "enterprise", "intrusion-set"),
            "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
        )
        self.assertIsNotNone(srv.resolve_stix_id("S0154", "enterprise", ("malware", "tool")))
        self.assertIsNotNone(srv.resolve_stix_id("M1051", "enterprise", "course-of-action"))
        self.assertIsNotNone(srv.resolve_stix_id("C0024", "enterprise", "campaign"))
        self.assertIsNotNone(srv.resolve_stix_id("DC0032", "enterprise", "x-mitre-data-component"))
        self.assertIsNotNone(srv.resolve_stix_id("A0003", "ics", "x-mitre-asset"))
        self.assertIsNotNone(srv.resolve_stix_id("enterprise-attack", "enterprise", "x-mitre-matrix"))

        # Nonexistent or mismatched type returns None cleanly
        self.assertIsNone(srv.resolve_stix_id("T999999", "enterprise", "attack-pattern"))
        self.assertIsNone(srv.resolve_stix_id("G0016", "enterprise", "attack-pattern"))
        self.assertIsNone(srv.resolve_stix_id("   ", "enterprise", "attack-pattern"))

    def test_all_25_stix_id_tools_accept_attack_ids(self) -> None:
        # 1. get_subtechniques_of_technique
        res = asyncio.run(srv.get_subtechniques_of_technique("T1566", domain="enterprise"))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)
        self.assertEqual(res["parent"]["attack_id"], "T1566")

        # 2. get_parent_technique_of_subtechnique
        res = asyncio.run(srv.get_parent_technique_of_subtechnique("T1566.002", domain="enterprise", include_description=False))
        self.assertTrue(res["found"])
        self.assertEqual(res["parent"]["attack_id"], "T1566")

        # 3. get_tactics_by_technique
        res = asyncio.run(srv.get_tactics_by_technique("T1190", domain="enterprise"))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 4. get_techniques_used_by_group
        res = asyncio.run(srv.get_techniques_used_by_group("G0016", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)
        self.assertEqual(res["group"]["attack_id"], "G0016")

        # 5. get_techniques_used_by_group_software
        res = asyncio.run(srv.get_techniques_used_by_group_software("G0016", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertEqual(res["total_count"], 205)
        self.assertEqual(res["count"], srv.DEFAULT_PAGE_LIMIT)
        self.assertTrue(res["has_more"])
        self.assertEqual(res["next_offset"], srv.DEFAULT_PAGE_LIMIT)

        # 6. get_software_used_by_group
        res = asyncio.run(srv.get_software_used_by_group("G0016", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 7. get_groups_using_technique
        res = asyncio.run(srv.get_groups_using_technique("T1190", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 8. get_groups_using_software
        res = asyncio.run(srv.get_groups_using_software("S0154", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 9. get_techniques_used_by_software
        res = asyncio.run(srv.get_techniques_used_by_software("S0154", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 10. get_software_using_technique
        res = asyncio.run(srv.get_software_using_technique("T1190", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 11. get_campaigns_attributed_to_group
        res = asyncio.run(srv.get_campaigns_attributed_to_group("G0016", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertEqual(res["count"], 2)

        # 12. get_groups_attributing_to_campaign
        res = asyncio.run(srv.get_groups_attributing_to_campaign("C0024", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 13. get_techniques_used_by_campaign
        res = asyncio.run(srv.get_techniques_used_by_campaign("C0024", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 14. get_campaigns_using_technique
        res = asyncio.run(srv.get_campaigns_using_technique("T1190", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 15. get_software_used_by_campaign
        res = asyncio.run(srv.get_software_used_by_campaign("C0024", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 16. get_campaigns_using_software
        res = asyncio.run(srv.get_campaigns_using_software("S0154", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 17. get_mitigations_mitigating_technique
        res = asyncio.run(srv.get_mitigations_mitigating_technique("T1190", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 18. get_techniques_mitigated_by_mitigation
        res = asyncio.run(srv.get_techniques_mitigated_by_mitigation("M1051", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 19. get_datacomponents_detecting_technique (sync)
        res = srv.get_datacomponents_detecting_technique("T1059.001", domain="enterprise", include_description=False, include_formatted=False)
        self.assertTrue(res["found"])
        self.assertGreaterEqual(res["count"], 3)

        # 20. get_techniques_detected_by_datacomponent
        res = asyncio.run(srv.get_techniques_detected_by_datacomponent("DC0032", domain="enterprise", include_description=False, limit=10, offset=0, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertEqual(res["count"], 10)
        self.assertGreater(res["total_count"], 100)

        # 21. get_detection_strategies_for_technique
        res = asyncio.run(srv.get_detection_strategies_for_technique("T1190", domain="enterprise", include_description=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 22. get_assets_targeted_by_technique
        res = asyncio.run(srv.get_assets_targeted_by_technique("T0816", domain="ics", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertEqual(res["count"], 18)

        # 23. get_techniques_targeting_asset
        res = asyncio.run(srv.get_techniques_targeting_asset("A0003", domain="ics", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 0)

        # 24. get_procedure_examples_by_technique
        res = asyncio.run(srv.get_procedure_examples_by_technique("T1190", domain="enterprise", include_description=False, limit=10, offset=0, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertEqual(res["count"], 10)
        self.assertGreater(res["total_count"], 10)

        # 25. get_tactics_by_matrix
        res = asyncio.run(srv.get_tactics_by_matrix("enterprise-attack", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(res["found"])
        self.assertGreater(res["count"], 10)

    def test_unresolvable_ids_return_structured_error_without_crash(self) -> None:
        bad_tech = asyncio.run(srv.get_subtechniques_of_technique("T999999", domain="enterprise"))
        self.assertFalse(bad_tech["found"])
        self.assertEqual(bad_tech["count"], 0)
        self.assertIn("T999999", bad_tech["message"])

        bad_det = asyncio.run(srv.get_detection_strategies_for_technique("NOT_AN_ID", domain="enterprise"))
        self.assertFalse(bad_det["found"])
        self.assertEqual(bad_det["count"], 0)
        self.assertIn("NOT_AN_ID", bad_det["message"])

        wrong_type = asyncio.run(srv.get_groups_using_technique("G0016", domain="enterprise"))
        self.assertFalse(wrong_type["found"])
        self.assertEqual(wrong_type["count"], 0)
        self.assertIn("G0016", wrong_type["message"])


class TestAliasesMetadataFilteringPaginationAndDocstrings(unittest.TestCase):
    """Verify requirements 2 through 8."""

    def test_software_aliases_extracted_across_tools(self) -> None:
        camp_sw = asyncio.run(srv.get_software_used_by_campaign("C0024", domain="enterprise", include_description=False))
        sunburst = next((s for s in camp_sw["software"] if s["name"] == "SUNBURST"), None)
        self.assertIsNotNone(sunburst)
        self.assertIn("Solorigate", sunburst["aliases"])

        all_sw = asyncio.run(srv.get_all_software(domain="enterprise", include_description=False, limit=200, offset=0, include_formatted=False))
        self.assertTrue(any(len(s["aliases"]) > 0 for s in all_sw["software"]))

        sw_list = asyncio.run(srv.get_software(domain="enterprise", include_description=False, limit=50, offset=0, include_formatted=False))
        self.assertTrue(all("aliases" in s for s in sw_list["software"]))

        sw_search = asyncio.run(srv.search_software("SUNBURST", domain="enterprise", include_description=False, include_formatted=False))
        sb_match = next((s for s in sw_search["software"] if s["name"] == "SUNBURST"), None)
        self.assertIsNotNone(sb_match)
        self.assertIn("Solorigate", sb_match["aliases"])

    def test_get_technique_by_id_docstring_and_enriched_metadata(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        desc = (tools["get_technique_by_id"].description or "").lstrip()
        self.assertFalse(desc.startswith('"'), f"Leading stray quote in docstring: {desc[:40]!r}")

        t1190 = asyncio.run(srv.get_technique_by_id("T1190", domain="enterprise", include_description=False))
        self.assertTrue(t1190["found"])
        tech = t1190["technique"]
        self.assertEqual(tech["id"], "T1190")
        self.assertIsInstance(tech["platforms"], list)
        self.assertGreater(len(tech["platforms"]), 0)
        self.assertIn("Initial Access", tech["tactics"])
        self.assertFalse(tech["is_subtechnique"])
        self.assertTrue(str(tech["mitre_url"]).startswith("https://attack.mitre.org/"))
        self.assertIsNotNone(tech["modified"])

        t1566_002 = asyncio.run(srv.get_technique_by_id("T1566.002", domain="enterprise", include_description=False, include_formatted=False))
        self.assertTrue(t1566_002["technique"]["is_subtechnique"])
        self.assertEqual(t1566_002["formatted"], "")

    def test_created_and_modified_after_stix_type_filter(self) -> None:
        unfiltered_c = asyncio.run(
            srv.get_objects_created_after("2025-01-01T00:00:00Z", domain="enterprise", include_description=False, limit=5, include_formatted=False)
        )
        filtered_c = asyncio.run(
            srv.get_objects_created_after(
                "2025-01-01T00:00:00Z",
                domain="enterprise",
                include_description=False,
                stix_type="attack-pattern",
                limit=50,
                include_formatted=False,
            )
        )
        self.assertTrue(filtered_c["found"])
        self.assertLess(filtered_c["total_count"], unfiltered_c["total_count"])
        self.assertTrue(all(o["type"] == "attack-pattern" for o in filtered_c["objects"]))
        self.assertEqual(filtered_c["formatted"], "")

        filtered_m = asyncio.run(
            srv.get_objects_modified_after(
                "2025-01-01T00:00:00Z",
                domain="enterprise",
                include_description=False,
                stix_type="intrusion-set",
                limit=50,
                include_formatted=False,
            )
        )
        self.assertTrue(filtered_m["found"])
        self.assertTrue(all(o["type"] == "intrusion-set" for o in filtered_m["objects"]))

    def test_new_pagination_schemas_and_include_formatted(self) -> None:
        newly_paginated = (
            "get_all_techniques",
            "get_all_parent_techniques",
            "get_all_subtechniques",
            "get_revoked_techniques",
            "get_all_groups",
            "get_all_software",
            "get_software",
            "get_all_mitigations",
            "get_all_datacomponents",
            "get_all_campaigns",
            "search_techniques",
            "search_groups",
            "search_software",
            "get_objects_by_content",
            "get_techniques_by_tactic",
            "get_procedure_examples_by_technique",
            "get_techniques_used_by_campaign",
            "get_techniques_mitigated_by_mitigation",
            "get_techniques_targeting_asset",
        )
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        for name in newly_paginated:
            props = tools[name].inputSchema.get("properties", {})
            self.assertIn("limit", props, f"{name} missing limit")
            self.assertIn("offset", props, f"{name} missing offset")
            self.assertIn("include_formatted", props, f"{name} missing include_formatted")
            self.assertEqual(props["limit"].get("default"), srv.DEFAULT_PAGE_LIMIT)
            self.assertEqual(props["offset"].get("default"), 0)

        p0 = asyncio.run(srv.get_all_techniques(domain="enterprise", limit=10, offset=0, include_formatted=False))
        p1 = asyncio.run(srv.get_all_techniques(domain="enterprise", limit=10, offset=10, include_formatted=True))
        self.assertEqual(p0["count"], 10)
        self.assertTrue(p0["has_more"])
        self.assertEqual(p0["next_offset"], 10)
        self.assertEqual(p0["formatted"], "")
        self.assertTrue(p1["formatted"])
        self.assertTrue(set(t["stix_id"] for t in p0["techniques"]).isdisjoint(t["stix_id"] for t in p1["techniques"]))

    def test_get_objects_by_content_cve_and_all_types(self) -> None:
        rel_res = asyncio.run(
            srv.get_objects_by_content("CVE-2021-44228", "relationship", domain="enterprise", include_formatted=False)
        )
        self.assertGreaterEqual(rel_res["total_count"], 5)
        self.assertTrue(all(o["type"] == "relationship" for o in rel_res["objects"]))
        self.assertTrue(all("source" in o and "target" in o for o in rel_res["objects"]))

        all_res = asyncio.run(
            srv.get_objects_by_content("CVE-2021-44228", "all", domain="enterprise", include_formatted=False)
        )
        self.assertGreaterEqual(all_res["total_count"], rel_res["total_count"])

    def test_software_by_alias_and_v20_1_docstrings(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        sw_desc = tools["get_software_by_alias"].description or ""
        self.assertNotIn("Beacon", sw_desc)
        self.assertIn("Solorigate", sw_desc)

        res_sol = asyncio.run(srv.get_software_by_alias("  solorigate  ", domain="enterprise", include_description=False, include_formatted=False))
        self.assertEqual(res_sol["count"], 1)
        self.assertEqual(res_sol["software"][0]["name"], "SUNBURST")

        res_sun = asyncio.run(srv.get_software_by_alias("SUNSHUTTLE", domain="enterprise", include_description=False, include_formatted=False))
        self.assertEqual(res_sun["count"], 1)
        self.assertEqual(res_sun["software"][0]["name"], "GoldMax")

        tactics_desc = tools["get_all_tactics"].description or ""
        self.assertNotIn("Defense Evasion", tactics_desc)
        self.assertIn("Stealth", tactics_desc)
        self.assertIn("Defense Impairment", tactics_desc)

        by_tactic_desc = tools["get_techniques_by_tactic"].description or ""
        self.assertIn("Stealth", by_tactic_desc)
        self.assertIn("Defense Impairment", by_tactic_desc)

        layer_desc = tools["generate_layer"].description or ""
        self.assertIn("DCxxxx", layer_desc)


if __name__ == "__main__":
    unittest.main()

"""Regression tests for MCP pagination schemas, bounds, ordering, P2 provenance, and v20.1 fixes."""

import asyncio
import json
import unittest

import mitre_mcp_server.server as srv


class TestPaginationContractsAndSchemas(unittest.TestCase):
    """Verify published MCP input schemas and pagination behavior across domains."""

    PAGINATED_TOOLS = (
        "get_objects_by_type",
        "get_objects_modified_after",
        "get_objects_created_after",
        "get_procedure_examples_by_tactic",
        "get_analytics",
        "get_techniques_by_platform",
        "get_techniques_detected_by_datacomponent",
    )

    def test_mcp_input_schemas_expose_limit_and_offset(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        for name in self.PAGINATED_TOOLS:
            self.assertIn(name, tools, f"Missing tool {name}")
            props = tools[name].inputSchema.get("properties", {})
            self.assertIn("limit", props, f"{name} schema missing limit")
            self.assertIn("offset", props, f"{name} schema missing offset")
            self.assertEqual(props["limit"].get("type"), "integer")
            self.assertEqual(props["limit"].get("default"), srv.DEFAULT_PAGE_LIMIT)
            self.assertEqual(props["limit"].get("minimum"), 1)
            self.assertEqual(props["limit"].get("maximum"), srv.MAX_PAGE_LIMIT)
            self.assertEqual(props["offset"].get("type"), "integer")
            self.assertEqual(props["offset"].get("default"), 0)
            self.assertEqual(props["offset"].get("minimum"), 0)

    def test_mcp_call_tool_reaches_page_2(self) -> None:
        raw_res = asyncio.run(
            srv.mcp.call_tool(
                "get_objects_by_type",
                {
                    "stix_type": "attack-pattern",
                    "domain": "mobile",
                    "include_description": False,
                    "limit": 100,
                    "offset": 100,
                },
            )
        )
        # FastMCP call_tool returns (content_list, {"result": payload}) or list[TextContent]
        if isinstance(raw_res, tuple) and len(raw_res) == 2 and isinstance(raw_res[1], dict):
            payload = raw_res[1].get("result", raw_res[1])
        else:
            content = raw_res[0] if isinstance(raw_res, list) else raw_res
            payload = json.loads(content.text)
        self.assertEqual(payload["offset"], 100)
        self.assertEqual(payload["total_count"], 125)
        self.assertEqual(payload["count"], 25)
        self.assertFalse(payload["has_more"])
        self.assertIsNone(payload["next_offset"])

        # Also verify invalid bounds are rejected at MCP tool boundary
        with self.assertRaises(Exception):
            asyncio.run(
                srv.mcp.call_tool(
                    "get_objects_by_type",
                    {
                        "stix_type": "attack-pattern",
                        "domain": "mobile",
                        "limit": 100,
                        "offset": -1,
                    },
                )
            )

    def test_get_objects_by_type_pages_and_completeness_all_domains(self) -> None:
        expected_totals = {"enterprise": 706, "mobile": 125, "ics": 104}
        for domain, expected_total in expected_totals.items():
            seen_ids: list[str] = []
            offset = 0
            page_num = 0
            while True:
                res = asyncio.run(
                    srv.get_objects_by_type(
                        stix_type="attack-pattern",
                        domain=domain,
                        remove_revoked_deprecated=True,
                        include_description=False,
                        limit=100,
                        offset=offset,
                    )
                )
                self.assertEqual(res["total_count"], expected_total)
                self.assertEqual(res["offset"], offset)
                self.assertEqual(res["limit"], 100)
                seen_ids.extend(o["stix_id"] for o in res["objects"])
                if not res["has_more"]:
                    self.assertIsNone(res["next_offset"])
                    break
                self.assertEqual(res["next_offset"], offset + res["count"])
                offset = res["next_offset"]
                page_num += 1
            self.assertGreaterEqual(page_num, 1)
            self.assertEqual(len(seen_ids), expected_total)
            self.assertEqual(len(set(seen_ids)), expected_total)

            # Past-end offset returns empty page cleanly
            past_end = asyncio.run(
                srv.get_objects_by_type(
                    stix_type="attack-pattern",
                    domain=domain,
                    include_description=False,
                    limit=100,
                    offset=expected_total + 10,
                )
            )
            self.assertEqual(past_end["count"], 0)
            self.assertEqual(past_end["total_count"], expected_total)
            self.assertFalse(past_end["has_more"])
            self.assertIsNone(past_end["next_offset"])

    def test_other_paginated_tools_pages_0_1_last_and_empty(self) -> None:
        # get_objects_modified_after
        p0 = asyncio.run(
            srv.get_objects_modified_after(
                timestamp="2026-11-01T00:00:00Z",
                domain="enterprise",
                include_description=False,
                limit=100,
                offset=0,
            )
        )
        self.assertEqual(p0["count"], 100)
        self.assertTrue(p0["has_more"])
        self.assertEqual(p0["next_offset"], 100)

        p1 = asyncio.run(
            srv.get_objects_modified_after(
                timestamp="2026-11-01T00:00:00Z",
                domain="enterprise",
                include_description=False,
                limit=100,
                offset=100,
            )
        )
        self.assertEqual(p1["offset"], 100)
        self.assertGreater(p1["count"], 0)
        self.assertEqual(p0["total_count"], p1["total_count"])
        self.assertTrue(set(o["stix_id"] for o in p0["objects"]).isdisjoint(o["stix_id"] for o in p1["objects"]))

        empty_mod = asyncio.run(
            srv.get_objects_modified_after(
                timestamp="2099-01-01T00:00:00Z",
                domain="enterprise",
                include_description=False,
                limit=50,
                offset=0,
            )
        )
        self.assertEqual(empty_mod["total_count"], 0)
        self.assertFalse(empty_mod["has_more"])
        self.assertIsNone(empty_mod["next_offset"])

        # get_objects_created_after
        c0 = asyncio.run(
            srv.get_objects_created_after(
                timestamp="2025-01-01T00:00:00Z",
                domain="enterprise",
                include_description=False,
                limit=100,
                offset=0,
            )
        )
        c1 = asyncio.run(
            srv.get_objects_created_after(
                timestamp="2025-01-01T00:00:00Z",
                domain="enterprise",
                include_description=False,
                limit=100,
                offset=100,
            )
        )
        self.assertEqual(c0["count"], 100)
        self.assertEqual(c1["count"], 100)
        self.assertTrue(c0["has_more"])
        self.assertTrue(set(o["stix_id"] for o in c0["objects"]).isdisjoint(o["stix_id"] for o in c1["objects"]))

        # get_procedure_examples_by_tactic
        ex0 = asyncio.run(
            srv.get_procedure_examples_by_tactic(
                tactic="Execution",
                domain="enterprise",
                include_description=False,
                limit=100,
                offset=0,
            )
        )
        ex_last_offset = ((ex0["total_count"] - 1) // 100) * 100
        ex_last = asyncio.run(
            srv.get_procedure_examples_by_tactic(
                tactic="Execution",
                domain="enterprise",
                include_description=False,
                limit=100,
                offset=ex_last_offset,
            )
        )
        self.assertFalse(ex_last["has_more"])
        self.assertIsNone(ex_last["next_offset"])
        self.assertEqual(ex_last_offset + ex_last["count"], ex0["total_count"])

        # get_analytics
        an0 = asyncio.run(srv.get_analytics(domain="enterprise", limit=50, offset=0))
        an1 = asyncio.run(srv.get_analytics(domain="enterprise", limit=50, offset=50))
        self.assertEqual(an0["count"], 50)
        self.assertTrue(an0["has_more"])
        self.assertTrue(set(a["stix_id"] for a in an0["analytics"]).isdisjoint(a["stix_id"] for a in an1["analytics"]))

    def test_invalid_pagination_bounds_rejected(self) -> None:
        bad_cases = [
            {"limit": 100, "offset": -1},
            {"limit": 0, "offset": 0},
            {"limit": -5, "offset": 0},
            {"limit": srv.MAX_PAGE_LIMIT + 1, "offset": 0},
            {"limit": True, "offset": 0},
            {"limit": 10, "offset": False},
        ]
        for kwargs in bad_cases:
            with self.assertRaises(ValueError):
                asyncio.run(srv.get_objects_by_type("attack-pattern", **kwargs))
            with self.assertRaises(ValueError):
                asyncio.run(srv.get_objects_created_after("2025-01-01T00:00:00Z", **kwargs))
            with self.assertRaises(ValueError):
                asyncio.run(srv.get_objects_modified_after("2026-11-01T00:00:00Z", **kwargs))
            with self.assertRaises(ValueError):
                asyncio.run(srv.get_procedure_examples_by_tactic("Execution", **kwargs))
            with self.assertRaises(ValueError):
                asyncio.run(srv.get_analytics(**kwargs))
            with self.assertRaises(ValueError):
                asyncio.run(srv.get_techniques_by_platform("Windows", **kwargs))
            with self.assertRaises(ValueError):
                asyncio.run(
                    srv.get_techniques_detected_by_datacomponent(
                        "x-mitre-data-component--02d090b6-8157-48da-98a2-517f7edd49fc",
                        **kwargs,
                    )
                )

    def test_max_page_limit_stays_under_1mb_ceiling(self) -> None:
        res = asyncio.run(
            srv.get_objects_by_type(
                stix_type="attack-pattern",
                domain="enterprise",
                include_description=True,
                limit=srv.MAX_PAGE_LIMIT,
                offset=0,
            )
        )
        self.assertLess(len(json.dumps(res)), 1_000_000)


class TestGroupSoftwareProvenanceAndRegressions(unittest.TestCase):
    """Verify P2 provenance fix and all 8 previous v20.1 fixes."""

    def test_p2_group_software_technique_provenance(self) -> None:
        group_id = "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"  # APT29
        res = asyncio.run(
            srv.get_techniques_used_by_group_software(
                group_stix_id=group_id,
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertEqual(res["count"], 205)
        direct_paths_count = 0
        indirect_paths_count = 0
        for tech in res["techniques"]:
            self.assertTrue(tech["relationships"], f"Empty relationships for {tech['stix_id']}")
            self.assertTrue(tech["provenance_paths"], f"Empty provenance_paths for {tech['stix_id']}")
            for rel in tech["relationships"]:
                self.assertEqual(rel["relationship_type"], "uses", f"Unexpected rel type in relationships: {rel}")
                self.assertFalse(
                    str(rel.get("source_ref") or "").startswith("campaign--"),
                    f"Campaign edge leaked into top-level relationships: {rel}",
                )
            for path in tech["provenance_paths"]:
                sw_id = path["software"]["stix_id"]
                s2t = path["software_uses_technique"]
                self.assertEqual(s2t["relationship_type"], "uses")
                self.assertEqual(s2t["source_ref"], sw_id)
                self.assertEqual(s2t["target_ref"], tech["stix_id"])
                if path["path_type"] == "direct":
                    direct_paths_count += 1
                    g2s = path["group_uses_software"]
                    self.assertEqual(g2s["relationship_type"], "uses")
                    self.assertEqual(g2s["source_ref"], group_id)
                    self.assertEqual(g2s["target_ref"], sw_id)
                elif path["path_type"] == "indirect_via_campaign":
                    indirect_paths_count += 1
                    self.assertNotIn("group_uses_software", path)
                    camp_id = path["campaign_stix_id"]
                    attr = path["campaign_attributed_to_group"]
                    c2s = path["campaign_uses_software"]
                    self.assertEqual(attr["relationship_type"], "attributed-to")
                    self.assertEqual(attr["source_ref"], camp_id)
                    self.assertEqual(attr["target_ref"], group_id)
                    self.assertEqual(c2s["relationship_type"], "uses")
                    self.assertEqual(c2s["source_ref"], camp_id)
                    self.assertEqual(c2s["target_ref"], sw_id)
                else:
                    self.fail(f"Unexpected path_type {path['path_type']} for APT29: {path}")

        self.assertGreater(direct_paths_count, 0)
        self.assertGreater(indirect_paths_count, 0)

        # Cross-verify a returned provenance path against both direct relationship APIs
        sample_tech = res["techniques"][0]
        sample_path = sample_tech["provenance_paths"][0]
        sw_id = sample_path["software"]["stix_id"]
        g2s_id = sample_path["group_uses_software"]["stix_id"]
        s2t_id = sample_path["software_uses_technique"]["stix_id"]

        sw_used_by_group = asyncio.run(
            srv.get_software_used_by_group(group_stix_id=group_id, domain="enterprise", include_description=False)
        )
        sw_match = [s for s in sw_used_by_group["software"] if s["stix_id"] == sw_id]
        self.assertTrue(sw_match, f"Software {sw_id} not found in get_software_used_by_group")
        self.assertIn(g2s_id, [r["stix_id"] for r in sw_match[0]["relationships"]])

        techs_by_sw = asyncio.run(
            srv.get_techniques_used_by_software(software_stix_id=sw_id, domain="enterprise", include_description=False)
        )
        tech_match = [t for t in techs_by_sw["techniques"] if t["stix_id"] == sample_tech["stix_id"]]
        self.assertTrue(tech_match, f"Technique {sample_tech['stix_id']} not found in get_techniques_used_by_software")
        self.assertIn(s2t_id, [r["stix_id"] for r in tech_match[0]["relationships"]])

    def test_previous_eight_fixes_no_regression(self) -> None:
        # 1. M1031 mitigated techniques
        m1031 = asyncio.run(
            srv.get_techniques_mitigated_by_mitigation(
                mitigation_stix_id="course-of-action--12241367-a8b7-49b4-b86e-2236901ba50c",
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertEqual(m1031["count"], 62)
        self.assertTrue(all(t["attack_id"] and t["name"] and t["stix_id"] for t in m1031["techniques"]))

        # 2. T0816 targeted ICS assets
        t0816 = asyncio.run(
            srv.get_assets_targeted_by_technique(
                technique_stix_id="attack-pattern--25dfc8ad-bd73-4dfd-84a9-3c3d383f76e9",
                domain="ics",
                include_description=False,
            )
        )
        self.assertEqual(t0816["count"], 18)
        self.assertTrue(all(a["attack_id"] and a["name"] and a["stix_id"] for a in t0816["assets"]))

        # 3. APT29 campaigns
        c_apt29 = asyncio.run(
            srv.get_campaigns_attributed_to_group(
                group_stix_id="intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertEqual(c_apt29["count"], 2)

        # 4. generate_layer(G0016) == 119 and versions.attack == 20.1
        g0016_layer = asyncio.run(srv.generate_layer(attack_id="G0016", domain="enterprise"))
        self.assertEqual(len(g0016_layer["layer"]["techniques"]), 119)
        self.assertEqual(g0016_layer["layer"]["versions"]["attack"], "20.1")

        # 5. generate_layer(DC0084) == 9
        dc0084_layer = asyncio.run(srv.generate_layer(attack_id="DC0084", domain="enterprise"))
        self.assertEqual(len(dc0084_layer["layer"]["techniques"]), 9)

        # 6. get_stix_type nonexistent ID -> found=False
        nonexistent = asyncio.run(srv.get_stix_type("attack-pattern--00000000-0000-0000-0000-000000000000"))
        self.assertFalse(nonexistent["found"])

        # 7. get_techniques_by_platform counts (paginated)
        win_ent = asyncio.run(srv.get_techniques_by_platform("Windows", domain="enterprise", include_description=False))
        and_mob = asyncio.run(srv.get_techniques_by_platform("Android", domain="mobile", include_description=False))
        win_ics = asyncio.run(srv.get_techniques_by_platform("Windows", domain="ics", include_description=False))
        self.assertEqual(win_ent["total_count"], 479)
        self.assertEqual(win_ent["count"], 100)
        self.assertTrue(win_ent["has_more"])
        self.assertEqual(win_ent["next_offset"], 100)
        self.assertEqual(and_mob["total_count"], 123)
        self.assertEqual(win_ics["total_count"], 69)
        self.assertEqual(win_ics["count"], 69)
        self.assertFalse(win_ics["has_more"])

        # 8. T1059.001 detection and DC0084
        t1059_001 = srv.get_datacomponents_detecting_technique(
            technique_stix_id="attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62",
            domain="enterprise",
            include_description=False,
        )
        self.assertGreaterEqual(t1059_001["count"], 3)
        self.assertEqual(len(t1059_001.get("detection_strategies", [])), 1)
        dc0084_techs = asyncio.run(
            srv.get_techniques_detected_by_datacomponent(
                datacomponent_stix_id="x-mitre-data-component--02d090b6-8157-48da-98a2-517f7edd49fc",
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertEqual(dc0084_techs["count"], 9)
        self.assertEqual(dc0084_techs["total_count"], 9)
        self.assertFalse(dc0084_techs["has_more"])

    def test_nine_v20_1_fixes(self) -> None:
        # 1. Case-insensitive alias lookup & software aliases populated
        camp_ci = asyncio.run(srv.get_campaigns_by_alias("operation north star", domain="enterprise", include_description=False))
        self.assertEqual(camp_ci["count"], 1)
        self.assertEqual(camp_ci["campaigns"][0]["attack_id"], "C0022")
        self.assertIn("Operation North Star", camp_ci["campaigns"][0]["aliases"])

        sw_ci = asyncio.run(srv.get_software_by_alias("cobalt strike", domain="enterprise", include_description=False))
        self.assertEqual(sw_ci["count"], 1)
        self.assertEqual(sw_ci["software"][0]["attack_id"], "S0154")
        self.assertTrue(sw_ci["software"][0]["aliases"])
        self.assertIn("Cobalt Strike", sw_ci["software"][0]["aliases"])

        # 2. Campaign aliases in structured JSON
        all_camps = asyncio.run(srv.get_all_campaigns(domain="enterprise", include_description=False))
        self.assertGreater(all_camps["count"], 0)
        self.assertTrue(all("aliases" in c for c in all_camps["campaigns"]))

        # 3. No debug block in mitigations & no internal path leakage in data stats
        mits = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d",
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertNotIn("debug", mits)

        dstats = asyncio.run(srv.get_data_stats())
        for dom_info in dstats.values():
            if dom_info.get("exists"):
                self.assertNotIn("/data/", dom_info["path"])
                self.assertTrue(dom_info["filename"].endswith(".json"))

        # 4. Procedure examples formatting & message wording
        proc_tactic = asyncio.run(
            srv.get_procedure_examples_by_tactic("Stealth", domain="enterprise", include_description=False, limit=5, offset=0)
        )
        self.assertEqual(proc_tactic["count"], 5)
        self.assertNotIn("STIX ID: relationship--", proc_tactic["formatted"])
        self.assertNotIn("Source Reference:", proc_tactic["formatted"])
        self.assertIn("->", proc_tactic["formatted"])

        proc_tech = asyncio.run(
            srv.get_procedure_examples_by_technique(
                technique_stix_id="attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d",
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertNotIn("showing how groups used", proc_tech["message"])

        # 5. get_all_datasources v20.1 deprecation guidance
        ds = asyncio.run(srv.get_all_datasources(domain="enterprise", remove_revoked_deprecated=True))
        self.assertEqual(ds["count"], 0)
        self.assertIn("get_detection_strategies_for_technique", ds["message"])
        self.assertIn("remove_revoked_deprecated=False", ds["message"])

        # 6. Canonical normalization of echoed inputs
        tt = asyncio.run(srv.get_technique_tactics("t1055", domain="enterprise"))
        self.assertEqual(tt["technique"]["id"], "T1055")
        self.assertIn("'T1055'", tt["message"])

        st = asyncio.run(srv.get_stats(domain="Enterprise"))
        self.assertEqual(st["domain"], "enterprise")

        tp = asyncio.run(srv.get_techniques_by_platform("windows", domain="enterprise", include_description=False, limit=10, offset=0))
        self.assertEqual(tp["platform"], "Windows")
        self.assertEqual(tp["count"], 10)
        self.assertEqual(tp["total_count"], 479)
        self.assertTrue(tp["has_more"])
        self.assertEqual(tp["next_offset"], 10)

        ttac = asyncio.run(srv.get_techniques_by_tactic("stealth", domain="enterprise", include_description=False))
        self.assertGreater(ttac["count"], 0)
        self.assertEqual(ttac["techniques"][0]["tactic"], "Stealth")

        # 7. include_description=False respected in nested relationships[].description
        gt = asyncio.run(srv.get_group_techniques("APT29", domain="enterprise", include_description=False))
        self.assertGreater(gt["count"], 0)
        for tech in gt["techniques"]:
            self.assertIsNone(tech["description"])
            for rel in tech["relationships"]:
                self.assertIsNone(rel["description"])

        # 8. get_techniques_targeting_asset includes attack_id
        assets = asyncio.run(srv.get_all_assets(domain="ics", include_description=False))
        self.assertGreater(assets["count"], 0)
        asset_techs = asyncio.run(
            srv.get_techniques_targeting_asset(assets["assets"][0]["stix_id"], domain="ics", include_description=False)
        )
        self.assertGreater(asset_techs["count"], 0)
        self.assertTrue(all("attack_id" in t and t["attack_id"] for t in asset_techs["techniques"]))

        # 9. Pagination on get_techniques_detected_by_datacomponent (DC0032 Process Creation has >100 techs)
        dcs = asyncio.run(srv.get_all_datacomponents(domain="enterprise", include_description=False))
        dc0032 = next(d for d in dcs["datacomponents"] if d.get("attack_id") == "DC0032")
        dc_p0 = asyncio.run(
            srv.get_techniques_detected_by_datacomponent(
                dc0032["stix_id"], domain="enterprise", include_description=False, limit=50, offset=0
            )
        )
        dc_p1 = asyncio.run(
            srv.get_techniques_detected_by_datacomponent(
                dc0032["stix_id"], domain="enterprise", include_description=False, limit=50, offset=50
            )
        )
        self.assertEqual(dc_p0["count"], 50)
        self.assertGreater(dc_p0["total_count"], 100)
        self.assertTrue(dc_p0["has_more"])
        self.assertEqual(dc_p0["next_offset"], 50)
        self.assertEqual(dc_p1["offset"], 50)
        self.assertTrue(set(t["stix_id"] for t in dc_p0["techniques"]).isdisjoint(t["stix_id"] for t in dc_p1["techniques"]))

    def test_six_live_verification_fixes(self) -> None:
        # 1. get_group_techniques exact-match-first prevents APT3->APT38 and APT1->APT17 collisions
        apt3 = asyncio.run(srv.get_group_techniques("APT3", domain="enterprise", include_description=False))
        self.assertTrue(apt3["found"])
        self.assertEqual(apt3["group"]["attack_id"], "G0022")
        self.assertEqual(apt3["group"]["name"], "APT3")

        apt1 = asyncio.run(srv.get_group_techniques("APT1", domain="enterprise", include_description=False))
        self.assertTrue(apt1["found"])
        self.assertEqual(apt1["group"]["attack_id"], "G0006")
        self.assertEqual(apt1["group"]["name"], "APT1")

        # 2. get_objects_by_content, get_objects_created_after, get_objects_modified_after
        #    exclude revoked/deprecated by default (and allow opting in with remove_revoked_deprecated=False)
        ps_active = asyncio.run(
            srv.get_objects_by_content("PowerShell", "attack-pattern", domain="enterprise", include_description=False)
        )
        ps_all = asyncio.run(
            srv.get_objects_by_content(
                "PowerShell",
                "attack-pattern",
                domain="enterprise",
                include_description=False,
                remove_revoked_deprecated=False,
            )
        )
        self.assertEqual(ps_active["count"], 47)
        self.assertEqual(ps_all["count"], 62)

        ca_active = asyncio.run(
            srv.get_objects_created_after(
                "2025-01-01T00:00:00.000Z", domain="enterprise", include_description=False, limit=5, offset=0
            )
        )
        ca_all = asyncio.run(
            srv.get_objects_created_after(
                "2025-01-01T00:00:00.000Z",
                domain="enterprise",
                include_description=False,
                remove_revoked_deprecated=False,
                limit=5,
                offset=0,
            )
        )
        self.assertEqual(ca_active["total_count"], 7087)
        self.assertEqual(ca_all["total_count"], 7091)

        ma_active = asyncio.run(
            srv.get_objects_modified_after(
                "2025-01-01T00:00:00.000Z", domain="enterprise", include_description=False, limit=5, offset=0
            )
        )
        ma_all = asyncio.run(
            srv.get_objects_modified_after(
                "2025-01-01T00:00:00.000Z",
                domain="enterprise",
                include_description=False,
                remove_revoked_deprecated=False,
                limit=5,
                offset=0,
            )
        )
        self.assertEqual(ma_active["total_count"], 25978)
        self.assertEqual(ma_all["total_count"], 26423)

        # 3. get_objects_by_name is case-insensitive and filters revoked/deprecated by default
        phish_lc = asyncio.run(srv.get_objects_by_name("phishing", "attack-pattern", domain="enterprise"))
        self.assertEqual(phish_lc["count"], 1)
        self.assertEqual(phish_lc["objects"][0]["attack_id"], "T1566")

        apt29_lc = asyncio.run(srv.get_objects_by_name("apt29", "intrusion-set", domain="enterprise"))
        self.assertEqual(apt29_lc["count"], 1)
        self.assertEqual(apt29_lc["objects"][0]["attack_id"], "G0016")

        cs_lc = asyncio.run(srv.get_objects_by_name("cobalt strike", "malware", domain="enterprise"))
        self.assertEqual(cs_lc["count"], 1)
        self.assertEqual(cs_lc["objects"][0]["attack_id"], "S0154")

        # 4. get_object_by_attack_id normalizes attack_id to canonical uppercase
        obj_lc = asyncio.run(
            srv.get_object_by_attack_id("t1059", "attack-pattern", domain="enterprise", include_description=False)
        )
        self.assertTrue(obj_lc["found"])
        self.assertEqual(obj_lc["object"]["id"], "T1059")
        self.assertIn("'T1059'", obj_lc["message"])

        # 5. Invalid timestamp errors preserve pagination schema fields
        bad_ca = asyncio.run(srv.get_objects_created_after("not-a-date", domain="enterprise", limit=10, offset=5))
        self.assertFalse(bad_ca["found"])
        self.assertEqual(bad_ca["total_count"], 0)
        self.assertEqual(bad_ca["offset"], 5)
        self.assertEqual(bad_ca["limit"], 10)
        self.assertFalse(bad_ca["has_more"])
        self.assertIsNone(bad_ca["next_offset"])

        bad_ma = asyncio.run(srv.get_objects_modified_after("not-a-date", domain="enterprise", limit=10, offset=5))
        self.assertFalse(bad_ma["found"])
        self.assertEqual(bad_ma["total_count"], 0)
        self.assertEqual(bad_ma["offset"], 5)
        self.assertEqual(bad_ma["limit"], 10)
        self.assertFalse(bad_ma["has_more"])
        self.assertIsNone(bad_ma["next_offset"])

        # 6. generate_layer validates domain against DOMAINS before path construction
        bad_dom = asyncio.run(srv.generate_layer("G0016", domain="bogus"))
        self.assertFalse(bad_dom["success"])
        self.assertIn("Invalid domain", bad_dom["message"])

    def test_deep_audit_fixes(self) -> None:
        # 1. Exact case-insensitive alias lookup without substring collisions or revoked leakage
        apt1 = asyncio.run(srv.get_groups_by_alias("APT1", domain="enterprise", include_description=False))
        self.assertEqual(apt1["count"], 1)
        self.assertEqual(apt1["groups"][0]["name"], "APT1")

        apt3 = asyncio.run(srv.get_groups_by_alias("APT3", domain="enterprise", include_description=False))
        self.assertEqual(apt3["count"], 1)
        self.assertEqual(apt3["groups"][0]["name"], "APT3")

        grp_at = asyncio.run(srv.get_groups_by_alias("at", domain="enterprise", include_description=False))
        self.assertEqual(grp_at["count"], 0)

        grp_rev_default = asyncio.run(srv.get_groups_by_alias("Night Dragon", domain="enterprise", include_description=False))
        self.assertEqual(grp_rev_default["count"], 0)
        grp_rev_all = asyncio.run(
            srv.get_groups_by_alias("Night Dragon", domain="enterprise", include_description=False, remove_revoked_deprecated=False)
        )
        self.assertEqual(grp_rev_all["count"], 1)

        sw_at = asyncio.run(srv.get_software_by_alias("at", domain="enterprise", include_description=False))
        self.assertEqual(sw_at["count"], 1)
        self.assertEqual(sw_at["software"][0]["name"], "at")

        sw_net = asyncio.run(srv.get_software_by_alias("net", domain="enterprise", include_description=False))
        self.assertEqual(sw_net["count"], 1)
        self.assertEqual(sw_net["software"][0]["name"], "Net")

        sw_tor = asyncio.run(srv.get_software_by_alias("Tor", domain="enterprise", include_description=False))
        self.assertEqual(sw_tor["count"], 1)
        self.assertEqual(sw_tor["software"][0]["name"], "Tor")

        sw_ping = asyncio.run(srv.get_software_by_alias("Ping", domain="enterprise", include_description=False))
        self.assertEqual(sw_ping["count"], 1)
        self.assertEqual(sw_ping["software"][0]["name"], "Ping")

        sw_darkmoon = asyncio.run(srv.get_software_by_alias("Darkmoon", domain="enterprise", include_description=False))
        self.assertEqual(sw_darkmoon["count"], 1)
        self.assertEqual(sw_darkmoon["software"][0]["name"], "PoisonIvy")

        camp_at = asyncio.run(srv.get_campaigns_by_alias("at", domain="enterprise", include_description=False))
        self.assertEqual(camp_at["count"], 0)
        camp_op = asyncio.run(srv.get_campaigns_by_alias("Operation", domain="enterprise", include_description=False))
        self.assertEqual(camp_op["count"], 0)

        # 2. get_techniques_by_platform rejects blank/whitespace and avoids substring collisions
        plat_blank = asyncio.run(srv.get_techniques_by_platform("   ", domain="enterprise", include_description=False))
        self.assertEqual(plat_blank["count"], 0)
        self.assertEqual(plat_blank["total_count"], 0)

        plat_win_partial = asyncio.run(srv.get_techniques_by_platform("Win", domain="enterprise", include_description=False))
        self.assertEqual(plat_win_partial["count"], 0)

        plat_a = asyncio.run(srv.get_techniques_by_platform("a", domain="enterprise", include_description=False))
        self.assertEqual(plat_a["count"], 0)

        plat_net = asyncio.run(srv.get_techniques_by_platform("Network", domain="enterprise", include_description=False, limit=5))
        self.assertEqual(plat_net["platform"], "Network Devices")
        self.assertEqual(plat_net["total_count"], 100)

        # 3. Whitespace-only queries in search_techniques, search_software, get_objects_by_content return 0
        self.assertEqual(asyncio.run(srv.search_techniques("   ", domain="enterprise"))["count"], 0)
        self.assertEqual(asyncio.run(srv.search_software("   ", domain="enterprise"))["count"], 0)
        self.assertEqual(
            asyncio.run(srv.get_objects_by_content("   ", "attack-pattern", domain="enterprise"))["count"], 0
        )

        # 4. get_layer_metadata reflects ATT&CK v20.1 platforms and strips domain whitespace
        lm_ent = asyncio.run(srv.get_layer_metadata(" enterprise "))
        self.assertTrue(lm_ent["success"])
        self.assertEqual(lm_ent["domain"], "enterprise")
        ent_plats = set(lm_ent["metadata"]["filters"]["platforms"])
        self.assertIn("ESXi", ent_plats)
        self.assertIn("Network Devices", ent_plats)
        self.assertNotIn("Network", ent_plats)

        lm_ics = asyncio.run(srv.get_layer_metadata("ics"))
        self.assertTrue(lm_ics["success"])
        self.assertIn("None", lm_ics["metadata"]["filters"]["platforms"])


if __name__ == "__main__":
    unittest.main()

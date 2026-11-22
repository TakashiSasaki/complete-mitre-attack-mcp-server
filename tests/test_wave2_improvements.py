"""Unit tests for Wave 2 improvements:
1. Pagination, include_formatted, and deterministic attack_id sorting on 10 high-volume relationship tools.
2. Resolved data_components in get_analytics.
3. Attribution provenance (attribution_source) in get_techniques_used_by_group & get_group_techniques.
4. Campaign ID (Cxxxx) support in generate_layer.
"""

import asyncio
import unittest

from mitreattack import release_info
import mitre_mcp_server.server as srv


WAVE2_PAGINATED_TOOLS = (
    "get_techniques_used_by_group",
    "get_group_techniques",
    "get_software_used_by_group",
    "get_techniques_used_by_software",
    "get_techniques_used_by_group_software",
    "get_groups_using_technique",
    "get_groups_using_software",
    "get_software_using_technique",
    "get_campaigns_using_technique",
    "get_campaigns_using_software",
)


class TestWave2RelationshipPaginationAndSorting(unittest.TestCase):
    """Verify pagination schemas, paging behavior, include_formatted, and attack_id sorting."""

    def test_mcp_schemas_expose_pagination_and_include_formatted(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        for name in WAVE2_PAGINATED_TOOLS:
            self.assertIn(name, tools, f"Missing tool {name}")
            props = tools[name].inputSchema.get("properties", {})
            self.assertIn("limit", props, f"{name} missing limit")
            self.assertIn("offset", props, f"{name} missing offset")
            self.assertIn("include_formatted", props, f"{name} missing include_formatted")
            self.assertEqual(props["limit"].get("default"), srv.DEFAULT_PAGE_LIMIT)
            self.assertEqual(props["limit"].get("minimum"), 1)
            self.assertEqual(props["limit"].get("maximum"), srv.MAX_PAGE_LIMIT)
            self.assertEqual(props["offset"].get("default"), 0)
            self.assertEqual(props["offset"].get("minimum"), 0)
            self.assertEqual(props["include_formatted"].get("default"), True)

    def test_pagination_sorting_and_include_formatted_across_all_10_tools(self) -> None:
        cases = [
            (srv.get_techniques_used_by_group, {"group_stix_id": "G0016"}, "techniques"),
            (srv.get_group_techniques, {"group_name": "APT29"}, "techniques"),
            (srv.get_software_used_by_group, {"group_stix_id": "G0016"}, "software"),
            (srv.get_techniques_used_by_software, {"software_stix_id": "S0154"}, "techniques"),
            (srv.get_techniques_used_by_group_software, {"group_stix_id": "G0016"}, "techniques"),
            (srv.get_groups_using_technique, {"technique_stix_id": "T1059.001"}, "groups"),
            (srv.get_groups_using_software, {"software_stix_id": "S0154"}, "groups"),
            (srv.get_software_using_technique, {"technique_stix_id": "T1059.001"}, "software"),
            (srv.get_campaigns_using_technique, {"technique_stix_id": "T1190"}, "campaigns"),
            (srv.get_campaigns_using_software, {"software_stix_id": "S0154"}, "campaigns"),
        ]

        for fn, kwargs, list_key in cases:
            with self.subTest(tool=fn.__name__):
                p0 = asyncio.run(
                    fn(
                        domain="enterprise",
                        include_description=False,
                        limit=3,
                        offset=0,
                        include_formatted=False,
                        **kwargs,
                    )
                )
                self.assertTrue(p0["found"])
                self.assertGreater(p0["total_count"], 0)
                self.assertEqual(p0["offset"], 0)
                self.assertEqual(p0["limit"], 3)
                self.assertEqual(p0["count"], min(3, p0["total_count"]))
                self.assertEqual(len(p0[list_key]), p0["count"])
                self.assertEqual(p0["formatted"], "")

                if p0["total_count"] > 3:
                    self.assertTrue(p0["has_more"])
                    self.assertEqual(p0["next_offset"], 3)

                    p1 = asyncio.run(
                        fn(
                            domain="enterprise",
                            include_description=False,
                            limit=3,
                            offset=3,
                            include_formatted=True,
                            **kwargs,
                        )
                    )
                    self.assertEqual(p1["offset"], 3)
                    self.assertEqual(p1["total_count"], p0["total_count"])
                    self.assertTrue(p1["formatted"])
                    ids0 = {item["stix_id"] for item in p0[list_key]}
                    ids1 = {item["stix_id"] for item in p1[list_key]}
                    self.assertTrue(ids0.isdisjoint(ids1))

                    # Verify deterministic ascending attack_id ordering across page boundary
                    combined = p0[list_key] + p1[list_key]
                    keys = [
                        srv._attack_id_sort_key(i.get("attack_id"), i.get("name"), i.get("stix_id"))
                        for i in combined
                    ]
                    self.assertEqual(keys, sorted(keys))

                # Invalid pagination bounds raise ValueError
                with self.assertRaises(ValueError):
                    asyncio.run(fn(domain="enterprise", limit=0, offset=0, **kwargs))
                with self.assertRaises(ValueError):
                    asyncio.run(fn(domain="enterprise", limit=10, offset=-1, **kwargs))


class TestWave2AnalyticsDataComponents(unittest.TestCase):
    """Verify get_analytics resolves data_components alongside data_component_refs."""

    def test_get_analytics_resolves_data_components(self) -> None:
        res = asyncio.run(srv.get_analytics(domain="enterprise", query="AN0219"))
        self.assertEqual(res["count"], 1)
        analytic = res["analytics"][0]
        self.assertEqual(analytic["attack_id"], "AN0219")
        self.assertIn("data_component_refs", analytic)
        self.assertIn("data_components", analytic)
        self.assertGreater(len(analytic["data_component_refs"]), 0)
        self.assertEqual(len(analytic["data_components"]), len(analytic["data_component_refs"]))

        for ref_id, dc in zip(analytic["data_component_refs"], analytic["data_components"]):
            self.assertEqual(dc["stix_id"], ref_id)
            self.assertTrue(str(dc["attack_id"] or "").startswith("DC"), f"Unexpected DC attack_id: {dc}")
            self.assertTrue(bool(dc["name"]), f"Missing DC name: {dc}")


class TestWave2GroupTechniqueAttributionProvenance(unittest.TestCase):
    """Verify attribution_source ('direct', 'campaign', 'both') on group technique lookups."""

    def test_attribution_source_values_and_consistency(self) -> None:
        g0016_res = asyncio.run(
            srv.get_techniques_used_by_group(
                "G0016",
                domain="enterprise",
                include_description=False,
                limit=200,
                offset=0,
                include_formatted=False,
            )
        )
        self.assertTrue(g0016_res["found"])
        self.assertEqual(g0016_res["total_count"], g0016_res["count"])
        gid = g0016_res["group"]["stix_id"]

        seen_sources = set()
        for tech in g0016_res["techniques"]:
            src = tech.get("attribution_source")
            self.assertIn(src, {"direct", "campaign", "both"})
            seen_sources.add(src)

            rels = tech["relationships"]
            has_direct = any(
                r.get("relationship_type") == "uses" and r.get("source_ref") == gid
                for r in rels
            )
            has_camp = any(
                r.get("relationship_type") == "attributed-to"
                or str(r.get("source_ref") or "").startswith("campaign--")
                for r in rels
            )
            if has_direct and has_camp:
                self.assertEqual(src, "both")
            elif has_camp:
                self.assertEqual(src, "campaign")
            else:
                self.assertEqual(src, "direct")

        self.assertEqual(seen_sources, {"direct", "campaign", "both"})

        # Also verify get_group_techniques exposes identical attribution_source
        apt29_res = asyncio.run(
            srv.get_group_techniques(
                "APT29",
                domain="enterprise",
                include_description=False,
                limit=200,
                offset=0,
                include_formatted=False,
            )
        )
        self.assertTrue(apt29_res["found"])
        self.assertEqual(
            [(t["attack_id"], t["attribution_source"]) for t in apt29_res["techniques"]],
            [(t["attack_id"], t["attribution_source"]) for t in g0016_res["techniques"]],
        )


class TestWave2GenerateLayerCampaigns(unittest.TestCase):
    """Verify generate_layer supports Cxxxx campaign IDs."""

    def test_generate_layer_campaign_success_and_validation(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        layer_desc = tools["generate_layer"].description or ""
        self.assertIn("Cxxxx", layer_desc)

        res = asyncio.run(srv.generate_layer("C0024", score=5, domain="enterprise"))
        self.assertTrue(res["success"], f"Expected success for C0024: {res}")
        self.assertEqual(res["attack_id"], "C0024")
        self.assertGreater(res["count"], 0)
        layer = res["layer"]
        self.assertIsNotNone(layer)
        self.assertIn("C0024", layer["name"])
        self.assertEqual(layer["versions"]["attack"], str(release_info.LATEST_VERSION))
        self.assertEqual(len(layer["techniques"]), res["count"])
        self.assertTrue(all(t["score"] == 5 for t in layer["techniques"]))

        # Case-insensitive + whitespace normalized
        res_ci = asyncio.run(srv.generate_layer("  c0024  ", score=3, domain="enterprise"))
        self.assertTrue(res_ci["success"])
        self.assertEqual(res_ci["count"], res["count"])

        # Nonexistent campaign ID returns clean failure
        missing = asyncio.run(srv.generate_layer("C999999", domain="enterprise"))
        self.assertFalse(missing["success"])
        self.assertIsNone(missing["layer"])

        # Invalid prefix error message mentions CXXXX
        bad = asyncio.run(srv.generate_layer("T1190", domain="enterprise"))
        self.assertFalse(bad["success"])
        self.assertIn("CXXXX", bad["message"])


if __name__ == "__main__":
    unittest.main()

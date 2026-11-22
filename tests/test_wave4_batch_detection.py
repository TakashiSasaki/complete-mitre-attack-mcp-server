"""Hermetic regression tests for Wave 4:
Backward-compatible batch detection-strategy lookup on `get_detection_strategies_for_technique`.
"""

import asyncio
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mitreattack import release_info
import mitre_mcp_server.server as srv


class TestWave4BatchDetectionStrategies(unittest.TestCase):
    """Verify backward-compatible single mode and deterministic batch mode."""

    def test_tool_count_and_mcp_schema(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        self.assertEqual(len(tools), 67)
        tool = tools["get_detection_strategies_for_technique"]
        props = tool.inputSchema.get("properties", {})
        self.assertIn("technique_stix_id", props)
        self.assertIn("technique_ids", props)
        self.assertIn("domain", props)
        self.assertIn("include_description", props)
        desc = tool.description or ""
        self.assertIn("Batch mode", desc)
        self.assertIn("technique_ids", desc)

    def test_single_technique_backward_compatibility(self) -> None:
        res = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertEqual(
            set(res.keys()),
            {"found", "technique_stix_id", "domain", "count", "detection_strategies", "message"},
        )
        self.assertTrue(res["found"])
        self.assertEqual(res["domain"], "enterprise")
        self.assertEqual(res["count"], 1)
        det = res["detection_strategies"][0]
        self.assertEqual(det["attack_id"], "DET0080")
        self.assertIsNone(det["description"])
        an_ids = [a["attack_id"] for a in det["analytics"]]
        self.assertEqual(
            sorted(an_ids),
            ["AN0219", "AN0220", "AN0221", "AN0222", "AN0223", "AN0224", "AN0225"],
        )
        self.assertTrue(all(a["description"] is None for a in det["analytics"]))
        self.assertTrue(all(len(a["data_components"]) > 0 for a in det["analytics"]))

        # Single invalid ID preserves exact legacy error shape
        bad = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="NOT_AN_ID",
                domain="enterprise",
            )
        )
        self.assertEqual(
            set(bad.keys()),
            {"found", "technique_stix_id", "domain", "count", "detection_strategies", "message"},
        )
        self.assertFalse(bad["found"])
        self.assertEqual(bad["count"], 0)
        self.assertEqual(bad["detection_strategies"], [])

    def test_batch_csv_list_combined_and_deterministic_sorting(self) -> None:
        res_csv = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190,T1059.001,T1003",
                domain="enterprise",
                include_description=False,
            )
        )
        res_list = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1003", "T1190", "t1059.001"],
                domain="enterprise",
                include_description=False,
            )
        )
        res_combined = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1059.001",
                technique_ids=["T1003", "T1190"],
                domain="enterprise",
                include_description=False,
            )
        )

        self.assertTrue(res_csv["found"])
        self.assertTrue(res_csv["batch"])
        self.assertEqual(res_csv, res_list)
        self.assertEqual(res_csv, res_combined)

        tech_ids = [t["attack_id"] for t in res_csv["techniques"]]
        self.assertEqual(tech_ids, ["T1003", "T1059.001", "T1190"])
        self.assertEqual(res_csv["counts"]["found"], 3)
        self.assertEqual(res_csv["counts"]["detection_strategies"], 3)
        self.assertEqual(res_csv["counts"]["analytics"], 11)
        self.assertEqual(res_csv["count"], 3)
        self.assertEqual(
            [d["attack_id"] for d in res_csv["coverage"]["detection_strategies"]],
            ["DET0080", "DET0234", "DET0455"],
        )

        # Metadata & caveat verification
        meta = res_csv["metadata"]
        self.assertEqual(meta["attack_version"], str(release_info.LATEST_VERSION))
        self.assertEqual(meta["domain"], "enterprise")
        self.assertEqual(meta["stix_spec_version"], "2.1")
        self.assertIn("enterprise-attack", meta["source_url"])
        self.assertIn("not a guarantee", meta["caveat"].lower())
        self.assertIn("cve", meta["caveat"].lower())

    def test_batch_deduplication_and_stix_alias_collapse(self) -> None:
        t1190_stix = "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c"
        res_a = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1190", "t1190", t1190_stix, "T1003", "T1003"],
                domain="enterprise",
            )
        )
        res_b = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=[t1190_stix, "T1003", "T1190"],
                domain="enterprise",
            )
        )

        self.assertEqual([t["attack_id"] for t in res_a["techniques"]], ["T1003", "T1190"])
        self.assertEqual([t["attack_id"] for t in res_b["techniques"]], ["T1003", "T1190"])
        self.assertEqual(res_a["counts"]["requested_inputs"], 5)
        self.assertEqual(res_a["counts"]["techniques_total"], 2)
        self.assertEqual(res_a["counts"]["duplicates_removed"], 3)
        t1190_row_a = next(t for t in res_a["techniques"] if t["attack_id"] == "T1190")
        t1190_row_b = next(t for t in res_b["techniques"] if t["attack_id"] == "T1190")
        self.assertEqual(t1190_row_a["matched_inputs"], sorted(["T1190", t1190_stix]))
        self.assertEqual(t1190_row_a, t1190_row_b)

    def test_statuses_valid_no_detection_not_found_invalid_and_unavailable(self) -> None:
        # Real revoked technique T1066 has no active v20.1 detection strategy
        res = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=[
                    "T1190",
                    "T1066",
                    "T9999",
                    "attack-pattern--00000000-0000-0000-0000-000000000000",
                    "NOT_AN_ID",
                    "G0016",
                    "T1190.abc",
                ],
                domain="enterprise",
            )
        )
        self.assertTrue(res["found"])
        by_input = {t["input"]: t for t in res["techniques"]}
        self.assertEqual(by_input["T1190"]["status"], "FOUND")
        self.assertEqual(by_input["T1066"]["status"], "VALID_NO_DETECTION")
        self.assertTrue(by_input["T1066"]["revoked"])
        self.assertEqual(by_input["T1066"]["detection_strategy_ids"], [])
        self.assertEqual(by_input["T9999"]["status"], "NOT_FOUND")
        self.assertEqual(
            by_input["attack-pattern--00000000-0000-0000-0000-000000000000"]["status"],
            "NOT_FOUND",
        )
        self.assertEqual(by_input["NOT_AN_ID"]["status"], "INVALID")
        self.assertEqual(by_input["G0016"]["status"], "INVALID")
        self.assertEqual(by_input["T1190.ABC"]["status"], "INVALID")

        self.assertEqual(res["counts"]["found"], 1)
        self.assertEqual(res["counts"]["valid_no_detection"], 1)
        self.assertEqual(res["counts"]["not_found"], 2)
        self.assertEqual(res["counts"]["invalid"], 3)

        # Hermetic synthetic VALID_NO_DETECTION on an active technique (T1190 with empty tech_to_ds)
        real_idx = srv._get_v20_detection_index("enterprise")
        patched_idx = dict(real_idx)
        patched_tech_to_ds = dict(real_idx["tech_to_ds"])
        patched_tech_to_ds.pop("attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c", None)
        patched_idx["tech_to_ds"] = patched_tech_to_ds
        with patch.object(srv, "_get_v20_detection_index", return_value=patched_idx):
            no_det = asyncio.run(
                srv.get_detection_strategies_for_technique(
                    technique_ids=["T1190"], domain="enterprise"
                )
            )
        self.assertTrue(no_det["found"])
        self.assertEqual(no_det["techniques"][0]["status"], "VALID_NO_DETECTION")
        self.assertFalse(no_det["techniques"][0]["revoked"])
        self.assertEqual(no_det["counts"]["valid_no_detection"], 1)
        self.assertEqual(no_det["counts"]["detection_strategies"], 0)

        # Hermetic unavailable domain bundle
        with patch.object(srv, "get_stix_path", return_value=Path("/nonexistent/missing.json")):
            unavail = asyncio.run(
                srv.get_detection_strategies_for_technique(
                    technique_ids=["T1190", "T1003"], domain="enterprise"
                )
            )
        self.assertFalse(unavail["found"])
        self.assertEqual(unavail["error_code"], "DOMAIN_UNAVAILABLE")
        self.assertEqual(unavail["counts"]["unavailable"], 2)
        self.assertTrue(all(t["status"] == "UNAVAILABLE" for t in unavail["techniques"]))

    def test_domain_isolation(self) -> None:
        # T0816 is ICS-only; T1190 is Enterprise-only
        ent = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T0816", "T1190"], domain="enterprise"
            )
        )
        ent_by_id = {t["input"]: t for t in ent["techniques"]}
        self.assertEqual(ent_by_id["T1190"]["status"], "FOUND")
        self.assertEqual(ent_by_id["T0816"]["status"], "NOT_FOUND")

        ics = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T0816", "T1190"], domain="ics"
            )
        )
        ics_by_id = {t["input"]: t for t in ics["techniques"]}
        self.assertEqual(ics_by_id["T0816"]["status"], "FOUND")
        self.assertEqual(ics_by_id["T1190"]["status"], "NOT_FOUND")
        self.assertGreater(len(ics_by_id["T0816"]["detection_strategy_ids"]), 0)

        # Invalid domain
        bad_dom = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1190"], domain="bogus-domain"
            )
        )
        self.assertFalse(bad_dom["found"])
        self.assertEqual(bad_dom["error_code"], "INVALID_DOMAIN")

    def test_bounded_input_size_and_empty_input(self) -> None:
        empty_cases = [
            {"technique_ids": []},
            {"technique_stix_id": " , , "},
            {"technique_ids": ["", "   "]},
        ]
        for kwargs in empty_cases:
            with self.subTest(kwargs=kwargs):
                res = asyncio.run(srv.get_detection_strategies_for_technique(**kwargs))
                self.assertFalse(res["found"])
                self.assertTrue(res["batch"])
                self.assertEqual(res["error_code"], "EMPTY_INPUT")

        too_many = [f"T{1000 + i}" for i in range(srv.MAX_BATCH_DETECTION_TECHNIQUES + 1)]
        over = asyncio.run(
            srv.get_detection_strategies_for_technique(technique_ids=too_many, domain="enterprise")
        )
        self.assertFalse(over["found"])
        self.assertTrue(over["batch"])
        self.assertEqual(over["error_code"], "BATCH_LIMIT_EXCEEDED")
        self.assertEqual(over["metadata"]["max_batch_size"], srv.MAX_BATCH_DETECTION_TECHNIQUES)

    def test_graph_relationship_integrity_and_optional_descriptions(self) -> None:
        compact = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190,T1059.001,T1003",
                domain="enterprise",
                include_description=False,
            )
        )
        verbose = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190,T1059.001,T1003",
                domain="enterprise",
                include_description=True,
            )
        )

        # Descriptions omitted when False, included when True
        self.assertTrue(all("description" not in d for d in compact["coverage"]["detection_strategies"]))
        self.assertTrue(all("description" not in a for a in compact["coverage"]["analytics"]))
        self.assertTrue(all("description" in a for a in verbose["coverage"]["analytics"]))
        self.assertLess(len(json.dumps(compact)), len(json.dumps(verbose)))

        # Graph referential integrity
        cov = compact["coverage"]
        ds_ids = {d["attack_id"] for d in cov["detection_strategies"]}
        an_ids = {a["attack_id"] for a in cov["analytics"]}
        dc_ids = {c["attack_id"] for c in cov["data_components"]}

        self.assertEqual(len(ds_ids), len(cov["detection_strategies"]))
        self.assertEqual(len(an_ids), len(cov["analytics"]))
        self.assertEqual(len(dc_ids), len(cov["data_components"]))

        t_ds_edges = {
            (e[0], e[1])
            for e in cov["edges"]["technique_to_detection_strategy"]
        }
        ds_an_edges = {
            (e[0], e[1])
            for e in cov["edges"]["detection_strategy_to_analytic"]
        }
        an_dc_edges = {
            (e[0], e[1])
            for e in cov["edges"]["analytic_to_data_component"]
        }

        for tech in compact["techniques"]:
            if tech["status"] == "FOUND":
                for ds_id in tech["detection_strategy_ids"]:
                    self.assertIn(ds_id, ds_ids)
                    self.assertIn((tech["attack_id"], ds_id), t_ds_edges)
                for an_id in tech["analytic_ids"]:
                    self.assertIn(an_id, an_ids)
                for dc_id in tech["data_component_ids"]:
                    self.assertIn(dc_id, dc_ids)
                self.assertGreater(len(tech["platforms"]), 0)
                self.assertGreater(len(tech["log_sources"]), 0)

        for ds in cov["detection_strategies"]:
            for an_id in ds["analytic_ids"]:
                self.assertIn(an_id, an_ids)
                self.assertIn((ds["attack_id"], an_id), ds_an_edges)

        for an in cov["analytics"]:
            for dc_id in an["data_component_ids"]:
                self.assertIn(dc_id, dc_ids)
                self.assertIn((an["attack_id"], dc_id), an_dc_edges)

    def test_batch_performance_warm_cache(self) -> None:
        # Warm cache first
        srv._get_v20_detection_index("enterprise")
        ad = srv.get_attack_data("enterprise")
        sample_techs = [
            ad.get_attack_id(t.id)
            for t in ad.get_techniques(remove_revoked_deprecated=True)[:25]
        ]
        sample_techs = [tid for tid in sample_techs if tid]

        t0 = time.perf_counter()
        res = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=sample_techs,
                domain="enterprise",
                include_description=False,
            )
        )
        elapsed = time.perf_counter() - t0
        self.assertTrue(res["found"])
        self.assertEqual(res["counts"]["found"], len(sample_techs))
        self.assertLess(elapsed, 2.0, f"Batch lookup for 25 techniques took {elapsed:.3f}s")


if __name__ == "__main__":
    unittest.main()

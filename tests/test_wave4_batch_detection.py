"""Hermetic regression tests for Wave 4:
Backward-compatible batch detection-strategy lookup on `get_detection_strategies_for_technique`,
including compact default mode, opt-in full mode parity, and token-efficiency size gates.
"""

import asyncio
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from mitreattack import release_info
import mitre_mcp_server.server as srv

_tc = unittest.TestCase()


class TestWave4BatchDetectionStrategies(unittest.TestCase):
    """Verify backward-compatible single mode and deterministic compact/full batch modes."""

    def test_tool_count_and_mcp_schema(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        self.assertEqual(len(tools), 67)
        tool = tools["get_detection_strategies_for_technique"]
        props = tool.inputSchema.get("properties", {})
        self.assertIn("technique_stix_id", props)
        self.assertIn("technique_ids", props)
        self.assertIn("domain", props)
        self.assertIn("include_description", props)
        self.assertIn("detail_level", props)
        self.assertEqual(props["detail_level"].get("default"), "compact")
        self.assertEqual(set(props["detail_level"].get("enum", [])), {"compact", "full"})
        self.assertIn("include_log_sources", props)
        self.assertEqual(props["include_log_sources"].get("default"), False)
        desc = tool.description or ""
        self.assertIn("Batch mode", desc)
        self.assertIn("detail_level", desc)

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

    def test_batch_compact_default_csv_list_combined_and_deterministic_sorting(self) -> None:
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
        self.assertEqual(res_csv["detail_level"], "compact")
        self.assertEqual(res_csv, res_list)
        self.assertEqual(res_csv, res_combined)

        tech_ids = [t["attack_id"] for t in res_csv["techniques"]]
        self.assertEqual(tech_ids, ["T1003", "T1059.001", "T1190"])
        self.assertTrue(all("name" in t and t["name"] for t in res_csv["techniques"]))
        self.assertEqual(res_csv["counts"]["found"], 3)
        self.assertEqual(res_csv["counts"]["detection_strategies"], 3)
        self.assertEqual(res_csv["counts"]["analytics"], 11)
        self.assertEqual(res_csv["count"], 3)
        self.assertEqual(
            list(res_csv["coverage"]["detection_strategies"].keys()),
            ["DET0080", "DET0234", "DET0455"],
        )

        # Metadata & caveat verification
        meta = res_csv["metadata"]
        self.assertEqual(meta["attack_version"], str(release_info.LATEST_VERSION))
        self.assertEqual(meta["domain"], "enterprise")
        self.assertEqual(meta["detail_level"], "compact")
        self.assertIn("enterprise-attack", meta["source_url"])
        self.assertIn("freshness_status", meta)
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
        by_key = {t.get("attack_id") or t.get("input"): t for t in res["techniques"]}
        self.assertEqual(by_key["T1190"]["status"], "FOUND")
        self.assertEqual(by_key["T1066"]["status"], "VALID_NO_DETECTION")
        self.assertTrue(by_key["T1066"].get("revoked"))
        self.assertNotIn("T1066", res["coverage"]["edges"]["technique_to_detection_strategy"])
        self.assertEqual(by_key["T9999"]["status"], "NOT_FOUND")
        self.assertEqual(
            by_key["attack-pattern--00000000-0000-0000-0000-000000000000"]["status"],
            "NOT_FOUND",
        )
        self.assertEqual(by_key["NOT_AN_ID"]["status"], "INVALID")
        self.assertEqual(by_key["G0016"]["status"], "INVALID")
        self.assertEqual(by_key["T1190.ABC"]["status"], "INVALID")

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
        self.assertNotIn("revoked", no_det["techniques"][0])
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

        # Invalid detail_level returns structured error
        bad_lvl = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1190"], domain="enterprise", detail_level="bogus"  # type: ignore[arg-type]
            )
        )
        self.assertFalse(bad_lvl["found"])
        self.assertEqual(bad_lvl["error_code"], "INVALID_DETAIL_LEVEL")

    def test_domain_isolation(self) -> None:
        ent = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T0816", "T1190"], domain="enterprise"
            )
        )
        ent_by_id = {t.get("attack_id") or t.get("input"): t for t in ent["techniques"]}
        self.assertEqual(ent_by_id["T1190"]["status"], "FOUND")
        self.assertEqual(ent_by_id["T0816"]["status"], "NOT_FOUND")

        ics = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T0816", "T1190"], domain="ics"
            )
        )
        ics_by_id = {t.get("attack_id") or t.get("input"): t for t in ics["techniques"]}
        self.assertEqual(ics_by_id["T0816"]["status"], "FOUND")
        self.assertEqual(ics_by_id["T1190"]["status"], "NOT_FOUND")
        self.assertGreater(
            len(ics["coverage"]["edges"]["technique_to_detection_strategy"].get("T0816", [])),
            0,
        )

        bad_dom = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_ids=["T1190"], domain="bogus-domain"
            )
        )
        self.assertFalse(bad_dom["found"])
        self.assertEqual(bad_dom["error_code"], "INVALID_DOMAIN")

    def test_bounded_input_size_limit(self) -> None:
        too_many = [f"T{1000 + i}" for i in range(srv.MAX_BATCH_DETECTION_TECHNIQUES + 1)]
        over = asyncio.run(
            srv.get_detection_strategies_for_technique(technique_ids=too_many, domain="enterprise")
        )
        self.assertFalse(over["found"])
        self.assertTrue(over["batch"])
        self.assertEqual(over["error_code"], "BATCH_LIMIT_EXCEEDED")
        self.assertEqual(over["metadata"]["max_batch_size"], srv.MAX_BATCH_DETECTION_TECHNIQUES)

    def test_compact_full_parity_graph_integrity_and_optional_fields(self) -> None:
        compact = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190,T1059.001,T1003",
                domain="enterprise",
                include_description=False,
                detail_level="compact",
            )
        )
        compact_ls = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190,T1059.001,T1003",
                domain="enterprise",
                include_description=False,
                detail_level="compact",
                include_log_sources=True,
            )
        )
        full = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190,T1059.001,T1003",
                domain="enterprise",
                include_description=False,
                detail_level="full",
            )
        )
        full_desc = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190,T1059.001,T1003",
                domain="enterprise",
                include_description=True,
                detail_level="full",
            )
        )

        # Counts and statuses match 100% between compact and full
        self.assertEqual(compact["counts"], full["counts"])
        self.assertEqual(
            [(t["attack_id"], t["name"], t["status"]) for t in compact["techniques"]],
            [(t["attack_id"], t["name"], t["status"]) for t in full["techniques"]],
        )

        # Entity IDs & names match 100% between compact and full
        self.assertEqual(
            compact["coverage"]["detection_strategies"],
            {d["attack_id"]: d["name"] for d in full["coverage"]["detection_strategies"]},
        )
        self.assertEqual(
            compact["coverage"]["analytics"],
            {
                a["attack_id"]: {"name": a["name"], "platforms": a["platforms"]}
                for a in full["coverage"]["analytics"]
            },
        )
        self.assertEqual(
            compact["coverage"]["data_components"],
            {c["attack_id"]: c["name"] for c in full["coverage"]["data_components"]},
        )

        # Edge sets reconstructed from compact adjacency maps match full edge pairs 100%
        def _adj_to_pairs(adj: dict) -> list:
            return [[src, dst] for src, dsts in adj.items() for dst in dsts]

        for edge_key in (
            "technique_to_detection_strategy",
            "detection_strategy_to_analytic",
            "analytic_to_data_component",
        ):
            self.assertEqual(
                _adj_to_pairs(compact["coverage"]["edges"][edge_key]),
                full["coverage"]["edges"][edge_key],
            )

        # Referential integrity of compact graph
        c_cov = compact["coverage"]
        ds_ids = set(c_cov["detection_strategies"].keys())
        an_ids = set(c_cov["analytics"].keys())
        dc_ids = set(c_cov["data_components"].keys())
        for tech in compact["techniques"]:
            if tech["status"] == "FOUND":
                t_ds = c_cov["edges"]["technique_to_detection_strategy"].get(tech["attack_id"], [])
                self.assertGreater(len(t_ds), 0)
                for ds_id in t_ds:
                    self.assertIn(ds_id, ds_ids)
                    for an_id in c_cov["edges"]["detection_strategy_to_analytic"].get(ds_id, []):
                        self.assertIn(an_id, an_ids)
                        for dc_id in c_cov["edges"]["analytic_to_data_component"].get(an_id, []):
                            self.assertIn(dc_id, dc_ids)

        # Opt-in log sources in compact mode
        self.assertTrue(
            all("log_sources" in a for a in compact_ls["coverage"]["analytics"].values())
        )
        self.assertTrue(
            all(
                isinstance(dc, dict) and "log_sources" in dc
                for dc in compact_ls["coverage"]["data_components"].values()
            )
        )
        # Opt-in descriptions in full mode
        self.assertTrue(all("description" not in a for a in full["coverage"]["analytics"]))
        self.assertTrue(all("description" in a for a in full_desc["coverage"]["analytics"]))
        self.assertLess(len(json.dumps(compact)), len(json.dumps(full)))
        self.assertLess(len(json.dumps(full)), len(json.dumps(full_desc)))

    def test_token_efficiency_size_gate(self) -> None:
        # 3-technique size gate: compact <= 75% of one-by-one and < 6000 chars
        ids_3 = ["T1190", "T1059.001", "T1003"]
        obo_3 = sum(
            len(
                json.dumps(
                    asyncio.run(
                        srv.get_detection_strategies_for_technique(
                            tid, domain="enterprise", include_description=False
                        )
                    )
                )
            )
            for tid in ids_3
        )
        batch_3 = len(
            json.dumps(
                asyncio.run(
                    srv.get_detection_strategies_for_technique(
                        ",".join(ids_3), domain="enterprise", include_description=False
                    )
                )
            )
        )
        self.assertLessEqual(
            batch_3,
            int(obo_3 * 0.75),
            f"3-tech compact batch ({batch_3}) exceeded 75% of one-by-one ({obo_3})",
        )
        self.assertLess(batch_3, 6000, f"3-tech compact batch ({batch_3}) >= 6000 chars")

        # 10-technique size gate: compact <= 80% of one-by-one
        ids_10 = [
            "T1190", "T1059.001", "T1003", "T1055", "T1566",
            "T1021", "T1078", "T1082", "T1053", "T1105",
        ]
        obo_10 = sum(
            len(
                json.dumps(
                    asyncio.run(
                        srv.get_detection_strategies_for_technique(
                            tid, domain="enterprise", include_description=False
                        )
                    )
                )
            )
            for tid in ids_10
        )
        batch_10 = len(
            json.dumps(
                asyncio.run(
                    srv.get_detection_strategies_for_technique(
                        ",".join(ids_10), domain="enterprise", include_description=False
                    )
                )
            )
        )
        self.assertLessEqual(
            batch_10,
            int(obo_10 * 0.80),
            f"10-tech compact batch ({batch_10}) exceeded 80% of one-by-one ({obo_10})",
        )

    def test_batch_performance_warm_cache(self) -> None:
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


EMPTY_INPUT_CASES = [
    {"technique_ids": []},
    {"technique_stix_id": " , , "},
    {"technique_ids": ["", "   "]},
]


@pytest.mark.parametrize(
    "kwargs",
    EMPTY_INPUT_CASES,
    ids=["empty_list", "blank_comma_string", "blank_list_items"],
)
def test_empty_input(kwargs) -> None:
    res = asyncio.run(srv.get_detection_strategies_for_technique(**kwargs))
    _tc.assertFalse(res["found"])
    _tc.assertTrue(res["batch"])
    _tc.assertEqual(res["error_code"], "EMPTY_INPUT")


if __name__ == "__main__":
    unittest.main()

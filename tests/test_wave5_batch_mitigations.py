"""Hermetic regression tests for Wave 5:
Backward-compatible batch mitigation lookup on `get_mitigations_mitigating_technique`,
including compact default mode, opt-in full mode parity, token-efficiency size gates,
and non-regression of `get_detection_strategies_for_technique`.
"""

import asyncio
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mitreattack import release_info
import mitre_mcp_server.server as srv


class TestWave5BatchMitigations(unittest.TestCase):
    """Verify backward-compatible single mode and deterministic compact/full batch modes."""

    def test_tool_count_and_mcp_schema(self) -> None:
        tools = {t.name: t for t in asyncio.run(srv.mcp.list_tools())}
        self.assertEqual(len(tools), 67)
        tool = tools["get_mitigations_mitigating_technique"]
        props = tool.inputSchema.get("properties", {})
        self.assertIn("technique_stix_id", props)
        self.assertIn("technique_ids", props)
        self.assertIn("domain", props)
        self.assertIn("include_description", props)
        self.assertIn("include_formatted", props)
        self.assertIn("detail_level", props)
        self.assertEqual(props["detail_level"].get("default"), "compact")
        self.assertEqual(set(props["detail_level"].get("enum", [])), {"compact", "full"})
        desc = tool.description or ""
        self.assertIn("Batch mode", desc)
        self.assertIn("detail_level", desc)

    def test_single_technique_backward_compatibility(self) -> None:
        res = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
                include_formatted=False,
            )
        )
        self.assertEqual(
            set(res.keys()),
            {"found", "technique", "count", "mitigations", "formatted", "message"},
        )
        self.assertTrue(res["found"])
        self.assertEqual(res["technique"]["attack_id"], "T1190")
        self.assertEqual(res["count"], 8)
        self.assertEqual(res["formatted"], "")
        self.assertTrue(all(m["description"] is None for m in res["mitigations"]))
        self.assertEqual(
            len(json.dumps(res)),
            1521,
        )
        self.assertEqual(
            len(json.dumps(res, separators=(",", ":"))),
            1442,
        )

        # Single with include_formatted=True
        res_fmt = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1190",
                domain="enterprise",
                include_description=False,
                include_formatted=True,
            )
        )
        self.assertTrue(res_fmt["found"])
        self.assertIn("ID: M1048", res_fmt["formatted"])

        # Single invalid ID preserves exact legacy error shape
        bad = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="NOT_AN_ID",
                domain="enterprise",
            )
        )
        self.assertEqual(
            set(bad.keys()),
            {"found", "technique", "count", "mitigations", "formatted", "message"},
        )
        self.assertFalse(bad["found"])
        self.assertIsNone(bad["technique"])
        self.assertEqual(bad["count"], 0)
        self.assertEqual(bad["mitigations"], [])
        self.assertEqual(bad["formatted"], "")

        # Single valid technique with 0 mitigations preserves legacy found=False with non-null technique
        no_mit = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1066",
                domain="enterprise",
            )
        )
        self.assertEqual(
            set(no_mit.keys()),
            {"found", "technique", "count", "mitigations", "formatted", "message"},
        )
        self.assertFalse(no_mit["found"])
        self.assertIsNotNone(no_mit["technique"])
        self.assertEqual(no_mit["technique"]["attack_id"], "T1066")
        self.assertEqual(no_mit["count"], 0)
        self.assertEqual(no_mit["mitigations"], [])

    def test_batch_compact_default_csv_list_combined_and_deterministic_sorting(self) -> None:
        res_csv = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1190,T1203,T1595.002",
                domain="enterprise",
                include_description=False,
            )
        )
        res_list = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_ids=["T1595.002", "T1190", "t1203"],
                domain="enterprise",
                include_description=False,
            )
        )
        res_combined = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1203",
                technique_ids=["T1595.002", "T1190"],
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
        self.assertEqual(tech_ids, ["T1190", "T1203", "T1595.002"])
        self.assertTrue(all("name" in t and t["name"] for t in res_csv["techniques"]))
        self.assertEqual(res_csv["counts"]["found"], 3)
        self.assertEqual(res_csv["counts"]["valid_no_mitigation"], 0)
        # T1190 (8) + T1203 (3: M1048, M1050, M1051 shared with T1190) + T1595.002 (1: M1056) = 9 unique mitigations
        self.assertEqual(res_csv["counts"]["mitigations"], 9)
        self.assertEqual(res_csv["count"], 9)
        self.assertEqual(
            list(res_csv["coverage"]["mitigations"].keys()),
            ["M1016", "M1026", "M1030", "M1035", "M1037", "M1048", "M1050", "M1051", "M1056"],
        )

        # Do not invent log source links in mitigation coverage
        self.assertNotIn("log_sources", json.dumps(res_csv))

        # Metadata & caveat verification
        meta = res_csv["metadata"]
        self.assertEqual(meta["attack_version"], str(release_info.LATEST_VERSION))
        self.assertEqual(meta["domain"], "enterprise")
        self.assertEqual(meta["detail_level"], "compact")
        self.assertIn("enterprise-attack", meta["source_url"])
        self.assertIn("freshness_status", meta)
        self.assertIn("not a guarantee", meta["caveat"].lower())
        self.assertIn("prevention", meta["caveat"].lower())

    def test_batch_deduplication_and_stix_alias_collapse(self) -> None:
        t1190_stix = "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c"
        res_a = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_ids=["T1190", "t1190", t1190_stix, "T1203", "T1203"],
                domain="enterprise",
            )
        )
        res_b = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_ids=[t1190_stix, "T1203", "T1190"],
                domain="enterprise",
            )
        )

        self.assertEqual([t["attack_id"] for t in res_a["techniques"]], ["T1190", "T1203"])
        self.assertEqual([t["attack_id"] for t in res_b["techniques"]], ["T1190", "T1203"])
        self.assertEqual(res_a["counts"]["requested_inputs"], 5)
        self.assertEqual(res_a["counts"]["techniques_total"], 2)
        self.assertEqual(res_a["counts"]["duplicates_removed"], 3)
        t1190_row_a = next(t for t in res_a["techniques"] if t["attack_id"] == "T1190")
        t1190_row_b = next(t for t in res_b["techniques"] if t["attack_id"] == "T1190")
        self.assertEqual(t1190_row_a["matched_inputs"], sorted(["T1190", t1190_stix]))
        self.assertEqual(t1190_row_a, t1190_row_b)

    def test_statuses_valid_no_mitigation_not_found_invalid_and_unavailable(self) -> None:
        res = asyncio.run(
            srv.get_mitigations_mitigating_technique(
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
        self.assertEqual(by_key["T1066"]["status"], "VALID_NO_MITIGATION")
        self.assertTrue(by_key["T1066"].get("revoked"))
        self.assertNotIn("T1066", res["coverage"]["edges"]["technique_to_mitigation"])
        self.assertEqual(by_key["T9999"]["status"], "NOT_FOUND")
        self.assertEqual(
            by_key["attack-pattern--00000000-0000-0000-0000-000000000000"]["status"],
            "NOT_FOUND",
        )
        self.assertEqual(by_key["NOT_AN_ID"]["status"], "INVALID")
        self.assertEqual(by_key["G0016"]["status"], "INVALID")
        self.assertEqual(by_key["T1190.ABC"]["status"], "INVALID")

        self.assertEqual(res["counts"]["found"], 1)
        self.assertEqual(res["counts"]["valid_no_mitigation"], 1)
        self.assertEqual(res["counts"]["not_found"], 2)
        self.assertEqual(res["counts"]["invalid"], 3)

        # When only VALID_NO_MITIGATION techniques resolve, found is still True (resolved in domain)
        only_no_mit = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1066,T9999",
                domain="enterprise",
            )
        )
        self.assertTrue(only_no_mit["found"])
        self.assertEqual(only_no_mit["counts"]["found"], 0)
        self.assertEqual(only_no_mit["counts"]["valid_no_mitigation"], 1)
        self.assertEqual(only_no_mit["counts"]["not_found"], 1)

        # When all inputs are NOT_FOUND or INVALID, found is False
        none_resolved = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T9999,NOT_AN_ID",
                domain="enterprise",
            )
        )
        self.assertFalse(none_resolved["found"])
        self.assertEqual(none_resolved["counts"]["found"], 0)
        self.assertEqual(none_resolved["counts"]["valid_no_mitigation"], 0)

        # Hermetic unavailable domain bundle
        with patch.object(srv, "get_stix_path", return_value=Path("/nonexistent/missing.json")):
            unavail = asyncio.run(
                srv.get_mitigations_mitigating_technique(
                    technique_ids=["T1190", "T1203"], domain="enterprise"
                )
            )
        self.assertFalse(unavail["found"])
        self.assertEqual(unavail["error_code"], "DOMAIN_UNAVAILABLE")
        self.assertEqual(unavail["counts"]["unavailable"], 2)
        self.assertTrue(all(t["status"] == "UNAVAILABLE" for t in unavail["techniques"]))

        # Invalid detail_level returns structured error
        bad_lvl = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_ids=["T1190"], domain="enterprise", detail_level="bogus"  # type: ignore[arg-type]
            )
        )
        self.assertFalse(bad_lvl["found"])
        self.assertEqual(bad_lvl["error_code"], "INVALID_DETAIL_LEVEL")

    def test_domain_isolation(self) -> None:
        ent = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_ids=["T0816", "T1190"], domain="enterprise"
            )
        )
        ent_by_id = {t.get("attack_id") or t.get("input"): t for t in ent["techniques"]}
        self.assertEqual(ent_by_id["T1190"]["status"], "FOUND")
        self.assertEqual(ent_by_id["T0816"]["status"], "NOT_FOUND")

        ics = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_ids=["T0816", "T1190"], domain="ics"
            )
        )
        ics_by_id = {t.get("attack_id") or t.get("input"): t for t in ics["techniques"]}
        self.assertEqual(ics_by_id["T0816"]["status"], "FOUND")
        self.assertEqual(ics_by_id["T1190"]["status"], "NOT_FOUND")
        self.assertGreater(
            len(ics["coverage"]["edges"]["technique_to_mitigation"].get("T0816", [])),
            0,
        )

        bad_dom = asyncio.run(
            srv.get_mitigations_mitigating_technique(
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
                res = asyncio.run(srv.get_mitigations_mitigating_technique(**kwargs))
                self.assertFalse(res["found"])
                self.assertTrue(res["batch"])
                self.assertEqual(res["error_code"], "EMPTY_INPUT")

        too_many = [f"T{1000 + i}" for i in range(srv.MAX_BATCH_DETECTION_TECHNIQUES + 1)]
        over = asyncio.run(
            srv.get_mitigations_mitigating_technique(technique_ids=too_many, domain="enterprise")
        )
        self.assertFalse(over["found"])
        self.assertTrue(over["batch"])
        self.assertEqual(over["error_code"], "BATCH_LIMIT_EXCEEDED")
        self.assertEqual(over["metadata"]["max_batch_size"], srv.MAX_BATCH_DETECTION_TECHNIQUES)

    def test_compact_full_parity_graph_integrity_and_optional_fields(self) -> None:
        compact = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1190,T1203,T1595.002",
                domain="enterprise",
                include_description=False,
                detail_level="compact",
            )
        )
        compact_desc = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1190,T1203,T1595.002",
                domain="enterprise",
                include_description=True,
                detail_level="compact",
            )
        )
        full = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1190,T1203,T1595.002",
                domain="enterprise",
                include_description=False,
                detail_level="full",
            )
        )
        full_desc = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                technique_stix_id="T1190,T1203,T1595.002",
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
            compact["coverage"]["mitigations"],
            {m["attack_id"]: m["name"] for m in full["coverage"]["mitigations"]},
        )

        # Edge sets reconstructed from compact adjacency maps match full edge pairs 100%
        def _adj_to_pairs(adj: dict) -> list:
            return [[src, dst] for src, dsts in adj.items() for dst in dsts]

        self.assertEqual(
            _adj_to_pairs(compact["coverage"]["edges"]["technique_to_mitigation"]),
            full["coverage"]["edges"]["technique_to_mitigation"],
        )

        # Referential integrity of compact graph
        c_cov = compact["coverage"]
        m_ids = set(c_cov["mitigations"].keys())
        for tech in compact["techniques"]:
            if tech["status"] == "FOUND":
                t_ms = c_cov["edges"]["technique_to_mitigation"].get(tech["attack_id"], [])
                self.assertGreater(len(t_ms), 0)
                for m_id in t_ms:
                    self.assertIn(m_id, m_ids)

        # Opt-in descriptions in compact and full mode
        self.assertTrue(
            all(
                isinstance(v, dict) and "description" in v and v["description"]
                for v in compact_desc["coverage"]["mitigations"].values()
            )
        )
        self.assertTrue(all("description" not in m for m in full["coverage"]["mitigations"]))
        self.assertTrue(all("description" in m and m["description"] for m in full_desc["coverage"]["mitigations"]))
        self.assertLess(len(json.dumps(compact)), len(json.dumps(full)))
        self.assertLess(len(json.dumps(full)), len(json.dumps(full_desc)))

    def test_token_efficiency_size_gate_and_detection_nonregression(self) -> None:
        # Baseline methodology comparison: T1190, T1203, T1595.002
        ids_3 = ["T1190", "T1203", "T1595.002"]
        per_tech_res = {
            tid: asyncio.run(
                srv.get_mitigations_mitigating_technique(
                    tid,
                    domain="enterprise",
                    include_description=False,
                    include_formatted=False,
                )
            )
            for tid in ids_3
        }
        per_tech_default_sizes = {tid: len(json.dumps(r)) for tid, r in per_tech_res.items()}
        per_tech_compact_sizes = {
            tid: len(json.dumps(r, separators=(",", ":"))) for tid, r in per_tech_res.items()
        }
        self.assertEqual(per_tech_default_sizes["T1190"], 1521)
        self.assertEqual(per_tech_default_sizes["T1203"], 761)
        self.assertEqual(per_tech_default_sizes["T1595.002"], 440)
        obo_default_total = sum(per_tech_default_sizes.values())
        self.assertEqual(obo_default_total, 2722)

        self.assertEqual(per_tech_compact_sizes["T1190"], 1442)
        self.assertEqual(per_tech_compact_sizes["T1203"], 722)
        self.assertEqual(per_tech_compact_sizes["T1595.002"], 417)
        obo_compact_total = sum(per_tech_compact_sizes.values())
        self.assertEqual(obo_compact_total, 2581)

        batch_res = asyncio.run(
            srv.get_mitigations_mitigating_technique(
                ",".join(ids_3),
                domain="enterprise",
                include_description=False,
                include_formatted=False,
            )
        )
        batch_default = len(json.dumps(batch_res))
        batch_compact = len(json.dumps(batch_res, separators=(",", ":")))
        self.assertLess(batch_default, obo_default_total)
        self.assertLess(batch_compact, obo_compact_total)
        self.assertLess(batch_default, 2000)

        # 10-technique size gate: compact batch significantly smaller than one-by-one
        ids_10 = [
            "T1190", "T1203", "T1595.002", "T1059.001", "T1003",
            "T1055", "T1566", "T1021", "T1078", "T1053",
        ]
        obo_10 = sum(
            len(
                json.dumps(
                    asyncio.run(
                        srv.get_mitigations_mitigating_technique(
                            tid,
                            domain="enterprise",
                            include_description=False,
                            include_formatted=False,
                        )
                    )
                )
            )
            for tid in ids_10
        )
        batch_10 = len(
            json.dumps(
                asyncio.run(
                    srv.get_mitigations_mitigating_technique(
                        ",".join(ids_10),
                        domain="enterprise",
                        include_description=False,
                        include_formatted=False,
                    )
                )
            )
        )
        self.assertLessEqual(
            batch_10,
            int(obo_10 * 0.50),
            f"10-tech compact batch ({batch_10}) exceeded 50% of one-by-one ({obo_10})",
        )

        # Non-regression of get_detection_strategies_for_technique compact behavior
        det_res = asyncio.run(
            srv.get_detection_strategies_for_technique(
                technique_stix_id="T1190,T1059.001,T1003",
                domain="enterprise",
                include_description=False,
            )
        )
        self.assertTrue(det_res["found"])
        self.assertTrue(det_res["batch"])
        self.assertEqual(det_res["detail_level"], "compact")
        self.assertEqual(det_res["counts"]["found"], 3)
        self.assertEqual(det_res["counts"]["detection_strategies"], 3)


if __name__ == "__main__":
    unittest.main()

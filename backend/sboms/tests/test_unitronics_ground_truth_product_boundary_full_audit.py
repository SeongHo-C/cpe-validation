from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from sboms.unitronics_ground_truth_product_boundary_full_audit import (
    AUDIT_FIELDS,
    BOUNDARY_SPECS,
    EXPECTED_CURRENT_DECISIONS,
    ProductBoundaryAuditAnalysis,
    classify_boundary,
    write_product_boundary_full_audit,
    _projected_decisions,
)


class ProductBoundaryRegistryTests(SimpleTestCase):
    def test_registry_exactly_covers_40_unique_components(self) -> None:
        self.assertEqual(len(BOUNDARY_SPECS), 40)
        self.assertEqual(
            len({spec.component_id for spec in BOUNDARY_SPECS.values()}),
            40,
        )
        self.assertTrue(
            all(spec.official_urls for spec in BOUNDARY_SPECS.values())
        )

    def test_wireguard_known_defect_is_removed(self) -> None:
        spec = BOUNDARY_SPECS["wireguard-tools"]

        result = classify_boundary(
            spec=spec,
            current_family=("a", "wireguard", "wireguard"),
            direct_family_found=False,
            configuration_only_found=False,
        )

        self.assertEqual(result["product_boundary_status"], "DIFFERENT_PRODUCT")
        self.assertEqual(result["version_space_status"], "MISMATCH")
        self.assertEqual(result["audit_status"], "REMOVE_CPE")

    def test_mosquitto_library_remains_in_official_project_boundary(self) -> None:
        spec = BOUNDARY_SPECS["libmosquitto-ssl"]

        result = classify_boundary(
            spec=spec,
            current_family=("a", "eclipse", "mosquitto"),
            direct_family_found=True,
            configuration_only_found=False,
        )

        self.assertEqual(result["product_boundary_status"], "SAME_PRODUCT")
        self.assertEqual(result["audit_status"], "KEEP")

    def test_projection_moves_wireguard_to_no_direct_cpe(self) -> None:
        current = Counter(EXPECTED_CURRENT_DECISIONS)
        rows = [
            {
                "current_validation_result": "VERSION_NOT_IN_DICTIONARY",
                "recommended_validation_result": (
                    "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
                ),
            }
        ]

        projected = _projected_decisions(current, rows)

        self.assertEqual(projected["VERSION_NOT_IN_DICTIONARY"], 16)
        self.assertEqual(
            projected["DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"],
            538,
        )


class ProductBoundaryOutputTests(SimpleTestCase):
    def test_writer_creates_only_four_requested_artifacts(self) -> None:
        row = {field: "" for field in AUDIT_FIELDS}
        row.update(
            {
                "component_id": "1",
                "name": "example",
                "risk_flags": "[]",
                "audit_status": "KEEP",
            }
        )
        decisions = {
            decision: 0 for decision in EXPECTED_CURRENT_DECISIONS
        }
        summary = {
            "scope": {"input_cpe_bearing_components": 1},
            "audit_status": {
                "KEEP": 1,
                "CHANGE_CPE": 0,
                "REMOVE_CPE": 0,
                "REVIEW_REQUIRED": 0,
            },
            "statistics": {
                "product_boundary_mismatch_count": 0,
                "version_space_mismatch_count": 0,
                "direct_replacement_cpe_found_count": 0,
                "no_direct_product_cpe_count": 0,
                "circular_evidence_risk_count": 0,
                "semantic_product_duplicate_count": 0,
            },
            "by_current_validation_result": {
                decision: {
                    "KEEP": 0,
                    "CHANGE_CPE": 0,
                    "REMOVE_CPE": 0,
                    "REVIEW_REQUIRED": 0,
                }
                for decision in (
                    "CPE_CONFIRMED",
                    "OFFICIAL_CPE_MAPPED",
                    "VERSION_NOT_IN_DICTIONARY",
                )
            },
            "changes": [],
            "representative_nvd_review": {
                "components": [],
                "case_count": 0,
                "raw_feeds": {},
            },
            "projection": {
                "current_cpe_bearing": 1,
                "projected_cpe_bearing": 1,
                "projected_distinct_canonical_cpes": 1,
                "projected_duplicate_groups": 0,
                "current_validation_result_distribution": decisions,
                "projected_validation_result_distribution": decisions,
            },
            "validation": {
                "input_row_count": 1,
                "unique_component_id_count": 1,
                "canonical_current_gt_parse_failure_count": 0,
                "audited_family_canonical_parse_failure_count": 0,
                "version_not_registered_input_count": 0,
                "version_not_registered_keep_all_invariants_count": 0,
                "wireguard_known_defect_redetected": True,
                "wireguard_approved_removal_retained": False,
                "finalized_state": False,
                "configuration_only_gate_violation_count": 0,
                "deprecated_final_recommendation_count": 0,
                "ground_truth_db_mutation_count": 0,
                "component_mutation_count": 0,
                "candidate_artifact_mutation_count": 0,
                "existing_audit_artifact_mutation_count": 0,
                "migration_count": 0,
                "commit_count": 0,
            },
        }
        analysis = ProductBoundaryAuditAnalysis([row], [], summary)
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "audit"

            paths = write_product_boundary_full_audit(analysis, output)

            self.assertEqual(
                {path.name for path in paths},
                {
                    "audit_report.md",
                    "audit_results.csv",
                    "high_risk_cases.csv",
                    "summary.json",
                },
            )
            with (output / "audit_results.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 1)
            parsed = json.loads((output / "summary.json").read_text())
            self.assertEqual(parsed["audit_status"]["KEEP"], 1)

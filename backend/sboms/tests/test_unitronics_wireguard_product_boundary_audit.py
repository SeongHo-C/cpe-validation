from __future__ import annotations

import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from sboms.models import GroundTruthDecision
from sboms.unitronics_wireguard_product_boundary_audit import (
    OBSERVED_VERSION,
    OFFICIAL_PROJECTS,
    WINDOWS_PRODUCT_CPE,
    UnitronicsWireguardAuditError,
    WireguardAuditAnalysis,
    judge_product_boundary,
    write_wireguard_product_boundary_audit,
)


def cpe_rows() -> list[dict[str, str]]:
    return [
        {
            "cpe": WINDOWS_PRODUCT_CPE,
            "version": "0.5.3",
            "product_boundary_signal": (
                "WIREGUARD_WINDOWS_VERSION_REFERENCE"
            ),
        }
    ]


def configuration_rows() -> list[dict[str, str]]:
    return [
        {
            "cve_id": "CVE-2021-46873",
            "platform_wording": "WINDOWS_CLIENT_AND_CONFIGURATION",
        },
        {
            "cve_id": "CVE-2023-35838",
            "platform_wording": "WINDOWS_CLIENT_AND_CONFIGURATION",
        },
    ]


def nvd_stats() -> dict[str, int]:
    return {"direct_wireguard_tools_expression_count": 0}


class WireguardProductBoundaryDecisionTests(SimpleTestCase):
    def test_independent_evidence_selects_different_product(self) -> None:
        result = judge_product_boundary(
            cpe_rows=cpe_rows(),
            direct_dictionary_products=[],
            configuration_rows=configuration_rows(),
            nvd_stats=nvd_stats(),
        )

        self.assertEqual(result["classification"], "DIFFERENT_PRODUCT")
        self.assertEqual(result["audited_actual_product"], "wireguard-tools")
        self.assertEqual(result["audited_actual_version"], "1.0.20210223")
        self.assertEqual(result["recommended_gt_cpe"], "")
        self.assertEqual(
            result["recommended_validation_result"],
            GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED,
        )

    def test_direct_tools_dictionary_entry_stops_deterministic_decision(
        self,
    ) -> None:
        with self.assertRaises(UnitronicsWireguardAuditError):
            judge_product_boundary(
                cpe_rows=cpe_rows(),
                direct_dictionary_products=[{"product": "wireguard-tools"}],
                configuration_rows=configuration_rows(),
                nvd_stats=nvd_stats(),
            )

    def test_incomplete_windows_constraint_stops_decision(self) -> None:
        rows = configuration_rows()
        rows[0]["platform_wording"] = "PLATFORM_SIGNAL_INCOMPLETE"

        with self.assertRaises(UnitronicsWireguardAuditError):
            judge_product_boundary(
                cpe_rows=cpe_rows(),
                direct_dictionary_products=[],
                configuration_rows=rows,
                nvd_stats=nvd_stats(),
            )

    def test_official_projects_keep_tools_kernel_and_windows_separate(
        self,
    ) -> None:
        projects = {row["project"] for row in OFFICIAL_PROJECTS}

        self.assertIn("wireguard-tools", projects)
        self.assertIn("wireguard-linux", projects)
        self.assertIn("wireguard-windows", projects)
        self.assertEqual(OBSERVED_VERSION, "1.0.20210223-4")


class WireguardProductBoundaryOutputTests(SimpleTestCase):
    def test_writer_creates_only_four_requested_artifacts(self) -> None:
        summary = {
            "official_project_structure": [],
            "cpe_dictionary": {
                "vendor_family_record_count": 0,
                "vendor_family_versions": [],
                "direct_wireguard_tools_matches": [],
            },
            "nvd_configuration": {
                "wireguard_family_criteria_count": 0,
                "wireguard_family_occurrence_count": 0,
                "wireguard_family_distinct_cve_count": 0,
                "wireguard_family_versions": [],
                "direct_wireguard_tools_expression_count": 0,
            },
            "judgment": {
                "classification": "DIFFERENT_PRODUCT",
            },
            "comparison": {
                "audit_status": "CHANGE_REQUIRED",
                "current": {
                    "current_actual_product": "WireGuard",
                    "current_actual_version": "1.0.20210223",
                    "current_gt_cpe": "old-cpe",
                    "current_validation_result": "VERSION_NOT_IN_DICTIONARY",
                },
                "audited": {
                    "audited_actual_product": "wireguard-tools",
                    "audited_actual_version": "1.0.20210223",
                    "recommended_validation_result": (
                        "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
                    ),
                },
            },
            "validation": {
                "cpe_canonical_parse_failure_count": 0,
                "ground_truth_db_mutation_count": 0,
                "component_mutation_count": 0,
                "candidate_artifact_mutation_count": 0,
                "migration_count": 0,
                "commit_count": 0,
                "database_state_before": {
                    "component_fingerprint": "component",
                    "ground_truth_fingerprint": "ground-truth",
                },
            },
        }
        analysis = WireguardAuditAnalysis([], [], summary)
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "audit"

            paths = write_wireguard_product_boundary_audit(analysis, output)

            self.assertEqual(len(paths), 4)
            self.assertEqual(
                {path.name for path in paths},
                {
                    "report.md",
                    "cpe_family.csv",
                    "configuration_cases.csv",
                    "summary.json",
                },
            )
            with (output / "cpe_family.csv").open(
                newline="",
                encoding="utf-8",
            ) as handle:
                self.assertEqual(list(csv.DictReader(handle)), [])
            parsed = json.loads((output / "summary.json").read_text())
            self.assertEqual(
                parsed["judgment"]["classification"],
                "DIFFERENT_PRODUCT",
            )

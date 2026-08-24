from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cpe_dictionary.models import CpeDictionarySnapshot
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    GroundTruthDecision,
    SBOMDocument,
)
from sboms.unitronics_ground_truth_finalization import (
    CPE_SNAPSHOT_ID,
    FINAL_DECISION,
    NVD_SNAPSHOT_ID,
    OLD_DECISION,
    OLD_GT_CPE,
    TARGET_COMPONENT_ID,
    CandidateRow,
    FinalizationPlan,
    FinalizationResult,
    UnitronicsGroundTruthFinalizationError,
    finalize_unitronics_ground_truth,
    load_finalization_plan,
    write_finalization_artifacts,
)
from sboms.unitronics_representative_finalization import DatabaseState


class UnitronicsGroundTruthFinalizationArtifactTests(SimpleTestCase):
    def test_final_plan_is_582_rows_with_one_approved_boundary_exclusion(self):
        plan = load_finalization_plan()
        wireguard = plan.by_name["wireguard-tools"]

        self.assertEqual(len(plan.rows), 582)
        self.assertEqual(
            sum(bool(row.proposed_gt_cpe) for row in plan.rows),
            39,
        )
        self.assertEqual(
            len(
                {
                    row.proposed_gt_cpe
                    for row in plan.rows
                    if row.proposed_gt_cpe
                }
            ),
            39,
        )
        self.assertEqual(wireguard.actual_product, "wireguard-tools")
        self.assertEqual(wireguard.actual_product_version, "1.0.20210223")
        self.assertEqual(wireguard.proposed_gt_cpe, "")
        self.assertEqual(wireguard.proposed_decision, FINAL_DECISION)

    def test_writer_creates_exactly_three_final_artifacts(self):
        result = FinalizationResult(
            applied_at="2026-08-25T00:00:00+09:00",
            before={},
            after={
                "ground_truth_records": 582,
                "cpe_bearing": 39,
                "cpe_null": 543,
                "distinct_canonical_gt_cpes": 39,
                "duplicate_canonical_gt_cpe_groups": 0,
                "deprecated_final_gt_count": 0,
                "canonical_parse_failure_count": 0,
                "decision_counts": {},
            },
            changed_ground_truth_record_ids=(1389,),
            candidate_cpe_mismatch_count_before=1,
            candidate_decision_mismatch_count_before=1,
            candidate_cpe_mismatch_count_after=0,
            candidate_decision_mismatch_count_after=0,
            component_mutation_count=0,
            wireguard_before={
                "ground_truth_cpe": OLD_GT_CPE,
                "decision": OLD_DECISION,
                "resolution_outcome": "MANUAL_FROM_OFFICIAL_FAMILY",
            },
            wireguard_after={
                "decision": FINAL_DECISION,
                "resolution_outcome": "DIRECT_OFFICIAL_NOT_CONFIRMED",
            },
            product_boundary_summary={
                "audit_status": {
                    "KEEP": 39,
                    "CHANGE_CPE": 0,
                    "REMOVE_CPE": 0,
                    "REVIEW_REQUIRED": 0,
                },
                "validation": {
                    "version_not_registered_keep_all_invariants_count": 16,
                },
            },
            independent_cpe_summary={
                "final_audit_status": {
                    "counts": {
                        "ACCEPTED": 39,
                        "CORRECTION_REQUIRED": 0,
                        "EVIDENCE_REVIEW_REQUIRED": 0,
                    }
                },
                "correction_counts": {"circular_evidence_risks": 0},
                "cpe_resolution": {"final_deprecated_gt_count": 0},
            },
            representative_regressions={},
            methodology={
                "verdict": "READY_FOR_FINALIZATION",
                "blocking_issue_count": 0,
                "ratings": {
                    "methodological_consistency": "PASS",
                    "evidence_traceability": "PASS_WITH_LIMITATION",
                    "computational_reproducibility": "PASS_WITH_LIMITATION",
                },
                "product_boundary_principle": "test",
                "flow": ["SBOM Component", "CPE Validation Result"],
                "prior_non_blocking_limitations": ["test limitation"],
            },
            artifact_hashes={},
        )
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "final"

            paths = write_finalization_artifacts(result, output)

            self.assertEqual(
                {path.name for path in paths},
                {"final_report.md", "methodology_summary.md", "summary.json"},
            )
            self.assertEqual(len(list(output.iterdir())), 3)


class UnitronicsGroundTruthFinalizationRollbackTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = CpeDictionarySnapshot.objects.create(
            snapshot_id=CPE_SNAPSHOT_ID,
            status=CpeDictionarySnapshot.Status.COMPLETE,
            feed_last_modified=timezone.now(),
            manifest_sha256="1" * 64,
            archive_sha256="2" * 64,
            content_sha256="3" * 64,
            member_count=1,
            expected_record_count=1,
            record_count=1,
            active_count=1,
            deprecated_count=0,
            completed_at=timezone.now(),
        )
        cls.sbom = SBOMDocument.objects.create(
            id=1364,
            manufacturer="Unitronics",
            product_name="UCR-ST-B8",
            product_version="52.07.13.7",
            source_path="test/unitronics.cdx.json",
            file_sha256="4" * 64,
            spec_version="1.5",
            generator_name="test",
            generator_version="1",
        )
        cls.component = Component.objects.create(
            id=TARGET_COMPONENT_ID,
            sbom_document=cls.sbom,
            bom_ref="wireguard-tools",
            component_type="library",
            name="wireguard-tools",
            version="1.0.20210223-4",
            cpe=(
                "cpe:2.3:a:wireguard-tools:wireguard-tools:"
                "1.0.20210223-4:*:*:*:*:*:*:*"
            ),
        )
        cls.record = ComponentCpeGroundTruth.objects.create(
            component=cls.component,
            snapshot=cls.snapshot,
            manual_ground_truth_cpe=OLD_GT_CPE,
            decision=OLD_DECISION,
        )

    def test_post_update_audit_failure_rolls_back_wireguard_change(self):
        record = (
            ComponentCpeGroundTruth.objects.select_related(
                "component", "ground_truth_cpe"
            )
            .prefetch_related("discrepancy_types", "correction_types")
            .get(pk=self.record.pk)
        )
        state = DatabaseState(
            records=[record],
            component_count=1,
            global_ground_truth_count=1,
            component_fingerprint="test",
            ground_truth_fingerprint="test",
            decision_counts={},
            cpe_present_count=1,
            cpe_null_count=0,
            distinct_canonical_gt_cpes=1,
            duplicate_canonical_gt_cpe_groups=0,
            duplicate_group_component_count=0,
            canonical_parse_failure_count=0,
            deprecated_final_gt_count=0,
            discrepancy_assignment_count=0,
            correction_assignment_count=0,
        )
        plan = FinalizationPlan(
            rows=(
                CandidateRow(
                    component_id=TARGET_COMPONENT_ID,
                    name="wireguard-tools",
                    observed_version="1.0.20210223-4",
                    actual_product="wireguard-tools",
                    actual_product_version="1.0.20210223",
                    proposed_gt_cpe="",
                    proposed_decision=FINAL_DECISION,
                    discrepancy_fields="N/A",
                ),
            ),
            artifact_hashes={},
        )
        with (
            mock.patch(
                "sboms.unitronics_ground_truth_finalization._database_state",
                return_value=state,
            ),
            mock.patch(
                "sboms.unitronics_ground_truth_finalization._validate_database_state"
            ),
            mock.patch(
                "sboms.unitronics_ground_truth_finalization._candidate_mismatches",
                side_effect=[
                    ({TARGET_COMPONENT_ID}, {TARGET_COMPONENT_ID}),
                    (set(), set()),
                ],
            ),
            mock.patch(
                "sboms.unitronics_ground_truth_finalization.build_product_boundary_full_audit",
                side_effect=UnitronicsGroundTruthFinalizationError(
                    "forced final audit failure"
                ),
            ),
            self.assertRaises(UnitronicsGroundTruthFinalizationError),
        ):
            finalize_unitronics_ground_truth(
                plan,
                cpe_snapshot=self.snapshot,
                nvd_snapshot=SimpleNamespace(snapshot_id=NVD_SNAPSHOT_ID),
            )

        self.record.refresh_from_db()
        self.assertEqual(self.record.manual_ground_truth_cpe, OLD_GT_CPE)
        self.assertEqual(
            self.record.decision,
            GroundTruthDecision.VERSION_NOT_IN_DICTIONARY,
        )

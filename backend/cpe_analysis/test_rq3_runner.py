from pathlib import Path

from django.test import SimpleTestCase

from cpe_analysis.rq3_runner import (
    GROUND_TRUTH_RELATIVE_PATH,
    NVD_SNAPSHOT_ID,
    _aggregate_result,
    _cause_category,
    classify_relation,
)


class RQ3RunnerContractTests(SimpleTestCase):
    def test_final_inputs_are_repository_relative_and_snapshot_is_fixed(self) -> None:
        self.assertEqual(
            GROUND_TRUTH_RELATIVE_PATH,
            Path("research/ground_truth/ground_truth.csv"),
        )
        self.assertNotIn("/tmp", str(GROUND_TRUTH_RELATIVE_PATH))
        self.assertEqual(NVD_SNAPSHOT_ID, "20260820T110357Z")

    def test_match_dominates_unresolved_for_same_component_cve(self) -> None:
        aggregates = {"ORIGINAL": {}, "GROUND_TRUTH": {}}
        _aggregate_result(
            aggregates,
            "ORIGINAL",
            1,
            "CVE-2026-0001",
            "UNSUPPORTED_VERSION_COMPARISON",
        )
        _aggregate_result(
            aggregates, "ORIGINAL", 1, "CVE-2026-0001", "MATCH"
        )
        aggregate = aggregates["ORIGINAL"][(1, "CVE-2026-0001")]
        self.assertEqual(aggregate.status, "MATCH")
        self.assertEqual(aggregate.evidence_leaf_count, 2)

    def test_unresolved_precedes_added_classification(self) -> None:
        category, reason = classify_relation(
            "UNRESOLVED",
            "MATCH",
            {"UNSUPPORTED_VERSION_COMPARISON"},
            set(),
        )
        self.assertEqual(category, "INDETERMINATE")
        self.assertEqual(reason, "ORIGINAL_UNSUPPORTED_VERSION")

    def test_gt_null_original_match_is_removed(self) -> None:
        self.assertEqual(
            classify_relation("MATCH", "NO_GT_CPE"),
            ("REMOVED_AFTER_CORRECTION", "GT_NO_CPE"),
        )

    def test_added_cause_categories_preserve_frozen_contract(self) -> None:
        self.assertEqual(
            _cause_category({frozenset({"VENDOR"})}), "VENDOR_ONLY"
        )
        self.assertEqual(
            _cause_category({frozenset({"VENDOR", "PRODUCT"})}),
            "MULTI_FIELD",
        )
        self.assertEqual(
            _cause_category(
                {frozenset({"VENDOR"}), frozenset({"PRODUCT"})}
            ),
            "MULTIPLE_POSSIBLE_BLOCKERS",
        )

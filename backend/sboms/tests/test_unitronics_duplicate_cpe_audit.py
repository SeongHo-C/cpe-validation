import csv
import json
from collections import Counter

from django.conf import settings
from django.test import SimpleTestCase

from sboms.unitronics_duplicate_cpe_audit import (
    GROUP_DECISIONS,
    KEEP_GT_CPE,
    OUTPUT_RELATIVE,
    REMOVE_DUPLICATED_GT_CPE,
    REVIEW_REQUIRED,
)


class UnitronicsDuplicateCpeAuditArtifactTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.root = settings.REPOSITORY_ROOT / OUTPUT_RELATIVE
        cls.summary = json.loads(
            (cls.root / "summary.json").read_text(encoding="utf-8")
        )
        with (cls.root / "duplicate_groups.csv").open(
            newline="",
            encoding="utf-8",
        ) as handle:
            cls.groups = list(csv.DictReader(handle))
        with (cls.root / "component_recommendations.csv").open(
            newline="",
            encoding="utf-8",
        ) as handle:
            cls.components = list(csv.DictReader(handle))

    def test_canonical_grouping_covers_all_48_cpe_records(self) -> None:
        grouping = self.summary["grouping"]

        self.assertEqual(grouping["distinct_canonical_gt_cpes"], 40)
        self.assertEqual(grouping["unique_gt_cpe_groups"], 33)
        self.assertEqual(grouping["duplicated_gt_cpe_groups"], 7)
        self.assertEqual(grouping["components_in_duplicate_groups"], 15)
        self.assertEqual(grouping["semantic_near_duplicate_groups"], 0)
        self.assertEqual(grouping["canonical_parse_failure_count"], 0)
        self.assertEqual(len(self.groups), 7)
        self.assertEqual(len(self.components), 48)
        self.assertEqual(
            len({row["component_id"] for row in self.components}),
            48,
        )

    def test_reviewed_group_registry_and_recommendations_are_exact(self) -> None:
        self.assertEqual(
            {row["canonical_gt_cpe"] for row in self.groups},
            set(GROUP_DECISIONS),
        )
        self.assertEqual(
            Counter(row["group_status"] for row in self.groups),
            Counter(
                {
                    "KEEP_SINGLE_REPRESENTATIVE": 6,
                    "REPRESENTATIVE_AMBIGUOUS": 1,
                }
            ),
        )
        self.assertEqual(
            Counter(row["recommendation"] for row in self.components),
            Counter(
                {
                    KEEP_GT_CPE: 39,
                    REMOVE_DUPLICATED_GT_CPE: 7,
                    REVIEW_REQUIRED: 2,
                }
            ),
        )
        removed = {
            row["component_name"]
            for row in self.components
            if row["recommendation"] == REMOVE_DUPLICATED_GT_CPE
        }
        self.assertEqual(
            removed,
            {
                "ip6tables",
                "libcap-bin",
                "libipset13",
                "liblua5.1.5",
                "libsqlite3-0",
                "strongswan-charon",
                "strongswan-swanctl",
            },
        )

    def test_projected_effect_and_read_only_guards_are_recorded(self) -> None:
        projected = self.summary["projected_if_recommendations_applied"]
        validation = self.summary["validation"]

        self.assertEqual(projected["current_cpe_bearing_components"], 48)
        self.assertEqual(projected["projected_cpe_bearing_components"], 41)
        self.assertEqual(projected["projected_distinct_canonical_gt_cpes"], 40)
        self.assertEqual(projected["projected_removed_duplicate_mappings"], 7)
        self.assertEqual(validation["ground_truth_db_mutation_count"], 0)
        self.assertEqual(validation["original_component_mutation_count"], 0)
        self.assertEqual(
            validation["ground_truth_fingerprint_before"],
            validation["ground_truth_fingerprint_after"],
        )
        self.assertEqual(
            validation["component_fingerprint_before"],
            validation["component_fingerprint_after"],
        )

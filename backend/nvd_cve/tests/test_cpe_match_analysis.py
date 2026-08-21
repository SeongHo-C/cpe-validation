from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from cpe.cpe23 import CPE23StructuralStatus
from nvd_cve.cpe_match_analysis import (
    NvdCpeMatchAnalysis,
    _contains_unescaped_wildcard,
    _field_token_category,
    _parse_profile,
    _version_category,
    render_analysis,
    write_analysis,
)


class NvdCpeMatchAnalysisHelperTests(SimpleTestCase):
    def test_version_categories_do_not_apply_semver(self) -> None:
        self.assertEqual(_version_category("*"), "star")
        self.assertEqual(_version_category("-"), "hyphen")
        self.assertEqual(_version_category("1.2.3-rc1"), "concrete")
        self.assertEqual(_version_category(""), "other")
        self.assertEqual(_version_category(None), "other")

    def test_field_token_categories_preserve_raw_values(self) -> None:
        self.assertEqual(_field_token_category("*"), "star")
        self.assertEqual(_field_token_category("-"), "hyphen")
        self.assertEqual(_field_token_category(""), "empty")
        self.assertEqual(_field_token_category("1.0\\:beta"), "concrete")

    def test_unescaped_wildcard_detection_respects_escapes(self) -> None:
        self.assertTrue(_contains_unescaped_wildcard("8.*"))
        self.assertTrue(_contains_unescaped_wildcard("8.?"))
        self.assertFalse(_contains_unescaped_wildcard(r"8.\*"))
        self.assertFalse(_contains_unescaped_wildcard(r"8.\?"))

    def test_parse_profile_reuses_structural_parser(self) -> None:
        criteria = "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"

        parsed, part, version, flags = _parse_profile(criteria)

        self.assertEqual(parsed.status, CPE23StructuralStatus.STRUCTURALLY_VALID)
        self.assertEqual(part, "a")
        self.assertEqual(version, "star")
        self.assertEqual(flags, [])

    def test_parse_profile_reports_empty_fields_without_correction(self) -> None:
        criteria = "cpe:2.3:a:::*:*:*:*:*:*:*:*"

        parsed, part, version, flags = _parse_profile(criteria)

        self.assertTrue(parsed.is_structurally_valid)
        self.assertEqual(part, "a")
        self.assertEqual(version, "star")
        self.assertIn("empty_vendor", flags)
        self.assertIn("empty_product", flags)


class NvdCpeMatchAnalysisOutputTests(SimpleTestCase):
    def minimal_summary(self) -> dict:
        return {
            "generated_at_utc": "2026-08-21T00:00:00+00:00",
            "dataset": {
                "snapshot_id": "20260820T110357Z",
                "snapshot_status": "COMPLETE",
                "manifest_sha256": "1" * 64,
                "content_sha256": "2" * 64,
                "cve_count": 1,
                "configuration_count": 1,
                "node_count": 1,
                "cpe_match_count": 1,
            },
            "criteria_cardinality": {
                "total_occurrences": 1,
                "distinct_criteria_strings": 1,
                "distinct_match_criteria_ids": 1,
                "vulnerable_true_occurrences": 1,
                "vulnerable_false_occurrences": 0,
                "vulnerable_null_occurrences": 0,
                "criteria_strings_occurring_once": 1,
                "criteria_strings_occurring_at_least_twice": 0,
                "maximum_criteria_occurrence_count": 1,
                "top_criteria_by_occurrence": [],
                "criteria_strings_linked_to_multiple_match_criteria_ids": 0,
                "match_criteria_ids_linked_to_multiple_criteria_strings": 0,
            },
            "cpe_field_profile": {
                "part_distribution": [],
                "version_distribution": [],
                "all_field_token_distribution": {},
            },
            "version_range_profile": {
                "range_absent_occurrences": 1,
                "range_present_occurrences": 0,
                "range_present_percent": 0.0,
                "actual_field_combinations": [],
                "boundary_field_presence": {},
            },
            "version_range_cross_analysis": {
                "occurrence_counts": {
                    key: {"range_absent": 0, "range_present": 0}
                    for key in ("star", "concrete", "hyphen", "other")
                },
                "distinct_criteria_cell_counts": {
                    key: {"range_absent": 0, "range_present": 0}
                    for key in ("star", "concrete", "hyphen", "other")
                },
                "criteria_strings_used_with_both_range_absent_and_present": 0,
            },
            "criteria_range_multiplicity": {
                "criteria_with_one_range_tuple": 1,
                "criteria_with_multiple_range_tuples": 0,
                "maximum_range_tuples_per_criteria": 1,
                "top_criteria_by_range_multiplicity": [],
            },
            "vulnerable_usage": {
                "groups_derived_from_criteria_aggregates": {
                    key: {
                        "distinct_criteria_strings": 0,
                        "occurrences": 0,
                        "distinct_cve_count": 0,
                    }
                    for key in (
                        "true_only",
                        "false_only",
                        "both",
                        "null_or_unexpected",
                    )
                }
            },
            "configuration_structure": {
                "configuration_entities": {
                    "entity_count": 1,
                    "operator": [],
                    "negate": [],
                },
                "node_entities": {
                    "entity_count": 1,
                    "operator": [],
                    "negate": [],
                },
                "cpe_match_occurrence_dimensions": {
                    "node_or_and_other": [],
                    "configuration_operator": [],
                    "configuration_or_node_negate_true": [],
                },
            },
            "exceptional_cases": {
                "structural_status_distribution": [],
                "parser_attention_categories": [],
            },
            "safety": {
                "database_queries_executed_in_read_only_transactions": True,
                "database_state_unchanged": True,
            },
            "validation": {"aggregate_invariants_passed": True},
        }

    def test_render_and_write_only_known_analysis_files(self) -> None:
        analysis = NvdCpeMatchAnalysis(summary=self.minimal_summary())
        rendered = render_analysis(analysis)

        self.assertEqual(set(rendered), {"summary.json", "report.md"})
        self.assertIn("raw `criteria`", rendered["report.md"])

        with TemporaryDirectory() as directory:
            output_directory = Path(directory) / "result"
            paths = write_analysis(analysis, output_directory)

            self.assertEqual(set(paths), {"summary.json", "report.md"})
            self.assertTrue(paths["summary.json"].is_file())
            self.assertTrue(paths["report.md"].is_file())

from django.test import SimpleTestCase

from cpe.cpe23_canonical import parse_cpe23
from cpe.version_matching import (
    DottedNumericComparison,
    VersionMatchResult,
    compare_strict_dotted_numeric,
    match_version_constraint,
)


def version(value: str):
    parsed = parse_cpe23(
        f"cpe:2.3:a:example:widget:{value}:*:*:*:*:*:*:*"
    )
    assert parsed.is_valid and parsed.name is not None
    return parsed.name.attribute("version")


class NoRangeVersionMatcherTests(SimpleTestCase):
    def test_any_has_no_version_restriction(self) -> None:
        self.assertEqual(
            match_version_constraint(version("*"), version("1.2.3")),
            VersionMatchResult.MATCH,
        )

    def test_concrete_uses_exact_logical_equality(self) -> None:
        self.assertEqual(
            match_version_constraint(version("1.2.3"), version("1.2.3")),
            VersionMatchResult.MATCH,
        )
        self.assertEqual(
            match_version_constraint(version("1.2.3"), version("1.2.4")),
            VersionMatchResult.NO_MATCH,
        )

    def test_na_and_concrete_do_not_match(self) -> None:
        self.assertEqual(
            match_version_constraint(version("-"), version("1.2.3")),
            VersionMatchResult.NO_MATCH,
        )

    def test_na_matches_na(self) -> None:
        self.assertEqual(
            match_version_constraint(version("-"), version("-")),
            VersionMatchResult.MATCH,
        )

    def test_special_versions_can_use_no_range_exact_equality(self) -> None:
        self.assertEqual(
            match_version_constraint(version("1.0p3"), version("1.0p3")),
            VersionMatchResult.MATCH,
        )
        self.assertEqual(
            match_version_constraint(version("1.0p3"), version("1.0p4")),
            VersionMatchResult.NO_MATCH,
        )

    def test_release_and_leading_v_are_not_normalized(self) -> None:
        for criteria, component in (
            ("1.2.3-1", "1.2.3"),
            ("v1.2.3", "1.2.3"),
            ("R1", "r1"),
        ):
            with self.subTest(criteria=criteria, component=component):
                self.assertEqual(
                    match_version_constraint(
                        version(criteria),
                        version(component),
                    ),
                    VersionMatchResult.NO_MATCH,
                )

    def test_formatted_string_decoding_is_not_version_normalization(self) -> None:
        self.assertEqual(
            match_version_constraint(version(r"1\.2"), version("1.2")),
            VersionMatchResult.MATCH,
        )


class StrictDottedNumericComparatorTests(SimpleTestCase):
    def test_numeric_not_lexicographic_order(self) -> None:
        self.assertEqual(
            compare_strict_dotted_numeric("1.2.9", "1.2.10"),
            DottedNumericComparison.LESS,
        )
        self.assertEqual(
            compare_strict_dotted_numeric("1.10", "1.9"),
            DottedNumericComparison.GREATER,
        )

    def test_leading_zero_segments_use_integer_representation(self) -> None:
        self.assertEqual(
            compare_strict_dotted_numeric("01.002.3", "1.2.3"),
            DottedNumericComparison.EQUAL,
        )

    def test_unequal_length_can_order_at_first_different_segment(self) -> None:
        self.assertEqual(
            compare_strict_dotted_numeric("1.3", "1.2.9"),
            DottedNumericComparison.GREATER,
        )

    def test_complete_prefix_is_unsupported(self) -> None:
        for left, right in (("1.2", "1.2.0"), ("1.2.0", "1.2")):
            with self.subTest(left=left, right=right):
                self.assertEqual(
                    compare_strict_dotted_numeric(left, right),
                    DottedNumericComparison.UNSUPPORTED,
                )


class NumericRangeVersionMatcherTests(SimpleTestCase):
    criteria = version("*")

    def assert_result(
        self,
        expected: VersionMatchResult,
        component: str,
        **ranges,
    ) -> None:
        self.assertEqual(
            match_version_constraint(
                self.criteria,
                version(component),
                **ranges,
            ),
            expected,
        )

    def test_start_including_only(self) -> None:
        self.assert_result(
            VersionMatchResult.MATCH,
            "1.0",
            version_start_including="1.0",
        )
        self.assert_result(
            VersionMatchResult.NO_MATCH,
            "0.9",
            version_start_including="1.0",
        )

    def test_start_excluding_only(self) -> None:
        self.assert_result(
            VersionMatchResult.NO_MATCH,
            "1.0",
            version_start_excluding="1.0",
        )
        self.assert_result(
            VersionMatchResult.MATCH,
            "1.1",
            version_start_excluding="1.0",
        )

    def test_end_including_only(self) -> None:
        self.assert_result(
            VersionMatchResult.MATCH,
            "2.0",
            version_end_including="2.0",
        )
        self.assert_result(
            VersionMatchResult.NO_MATCH,
            "2.1",
            version_end_including="2.0",
        )

    def test_end_excluding_only(self) -> None:
        self.assert_result(
            VersionMatchResult.NO_MATCH,
            "2.0",
            version_end_excluding="2.0",
        )
        self.assert_result(
            VersionMatchResult.MATCH,
            "1.9",
            version_end_excluding="2.0",
        )

    def test_two_sided_inclusive(self) -> None:
        for component in ("1.0", "1.5", "2.0"):
            with self.subTest(component=component):
                self.assert_result(
                    VersionMatchResult.MATCH,
                    component,
                    version_start_including="1.0",
                    version_end_including="2.0",
                )

    def test_two_sided_exclusive(self) -> None:
        for component, expected in (
            ("1.0", VersionMatchResult.NO_MATCH),
            ("1.5", VersionMatchResult.MATCH),
            ("2.0", VersionMatchResult.NO_MATCH),
        ):
            with self.subTest(component=component):
                self.assert_result(
                    expected,
                    component,
                    version_start_excluding="1.0",
                    version_end_excluding="2.0",
                )

    def test_mixed_inclusive_exclusive_combinations(self) -> None:
        self.assert_result(
            VersionMatchResult.MATCH,
            "1.0",
            version_start_including="1.0",
            version_end_excluding="2.0",
        )
        self.assert_result(
            VersionMatchResult.MATCH,
            "2.0",
            version_start_excluding="1.0",
            version_end_including="2.0",
        )

    def test_leading_zero_range_comparison(self) -> None:
        self.assert_result(
            VersionMatchResult.MATCH,
            "01.002.3",
            version_start_including="1.2.3",
            version_end_including="1.2.3",
        )


class UnsupportedRangeVersionMatcherTests(SimpleTestCase):
    criteria = version("*")

    def test_special_ordering_is_explicitly_unsupported(self) -> None:
        for component in (
            "1.0p3",
            "2024-05-17",
            "1.0-build7",
            "R1_2",
            "vendor7x",
        ):
            with self.subTest(component=component):
                self.assertEqual(
                    match_version_constraint(
                        self.criteria,
                        version(component),
                        version_end_excluding="2.0",
                    ),
                    VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON,
                )

    def test_special_endpoint_is_explicitly_unsupported(self) -> None:
        self.assertEqual(
            match_version_constraint(
                self.criteria,
                version("1.0"),
                version_end_excluding="1.0p4",
            ),
            VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON,
        )

    def test_prefix_ambiguity_is_explicitly_unsupported(self) -> None:
        self.assertEqual(
            match_version_constraint(
                self.criteria,
                version("1.2"),
                version_end_including="1.2.0",
            ),
            VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON,
        )

    def test_concrete_or_na_criteria_with_range_is_unsupported(self) -> None:
        for criteria in (version("1.0"), version("-")):
            with self.subTest(criteria=criteria.raw):
                self.assertEqual(
                    match_version_constraint(
                        criteria,
                        version("1.0"),
                        version_end_including="2.0",
                    ),
                    VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON,
                )

    def test_logical_component_version_cannot_be_range_ordered(self) -> None:
        for component in (version("*"), version("-")):
            with self.subTest(component=component.raw):
                self.assertEqual(
                    match_version_constraint(
                        self.criteria,
                        component,
                        version_end_including="2.0",
                    ),
                    VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON,
                )


class InvalidRangeVersionMatcherTests(SimpleTestCase):
    criteria = version("*")
    component = version("1.0")

    def test_empty_endpoint_is_invalid(self) -> None:
        for field in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    match_version_constraint(
                        self.criteria,
                        self.component,
                        **{field: ""},
                    ),
                    VersionMatchResult.INVALID_NVD_RANGE,
                )

    def test_both_start_forms_are_invalid(self) -> None:
        self.assertEqual(
            match_version_constraint(
                self.criteria,
                self.component,
                version_start_including="1.0",
                version_start_excluding="1.0",
            ),
            VersionMatchResult.INVALID_NVD_RANGE,
        )

    def test_both_end_forms_are_invalid(self) -> None:
        self.assertEqual(
            match_version_constraint(
                self.criteria,
                self.component,
                version_end_including="2.0",
                version_end_excluding="2.0",
            ),
            VersionMatchResult.INVALID_NVD_RANGE,
        )

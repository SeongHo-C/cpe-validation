from django.test import SimpleTestCase

from cpe.matching import (
    AttributeRelation,
    CPEAttributeMatchStatus,
    compare_cpe_attribute_values,
    match_cpe_attributes,
)
from cpe.version_matching import (
    VersionMatchResult,
    match_version_constraint,
)
from cpe.cpe23_canonical import parse_cpe23


ATTRIBUTES = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


def cpe(**overrides: str) -> str:
    values = {
        "part": "a",
        "vendor": "example",
        "product": "widget",
        "version": "1.0",
        "update": "*",
        "edition": "*",
        "language": "*",
        "sw_edition": "*",
        "target_sw": "*",
        "target_hw": "*",
        "other": "*",
    }
    values.update(overrides)
    return "cpe:2.3:" + ":".join(values[name] for name in ATTRIBUTES)


def parsed_name(raw: str):
    parsed = parse_cpe23(raw)
    assert parsed.is_valid and parsed.name is not None
    return parsed.name


class CPEAttributeMatcherTests(SimpleTestCase):
    def assert_match(self, criteria: str, component: str, **kwargs) -> None:
        result = match_cpe_attributes(criteria, component, **kwargs)
        self.assertEqual(result.status, CPEAttributeMatchStatus.MATCH)
        self.assertTrue(result.matched)

    def assert_no_match(
        self,
        criteria: str,
        component: str,
        **kwargs,
    ) -> None:
        result = match_cpe_attributes(criteria, component, **kwargs)
        self.assertEqual(result.status, CPEAttributeMatchStatus.NO_MATCH)
        self.assertFalse(result.matched)

    def test_any_source_matches_concrete_target(self) -> None:
        self.assert_match(cpe(version="*"), cpe(version="1.2.3"))

    def test_same_concrete_matches(self) -> None:
        self.assert_match(cpe(), cpe())

    def test_different_concrete_rejects(self) -> None:
        self.assert_no_match(cpe(version="1.0"), cpe(version="2.0"))

    def test_na_and_concrete_are_disjoint(self) -> None:
        self.assert_no_match(cpe(version="-"), cpe(version="1.0"))
        self.assert_no_match(cpe(version="1.0"), cpe(version="-"))

    def test_na_matches_na(self) -> None:
        self.assert_match(cpe(version="-"), cpe(version="-"))

    def test_core_identity_mismatches_reject(self) -> None:
        for attribute, value in (
            ("part", "o"),
            ("vendor", "other_vendor"),
            ("product", "other_product"),
        ):
            with self.subTest(attribute=attribute):
                self.assert_no_match(cpe(), cpe(**{attribute: value}))

    def test_additional_attribute_mismatches_reject(self) -> None:
        for attribute in (
            "update",
            "edition",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other",
        ):
            with self.subTest(attribute=attribute):
                self.assert_no_match(
                    cpe(**{attribute: "constraint"}),
                    cpe(**{attribute: "different"}),
                )

    def test_all_non_version_attributes_match_when_version_is_ignored(self) -> None:
        criteria = cpe(
            version="*",
            update="u1",
            edition="enterprise",
            language="en-us",
            sw_edition="server",
            target_sw="linux",
            target_hw="x86-64",
            other="special",
        )
        component = cpe(
            version="9.9",
            update="u1",
            edition="enterprise",
            language="en-us",
            sw_edition="server",
            target_sw="linux",
            target_hw="x86-64",
            other="special",
        )

        result = match_cpe_attributes(
            criteria,
            component,
            ignore_version=True,
        )

        self.assertTrue(result.matched)
        self.assertEqual(result.ignored_attributes, ("version",))
        self.assertEqual(len(result.comparisons), 10)

    def test_version_is_not_ignored_by_default(self) -> None:
        self.assert_no_match(cpe(version="1.0"), cpe(version="2.0"))
        self.assert_match(
            cpe(version="1.0"),
            cpe(version="2.0"),
            ignore_version=True,
        )

    def test_escaped_formatted_values_use_canonical_logical_value(self) -> None:
        self.assert_match(
            cpe(product=r"widget\.server"),
            cpe(product="widget.server"),
        )

    def test_escaped_wildcard_is_a_literal(self) -> None:
        self.assert_match(
            cpe(product=r"widget\*server"),
            cpe(product=r"widget\*server"),
        )
        self.assert_no_match(
            cpe(product=r"widget\*server"),
            cpe(product="widget-server"),
        )

    def test_source_endpoint_wildcards_are_directional_patterns(self) -> None:
        prefix = match_cpe_attributes(
            cpe(product="widget*"),
            cpe(product="widget_server"),
        )
        question = match_cpe_attributes(
            cpe(product="?idget"),
            cpe(product="widget"),
        )

        self.assertTrue(prefix.matched)
        self.assertTrue(question.matched)
        self.assertEqual(
            next(
                item.relation
                for item in prefix.comparisons
                if item.attribute == "product"
            ),
            AttributeRelation.SUPERSET,
        )

    def test_target_unquoted_wildcard_is_undefined(self) -> None:
        result = match_cpe_attributes(
            cpe(product="widget_server"),
            cpe(product="widget*"),
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            next(
                item.relation
                for item in result.comparisons
                if item.attribute == "product"
            ),
            AttributeRelation.UNDEFINED,
        )

    def test_non_version_wfn_literals_are_case_insensitive(self) -> None:
        self.assert_match(cpe(vendor="Example"), cpe(vendor="example"))

    def test_version_literal_is_case_insensitive_for_nist_wfn_matching(
        self,
    ) -> None:
        self.assert_match(cpe(version="R1"), cpe(version="r1"))

    def test_invalid_inputs_are_distinct(self) -> None:
        bad_criteria = match_cpe_attributes("not-a-cpe", cpe())
        bad_component = match_cpe_attributes(cpe(), "not-a-cpe")

        self.assertEqual(
            bad_criteria.status,
            CPEAttributeMatchStatus.INVALID_CRITERIA_CPE,
        )
        self.assertEqual(
            bad_component.status,
            CPEAttributeMatchStatus.INVALID_COMPONENT_CPE,
        )


class NISTCPE23NameMatchingConformanceTests(SimpleTestCase):
    """Official NISTIR 7696 and explicitly marked derived fixtures."""

    def attribute(self, value: str, name: str = "product"):
        return parsed_name(cpe(**{name: value})).attribute(name)

    def relation(
        self,
        source: str,
        target: str,
        *,
        name: str = "product",
    ) -> AttributeRelation:
        return compare_cpe_attribute_values(
            self.attribute(source, name),
            self.attribute(target, name),
        )

    def comparison_relation(self, result, attribute: str) -> AttributeRelation:
        return next(
            comparison.relation
            for comparison in result.comparisons
            if comparison.attribute == attribute
        )

    def test_nistir_7696_table_6_2_attribute_relation_matrix(self) -> None:
        # NISTIR 7696, section 6.1, p. 12, Table 6-2 (all 17 rows).
        cases = (
            ("01", "*", "*", AttributeRelation.EQUAL),
            ("02", "*", "-", AttributeRelation.SUPERSET),
            ("03", "*", "foo", AttributeRelation.SUPERSET),
            ("04", "*", "foo*", AttributeRelation.UNDEFINED),
            ("05", "-", "*", AttributeRelation.SUBSET),
            ("06", "-", "-", AttributeRelation.EQUAL),
            ("07", "-", "foo", AttributeRelation.DISJOINT),
            ("08", "-", "foo*", AttributeRelation.UNDEFINED),
            ("09", "foo", "foo", AttributeRelation.EQUAL),
            ("10", "foo", "bar", AttributeRelation.DISJOINT),
            ("11", "foo", "foo*", AttributeRelation.UNDEFINED),
            ("12", "foo", "-", AttributeRelation.DISJOINT),
            ("13", "foo", "*", AttributeRelation.SUBSET),
            ("14-positive", "9.*", "9.3", AttributeRelation.SUPERSET),
            ("14-negative", "9.*", "8.3", AttributeRelation.DISJOINT),
            ("15", "9.*", "*", AttributeRelation.SUBSET),
            ("16", "9.*", "-", AttributeRelation.DISJOINT),
            ("17", "9.*", "9.?", AttributeRelation.UNDEFINED),
        )
        for row, source, target, expected in cases:
            with self.subTest(row=row, source=source, target=target):
                self.assertEqual(self.relation(source, target), expected)

    def test_nistir_7696_literal_comparison_is_case_insensitive(self) -> None:
        # NISTIR 7696, section 6.1, p. 12 and section 7.3, p. 17.
        for name in ATTRIBUTES:
            if name == "part":
                continue
            with self.subTest(attribute=name):
                self.assertEqual(
                    self.relation("ReleaseA", "releasea", name=name),
                    AttributeRelation.EQUAL,
                )

    def test_nistir_7696_question_mark_matches_zero_or_one_character(
        self,
    ) -> None:
        # NISTIR 7696, section 6.3, p. 13: '?' means zero or one.
        for source, target in (
            ("?foo", "foo"),
            ("?foo", "xfoo"),
            ("foo?", "foo"),
            ("foo?", "foox"),
        ):
            with self.subTest(source=source, target=target):
                self.assertEqual(
                    self.relation(source, target),
                    AttributeRelation.SUPERSET,
                )
        for source, target in (("?foo", "xxfoo"), ("foo?", "fooxx")):
            with self.subTest(source=source, target=target):
                self.assertEqual(
                    self.relation(source, target),
                    AttributeRelation.DISJOINT,
                )

    def test_nistir_7696_wildcard_technical_constraints(self) -> None:
        # NISTIR 7696, section 5.2, pp. 9-10: quoted examples.
        for legal in ("?foo*", "*bar??", "?baz?", "*baz*"):
            with self.subTest(legal=legal):
                self.assertTrue(parse_cpe23(cpe(product=legal)).is_valid)
        for illegal in ("foo*bar", "bar??baz", "*?foobar", "foobar*?"):
            with self.subTest(illegal=illegal):
                self.assertFalse(parse_cpe23(cpe(product=illegal)).is_valid)

    def test_nistir_7696_escaped_special_characters_are_literals(self) -> None:
        # NISTIR 7696, sections 5.1 and 7.3; escaped wildcards are literal.
        cases = (
            (r"widget\.server", "widget.server"),
            (r"widget\-server", "widget-server"),
            (r"widget\_server", "widget_server"),
            (r"widget\*server", r"widget\*server"),
            (r"widget\?server", r"widget\?server"),
            (r"widget\\server", r"widget\\server"),
        )
        for source, target in cases:
            with self.subTest(source=source, target=target):
                self.assertEqual(
                    self.relation(source, target),
                    AttributeRelation.EQUAL,
                )

    def test_nistir_7696_target_wildcard_is_undefined(self) -> None:
        # NISTIR 7696, Table 6-2 rows 4, 8, 11, 17.
        for source in ("*", "-", "foo", "foo*"):
            with self.subTest(source=source):
                self.assertEqual(
                    self.relation(source, "bar*"),
                    AttributeRelation.UNDEFINED,
                )

    def test_nistir_7696_internet_explorer_full_wfn_example(self) -> None:
        # NISTIR 7696, section 1, p. 1: source is a target superset.
        source = (
            "cpe:2.3:a:microsoft:internet_explorer:8.*:*:*:*:*:*:*:*"
        )
        target = (
            "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:-:-:"
            "en-us:*:*:*:*"
        )
        result = match_cpe_attributes(source, target)

        self.assertEqual(result.status, CPEAttributeMatchStatus.MATCH)
        self.assertEqual(
            self.comparison_relation(result, "version"),
            AttributeRelation.SUPERSET,
        )
        for attribute in ("update", "edition", "language"):
            self.assertEqual(
                self.comparison_relation(result, attribute),
                AttributeRelation.SUPERSET,
            )

    def test_nistir_7696_table_6_3_multi_attribute_example(self) -> None:
        # NISTIR 7696, section 6.1, p. 13, Table 6-3.
        source = "cpe:2.3:a:Adobe:*:9.*:*:PalmOS:*:*:*:*:*"
        target = "cpe:2.3:a:*:Reader:9.3.2:-:-:*:*:*:*:*"
        result = match_cpe_attributes(source, target)
        expected = {
            "part": AttributeRelation.EQUAL,
            "vendor": AttributeRelation.SUBSET,
            "product": AttributeRelation.SUPERSET,
            "version": AttributeRelation.SUPERSET,
            "update": AttributeRelation.SUPERSET,
            "edition": AttributeRelation.DISJOINT,
        }

        self.assertEqual(result.status, CPEAttributeMatchStatus.NO_MATCH)
        for attribute, relation in expected.items():
            with self.subTest(attribute=attribute):
                self.assertEqual(
                    self.comparison_relation(result, attribute),
                    relation,
                )

    def test_nistir_7696_appendix_b_superset_example(self) -> None:
        # NISTIR 7696, Appendix B, p. 22: unspecified values default ANY.
        source = "cpe:2.3:o:microsoft:windows_2000:*:*:*:*:*:*:*:*"
        target = (
            "cpe:2.3:o:microsoft:windows_2000:*:sp3:pro:*:*:*:*:*"
        )
        self.assertTrue(match_cpe_attributes(source, target).matched)

    def test_nistir_7696_source_target_direction_is_not_symmetric(self) -> None:
        # NISTIR 7696, Table 6-2 rows 3 and 13; Appendix B.
        broad = cpe(product="*")
        concrete = cpe(product="reader")
        forward = match_cpe_attributes(broad, concrete)
        reverse = match_cpe_attributes(concrete, broad)

        self.assertTrue(forward.matched)
        self.assertEqual(
            self.comparison_relation(forward, "product"),
            AttributeRelation.SUPERSET,
        )
        self.assertFalse(reverse.matched)
        self.assertEqual(
            self.comparison_relation(reverse, "product"),
            AttributeRelation.SUBSET,
        )

    def test_nistir_7696_cpe_superset_aggregation(self) -> None:
        # NISTIR 7696, section 7.2, p. 16: EQUAL/SUPERSET only.
        cases = (
            (cpe(), cpe(), True, AttributeRelation.EQUAL),
            (
                cpe(product="*"),
                cpe(product="reader"),
                True,
                AttributeRelation.SUPERSET,
            ),
            (
                cpe(product="reader"),
                cpe(product="*"),
                False,
                AttributeRelation.SUBSET,
            ),
            (
                cpe(product="reader"),
                cpe(product="writer"),
                False,
                AttributeRelation.DISJOINT,
            ),
            (
                cpe(product="reader"),
                cpe(product="read*"),
                False,
                AttributeRelation.UNDEFINED,
            ),
        )
        for source, target, expected_match, expected_relation in cases:
            with self.subTest(
                expected_match=expected_match,
                expected_relation=expected_relation,
            ):
                result = match_cpe_attributes(source, target)
                self.assertEqual(result.matched, expected_match)
                self.assertEqual(
                    self.comparison_relation(result, "product"),
                    expected_relation,
                )

    def test_project_specific_exact_full_wfn_uses_all_11_attributes(
        self,
    ) -> None:
        # PROJECT_SPECIFIC_TEST derived from Table 6-2 row 9 and section 7.2.
        exact = cpe(
            vendor="Example",
            product="Widget",
            version="R1",
            update="UpdateA",
            edition="Professional",
            language="en-us",
            sw_edition="Server",
            target_sw="Linux",
            target_hw="x86-64",
            other="Special",
        )
        result = match_cpe_attributes(exact, exact)

        self.assertTrue(result.matched)
        self.assertEqual(len(result.comparisons), 11)
        self.assertTrue(
            all(
                comparison.relation is AttributeRelation.EQUAL
                for comparison in result.comparisons
            )
        )

    def test_project_specific_full_wfn_mismatches_are_disjoint(
        self,
    ) -> None:
        # PROJECT_SPECIFIC_TEST: inputs derived from Table 6-2 rows 7/10/12.
        source_values = {
            "part": "a",
            "vendor": "example",
            "product": "widget",
            "version": "1.0",
            "update": "u1",
            "edition": "standard",
            "language": "en-us",
            "sw_edition": "client",
            "target_sw": "linux",
            "target_hw": "x86-64",
            "other": "base",
        }
        source = cpe(**source_values)
        cases = (
            ("part", "o"),
            ("vendor", "other_vendor"),
            ("product", "other_product"),
            ("version", "2.0"),
            ("update", "u2"),
            ("edition", "professional"),
            ("language", "fr-fr"),
            ("sw_edition", "server"),
            ("target_sw", "windows"),
            ("target_hw", "arm64"),
            ("other", "special"),
        )
        for attribute, target_value in cases:
            with self.subTest(attribute=attribute):
                target_overrides = dict(source_values)
                target_overrides[attribute] = target_value
                target = cpe(**target_overrides)
                result = match_cpe_attributes(source, target)
                self.assertFalse(result.matched)
                self.assertEqual(
                    self.comparison_relation(result, attribute),
                    AttributeRelation.DISJOINT,
                )

        na_source = cpe(update="-")
        concrete_target = cpe(update="u1")
        na_result = match_cpe_attributes(na_source, concrete_target)
        self.assertFalse(na_result.matched)
        self.assertEqual(
            self.comparison_relation(na_result, "update"),
            AttributeRelation.DISJOINT,
        )

    def test_project_specific_range_architecture_ignores_only_version(
        self,
    ) -> None:
        # PROJECT_SPECIFIC_TEST: version ranges are outside NISTIR 7696.
        source = cpe(version="*", target_sw="linux")
        target = cpe(version="R1", target_sw="linux")
        mismatch = cpe(version="R1", target_sw="windows")

        result = match_cpe_attributes(source, target, ignore_version=True)
        self.assertTrue(result.matched)
        self.assertEqual(result.ignored_attributes, ("version",))
        self.assertEqual(len(result.comparisons), 10)
        self.assertFalse(
            match_cpe_attributes(
                source,
                mismatch,
                ignore_version=True,
            ).matched
        )


class SyntheticMatcherIntegrationTests(SimpleTestCase):
    """Mechanics-only fixtures; they make no vulnerability assertion."""

    def test_openssl_shape_matches_attributes_and_numeric_range(self) -> None:
        criteria = parsed_name(
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
        )
        component = parsed_name(
            "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
        )

        attributes = match_cpe_attributes(
            criteria,
            component,
            ignore_version=True,
        )
        version = match_version_constraint(
            criteria.attribute("version"),
            component.attribute("version"),
            version_start_including="1.0.0",
            version_end_excluding="2.0.0",
        )

        self.assertTrue(attributes.matched)
        self.assertEqual(version, VersionMatchResult.MATCH)

    def test_wrong_vendor_and_target_sw_are_rejected(self) -> None:
        criteria = cpe(
            vendor="openssl",
            product="openssl",
            version="*",
            target_sw="linux",
        )
        for component in (
            cpe(
                vendor="other",
                product="openssl",
                version="1.1.1",
                target_sw="linux",
            ),
            cpe(
                vendor="openssl",
                product="openssl",
                version="1.1.1",
                target_sw="windows",
            ),
        ):
            with self.subTest(component=component):
                self.assertFalse(
                    match_cpe_attributes(
                        criteria,
                        component,
                        ignore_version=True,
                    ).matched
                )

    def test_range_outside_and_special_ordering_are_distinct(self) -> None:
        criteria = parsed_name(cpe(version="*"))
        outside = parsed_name(cpe(version="2.0"))
        special = parsed_name(cpe(version="1.0p3"))

        self.assertEqual(
            match_version_constraint(
                criteria.attribute("version"),
                outside.attribute("version"),
                version_start_including="1.0",
                version_end_excluding="2.0",
            ),
            VersionMatchResult.NO_MATCH,
        )
        self.assertEqual(
            match_version_constraint(
                criteria.attribute("version"),
                special.attribute("version"),
                version_start_including="1.0",
                version_end_excluding="2.0",
            ),
            VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON,
        )

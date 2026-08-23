from django.test import SimpleTestCase

from cpe.cpe23_canonical import (
    CPE23CanonicalStatus,
    CPE23CanonicalizationError,
    CPE23ValueKind,
    canonicalize_cpe23,
    compare_cpe23,
    compare_cpe23_attributes,
    parse_cpe23,
    serialize_cpe23,
)


class CanonicalCPE23ParserTests(SimpleTestCase):
    def test_normal_cpe_has_all_eleven_attributes(self) -> None:
        raw = "cpe:2.3:a:haxx:curl:8.0.0:*:*:*:*:*:*:*"

        result = parse_cpe23(raw)

        self.assertTrue(result.is_valid)
        self.assertIsNotNone(result.name)
        assert result.name is not None
        self.assertEqual(len(result.name.attributes), 11)
        self.assertEqual(result.name.family, ("a", "haxx", "curl"))
        self.assertEqual(serialize_cpe23(result.name), raw)

    def test_any_na_and_empty_are_distinct(self) -> None:
        result = parse_cpe23(
            "cpe:2.3:o:example:system:*:-:*:*:*:*:*:*"
        )

        self.assertTrue(result.is_valid)
        assert result.name is not None
        self.assertEqual(
            result.name.attribute("version").kind,
            CPE23ValueKind.ANY,
        )
        self.assertEqual(
            result.name.attribute("update").kind,
            CPE23ValueKind.NA,
        )

        empty = parse_cpe23(
            "cpe:2.3:o:example:system::-:*:*:*:*:*:*"
        )
        self.assertEqual(
            empty.status,
            CPE23CanonicalStatus.INVALID_EMPTY_ATTRIBUTE,
        )

    def test_escaped_values_round_trip(self) -> None:
        raw = (
            r"cpe:2.3:a:example:product\:server:"
            r"1\.0\\build\!1:*:*:*:*:*:*:*"
        )

        canonical = canonicalize_cpe23(raw)
        reparsed = parse_cpe23(canonical)

        self.assertEqual(
            canonical,
            r"cpe:2.3:a:example:product\:server:"
            r"1.0\\build\!1:*:*:*:*:*:*:*",
        )
        self.assertTrue(reparsed.is_valid)
        self.assertEqual(serialize_cpe23(reparsed.name), canonical)
        self.assertTrue(compare_cpe23(raw, canonical))

    def test_percent_encoded_uri_form_is_not_formatted_string(self) -> None:
        encoded = parse_cpe23(
            "cpe:2.3:a:example:product%20name:1.0:*:*:*:*:*:*:*"
        )
        escaped_literal = parse_cpe23(
            r"cpe:2.3:a:example:product\%20name:1.0:*:*:*:*:*:*:*"
        )

        self.assertEqual(
            encoded.status,
            CPE23CanonicalStatus.INVALID_ATTRIBUTE,
        )
        self.assertTrue(escaped_literal.is_valid)

    def test_attribute_comparison_is_canonical_and_ordered(self) -> None:
        left = (
            r"cpe:2.3:a:example:product:1\.0:-:*:*:*:*:*:*"
        )
        equivalent = (
            "cpe:2.3:a:example:product:1.0:-:*:*:*:*:*:*"
        )
        different = (
            "cpe:2.3:a:example:product:2.0:*:*:*:*:*:*:*"
        )

        self.assertTrue(compare_cpe23(left, equivalent))
        self.assertEqual(compare_cpe23_attributes(left, equivalent), ())
        self.assertEqual(
            compare_cpe23_attributes(left, different),
            ("version", "update"),
        )

    def test_invalid_value_is_not_silently_comparable(self) -> None:
        with self.assertRaises(CPE23CanonicalizationError):
            compare_cpe23(
                "cpe:2.3:a:example:product:: *:*:*:*:*:*:*",
                "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
            )


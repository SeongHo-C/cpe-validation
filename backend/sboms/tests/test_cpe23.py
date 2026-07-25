from django.test import SimpleTestCase

from sboms.cpe23 import (
    CPE23StructuralStatus,
    parse_cpe23_formatted_string,
)


class CPE23ParserTests(SimpleTestCase):
    def test_structurally_valid_cpe(self) -> None:
        result = parse_cpe23_formatted_string(
            "cpe:2.3:a:haxx:curl:8.0.0:*:*:*:*:*:*:*"
        )

        self.assertEqual(
            result.status,
            CPE23StructuralStatus.STRUCTURALLY_VALID,
        )
        self.assertEqual(result.part_raw, "a")
        self.assertEqual(result.vendor_raw, "haxx")
        self.assertEqual(result.product_raw, "curl")
        self.assertEqual(result.version_raw, "8.0.0")

    def test_wildcard_and_na_are_preserved(self) -> None:
        result = parse_cpe23_formatted_string(
            "cpe:2.3:o:example:system:*:-:*:*:*:*:*:*"
        )

        self.assertEqual(
            result.status,
            CPE23StructuralStatus.STRUCTURALLY_VALID,
        )
        self.assertEqual(result.version_raw, "*")
        self.assertEqual(result.update_raw, "-")

    def test_escaped_colon_remains_in_one_field(self) -> None:
        result = parse_cpe23_formatted_string(
            r"cpe:2.3:a:example:product\:server:1.0:*:*:*:*:*:*:*"
        )

        self.assertEqual(
            result.status,
            CPE23StructuralStatus.STRUCTURALLY_VALID,
        )
        self.assertEqual(result.product_raw, r"product\:server")

    def test_escaped_backslash_is_preserved(self) -> None:
        result = parse_cpe23_formatted_string(
            r"cpe:2.3:a:example:product\\server:1.0:*:*:*:*:*:*:*"
        )

        self.assertEqual(
            result.status,
            CPE23StructuralStatus.STRUCTURALLY_VALID,
        )
        self.assertEqual(result.product_raw, r"product\\server")

    def test_invalid_prefix(self) -> None:
        for raw_cpe in (
            "cpe:2.2:a:example:product:1.0:*:*:*:*:*:*:*",
            "example:2.3:a:example:product:1.0:*:*:*:*:*:*:*",
        ):
            with self.subTest(raw_cpe=raw_cpe):
                result = parse_cpe23_formatted_string(raw_cpe)
                self.assertEqual(
                    result.status,
                    CPE23StructuralStatus.INVALID_PREFIX,
                )

    def test_missing_field(self) -> None:
        result = parse_cpe23_formatted_string(
            "cpe:2.3:a:example:product:1.0:*:*"
        )

        self.assertEqual(
            result.status,
            CPE23StructuralStatus.INVALID_FIELD_COUNT,
        )

    def test_extra_field(self) -> None:
        result = parse_cpe23_formatted_string(
            "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*:extra"
        )

        self.assertEqual(
            result.status,
            CPE23StructuralStatus.INVALID_FIELD_COUNT,
        )

    def test_trailing_backslash(self) -> None:
        result = parse_cpe23_formatted_string(
            "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*\\"
        )

        self.assertEqual(
            result.status,
            CPE23StructuralStatus.INVALID_ESCAPE,
        )

    def test_invalid_part(self) -> None:
        result = parse_cpe23_formatted_string(
            "cpe:2.3:x:example:product:1.0:*:*:*:*:*:*:*"
        )

        self.assertEqual(
            result.status,
            CPE23StructuralStatus.INVALID_PART,
        )

    def test_raw_cpe_is_preserved_exactly(self) -> None:
        raw_cpe = (
            r"cpe:2.3:a:Example:Product\:Server:*:-:*:*:*:*:*:*"
        )

        result = parse_cpe23_formatted_string(raw_cpe)

        self.assertEqual(result.raw_cpe, raw_cpe)

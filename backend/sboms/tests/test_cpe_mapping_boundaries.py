from django.test import SimpleTestCase

from cpe.cpe23_canonical import CPE23ValueKind
from cpe.mapping_boundaries import (
    CPEReferenceRecord,
    ConfigurationGateStatus,
    DeprecatedFamilyStatus,
    DeprecatedResolutionStatus,
    StableTemplateStatus,
    configuration_only_gate,
    resolve_deprecated_cpe,
    resolve_deprecated_family_alias,
    resolve_stable_template,
)


def cpe(
    product: str,
    version: str,
    *,
    vendor: str = "example",
    update: str = "*",
    target_sw: str = "*",
) -> str:
    return (
        f"cpe:2.3:a:{vendor}:{product}:{version}:{update}:*:*:*:"
        f"{target_sw}:*:*"
    )


class StableTemplateTests(SimpleTestCase):
    def test_unique_template_generates_normalized_version(self) -> None:
        result = resolve_stable_template(
            [cpe("product", "1.0"), cpe("product", "1.1")],
            family=("a", "example", "product"),
            normalized_version="1.2",
        )

        self.assertEqual(
            result.status,
            StableTemplateStatus.UNIQUE_STABLE_TEMPLATE,
        )
        self.assertEqual(result.generated_cpe, cpe("product", "1.2"))
        self.assertFalse(result.review_required)

    def test_multiple_compatible_templates_block_generation(self) -> None:
        result = resolve_stable_template(
            [
                cpe("product", "1.0", target_sw="linux"),
                cpe("product", "1.0", target_sw="windows"),
            ],
            family=("a", "example", "product"),
            normalized_version="1.1",
        )

        self.assertEqual(
            result.status,
            StableTemplateStatus.MULTIPLE_COMPATIBLE_TEMPLATES,
        )
        self.assertIsNone(result.selected_template)
        self.assertIsNone(result.generated_cpe)
        self.assertTrue(result.review_required)

    def test_no_compatible_template_blocks_generation(self) -> None:
        result = resolve_stable_template(
            [cpe("other", "1.0")],
            family=("a", "example", "product"),
            normalized_version="1.1",
        )

        self.assertEqual(
            result.status,
            StableTemplateStatus.NO_STABLE_TEMPLATE,
        )
        self.assertTrue(result.review_required)

    def test_strongswan_like_final_release_preserves_na_update(self) -> None:
        result = resolve_stable_template(
            [
                cpe("strongswan", "5.9.11", vendor="strongswan", update="-"),
                cpe("strongswan", "5.9.12", vendor="strongswan", update="-"),
                cpe(
                    "strongswan",
                    "5.9.13",
                    vendor="strongswan",
                    update="rc1",
                ),
            ],
            family=("a", "strongswan", "strongswan"),
            normalized_version="5.9.14",
            compatibility=lambda name: (
                name.attribute("update").kind is CPE23ValueKind.NA
            ),
        )

        self.assertEqual(
            result.status,
            StableTemplateStatus.UNIQUE_STABLE_TEMPLATE,
        )
        self.assertEqual(
            result.generated_cpe,
            cpe("strongswan", "5.9.14", vendor="strongswan", update="-"),
        )


class DeprecatedResolverTests(SimpleTestCase):
    def test_one_to_one_reaches_active(self) -> None:
        records = {
            "a": CPEReferenceRecord("a", cpe("old", "1"), True, ("b",)),
            "b": CPEReferenceRecord("b", cpe("new", "1"), False),
        }

        result = resolve_deprecated_cpe(records, "a")

        self.assertEqual(
            result.resolution_status,
            DeprecatedResolutionStatus.RESOLVED_ACTIVE,
        )
        self.assertEqual(result.resolved_active_endpoint, cpe("new", "1"))
        self.assertEqual(result.replacement_depth, 1)

    def test_multi_hop_reaches_final_active(self) -> None:
        records = {
            "a": CPEReferenceRecord("a", cpe("old", "1"), True, ("b",)),
            "b": CPEReferenceRecord("b", cpe("middle", "1"), True, ("c",)),
            "c": CPEReferenceRecord("c", cpe("new", "1"), False),
        }

        result = resolve_deprecated_cpe(records, "a")

        self.assertEqual(
            result.resolution_status,
            DeprecatedResolutionStatus.RESOLVED_ACTIVE,
        )
        self.assertEqual(result.replacement_depth, 2)
        self.assertEqual(
            result.replacement_chains,
            ((cpe("old", "1"), cpe("middle", "1"), cpe("new", "1")),),
        )

    def test_multiple_replacements_are_never_first_edge_selected(self) -> None:
        records = {
            "a": CPEReferenceRecord(
                "a", cpe("old", "1"), True, ("b", "c")
            ),
            "b": CPEReferenceRecord("b", cpe("new", "1"), False),
            "c": CPEReferenceRecord("c", cpe("new", "2"), False),
        }

        ambiguous = resolve_deprecated_cpe(records, "a")
        compatible = resolve_deprecated_cpe(
            records,
            "a",
            compatibility=lambda name: (
                name.attribute("version").canonical == "2"
            ),
        )

        self.assertEqual(
            ambiguous.resolution_status,
            DeprecatedResolutionStatus.MULTIPLE_COMPATIBLE_ENDPOINTS,
        )
        self.assertIsNone(ambiguous.resolved_active_endpoint)
        self.assertTrue(ambiguous.review_required)
        self.assertEqual(
            compatible.resolution_status,
            DeprecatedResolutionStatus.RESOLVED_ACTIVE,
        )
        self.assertEqual(compatible.resolved_active_endpoint, cpe("new", "2"))

    def test_cycle_is_detected_even_with_an_active_sibling_branch(self) -> None:
        records = {
            "a": CPEReferenceRecord(
                "a", cpe("old", "1"), True, ("b", "c")
            ),
            "b": CPEReferenceRecord("b", cpe("middle", "1"), True, ("a",)),
            "c": CPEReferenceRecord("c", cpe("new", "1"), False),
        }

        result = resolve_deprecated_cpe(records, "a")

        self.assertEqual(
            result.resolution_status,
            DeprecatedResolutionStatus.CYCLE_DETECTED,
        )
        self.assertTrue(result.cycle_detected)
        self.assertIsNone(result.resolved_active_endpoint)

    def test_missing_reference_is_explicit(self) -> None:
        records = {
            "a": CPEReferenceRecord(
                "a", cpe("old", "1"), True, ("missing",)
            ),
        }

        result = resolve_deprecated_cpe(records, "a")

        self.assertEqual(
            result.resolution_status,
            DeprecatedResolutionStatus.MISSING_REFERENCE,
        )
        self.assertEqual(result.missing_references, ("missing",))

    def test_deprecated_dead_end_is_not_promoted(self) -> None:
        records = {
            "a": CPEReferenceRecord("a", cpe("old", "1"), True, ()),
        }

        result = resolve_deprecated_cpe(records, "a")

        self.assertEqual(
            result.resolution_status,
            DeprecatedResolutionStatus.DEPRECATED_DEAD_END,
        )
        self.assertIsNone(result.resolved_active_endpoint)

    def test_family_alias_requires_one_active_family(self) -> None:
        records = {
            "a": CPEReferenceRecord("a", cpe("old", "1"), True, ("b",)),
            "b": CPEReferenceRecord("b", cpe("new", "1"), False),
        }

        result = resolve_deprecated_family_alias(records, ["a"])

        self.assertEqual(
            result.status,
            DeprecatedFamilyStatus.RESOLVED_ACTIVE_FAMILY,
        )
        self.assertEqual(
            result.resolved_active_family,
            ("a", "example", "new"),
        )


class ConfigurationOnlyGateTests(SimpleTestCase):
    def test_active_product_blocks_configuration_lookup(self) -> None:
        result = configuration_only_gate(
            active_product_count=1,
            deprecated_product_count=0,
        )

        self.assertEqual(
            result.status,
            ConfigurationGateStatus.BLOCKED_ACTIVE_PRODUCT,
        )
        self.assertFalse(result.configuration_lookup_allowed)

    def test_deprecated_product_blocks_configuration_lookup(self) -> None:
        result = configuration_only_gate(
            active_product_count=0,
            deprecated_product_count=2,
        )

        self.assertEqual(
            result.status,
            ConfigurationGateStatus.BLOCKED_DEPRECATED_PRODUCT,
        )
        self.assertFalse(result.configuration_lookup_allowed)

    def test_lookup_is_allowed_only_when_dictionary_family_is_absent(self) -> None:
        result = configuration_only_gate(
            active_product_count=0,
            deprecated_product_count=0,
        )

        self.assertEqual(result.status, ConfigurationGateStatus.ALLOWED)
        self.assertTrue(result.configuration_lookup_allowed)


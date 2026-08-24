import csv

from django.conf import settings
from django.test import SimpleTestCase

from cpe.cpe23_canonical import canonicalize_cpe23, parse_cpe23
from sboms.unitronics_ground_truth_cpe_audit import (
    AUDIT_PRODUCT_SPECS,
    ExactEvidence,
    PassAResult,
    _build_expression,
    _current_comparison,
    _exact_evidence,
    audit_product_version,
)


class UnitronicsGroundTruthCpeAuditTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        root = settings.REPOSITORY_ROOT / "analysis/results"
        with (
            root
            / "unitronics-ground-truth-preanalysis/"
            "61602e128acb__52.07.13.7/components.csv"
        ).open(newline="", encoding="utf-8") as handle:
            cls.components = {
                row["name"]: row for row in csv.DictReader(handle)
            }

    def test_independent_registry_covers_exact_48_names(self) -> None:
        root = settings.REPOSITORY_ROOT / "analysis/results"
        with (
            root
            / "unitronics-ground-truth-candidate-build/"
            "61602e128acb__52.07.13.7/components.csv"
        ).open(newline="", encoding="utf-8") as handle:
            scope_names = {
                row["name"]
                for row in csv.DictReader(handle)
                if row["proposed_gt_cpe"]
            }
        self.assertEqual(len(scope_names), 48)
        self.assertEqual(scope_names, AUDIT_PRODUCT_SPECS.keys())

    def test_all_independent_expressions_are_canonical(self) -> None:
        for name, spec in AUDIT_PRODUCT_SPECS.items():
            with self.subTest(name=name):
                expression = _build_expression(spec)
                self.assertEqual(canonicalize_cpe23(expression), expression)

    def test_family_specific_non_version_attributes_are_preserved(self) -> None:
        expected_updates = {
            "libusb-1.0-0": "-",
            "open62541": "-",
            "strongswan": "-",
            "strongswan-charon": "-",
            "strongswan-swanctl": "-",
            "openwrt": "-",
            "lua": "*",
            "liblua5.1.5": "*",
            "libc": "*",
        }
        for name, update in expected_updates.items():
            with self.subTest(name=name):
                parsed = parse_cpe23(_build_expression(AUDIT_PRODUCT_SPECS[name]))
                self.assertIsNotNone(parsed.name)
                self.assertEqual(parsed.name.attribute("update").canonical, update)
        parsed = parse_cpe23(_build_expression(AUDIT_PRODUCT_SPECS["openvpn-openssl"]))
        self.assertIsNotNone(parsed.name)
        self.assertEqual(parsed.name.attribute("sw_edition").canonical, "community")

    def test_wpa_exact_devel_identifier_uses_approved_cpe_update(self) -> None:
        component = self.components["wpa_supplicant"]
        extracted = _exact_evidence("wpa_supplicant", component, None)
        self.assertEqual(extracted.observed_version, "2.11-devel")
        evidence = ExactEvidence(
            component_id=component["component_id"],
            name=component["name"],
            observed_version=component["version"],
            source="NON_OPKG_DIRECT_ARTIFACT",
            source_name=component["name"],
            description=component["matching_evidence"],
            representative_paths=component["properties_paths"],
            detected_identifiers=("wpa_supplicant v2.11-devel",),
            is_opkg=False,
        )
        result = audit_product_version(evidence)
        self.assertEqual(result.status, "PRODUCT_VERSION_CONFIRMED")
        self.assertEqual(result.product, "wpa_supplicant")
        self.assertEqual(result.version, "2.11-devel")
        self.assertEqual(result.cpe_version, "2.11")
        self.assertNotIn("original", result.product_evidence.lower())
        expression = _build_expression(AUDIT_PRODUCT_SPECS["wpa_supplicant"])
        self.assertEqual(
            expression,
            "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*",
        )

    def test_wpa_approved_candidate_is_accepted_as_version_not_registered(self) -> None:
        spec = AUDIT_PRODUCT_SPECS["wpa_supplicant"]
        pass_a = PassAResult(
            status="PRODUCT_VERSION_CONFIRMED",
            product=spec.product,
            vendor=spec.vendor,
            version=spec.version,
            cpe_version=spec.cpe_version,
            product_evidence="independent exact-firmware product evidence",
            version_evidence="exact identifier preserves -devel",
            strength=spec.strength,
            evidence_refs=spec.evidence_refs,
            family=spec.family,
            template=spec.template,
        )
        current = {
            "original_cpe": (
                "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*"
            ),
            "actual_product": "wpa_supplicant",
            "actual_product_version": "2.11-devel",
            "proposed_gt_cpe": (
                "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*"
            ),
            "proposed_decision": "VERSION_NOT_IN_DICTIONARY",
            "discrepancy_fields": '["UPDATE"]',
        }
        pass_b = {
            "gt_cpe": _build_expression(spec),
            "resolution_path": "VERSION_NOT_IN_DICTIONARY",
        }

        result = _current_comparison(current, pass_a, pass_b)

        self.assertEqual(result["final_audit_status"], "ACCEPTED")
        self.assertFalse(result["version_correction"])
        self.assertFalse(result["gt_cpe_correction"])
        self.assertFalse(result["validation_result_correction"])
        self.assertFalse(result["discrepancy_field_correction"])
        self.assertEqual(
            result["audited_validation_result"],
            "VERSION_NOT_IN_DICTIONARY",
        )
        self.assertEqual(result["audited_discrepancy_fields"], ["UPDATE"])

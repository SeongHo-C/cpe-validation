import csv
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase

from cpe.cpe23_canonical import canonicalize_cpe23
from sboms.unitronics_ground_truth_candidate_build import (
    APPROVED_DERIVED_SPLITS,
    APPROVED_PRODUCT_BOUNDARY_EXCLUSIONS,
    APPROVED_REPRESENTATIVES,
    DECISION_CODES,
    EXPECTED_FAMILY_TEMPLATES,
    apply_representative_component_policy,
    adjudicate_component,
    resolve_prerelease_update_expression,
    validate_product_boundary_approvals,
    validate_representative_approvals,
)


class UnitronicsGroundTruthCandidateAdjudicationTests(SimpleTestCase):
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
        with (
            root
            / "unitronics-source-package-analysis/"
            "61602e128acb__52.07.13.7/packages.csv"
        ).open(newline="", encoding="utf-8") as handle:
            cls.packages = {
                row["package"]: row for row in csv.DictReader(handle)
            }

    def judgment(self, name: str):
        return adjudicate_component(
            self.components[name],
            self.packages.get(name),
        )

    def test_previous_runtime_review_is_not_a_hard_gate(self) -> None:
        data_sender = self.judgment("data-sender")
        self.assertEqual(
            data_sender.classification,
            "PRODUCT_IDENTITY_CONFIRMED",
        )
        self.assertEqual(data_sender.product, "Data Sender")
        self.assertEqual(data_sender.version, "1.15-1")

    def test_structural_exclusions_do_not_inherit_parent_cpe(self) -> None:
        for name in (
            "kmod-crypto-aead",
            "strongswan-mod-openssl",
            "vuci-app-core-ui",
            "libext2fs2",
            "sed",
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    self.judgment(name).classification,
                    "DIRECT_SUBCOMPONENT_NO_PARENT_INHERITANCE",
                )

    def test_core_library_cli_and_public_products_are_adjudicated(self) -> None:
        expected = {
            "libopenssl3": ("OpenSSL", "3.0.14"),
            "libcurl4": ("libcurl", "8.11.0"),
            "busybox": ("BusyBox", "1.34.1"),
            "libsqlite3-0": ("SQLite", "3.41.2"),
            "linux_kernel": ("Linux kernel", "5.15.176"),
            "ppp": ("PPP/pppd", "2.4.9.git-2021-01-04"),
        }
        for name, result in expected.items():
            with self.subTest(name=name):
                judgment = self.judgment(name)
                self.assertEqual(
                    judgment.classification,
                    "PRODUCT_IDENTITY_CONFIRMED",
                )
                self.assertEqual(
                    (judgment.product, judgment.version),
                    result,
                )

    def test_approved_representative_registry_is_exact(self) -> None:
        self.assertEqual(
            set(APPROVED_DERIVED_SPLITS),
            {
                "ip6tables",
                "libcap-bin",
                "libipset13",
                "liblua5.1.5",
                "libsqlite3-0",
                "openssl-util",
                "strongswan-charon",
                "strongswan-swanctl",
            },
        )
        self.assertEqual(
            APPROVED_REPRESENTATIVES,
            {
                "iptables",
                "libcap",
                "ipset",
                "lua",
                "sqlite",
                "libopenssl3",
                "strongswan",
            },
        )

    def test_approved_audit_artifacts_match_registry(self) -> None:
        validate_representative_approvals(
            settings.REPOSITORY_ROOT / "analysis/results"
        )

    def test_approved_product_boundary_artifacts_match_registry(self) -> None:
        validate_product_boundary_approvals(
            settings.REPOSITORY_ROOT / "analysis/results"
        )

    def test_wireguard_tools_preserves_version_without_false_cpe_family(
        self,
    ) -> None:
        judgment = self.judgment("wireguard-tools")

        self.assertEqual(
            set(APPROVED_PRODUCT_BOUNDARY_EXCLUSIONS),
            {"wireguard-tools"},
        )
        self.assertEqual(judgment.classification, "PRODUCT_IDENTITY_CONFIRMED")
        self.assertEqual(judgment.product, "wireguard-tools")
        self.assertEqual(judgment.version, "1.0.20210223")
        self.assertIsNone(judgment.family)
        self.assertIn(
            "APPROVED_PRODUCT_BOUNDARY_EXCLUSION:a:wireguard:wireguard",
            judgment.family_basis,
        )

    def test_policy_removes_only_approved_split_cpe(self) -> None:
        parent_cpe = "cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*"
        rows = [
            {
                "component_id": "199888",
                "name": "libopenssl3",
                "proposed_gt_cpe": parent_cpe,
                "proposed_decision": "OFFICIAL_CPE_MAPPED",
                "cpe_resolution_path": "ACTIVE_EXACT",
                "decision_reason": "ACTIVE_EXACT",
                "discrepancy_fields": '["VENDOR"]',
            },
            {
                "component_id": "199958",
                "name": "openssl-util",
                "proposed_gt_cpe": parent_cpe,
                "proposed_decision": "OFFICIAL_CPE_MAPPED",
                "cpe_resolution_path": "ACTIVE_EXACT",
                "decision_reason": "ACTIVE_EXACT",
                "discrepancy_fields": '["VENDOR"]',
            },
        ]
        subset = {"openssl-util": APPROVED_DERIVED_SPLITS["openssl-util"]}
        with mock.patch(
            "sboms.unitronics_ground_truth_candidate_build.APPROVED_DERIVED_SPLITS",
            subset,
        ):
            apply_representative_component_policy(rows)

        representative, split = rows
        self.assertEqual(representative["proposed_gt_cpe"], parent_cpe)
        self.assertEqual(representative["proposed_decision"], "OFFICIAL_CPE_MAPPED")
        self.assertEqual(split["proposed_gt_cpe"], "")
        self.assertEqual(
            split["proposed_decision"],
            "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
        )
        self.assertEqual(split["discrepancy_fields"], "N/A")

    def test_unproved_product_version_boundary_remains_unresolved(self) -> None:
        for name in ("libmodbus", "shellinabox", "wpad-openssl"):
            with self.subTest(name=name):
                judgment = self.judgment(name)
                self.assertEqual(judgment.classification, "UNRESOLVED")
                self.assertEqual(judgment.strength, "WEAK")

    def test_wpa_development_version_is_preserved_and_split_for_cpe(self) -> None:
        judgment = self.judgment("wpa_supplicant")

        self.assertEqual(judgment.version, "2.11-devel")
        self.assertEqual(judgment.cpe_version, "2.11")
        self.assertEqual(judgment.cpe_update, "devel")
        self.assertEqual(judgment.prerelease_policy, "MOVE_TO_UPDATE")
        self.assertEqual(
            EXPECTED_FAMILY_TEMPLATES[(judgment.family, judgment.cpe_version)],
            "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*",
        )

    def test_prerelease_update_requires_family_support(self) -> None:
        family = ("a", "w1.fi", "wpa_supplicant")
        active_cpes = [
            "cpe:2.3:a:w1.fi:wpa_supplicant:0.6.10:pre1:*:*:*:*:*:*",
            "cpe:2.3:a:w1.fi:wpa_supplicant:0.6.10:pre4:*:*:*:*:*:*",
        ]

        expression, status = resolve_prerelease_update_expression(
            active_cpes,
            family=family,
            version="2.11",
            update="devel",
        )

        self.assertEqual(status, "UNIQUE_SUPPORTED_PRERELEASE_TEMPLATE")
        self.assertEqual(
            expression,
            "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*",
        )
        unsupported, unsupported_status = resolve_prerelease_update_expression(
            ["cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"],
            family=("a", "example", "product"),
            version="2.0",
            update="devel",
        )
        self.assertIsNone(unsupported)
        self.assertEqual(
            unsupported_status,
            "PRERELEASE_TEMPLATE_NOT_SUPPORTED",
        )

    def test_fixed_taxonomy_and_release_templates_are_canonical(self) -> None:
        self.assertEqual(
            DECISION_CODES,
            (
                "CPE_CONFIRMED",
                "OFFICIAL_CPE_MAPPED",
                "VERSION_NOT_IN_DICTIONARY",
                "NVD_CONFIGURATION_ONLY",
                "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
                "UNRESOLVED",
            ),
        )
        for cpe in EXPECTED_FAMILY_TEMPLATES.values():
            with self.subTest(cpe=cpe):
                self.assertEqual(canonicalize_cpe23(cpe), cpe)

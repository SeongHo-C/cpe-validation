import csv
from collections import Counter

from django.conf import settings
from django.test import SimpleTestCase

from cpe.cpe23_canonical import compare_cpe23
from cpe.mapping_boundaries import (
    StableTemplateStatus,
    configuration_only_gate,
    resolve_stable_template,
)


class UnitronicsMappingBoundaryRegressionTests(SimpleTestCase):
    def test_existing_eleven_decisions_are_unchanged(self) -> None:
        artifact = (
            settings.REPOSITORY_ROOT
            / "analysis/results/unitronics-cpe-mapping-decision-dry-run"
            / "61602e128acb__52.07.13.7/representative_cases.csv"
        )
        with artifact.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        evidence_templates = {
            ("a", "haxx", "libcurl"): (
                "cpe:2.3:a:haxx:libcurl:8.12.0:*:*:*:*:*:*:*"
            ),
            ("a", "netfilter", "iptables"): (
                "cpe:2.3:a:netfilter:iptables:1.8.3:*:*:*:*:*:*:*"
            ),
            ("a", "strongswan", "strongswan"): (
                "cpe:2.3:a:strongswan:strongswan:5.9.12:-:*:*:*:*:*:*"
            ),
            ("a", "e2fsprogs_project", "e2fsprogs"): (
                "cpe:2.3:a:e2fsprogs_project:e2fsprogs:1.46.5:*:*:*:*:*:*:*"
            ),
        }
        actual_decisions: list[str] = []
        for row in rows:
            branch = row["mapping_branch"]
            if branch == "ACTIVE_EXACT":
                actual = (
                    "CPE_CONFIRMED"
                    if compare_cpe23(row["original_cpe"], row["proposed_gt_cpe"])
                    else "OFFICIAL_CPE_MAPPED"
                )
            elif branch == "VERSION_NOT_IN_DICTIONARY":
                family = (
                    row["search_part"],
                    row["search_vendor"],
                    row["search_product"],
                )
                template = resolve_stable_template(
                    [evidence_templates[family]],
                    family=family,
                    normalized_version=row["normalized_product_version"],
                )
                self.assertEqual(
                    template.status,
                    StableTemplateStatus.UNIQUE_STABLE_TEMPLATE,
                )
                self.assertEqual(template.generated_cpe, row["proposed_gt_cpe"])
                actual = "VERSION_NOT_IN_DICTIONARY"
            elif branch == "NO_DIRECT_CPE":
                gate = configuration_only_gate(
                    active_product_count=int(row["active_product_family_count"]),
                    deprecated_product_count=int(
                        row["deprecated_product_family_count"]
                    ),
                )
                self.assertTrue(gate.configuration_lookup_allowed)
                self.assertEqual(row["configuration_only_match"], "false")
                actual = "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
            else:
                self.fail(f"Unexpected regression branch: {branch}")
            self.assertEqual(actual, row["proposed_decision"])
            actual_decisions.append(actual)

        self.assertEqual(len(rows), 11)
        self.assertEqual(
            Counter(actual_decisions),
            Counter(
                {
                    "CPE_CONFIRMED": 1,
                    "OFFICIAL_CPE_MAPPED": 3,
                    "VERSION_NOT_IN_DICTIONARY": 6,
                    "NVD_CONFIGURATION_ONLY": 0,
                    "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED": 1,
                    "UNRESOLVED": 0,
                }
            ),
        )

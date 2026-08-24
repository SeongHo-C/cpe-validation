import csv

from django.conf import settings
from django.test import SimpleTestCase

from sboms.unitronics_ground_truth_human_validation import (
    WPA_COMPONENT_ID,
    refresh_wpa_supplicant_card,
)


class UnitronicsGroundTruthHumanValidationTests(SimpleTestCase):
    def test_only_wpa_card_is_refreshed_with_approved_values(self) -> None:
        directory = (
            settings.REPOSITORY_ROOT
            / "analysis/results/unitronics-ground-truth-candidate-build/"
            "61602e128acb__52.07.13.7"
        )
        source = (directory / "unitronics_gt_human_validation.html").read_text(
            encoding="utf-8"
        )
        with (directory / "components.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            current = next(
                row
                for row in csv.DictReader(handle)
                if row["component_id"] == WPA_COMPONENT_ID
            )
        approved = {
            **current,
            "actual_product_version": "2.11-devel",
            "version_evidence": (
                "Exact firmware evidence identifies wpa_supplicant 2.11-devel; "
                "approved prerelease policy applies."
            ),
            "proposed_gt_cpe": (
                "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*"
            ),
            "proposed_decision": "VERSION_NOT_IN_DICTIONARY",
            "discrepancy_fields": '["UPDATE"]',
        }
        manifest = {
            "evidence_id": "LOCAL-11",
            "locator": (
                "cpe-prerelease-version-policy/"
                "wpa_supplicant-2.11-devel/summary.json"
            ),
            "sha256": "0" * 64,
        }

        rendered = refresh_wpa_supplicant_card(source, approved, manifest)

        token = f'data-component-id="{WPA_COMPONENT_ID}"'
        old_position = source.index(token)
        new_position = rendered.index(token)
        old_start = source.rfind('<details class="review-card', 0, old_position)
        new_start = rendered.rfind('<details class="review-card', 0, new_position)
        boundary = '<details class="result-group" id="group-unresolved"'
        self.assertEqual(source[:old_start], rendered[:new_start])
        self.assertEqual(
            source[source.index(boundary, old_position) :],
            rendered[rendered.index(boundary, new_position) :],
        )
        wpa_card = rendered[new_start : rendered.index(boundary, new_position)]
        self.assertIn("Actual Product Version</span><strong>2.11-devel", wpa_card)
        self.assertIn(
            "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*",
            wpa_card,
        )
        self.assertIn("Incorrect CPE Fields</span><strong>Update", wpa_card)
        self.assertIn(
            '<tr class="changed"><th>Update</th><td><code>*</code></td>'
            '<td><code>devel</code></td></tr>',
            wpa_card,
        )
        self.assertIn('data-evidence-ref="LOCAL-11"', wpa_card)

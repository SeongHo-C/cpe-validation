from __future__ import annotations

import csv
import html
import json
import re
from pathlib import Path

from cpe.cpe23 import CPE23_ATTRIBUTE_NAMES
from cpe.cpe23_canonical import parse_cpe23


WPA_COMPONENT_ID = "200198"
WPA_EXPECTED_VERSION = "2.11-devel"
WPA_EXPECTED_CPE = (
    "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*"
)
RESULT_LABELS = {
    "VERSION_NOT_IN_DICTIONARY": "Version Not Registered",
}
FIELD_LABELS = {
    "part": "Part",
    "vendor": "Vendor",
    "product": "Product",
    "version": "Version",
    "update": "Update",
    "edition": "Edition",
    "language": "Language",
    "sw_edition": "SW Edition",
    "target_sw": "Target SW",
    "target_hw": "Target HW",
    "other": "Other",
}


class UnitronicsHumanValidationError(Exception):
    pass


def _replace_once(value: str, pattern: str, replacement: str) -> str:
    result, count = re.subn(pattern, replacement, value, count=1, flags=re.DOTALL)
    if count != 1:
        raise UnitronicsHumanValidationError(
            f"Expected exactly one HTML match for pattern: {pattern}"
        )
    return result


def _canonical_names(row: dict[str, str]):
    original = parse_cpe23(row["original_cpe"])
    proposed = parse_cpe23(row["proposed_gt_cpe"])
    if original.name is None or proposed.name is None:
        raise UnitronicsHumanValidationError("wpa_supplicant CPE is not canonical")
    return original.name, proposed.name


def _comparison_rows(row: dict[str, str]) -> str:
    original, proposed = _canonical_names(row)
    rendered: list[str] = []
    for attribute in CPE23_ATTRIBUTE_NAMES:
        old = original.attribute(attribute).canonical
        new = proposed.attribute(attribute).canonical
        css_class = "same" if old == new else "changed"
        rendered.append(
            f'<tr class="{css_class}"><th>{FIELD_LABELS[attribute]}</th>'
            f"<td><code>{html.escape(old)}</code></td>"
            f"<td><code>{html.escape(new)}</code></td></tr>"
        )
    return "".join(rendered)


def _template_rows(row: dict[str, str]) -> str:
    _, proposed = _canonical_names(row)
    return "".join(
        f"<tr><th>{FIELD_LABELS[attribute]}</th>"
        f"<td><code>{html.escape(proposed.attribute(attribute).canonical)}</code></td></tr>"
        for attribute in CPE23_ATTRIBUTE_NAMES[4:]
    )


def _policy_evidence_item(manifest_row: dict[str, str]) -> str:
    location = manifest_row["locator"]
    return (
        f'<li data-evidence-ref="{html.escape(manifest_row["evidence_id"])}">'
        f'<strong>{html.escape(manifest_row["evidence_id"])}</strong> — '
        f'<a href="../../{html.escape(location)}">{html.escape(location)}</a>'
        f'<small>SHA-256 {html.escape(manifest_row["sha256"])}</small></li>'
    )


def refresh_wpa_supplicant_card(
    source_html: str,
    row: dict[str, str],
    policy_manifest_row: dict[str, str],
) -> str:
    if (
        row.get("component_id") != WPA_COMPONENT_ID
        or row.get("name") != "wpa_supplicant"
        or row.get("actual_product_version") != WPA_EXPECTED_VERSION
        or row.get("proposed_gt_cpe") != WPA_EXPECTED_CPE
        or row.get("proposed_decision") != "VERSION_NOT_IN_DICTIONARY"
        or json.loads(row.get("discrepancy_fields", "null")) != ["UPDATE"]
    ):
        raise UnitronicsHumanValidationError(
            "Candidate row does not contain the approved wpa_supplicant values"
        )
    if (
        policy_manifest_row.get("evidence_id") != "LOCAL-11"
        or "cpe-prerelease-version-policy" not in policy_manifest_row.get(
            "locator", ""
        )
    ):
        raise UnitronicsHumanValidationError(
            "Approved prerelease-policy manifest evidence is absent"
        )

    token_position = source_html.find(f'data-component-id="{WPA_COMPONENT_ID}"')
    if token_position < 0:
        raise UnitronicsHumanValidationError("wpa_supplicant review card is absent")
    card_start = source_html.rfind(
        '<details class="review-card', 0, token_position
    )
    group_boundary = (
        "\n        </div>\n      </details>\n            \n"
        '      <details class="result-group" id="group-unresolved"'
    )
    card_end = source_html.find(group_boundary, token_position)
    if card_start < 0 or card_end < 0:
        raise UnitronicsHumanValidationError(
            "Could not isolate the wpa_supplicant review card"
        )
    card = source_html[card_start:card_end]

    escaped_version = html.escape(row["actual_product_version"])
    escaped_gt = html.escape(row["proposed_gt_cpe"])
    escaped_reason = html.escape(row["version_evidence"])
    result_label = RESULT_LABELS[row["proposed_decision"]]
    search_value = " ".join(
        (
            row["name"],
            row["observed_version"],
            row["source"],
            row["source_name"],
            row["actual_product"],
            row["actual_vendor"],
            row["actual_product_version"],
            row["original_cpe"],
            row["proposed_gt_cpe"],
        )
    ).lower()

    card = _replace_once(
        card,
        r'(data-search=")[^"]*(")',
        rf"\g<1>{html.escape(search_value, quote=True)}\g<2>",
    )
    card = _replace_once(
        card,
        r'(<span>Actual Product Version</span><strong>)[^<]*(</strong>)',
        rf"\g<1>{escaped_version}\g<2>",
    )
    card = _replace_once(
        card,
        r'(<span class="field-label">Why this version\?</span>).*?(</p>)',
        rf"\g<1>{escaped_reason}\g<2>",
    )
    card = _replace_once(
        card,
        rf'(<code id="cpe-{WPA_COMPONENT_ID}-gt">)[^<]*(</code>)',
        rf"\g<1>{escaped_gt}\g<2>",
    )
    card = _replace_once(
        card,
        r'(<div class="cpe-block validation-result">.*?<strong>)[^<]*(</strong>)',
        rf"\g<1>{html.escape(result_label)}\g<2>",
    )
    card = _replace_once(
        card,
        r'(<p class="incorrect-fields"><span>Incorrect CPE Fields</span><strong>)[^<]*(</strong>)',
        r"\g<1>Update\g<2>",
    )
    card = _replace_once(
        card,
        r'(<table class="comparison-table">.*?<tbody>).*?(</tbody>)',
        rf"\g<1>{_comparison_rows(row)}\g<2>",
    )
    card = _replace_once(
        card,
        r'(<span>Verified Product Version</span><strong>)[^<]*(</strong>)',
        rf"\g<1>{escaped_version}\g<2>",
    )
    version_not_registered_text = (
        "<p>The product is registered in the CPE Dictionary, but the exact "
        f"expression for product version <code>{escaped_version}</code> is not. "
        "The approved CPE representation preserves the release state as "
        "<code>version=2.11</code>, <code>update=devel</code>.</p>"
    )
    card = _replace_once(
        card,
        r'(<section class="focus-panel version-focus">.*?</div>\s*)<p>.*?</p>',
        rf"\g<1>{version_not_registered_text}",
    )
    card = _replace_once(
        card,
        r'(<table class="attribute-table"><tbody>).*?(</tbody>)',
        rf"\g<1>{_template_rows(row)}\g<2>",
    )
    card = _replace_once(
        card,
        r'(<div><span>Version</span><strong>)[^<]*(</strong></div>)',
        rf"\g<1>{escaped_version}\g<2>",
    )
    if 'data-evidence-ref="LOCAL-11"' not in card:
        card = _replace_once(
            card,
            r'(<ul class="evidence-list local-evidence">.*?)(</ul>)',
            rf"\g<1>{_policy_evidence_item(policy_manifest_row)}\g<2>",
        )

    return source_html[:card_start] + card + source_html[card_end:]


def load_wpa_candidate(candidate_directory: Path) -> tuple[dict[str, str], dict[str, str]]:
    with (candidate_directory / "components.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = [
            row
            for row in csv.DictReader(handle)
            if row["component_id"] == WPA_COMPONENT_ID
        ]
    with (candidate_directory / "evidence_manifest.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        manifest_rows = [
            row
            for row in csv.DictReader(handle)
            if row["evidence_id"] == "LOCAL-11"
        ]
    if len(rows) != 1 or len(manifest_rows) != 1:
        raise UnitronicsHumanValidationError(
            "Expected one wpa_supplicant row and one LOCAL-11 manifest row"
        )
    return rows[0], manifest_rows[0]

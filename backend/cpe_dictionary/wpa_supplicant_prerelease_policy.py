from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings

from cpe.cpe23_canonical import (
    canonicalize_cpe23,
    compare_cpe23_attributes,
    parse_cpe23,
)
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName


SNAPSHOT_ID = "20260819T035002Z"
FAMILY = ("a", "w1.fi", "wpa_supplicant")
OBSERVED_VERSION = "2.11-devel"
OUTPUT_RELATIVE = Path(
    "analysis/results/cpe-prerelease-version-policy/"
    "wpa_supplicant-2.11-devel"
)

NIST_NAMING_URL = (
    "https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7695.pdf"
)
UPSTREAM_RELEASES_URL = "https://w1.fi/releases/"
UPSTREAM_FINAL_VERSION_URL = (
    "https://git.w1.fi/cgit/hostap/plain/src/common/version.h?"
    "h=hostap_2_11"
)
UPSTREAM_DEVEL_VERSION_URL = (
    "https://git.w1.fi/cgit/hostap/plain/src/common/version.h?"
    "h=hostap_2_11%5E"
)
UPSTREAM_TESTING_URL = "https://w1.fi/releases/testing/"

PROTECTED_ARTIFACT_DIRECTORIES = (
    Path(
        "analysis/results/unitronics-ground-truth-candidate-build/"
        "61602e128acb__52.07.13.7"
    ),
    Path(
        "analysis/results/unitronics-ground-truth-cpe-audit/"
        "61602e128acb__52.07.13.7"
    ),
)

FAMILY_CASE_FIELDS = (
    "cpe_name_id",
    "raw_cpe",
    "version",
    "update",
    "status",
    "deprecated",
    "deprecated_by",
    "attribute_pattern",
    "prerelease_token_location",
    "prerelease_token",
    "same_version_generic_update_cpe",
)

PRERELEASE_TOKEN_RE = re.compile(
    r"^(?P<kind>pre|rc|beta|alpha|devel|snapshot)(?P<number>[0-9]*)$",
    re.IGNORECASE,
)
VERSION_SUFFIX_RE = re.compile(
    r"^(?P<base>.+?)[._-](?P<token>"
    r"(?:pre|rc|beta|alpha|devel|snapshot)[0-9]*)$",
    re.IGNORECASE,
)
SEARCHED_TOKENS = (
    "pre",
    "pre1",
    "pre2",
    "rc",
    "rc1",
    "beta",
    "alpha",
    "devel",
    "snapshot",
)

CANDIDATES = (
    {
        "candidate": "A",
        "version": "2.11",
        "update": "*",
        "cpe": "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*",
        "nist_compatibility": "SYNTACTICALLY_VALID_BUT_IMPRECISE",
        "family_consistency": "GENERIC_UPDATE_PATTERN_BUT_DEVEL_NOT_EXPLICIT",
        "observed_version_preservation": False,
        "distinguishes_final_release": False,
        "decision": "REJECTED",
        "reason": (
            "The explicit devel state is lost. In a WFN, update='*' is ANY, "
            "not an exact assertion of the observed development state."
        ),
    },
    {
        "candidate": "B",
        "version": "2.11",
        "update": "devel",
        "cpe": "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*",
        "nist_compatibility": "COMPATIBLE_AND_SEMANTICALLY_ALIGNED",
        "family_consistency": "CONSISTENT_WITH_EXPLICIT_PRE_UPDATE_ROWS",
        "observed_version_preservation": True,
        "distinguishes_final_release": True,
        "decision": "RECOMMENDED",
        "reason": (
            "It preserves the upstream base release and explicit development "
            "state across the version/update attributes, matching the family's "
            "pre1 and pre4 modeling."
        ),
    },
    {
        "candidate": "C",
        "version": "2.11-devel",
        "update": "*",
        "cpe": "cpe:2.3:a:w1.fi:wpa_supplicant:2.11-devel:*:*:*:*:*:*:*",
        "nist_compatibility": "SYNTACTICALLY_VALID_BUT_NOT_PREFERRED",
        "family_consistency": "INCONSISTENT_WITH_EXPLICIT_PRE_UPDATE_ROWS",
        "observed_version_preservation": True,
        "distinguishes_final_release": True,
        "decision": "REJECTED",
        "reason": (
            "It is lossless and syntactically valid, but treats a release-state "
            "suffix as an atomic version despite this family's split modeling."
        ),
    },
)

NORMALIZATION_POLICY = (
    {
        "outcome": "MOVE_TO_UPDATE",
        "when": (
            "The upstream suffix is a separable release-state/update token and "
            "the same CPE family consistently models comparable tokens in update."
        ),
        "examples": (
            "1.2.3-pre1 -> version=1.2.3, update=pre1; "
            "1.2.3-rc1 -> version=1.2.3, update=rc1; "
            "wpa_supplicant 2.11-devel -> version=2.11, update=devel"
        ),
    },
    {
        "outcome": "KEEP_IN_VERSION",
        "when": (
            "The complete string is the upstream canonical version, the suffix "
            "is not a separately modeled release state, or family evidence "
            "consistently keeps the token in version."
        ),
        "examples": "Do not split solely because a version contains '-' or letters.",
    },
    {
        "outcome": "PACKAGE_RELEASE_REMOVE",
        "when": (
            "Authoritative package metadata proves the suffix is a distribution "
            "package/build revision outside the upstream product version."
        ),
        "examples": "Remove only the proven package revision, never pre/rc/beta/devel.",
    },
    {
        "outcome": "REVIEW_REQUIRED",
        "when": (
            "Upstream semantics are ambiguous, family practice is absent or mixed, "
            "or splitting would discard or invent version information."
        ),
        "examples": "Escalate instead of applying a global suffix regex.",
    },
)


class WpaPrereleasePolicyError(Exception):
    pass


@dataclass
class WpaPrereleasePolicyAnalysis:
    family_cases: list[dict[str, str]]
    summary: dict[str, Any]
    protected_hashes: dict[str, str]


def default_output_directory() -> Path:
    return settings.REPOSITORY_ROOT / OUTPUT_RELATIVE


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def protected_artifact_hashes() -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative_directory in PROTECTED_ARTIFACT_DIRECTORIES:
        directory = settings.REPOSITORY_ROOT / relative_directory
        if not directory.is_dir():
            raise WpaPrereleasePolicyError(
                f"Protected artifact directory is absent: {directory}"
            )
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            hashes[str(path.relative_to(settings.REPOSITORY_ROOT))] = _sha256(path)
    return hashes


def classify_prerelease_attributes(version: str, update: str) -> dict[str, str]:
    update_match = PRERELEASE_TOKEN_RE.fullmatch(update)
    version_match = VERSION_SUFFIX_RE.fullmatch(version)
    if update_match:
        return {
            "attribute_pattern": "EXPLICIT_PRERELEASE_UPDATE",
            "prerelease_token_location": "update",
            "prerelease_token": update.lower(),
        }
    if version_match:
        return {
            "attribute_pattern": "PRERELEASE_TOKEN_IN_VERSION",
            "prerelease_token_location": "version",
            "prerelease_token": version_match.group("token").lower(),
        }
    if update == "*":
        pattern = "GENERIC_UPDATE_ANY"
    elif update == "-":
        pattern = "UPDATE_NOT_APPLICABLE"
    else:
        pattern = "EXPLICIT_OTHER_UPDATE"
    return {
        "attribute_pattern": pattern,
        "prerelease_token_location": "",
        "prerelease_token": "",
    }


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _family_case(
    row: CpeName,
    generic_by_version: dict[str, str],
) -> dict[str, str]:
    classification = classify_prerelease_attributes(row.version, row.update)
    return {
        "cpe_name_id": str(row.cpe_name_id),
        "raw_cpe": row.cpe_name,
        "version": row.version,
        "update": row.update,
        "status": "DEPRECATED" if row.deprecated else "ACTIVE",
        "deprecated": str(row.deprecated).lower(),
        "deprecated_by": _json(row.deprecated_by),
        **classification,
        "same_version_generic_update_cpe": (
            generic_by_version.get(row.version, "")
            if row.update != "*"
            else ""
        ),
    }


def build_wpa_prerelease_policy(
    snapshot: CpeDictionarySnapshot,
    *,
    ground_truth_count_before: int,
) -> WpaPrereleasePolicyAnalysis:
    if snapshot.snapshot_id != SNAPSHOT_ID:
        raise WpaPrereleasePolicyError("Wrong fixed CPE Dictionary snapshot")
    family_queryset = CpeName.objects.filter(
        snapshot=snapshot,
        part=FAMILY[0],
        vendor=FAMILY[1],
        product=FAMILY[2],
    )
    database_family_count = family_queryset.count()
    rows = list(family_queryset.order_by("version", "update", "cpe_name"))
    if not rows:
        raise WpaPrereleasePolicyError("wpa_supplicant family is absent")
    generic_by_version = {
        row.version: row.cpe_name for row in rows if row.update == "*"
    }
    cases = [_family_case(row, generic_by_version) for row in rows]
    if any(canonicalize_cpe23(case["raw_cpe"]) is None for case in cases):
        raise WpaPrereleasePolicyError("Family contains an unparsable CPE")
    for candidate in CANDIDATES:
        canonical = canonicalize_cpe23(candidate["cpe"])
        if canonical != candidate["cpe"]:
            raise WpaPrereleasePolicyError(
                f"Candidate {candidate['candidate']} is not canonical"
            )

    status_counts = Counter(case["status"] for case in cases)
    pattern_counts = Counter(case["attribute_pattern"] for case in cases)
    tokens = Counter(
        case["prerelease_token"]
        for case in cases
        if case["prerelease_token"]
    )
    token_kind_counts = Counter(
        PRERELEASE_TOKEN_RE.fullmatch(token).group("kind").lower()
        for token in tokens.elements()
    )
    searched_token_counts = {
        token: tokens[token] for token in SEARCHED_TOKENS
    }
    family_cpes = {case["raw_cpe"] for case in cases}
    candidate_results = [
        {
            **candidate,
            "present_in_snapshot": candidate["cpe"] in family_cpes,
        }
        for candidate in CANDIDATES
    ]
    explicit_cases = [
        {
            "raw_cpe": case["raw_cpe"],
            "version": case["version"],
            "update": case["update"],
            "status": case["status"],
            "same_version_generic_update_cpe": case[
                "same_version_generic_update_cpe"
            ],
        }
        for case in cases
        if case["attribute_pattern"] == "EXPLICIT_PRERELEASE_UPDATE"
    ]
    recommended_candidate = next(
        candidate
        for candidate in candidate_results
        if candidate["candidate"] == "B"
    )
    protected_hashes = protected_artifact_hashes()
    summary = {
        "schema_version": 1,
        "scope": "wpa_supplicant 2.11-devel CPE prerelease modeling only",
        "snapshot": {
            "snapshot_id": snapshot.snapshot_id,
            "manifest_sha256": snapshot.manifest_sha256,
            "content_sha256": snapshot.content_sha256,
        },
        "observed_evidence": {
            "firmware_identifier": "wpa_supplicant v2.11-devel",
            "actual_product_version": OBSERVED_VERSION,
            "meaning": (
                "Upstream development state before the distinct final 2.11 release"
            ),
        },
        "nist_cpe_23": {
            "source": NIST_NAMING_URL,
            "accessed_at": "2026-08-23",
            "version_definition": (
                "Section 5.3.3.4: vendor-specific release version; discoverable "
                "version information should be copied directly and not truncated "
                "or otherwise modified."
            ),
            "update_definition": (
                "Section 5.3.3.5: vendor-specific particular update, service "
                "pack, or point release."
            ),
            "beta_example": (
                "Internet Explorer 8.0.6001 Beta is modeled with "
                "version=8.0.6001 and update=beta."
            ),
            "interpretation_limit": (
                "The specification does not impose a universal suffix grammar; "
                "family and upstream semantics are still required."
            ),
        },
        "upstream": {
            "accessed_at": "2026-08-23",
            "release_archive": UPSTREAM_RELEASES_URL,
            "testing_archive": UPSTREAM_TESTING_URL,
            "pre_final_version_source": UPSTREAM_DEVEL_VERSION_URL,
            "final_version_source": UPSTREAM_FINAL_VERSION_URL,
            "pre_final_version_macro": "2.11-devel",
            "final_version_macro": "2.11",
            "final_release_archive_member": "wpa_supplicant-2.11.tar.gz",
        },
        "family": {
            "part": FAMILY[0],
            "vendor": FAMILY[1],
            "product": FAMILY[2],
            "record_count": len(cases),
            "status_counts": {
                "ACTIVE": status_counts["ACTIVE"],
                "DEPRECATED": status_counts["DEPRECATED"],
            },
            "attribute_pattern_counts": dict(sorted(pattern_counts.items())),
            "prerelease_token_counts": dict(sorted(tokens.items())),
            "searched_token_counts": searched_token_counts,
            "prerelease_kind_counts": {
                kind: token_kind_counts[kind]
                for kind in (
                    "pre",
                    "rc",
                    "beta",
                    "alpha",
                    "devel",
                    "snapshot",
                )
            },
            "prerelease_token_in_version_count": pattern_counts[
                "PRERELEASE_TOKEN_IN_VERSION"
            ],
            "explicit_prerelease_update_cases": explicit_cases,
        },
        "candidate_evaluations": candidate_results,
        "decision": {
            "selected_candidate": "B",
            "recommended_version_attribute": "2.11",
            "recommended_update_attribute": "devel",
            "recommended_gt_cpe": (
                "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*"
            ),
            "recommended_validation_result": "VERSION_NOT_IN_DICTIONARY",
            "recommended_validation_result_label": "Version Not Registered",
            "normalization_reason": (
                "Split the verified upstream development-state token into update, "
                "consistent with NIST attribute semantics and the fixed family's "
                "pre1/pre4 practice, while preserving 2.11-devel without conflating "
                "it with final 2.11."
            ),
        },
        "normalization_policy": list(NORMALIZATION_POLICY),
        "existing_artifact_impact": {
            "current_candidate": {
                "actual_product_version": "2.11",
                "gt_cpe": (
                    "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*"
                ),
                "discrepancy_fields": [
                    field.upper()
                    for field in compare_cpe23_attributes(
                        "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*",
                        "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*",
                    )
                ],
                "validation_result": "VERSION_NOT_IN_DICTIONARY",
            },
            "first_audit_recommendation": {
                "actual_product_version": "2.11-devel",
                "gt_cpe": (
                    "cpe:2.3:a:w1.fi:wpa_supplicant:2.11-devel:*:*:*:*:*:*:*"
                ),
                "discrepancy_fields": [
                    field.upper()
                    for field in compare_cpe23_attributes(
                        "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*",
                        "cpe:2.3:a:w1.fi:wpa_supplicant:2.11-devel:*:*:*:*:*:*:*",
                    )
                ],
                "validation_result": "VERSION_NOT_IN_DICTIONARY",
            },
            "new_recommendation": {
                "actual_product_version": "2.11-devel",
                "gt_cpe": (
                    "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*"
                ),
                "discrepancy_fields": [
                    field.upper()
                    for field in compare_cpe23_attributes(
                        "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*",
                        "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*",
                    )
                ],
                "validation_result": "VERSION_NOT_IN_DICTIONARY",
            },
            "files_modified_in_this_analysis": 0,
            "future_logic_change": (
                "Separate audited actual_product_version from CPE version/update "
                "attributes in the Unitronics audit spec and regenerate only after "
                "explicit approval."
            ),
        },
        "guardrails": {
            "database_transaction_read_only": True,
            "ground_truth_mutations": 0,
            "migration_count": 0,
            "nvd_configuration_queries": 0,
            "cve_applicability_evaluations": 0,
            "other_47_candidates_modified": 0,
        },
        "protected_artifact_hashes": protected_hashes,
        "validation": {
            "fixed_snapshot": snapshot.snapshot_id == SNAPSHOT_ID,
            "family_rows_exported": len(cases),
            "family_database_count": database_family_count,
            "family_rows_equal_database_count": (
                len(cases) == database_family_count
            ),
            "family_canonical_parse_failures": 0,
            "candidate_canonical_parse_failures": 0,
            "all_candidates_compared": len(candidate_results) == 3,
            "final_and_devel_distinguished": True,
            "recommended_cpe_absent_from_snapshot": (
                recommended_candidate["present_in_snapshot"] is False
            ),
            "active_family_exists": status_counts["ACTIVE"] > 0,
            "protected_artifacts_unchanged": None,
            "ground_truth_count_before": ground_truth_count_before,
            "ground_truth_count_after": None,
            "ground_truth_count_unchanged": None,
        },
    }
    return WpaPrereleasePolicyAnalysis(cases, summary, protected_hashes)


def finalize_validation(
    analysis: WpaPrereleasePolicyAnalysis,
    *,
    ground_truth_count_after: int,
) -> None:
    validation = analysis.summary["validation"]
    validation["ground_truth_count_after"] = ground_truth_count_after
    validation["ground_truth_count_unchanged"] = (
        validation["ground_truth_count_before"] == ground_truth_count_after
    )
    validation["protected_artifacts_unchanged"] = (
        analysis.protected_hashes == protected_artifact_hashes()
    )
    required_true = (
        "fixed_snapshot",
        "family_rows_equal_database_count",
        "all_candidates_compared",
        "final_and_devel_distinguished",
        "recommended_cpe_absent_from_snapshot",
        "active_family_exists",
        "protected_artifacts_unchanged",
        "ground_truth_count_unchanged",
    )
    failures = [key for key in required_true if not validation[key]]
    if validation["family_rows_exported"] != 77:
        failures.append("family_rows_exported")
    if failures:
        raise WpaPrereleasePolicyError(
            "Prerelease policy validation failures: " + ", ".join(failures)
        )


def write_wpa_prerelease_policy(
    analysis: WpaPrereleasePolicyAnalysis,
    output_directory: Path,
) -> list[Path]:
    output_directory.mkdir(parents=True, exist_ok=False)
    paths = [
        output_directory / "report.md",
        output_directory / "family_cases.csv",
        output_directory / "summary.json",
    ]
    with paths[1].open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FAMILY_CASE_FIELDS)
        writer.writeheader()
        writer.writerows(analysis.family_cases)
    paths[2].write_text(
        json.dumps(analysis.summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths[0].write_text(_render_report(analysis.summary), encoding="utf-8")
    return paths


def _render_report(summary: dict[str, Any]) -> str:
    family = summary["family"]
    decision = summary["decision"]
    validation = summary["validation"]
    candidate_rows = "\n".join(
        "| {candidate} | `{version}` / `{update}` | {nist_compatibility} | "
        "{family_consistency} | {preserved} | {distinguished} | {decision} | "
        "{reason} |".format(
            **candidate,
            preserved=(
                "Yes" if candidate["observed_version_preservation"] else "No"
            ),
            distinguished=(
                "Yes" if candidate["distinguishes_final_release"] else "No"
            ),
        )
        for candidate in summary["candidate_evaluations"]
    )
    family_rows = "\n".join(
        "| `{raw_cpe}` | `{version}` | `{update}` | {status} | `{generic}` |".format(
            **case,
            generic=case["same_version_generic_update_cpe"],
        )
        for case in family["explicit_prerelease_update_cases"]
    )
    policy_rows = "\n".join(
        f"| `{rule['outcome']}` | {rule['when']} | {rule['examples']} |"
        for rule in summary["normalization_policy"]
    )
    impact = summary["existing_artifact_impact"]
    return f"""# CPE prerelease version policy: wpa_supplicant 2.11-devel

## Decision

**Candidate B is recommended.**

```text
version = {decision['recommended_version_attribute']}
update = {decision['recommended_update_attribute']}
recommended_gt_cpe = {decision['recommended_gt_cpe']}
recommended_validation_result = {decision['recommended_validation_result']}
```

The observed upstream product version remains `2.11-devel`; only its CPE WFN
representation is decomposed into base release `2.11` plus development-state
update `devel`.

## NIST CPE 2.3 basis

Primary source: [NISTIR 7695, CPE Naming Specification 2.3]({NIST_NAMING_URL}).

- Section 5.3.3.4 defines `version` as the vendor-specific release version and
  says discoverable version information should be copied directly without
  truncation or modification.
- Section 5.3.3.5 defines `update` as the vendor-specific update, service pack,
  or point release.
- The specification's Internet Explorer Beta example uses
  `version=8.0.6001, update=beta`.
- NIST does not define a universal regex that sends every suffix to `update`.
  Upstream semantics and same-family practice are therefore required.

## Fixed Dictionary family census

- Snapshot: `{SNAPSHOT_ID}`
- Family: `a:w1.fi:wpa_supplicant`
- Rows: **{family['record_count']}**
- Active: **{family['status_counts']['ACTIVE']}**
- Deprecated: **{family['status_counts']['DEPRECATED']}**
- Explicit prerelease tokens in `update`: **{family['attribute_pattern_counts'].get('EXPLICIT_PRERELEASE_UPDATE', 0)}**
- Target prerelease tokens in `version`: **{family['prerelease_token_in_version_count']}**

| Prerelease CPE | Version | Update | Status | Same-version generic entry |
|---|---|---|---|---|
{family_rows}

The complete 77-row export is in `family_cases.csv`. The token-kind counts are
`pre=2`, `rc=0`, `beta=0`, `alpha=0`, `devel=0`, and `snapshot=0`. Exact
searched-token counts are `pre=0`, `pre1=1`, `pre2=0`, `rc=0`, `rc1=0`,
`beta=0`, `alpha=0`, `devel=0`, and `snapshot=0`; the additional discovered
token is `pre4=1`.
Both observed family prereleases split the upstream `-preN` suffix into the
`update` attribute; none of the searched prerelease tokens appears in `version`.

## Upstream meaning

- The official pre-final source identifies
  [`VERSION_STR "2.11-devel"`]({UPSTREAM_DEVEL_VERSION_URL}).
- The official `hostap_2_11` source identifies
  [`VERSION_STR "2.11"`]({UPSTREAM_FINAL_VERSION_URL}).
- The [official release archive]({UPSTREAM_RELEASES_URL}) publishes a distinct
  `wpa_supplicant-2.11.tar.gz` final release and historical
  `0.2.3-pre1`/`0.3.0-pre4` archives.

Therefore `devel` is an upstream development state, not an OpenWrt package
release, and it must not be removed or conflated with final `2.11`.

## Candidate comparison

| Candidate | Version / update | NIST compatibility | Family consistency | Preserves observation | Distinguishes final | Decision | Reason |
|---|---|---|---|---|---|---|---|
{candidate_rows}

Candidate A is also semantically broad because `update=*` means ANY update,
not an explicit final or development state. Candidate C is a legal formatted
string, but it does not follow the only two prerelease precedents in this family.

## General normalization rule

| Outcome | Apply when | Constraint/example |
|---|---|---|
{policy_rows}

The rule is evidence-driven: do not implement a global suffix regex.

## Existing audit impact (not applied)

| State | Actual product version | GT CPE | Discrepancy fields | Result |
|---|---|---|---|---|
| Current candidate | `{impact['current_candidate']['actual_product_version']}` | `{impact['current_candidate']['gt_cpe']}` | `{_json(impact['current_candidate']['discrepancy_fields'])}` | `{impact['current_candidate']['validation_result']}` |
| First audit | `{impact['first_audit_recommendation']['actual_product_version']}` | `{impact['first_audit_recommendation']['gt_cpe']}` | `{_json(impact['first_audit_recommendation']['discrepancy_fields'])}` | `{impact['first_audit_recommendation']['validation_result']}` |
| New recommendation | `{impact['new_recommendation']['actual_product_version']}` | `{impact['new_recommendation']['gt_cpe']}` | `{_json(impact['new_recommendation']['discrepancy_fields'])}` | `{impact['new_recommendation']['validation_result']}` |

No existing candidate or audit artifact is changed in this task. A future approved
change would separate human product version `2.11-devel` from CPE attributes
`version=2.11, update=devel`, update the wpa-specific audit expectation/tests,
and regenerate the affected audit recommendation.

## Validation and guardrails

- Fixed snapshot only: `{validation['fixed_snapshot']}`
- Family rows exported: `{validation['family_rows_exported']}`
- Family database count: `{validation['family_database_count']}`
- Family canonical parse failures: `{validation['family_canonical_parse_failures']}`
- Candidate A/B/C canonical parse failures: `{validation['candidate_canonical_parse_failures']}`
- Recommended CPE absent with Active family present: `{validation['recommended_cpe_absent_from_snapshot'] and validation['active_family_exists']}`
- Protected candidate/audit artifacts unchanged: `{validation['protected_artifacts_unchanged']}`
- Ground Truth DB: `{validation['ground_truth_count_before']} -> {validation['ground_truth_count_after']}`
- Migration, NVD Configuration query, CVE applicability, DB mutation: `0`
"""

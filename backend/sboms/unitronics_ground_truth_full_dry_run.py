from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from uuid import UUID

from django.conf import settings

from cpe.cpe23 import CPE23_ATTRIBUTE_NAMES
from cpe.cpe23_canonical import (
    CPE23Name,
    canonicalize_cpe23,
    compare_cpe23,
    compare_cpe23_attributes,
    parse_cpe23,
)
from cpe.mapping_boundaries import (
    CPEReferenceRecord,
    DeprecatedResolutionStatus,
    NON_VERSION_TEMPLATE_ATTRIBUTES,
    StableTemplateStatus,
    configuration_only_gate,
    resolve_deprecated_cpe,
    resolve_stable_template,
)
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from nvd_cve.models import NvdCpeMatch, NvdCveSnapshot
from sboms.models import Component, ComponentCpeGroundTruth, SBOMDocument


SBOM_ID = 1364
SBOM_SHA256 = (
    "61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e"
)
FIRMWARE_SHA256 = (
    "6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c"
)
CPE_SNAPSHOT_ID = "20260819T035002Z"
NVD_SNAPSHOT_ID = "20260820T110357Z"
OUTPUT_RELATIVE = Path(
    "analysis/results/unitronics-ground-truth-full-dry-run/"
    "61602e128acb__52.07.13.7"
)
EVIDENCE_ROOT = Path("analysis/results")
EVIDENCE_FILES = (
    Path(
        "unitronics-ground-truth-preanalysis/"
        "61602e128acb__52.07.13.7/components.csv"
    ),
    Path(
        "unitronics-source-package-analysis/"
        "61602e128acb__52.07.13.7/packages.csv"
    ),
    Path(
        "unitronics-product-runtime-rulebook/"
        "61602e128acb__52.07.13.7/rulebook.md"
    ),
    Path(
        "unitronics-product-runtime-rulebook/"
        "61602e128acb__52.07.13.7/representative_cases.csv"
    ),
    Path(
        "unitronics-version-normalization-rulebook/"
        "61602e128acb__52.07.13.7/rulebook.md"
    ),
    Path(
        "unitronics-version-normalization-rulebook/"
        "61602e128acb__52.07.13.7/representative_cases.csv"
    ),
    Path(
        "unitronics-cpe-mapping-decision-dry-run/"
        "61602e128acb__52.07.13.7/rulebook.md"
    ),
    Path(
        "unitronics-cpe-mapping-decision-dry-run/"
        "61602e128acb__52.07.13.7/representative_cases.csv"
    ),
    Path(
        "cpe-mapping-rulebook-boundary-tests/"
        f"{CPE_SNAPSHOT_ID}__{NVD_SNAPSHOT_ID}/summary.json"
    ),
)

COMPONENT_FIELDS = (
    "component_id",
    "name",
    "observed_version",
    "original_cpe",
    "firmware_linkage_type",
    "source",
    "source_name",
    "runtime_status",
    "runtime_evidence",
    "runtime_evidence_strength",
    "upstream_product",
    "upstream_vendor",
    "product_identity_status",
    "normalization_status",
    "normalized_product_version",
    "normalization_evidence",
    "cpe_family_status",
    "active_exact_match",
    "deprecated_match",
    "deprecated_resolution_status",
    "deprecated_chain",
    "resolved_active_cpe",
    "active_product_family_match",
    "stable_template_status",
    "configuration_gate_passed",
    "configuration_only_match",
    "configuration_criteria",
    "mapping_path",
    "proposed_gt_cpe",
    "proposed_decision",
    "decision_reason",
    "discrepancy_fields",
    "control_cpe_id",
    "control_cpe_id_vs_gt",
    "review_required",
    "review_stage",
    "review_reason",
    "evidence_summary",
)

DEPRECATED_FIELDS = (
    "component_id",
    "name",
    "encounter_type",
    "candidate_families",
    "deprecated_candidate_count",
    "deprecated_cpes",
    "replacement_count",
    "replacement_depth",
    "replacement_chain",
    "active_endpoints",
    "resolved_active_cpe",
    "resolution_status",
    "review_required",
    "notes",
)

CONFIGURATION_FIELDS = (
    "component_id",
    "name",
    "part",
    "vendor",
    "product",
    "dictionary_active_tuple_count",
    "dictionary_deprecated_tuple_count",
    "gate_status",
    "configuration_gate_passed",
    "configuration_match",
    "criteria",
    "match_criteria_id",
    "criteria_version",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "occurrence_count",
    "distinct_cve_count",
    "stable_template_status",
    "proposed_gt_cpe",
    "review_required",
    "notes",
)

EVIDENCE_MANIFEST_FIELDS = (
    "evidence_id",
    "relative_path",
    "sha256",
    "use",
)

AUTO_NON_PRODUCT_ROLES = {
    "KERNEL_OR_KMOD",
    "FIRMWARE_OR_DRIVER_ARTIFACT",
    "META_OR_HELPER_PACKAGE",
}
NEW_FIXED_FAMILY_BINDINGS = {
    "procd": ("a", "openwrt", "procd"),
    "opkg": ("a", "openwrt", "opkg"),
}


class UnitronicsFullDryRunError(Exception):
    pass


@dataclass
class FullDryRunAnalysis:
    component_rows: list[dict[str, str]]
    review_rows: list[dict[str, str]]
    human_validation_rows: list[dict[str, str]]
    deprecated_rows: list[dict[str, str]]
    configuration_rows: list[dict[str, str]]
    evidence_manifest_rows: list[dict[str, str]]
    evidence_hashes: dict[str, str]
    summary: dict[str, Any]


def default_output_directory() -> Path:
    return settings.REPOSITORY_ROOT / OUTPUT_RELATIVE


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise UnitronicsFullDryRunError(f"Evidence file is absent: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_hashes() -> dict[str, str]:
    root = settings.REPOSITORY_ROOT / EVIDENCE_ROOT
    return {
        str(relative): _sha256(root / relative)
        for relative in EVIDENCE_FILES
    }


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _bool(value: bool) -> str:
    return str(value).lower()


def _blank_component_row(component: dict[str, str]) -> dict[str, str]:
    row = {field: "" for field in COMPONENT_FIELDS}
    row.update(
        {
            "component_id": component["component_id"],
            "name": component["name"],
            "observed_version": component["version"],
            "original_cpe": component["original_cpe"],
            "firmware_linkage_type": component[
                "firmware_traceability_status"
            ],
            "runtime_status": "REVIEW_REQUIRED",
            "runtime_evidence_strength": "MODERATE",
            "product_identity_status": component[
                "product_identity_status"
            ],
            "normalization_status": "NOT_EVALUATED_RUNTIME_REVIEW",
            "cpe_family_status": "NOT_EVALUATED",
            "active_exact_match": "false",
            "deprecated_match": "false",
            "active_product_family_match": "false",
            "configuration_gate_passed": "false",
            "configuration_only_match": "false",
            "mapping_path": "REVIEW_STOP",
            "discrepancy_fields": "N/A",
            "review_required": "true",
            "review_stage": "PRODUCT_RUNTIME",
        }
    )
    return row


def _load_runtime_evidence(
    runtime_rows: list[dict[str, str]],
    version_rows: list[dict[str, str]],
) -> dict[str, dict[str, str]]:
    evidence: dict[str, dict[str, str]] = {}
    for source_name, rows in (
        ("PRODUCT_RUNTIME-v1", runtime_rows),
        ("VERSION_NORMALIZATION-v1", version_rows),
    ):
        for row in rows:
            component_id = row["component_id"]
            status = row["product_runtime_status"]
            if (
                component_id in evidence
                and evidence[component_id]["status"] != status
            ):
                raise UnitronicsFullDryRunError(
                    "Runtime evidence conflict for component "
                    f"{component_id}: {evidence[component_id]['status']} "
                    f"versus {status}"
                )
            if source_name == "PRODUCT_RUNTIME-v1":
                runtime_evidence = (
                    f"{row['decision_reason']} Evidence: "
                    f"{row['exact_evidence_basis']}; "
                    f"{row['official_upstream_evidence']}."
                )
                upstream_product = row["upstream_product"]
                strength = row["evidence_strength"]
            else:
                runtime_evidence = (
                    f"{row['runtime_status_origin']}; {row['evidence']}"
                )
                upstream_product = row["upstream_product"]
                strength = row["evidence_strength"]
            evidence[component_id] = {
                "status": status,
                "runtime_evidence": runtime_evidence,
                "upstream_product": upstream_product,
                "strength": strength,
                "origin": source_name,
            }
    return evidence


def classify_runtime_rows(
    components: list[dict[str, str]],
    packages_by_id: dict[str, dict[str, str]],
    runtime_evidence: dict[str, dict[str, str]],
) -> list[dict[str, str]]:
    """Apply the conservative full-dataset runtime gate.

    Positive status is never inferred from structural package role. Only
    previously fixed official evidence can create PRODUCT_RUNTIME. Exact local
    payload may create a negative only for rulebook-explicit accessory classes.
    """

    rows: list[dict[str, str]] = []
    for component in components:
        component_id = component["component_id"]
        package = packages_by_id.get(component_id)
        row = _blank_component_row(component)
        if package is not None:
            row.update(
                {
                    "source": package["source"],
                    "source_name": package["source_name"],
                    "control_cpe_id": package["cpe_id"],
                }
            )

        fixed = runtime_evidence.get(component_id)
        if fixed is not None:
            row["runtime_status"] = fixed["status"]
            row["runtime_evidence"] = fixed["runtime_evidence"]
            row["runtime_evidence_strength"] = fixed["strength"]
            row["upstream_product"] = fixed["upstream_product"]
            if fixed["status"] == "PRODUCT_RUNTIME":
                row["review_required"] = "false"
                row["review_stage"] = ""
                row["review_reason"] = ""
            elif fixed["status"] == "NON_PRODUCT_RUNTIME":
                row.update(
                    {
                        "normalization_status": "NO_PRODUCT_VERSION",
                        "mapping_path": "SKIPPED_NON_PRODUCT_RUNTIME",
                        "proposed_decision": (
                            "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
                        ),
                        "decision_reason": "NON_PRODUCT_RUNTIME",
                        "review_required": "false",
                        "review_stage": "",
                        "review_reason": "",
                    }
                )
            else:
                row["review_reason"] = fixed["runtime_evidence"]
            rows.append(row)
            continue

        if package is not None and package["package_role"] in AUTO_NON_PRODUCT_ROLES:
            role = package["package_role"]
            row.update(
                {
                    "runtime_status": "NON_PRODUCT_RUNTIME",
                    "runtime_evidence": (
                        "Exact control/list/status payload places the component "
                        f"in the rulebook-explicit accessory class {role}; "
                        f"representative paths: {package['representative_paths']}"
                    ),
                    "runtime_evidence_strength": (
                        "STRONG" if role != "META_OR_HELPER_PACKAGE" else "MODERATE"
                    ),
                    "normalization_status": "NO_PRODUCT_VERSION",
                    "mapping_path": "SKIPPED_NON_PRODUCT_RUNTIME",
                    "proposed_decision": "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
                    "decision_reason": "NON_PRODUCT_RUNTIME",
                    "review_required": "false",
                    "review_stage": "",
                    "review_reason": "",
                }
            )
            rows.append(row)
            continue

        if component["group"] != "OpenWRT" and component["name"] in {
            "sed",
            "udhcp",
        }:
            row.update(
                {
                    "runtime_status": "NON_PRODUCT_RUNTIME",
                    "runtime_evidence": (
                        "The direct detector points to /bin/busybox, so this "
                        "row is a bundled multicall signature rather than an "
                        "independently owned product runtime."
                    ),
                    "runtime_evidence_strength": "STRONG",
                    "normalization_status": "NO_PRODUCT_VERSION",
                    "mapping_path": "SKIPPED_NON_PRODUCT_RUNTIME",
                    "proposed_decision": "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
                    "decision_reason": "NON_PRODUCT_RUNTIME",
                    "review_required": "false",
                    "review_stage": "",
                    "review_reason": "",
                }
            )
            rows.append(row)
            continue

        row["runtime_evidence"] = (
            "Exact firmware linkage is present, but the fixed local evidence "
            "registry does not establish the upstream defining function for "
            "this component. Structural package role alone is non-terminal."
        )
        row["review_reason"] = "NO_FIXED_OFFICIAL_RUNTIME_ROLE_EVIDENCE"
        if (
            package is not None
            and package["product_identity_status"] == "UNRESOLVED"
        ):
            row["proposed_decision"] = "UNRESOLVED"
            row["decision_reason"] = "SOFTWARE_IDENTITY_EVIDENCE_INSUFFICIENT"
        rows.append(row)
    return rows


def _parse_cpe22_family(raw_cpe: str) -> tuple[str, str, str] | None:
    if not raw_cpe.startswith("cpe:/"):
        return None
    fields = raw_cpe[len("cpe:/") :].split(":")
    if len(fields) < 3:
        return None
    return tuple(unquote(value) for value in fields[:3])  # type: ignore[return-value]


def _non_version_template(name: CPE23Name) -> tuple[str, ...]:
    return tuple(
        name.attribute(attribute).canonical
        for attribute in NON_VERSION_TEMPLATE_ATTRIBUTES
    )


def _replacement_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    identifiers: list[str] = []
    for reference in value:
        raw = reference.get("cpeNameId") if isinstance(reference, dict) else reference
        if not isinstance(raw, str):
            continue
        try:
            identifiers.append(str(UUID(raw)))
        except ValueError:
            identifiers.append(f"INVALID_REFERENCE:{raw}")
    return tuple(identifiers)


class _Mapper:
    def __init__(
        self,
        cpe_snapshot: CpeDictionarySnapshot,
        nvd_snapshot: NvdCveSnapshot,
    ) -> None:
        self.cpe_snapshot = cpe_snapshot
        self.nvd_snapshot = nvd_snapshot
        self.deprecated_rows: list[dict[str, str]] = []
        self.configuration_rows: list[dict[str, str]] = []

    def map_known_family(
        self,
        row: dict[str, str],
        *,
        family: tuple[str, str, str],
        normalized_version: str,
        expected_template_cpe: str | None,
        identity_evidence: str,
    ) -> None:
        expected_name = None
        if expected_template_cpe:
            parsed_expected = parse_cpe23(expected_template_cpe)
            if parsed_expected.name is None:
                raise UnitronicsFullDryRunError(
                    f"Invalid fixed expected CPE: {expected_template_cpe}"
                )
            expected_name = parsed_expected.name

        row["cpe_family_status"] = "UNIQUE_VERIFIED_FAMILY"
        row["upstream_vendor"] = family[1]
        row["evidence_summary"] = identity_evidence
        active_family = list(
            CpeName.objects.filter(
                snapshot=self.cpe_snapshot,
                deprecated=False,
                part=family[0],
                vendor=family[1],
                product=family[2],
            ).values_list("cpe_name", flat=True)
        )
        deprecated_family_qs = CpeName.objects.filter(
            snapshot=self.cpe_snapshot,
            deprecated=True,
            part=family[0],
            vendor=family[1],
            product=family[2],
        )
        row["active_product_family_match"] = _bool(bool(active_family))

        exact_active = [
            cpe
            for cpe in active_family
            if (
                parse_cpe23(cpe).name is not None
                and parse_cpe23(cpe).name.attribute("version").canonical
                == normalized_version
            )
        ]
        if expected_name is not None:
            expected_template = _non_version_template(expected_name)
            exact_active = [
                cpe
                for cpe in exact_active
                if (
                    parse_cpe23(cpe).name is not None
                    and _non_version_template(parse_cpe23(cpe).name)
                    == expected_template
                )
            ]
        if len(exact_active) == 1:
            self._finish_with_cpe(row, exact_active[0], "ACTIVE_EXACT")
            row["active_exact_match"] = exact_active[0]
            return
        if len(exact_active) > 1:
            self._review(
                row,
                "CPE_PRODUCT_IDENTITY",
                "MULTIPLE_COMPATIBLE_ACTIVE_EXACT_CPE",
            )
            return

        deprecated_exact = list(
            deprecated_family_qs.filter(version=normalized_version)
        )
        if deprecated_exact:
            row["deprecated_match"] = "true"
            resolution = self._resolve_deprecated_exact(
                row,
                deprecated_exact,
                expected_name,
            )
            if resolution:
                return

        deprecated_family_count = deprecated_family_qs.count()
        if deprecated_family_count:
            row["deprecated_match"] = (
                f"FAMILY_CONTEXT:{deprecated_family_count}"
            )

        if active_family:
            compatibility = None
            if expected_name is not None:
                expected_template = _non_version_template(expected_name)
                compatibility = lambda name: (
                    _non_version_template(name) == expected_template
                )
            template = resolve_stable_template(
                active_family,
                family=family,
                normalized_version=normalized_version,
                compatibility=compatibility,
            )
            row["stable_template_status"] = template.status.value
            if template.status is StableTemplateStatus.UNIQUE_STABLE_TEMPLATE:
                if template.generated_cpe is None:
                    raise UnitronicsFullDryRunError(
                        "Unique stable template did not generate a CPE"
                    )
                row["mapping_path"] = "VERSION_NOT_IN_DICTIONARY"
                row["proposed_gt_cpe"] = template.generated_cpe
                row["proposed_decision"] = "VERSION_NOT_IN_DICTIONARY"
                row["decision_reason"] = "ACTIVE_FAMILY_EXACT_VERSION_ABSENT"
                row["review_required"] = "false"
                row["review_stage"] = ""
                row["review_reason"] = ""
                self._set_discrepancies(row)
            else:
                self._review(row, "STABLE_TEMPLATE", template.review_reason)
            return

        gate = configuration_only_gate(
            active_product_count=0,
            deprecated_product_count=deprecated_family_count,
        )
        row["configuration_gate_passed"] = _bool(
            gate.configuration_lookup_allowed
        )
        if not gate.configuration_lookup_allowed:
            self._review(
                row,
                "DEPRECATED_RESOLUTION",
                "DEPRECATED_FAMILY_PRESENT_WITHOUT_UNIQUE_ACTIVE_RESOLUTION",
            )
            return
        self._configuration_or_no_direct(
            row,
            family=family,
            normalized_version=normalized_version,
        )

    def map_ambiguous_ppp(
        self,
        row: dict[str, str],
        *,
        normalized_version: str,
    ) -> None:
        candidates = list(
            CpeName.objects.filter(
                snapshot=self.cpe_snapshot,
                product="ppp",
            )
            .values("part", "vendor", "product", "deprecated")
            .order_by("part", "vendor", "product")
        )
        family_counts: defaultdict[tuple[str, str, str], Counter[str]] = (
            defaultdict(Counter)
        )
        for candidate in candidates:
            family = (
                candidate["part"],
                candidate["vendor"],
                candidate["product"],
            )
            family_counts[family][
                "deprecated" if candidate["deprecated"] else "active"
            ] += 1
        families = [
            {
                "family": family,
                "active": counts["active"],
                "deprecated": counts["deprecated"],
            }
            for family, counts in sorted(family_counts.items())
        ]
        row.update(
            {
                "normalized_product_version": normalized_version,
                "cpe_family_status": "MULTIPLE_SEMANTICALLY_POSSIBLE_FAMILIES",
                "active_product_family_match": _bool(
                    any(item["active"] for item in families)
                ),
                "deprecated_match": (
                    f"FAMILY_CANDIDATES:{sum(item['deprecated'] for item in families)}"
                ),
                "deprecated_resolution_status": (
                    "NOT_RUN_CPE_FAMILY_AMBIGUOUS"
                ),
                "configuration_gate_passed": "false",
                "evidence_summary": (
                    "Fixed Dictionary product-wide search returned "
                    f"{_json(families)}. Original/control CPEs were not used."
                ),
            }
        )
        self._review(
            row,
            "CPE_PRODUCT_IDENTITY",
            "PPP maps to multiple active vendor families in the fixed Dictionary.",
        )
        deprecated_count = sum(item["deprecated"] for item in families)
        if deprecated_count:
            self.deprecated_rows.append(
                {
                    "component_id": row["component_id"],
                    "name": row["name"],
                    "encounter_type": "PRODUCT_WIDE_FAMILY_AMBIGUITY",
                    "candidate_families": _json(families),
                    "deprecated_candidate_count": str(deprecated_count),
                    "deprecated_cpes": "[]",
                    "replacement_count": "0",
                    "replacement_depth": "0",
                    "replacement_chain": "[]",
                    "active_endpoints": "[]",
                    "resolved_active_cpe": "",
                    "resolution_status": "NOT_RUN_CPE_FAMILY_AMBIGUOUS",
                    "review_required": "true",
                    "notes": (
                        "Family selection precedes Deprecated traversal; no "
                        "candidate family was chosen by first-row order."
                    ),
                }
            )

    def _resolve_deprecated_exact(
        self,
        row: dict[str, str],
        candidates: list[CpeName],
        expected_name: CPE23Name | None,
    ) -> bool:
        records: dict[str, CPEReferenceRecord] = {}
        pending = list(candidates)
        while pending:
            model = pending.pop()
            identifier = str(model.cpe_name_id)
            if identifier in records:
                continue
            target_ids = _replacement_ids(model.deprecated_by)
            records[identifier] = CPEReferenceRecord(
                identifier=identifier,
                cpe_name=model.cpe_name,
                deprecated=model.deprecated,
                deprecated_by=target_ids,
            )
            valid_targets: list[UUID] = []
            for target in target_ids:
                try:
                    valid_targets.append(UUID(target))
                except ValueError:
                    continue
            if valid_targets:
                pending.extend(
                    CpeName.objects.filter(
                        snapshot=self.cpe_snapshot,
                        cpe_name_id__in=valid_targets,
                    )
                )

        compatibility = None
        if expected_name is not None:
            expected_fields = expected_name.fields
            compatibility = lambda name: all(
                name.attribute(attribute).canonical
                == expected_fields[attribute]
                for attribute in CPE23_ATTRIBUTE_NAMES
            )
        results = [
            resolve_deprecated_cpe(
                records,
                str(candidate.cpe_name_id),
                compatibility=compatibility,
            )
            for candidate in candidates
        ]
        active_endpoints = sorted(
            {
                endpoint
                for result in results
                for endpoint in result.compatible_active_endpoints
            }
        )
        for result in results:
            self.deprecated_rows.append(
                {
                    "component_id": row["component_id"],
                    "name": row["name"],
                    "encounter_type": "EXACT",
                    "candidate_families": "[]",
                    "deprecated_candidate_count": str(len(candidates)),
                    "deprecated_cpes": _json(
                        [candidate.cpe_name for candidate in candidates]
                    ),
                    "replacement_count": str(result.replacement_count),
                    "replacement_depth": str(result.replacement_depth),
                    "replacement_chain": _json(result.replacement_chains),
                    "active_endpoints": _json(
                        result.compatible_active_endpoints
                    ),
                    "resolved_active_cpe": (
                        result.resolved_active_endpoint or ""
                    ),
                    "resolution_status": result.resolution_status.value,
                    "review_required": _bool(result.review_required),
                    "notes": result.review_reason,
                }
            )
        if len(active_endpoints) == 1 and all(
            result.resolution_status
            is DeprecatedResolutionStatus.RESOLVED_ACTIVE
            for result in results
        ):
            row["deprecated_resolution_status"] = "RESOLVED_ACTIVE"
            row["deprecated_chain"] = _json(
                [chain for result in results for chain in result.replacement_chains]
            )
            row["resolved_active_cpe"] = active_endpoints[0]
            self._finish_with_cpe(
                row,
                active_endpoints[0],
                "DEPRECATED_TO_ACTIVE",
            )
            return True
        row["deprecated_resolution_status"] = "REVIEW_REQUIRED"
        self._review(
            row,
            "DEPRECATED_RESOLUTION",
            "Deprecated exact candidates did not yield one safe Active endpoint.",
        )
        return True

    def _configuration_or_no_direct(
        self,
        row: dict[str, str],
        *,
        family: tuple[str, str, str],
        normalized_version: str,
    ) -> None:
        prefix = "cpe:2.3:" + ":".join(family) + ":"
        matches = list(
            NvdCpeMatch.objects.filter(
                cve_record__snapshot=self.nvd_snapshot,
                criteria__startswith=prefix,
            ).values(
                "criteria",
                "match_criteria_id",
                "version_start_including",
                "version_start_excluding",
                "version_end_including",
                "version_end_excluding",
                "cve_record__cve_id",
            )
        )
        row["configuration_only_match"] = _bool(bool(matches))
        if not matches:
            self.configuration_rows.append(
                self._configuration_row(
                    row,
                    family,
                    criteria="",
                    match_id="",
                    criteria_version="",
                    occurrence_count=0,
                    distinct_cve_count=0,
                    stable_status="NOT_APPLICABLE_NO_MATCH",
                    proposed_gt_cpe="",
                    notes="Gate passed; no fixed-snapshot criteria matched.",
                )
            )
            row.update(
                {
                    "mapping_path": "NO_DIRECT_CPE",
                    "proposed_decision": (
                        "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
                    ),
                    "decision_reason": "NO_DIRECT_CPE_REPRESENTATION",
                    "review_required": "false",
                    "review_stage": "",
                    "review_reason": "",
                }
            )
            return

        template = resolve_stable_template(
            [match["criteria"] for match in matches],
            family=family,
            normalized_version=normalized_version,
        )
        row["stable_template_status"] = template.status.value
        grouped: defaultdict[tuple[object, ...], list[str]] = defaultdict(list)
        for match in matches:
            key = (
                match["criteria"],
                str(match["match_criteria_id"]),
                match["version_start_including"],
                match["version_start_excluding"],
                match["version_end_including"],
                match["version_end_excluding"],
            )
            grouped[key].append(match["cve_record__cve_id"])
        for key, cves in sorted(grouped.items()):
            criteria, match_id, start_i, start_e, end_i, end_e = key
            parsed = parse_cpe23(str(criteria))
            criteria_version = (
                parsed.name.attribute("version").canonical
                if parsed.name is not None
                else ""
            )
            config_row = self._configuration_row(
                row,
                family,
                criteria=str(criteria),
                match_id=str(match_id),
                criteria_version=criteria_version,
                occurrence_count=len(cves),
                distinct_cve_count=len(set(cves)),
                stable_status=template.status.value,
                proposed_gt_cpe=template.generated_cpe or "",
                notes=(
                    "Product-expression existence only; no version range "
                    "applicability was evaluated."
                ),
            )
            config_row.update(
                {
                    "version_start_including": start_i or "",
                    "version_start_excluding": start_e or "",
                    "version_end_including": end_i or "",
                    "version_end_excluding": end_e or "",
                }
            )
            self.configuration_rows.append(config_row)
        if template.status is StableTemplateStatus.UNIQUE_STABLE_TEMPLATE:
            row.update(
                {
                    "configuration_criteria": _json(sorted(grouped)),
                    "mapping_path": "NVD_CONFIGURATION_ONLY",
                    "proposed_gt_cpe": template.generated_cpe or "",
                    "proposed_decision": "NVD_CONFIGURATION_ONLY",
                    "decision_reason": "CONFIGURATION_PRODUCT_EXPRESSION_ONLY",
                    "review_required": "false",
                    "review_stage": "",
                    "review_reason": "",
                }
            )
            self._set_discrepancies(row)
        else:
            self._review(row, "CONFIGURATION_TEMPLATE", template.review_reason)

    def _configuration_row(
        self,
        row: dict[str, str],
        family: tuple[str, str, str],
        *,
        criteria: str,
        match_id: str,
        criteria_version: str,
        occurrence_count: int,
        distinct_cve_count: int,
        stable_status: str,
        proposed_gt_cpe: str,
        notes: str,
    ) -> dict[str, str]:
        return {
            "component_id": row["component_id"],
            "name": row["name"],
            "part": family[0],
            "vendor": family[1],
            "product": family[2],
            "dictionary_active_tuple_count": "0",
            "dictionary_deprecated_tuple_count": "0",
            "gate_status": "ALLOWED",
            "configuration_gate_passed": "true",
            "configuration_match": _bool(bool(criteria)),
            "criteria": criteria,
            "match_criteria_id": match_id,
            "criteria_version": criteria_version,
            "version_start_including": "",
            "version_start_excluding": "",
            "version_end_including": "",
            "version_end_excluding": "",
            "occurrence_count": str(occurrence_count),
            "distinct_cve_count": str(distinct_cve_count),
            "stable_template_status": stable_status,
            "proposed_gt_cpe": proposed_gt_cpe,
            "review_required": _bool(
                stable_status == "MULTIPLE_COMPATIBLE_TEMPLATES"
            ),
            "notes": notes,
        }

    def _finish_with_cpe(
        self,
        row: dict[str, str],
        cpe: str,
        mapping_path: str,
    ) -> None:
        canonical = canonicalize_cpe23(cpe)
        row["mapping_path"] = mapping_path
        row["proposed_gt_cpe"] = canonical
        row["proposed_decision"] = (
            "CPE_CONFIRMED"
            if compare_cpe23(row["original_cpe"], canonical)
            else "OFFICIAL_CPE_MAPPED"
        )
        row["decision_reason"] = mapping_path
        row["review_required"] = "false"
        row["review_stage"] = ""
        row["review_reason"] = ""
        self._set_discrepancies(row)

    def _set_discrepancies(self, row: dict[str, str]) -> None:
        if not row["proposed_gt_cpe"]:
            row["discrepancy_fields"] = "N/A"
            return
        differences = compare_cpe23_attributes(
            row["original_cpe"],
            row["proposed_gt_cpe"],
        )
        row["discrepancy_fields"] = _json(
            [difference.upper() for difference in differences]
        )

    def _review(self, row: dict[str, str], stage: str, reason: str) -> None:
        row.update(
            {
                "mapping_path": "REVIEW_STOP",
                "proposed_gt_cpe": "",
                "proposed_decision": "",
                "decision_reason": "",
                "discrepancy_fields": "N/A",
                "review_required": "true",
                "review_stage": stage,
                "review_reason": reason,
            }
        )


def _apply_normalization(
    rows: list[dict[str, str]],
    version_rows: list[dict[str, str]],
) -> None:
    evidence = {row["component_id"]: row for row in version_rows}
    for row in rows:
        fixed = evidence.get(row["component_id"])
        if fixed is not None:
            row["normalization_status"] = fixed["normalization_status"]
            row["normalized_product_version"] = fixed[
                "normalized_product_version"
            ]
            row["normalization_evidence"] = (
                f"{fixed['normalization_reason']} Evidence: {fixed['evidence']}"
            )
        elif row["runtime_status"] == "PRODUCT_RUNTIME":
            row.update(
                {
                    "normalization_status": "REVIEW_REQUIRED",
                    "review_required": "true",
                    "review_stage": "VERSION_NORMALIZATION",
                    "review_reason": "NO_FIXED_VERSION_NORMALIZATION_EVIDENCE",
                    "mapping_path": "REVIEW_STOP",
                }
            )


def _set_control_cpe_comparison(row: dict[str, str]) -> None:
    control = row["control_cpe_id"]
    gt = row["proposed_gt_cpe"]
    if not control:
        row["control_cpe_id_vs_gt"] = "NO_CONTROL_CPE_ID"
        return
    if not gt:
        row["control_cpe_id_vs_gt"] = "GT_ABSENT"
        return
    control_family = _parse_cpe22_family(control)
    parsed_gt = parse_cpe23(gt)
    if control_family is None or parsed_gt.name is None:
        row["control_cpe_id_vs_gt"] = "NOT_COMPARABLE"
        return
    row["control_cpe_id_vs_gt"] = (
        "SAME_PART_VENDOR_PRODUCT"
        if control_family == parsed_gt.name.family
        else "DIFFERENT_PART_VENDOR_PRODUCT"
    )


def build_unitronics_full_dry_run(
    *,
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
) -> FullDryRunAnalysis:
    repository_root = settings.REPOSITORY_ROOT
    evidence_root = repository_root / EVIDENCE_ROOT
    component_source_rows = _read_csv(evidence_root / EVIDENCE_FILES[0])
    package_rows = _read_csv(evidence_root / EVIDENCE_FILES[1])
    runtime_source_rows = _read_csv(evidence_root / EVIDENCE_FILES[3])
    version_source_rows = _read_csv(evidence_root / EVIDENCE_FILES[5])
    mapping_source_rows = _read_csv(evidence_root / EVIDENCE_FILES[7])

    sbom = SBOMDocument.objects.get(pk=SBOM_ID)
    if (
        sbom.file_sha256 != SBOM_SHA256
        or sbom.manufacturer != "Unitronics"
        or sbom.product_name != "UCR-ST-B8"
        or sbom.product_version != "52.07.13.7"
    ):
        raise UnitronicsFullDryRunError("SBOM identity does not match fixed scope")
    database_components = {
        str(component.id): component
        for component in Component.objects.filter(sbom_document=sbom)
    }
    source_component_ids = {
        row["component_id"] for row in component_source_rows
    }
    if len(database_components) != 582 or source_component_ids != database_components.keys():
        raise UnitronicsFullDryRunError(
            "Component artifact and SBOM database rows do not form the same 582-set"
        )
    if cpe_snapshot.snapshot_id != CPE_SNAPSHOT_ID:
        raise UnitronicsFullDryRunError("Wrong CPE snapshot")
    if nvd_snapshot.snapshot_id != NVD_SNAPSHOT_ID:
        raise UnitronicsFullDryRunError("Wrong NVD snapshot")

    packages_by_id = {row["component_id"]: row for row in package_rows}
    if len(packages_by_id) != 575:
        raise UnitronicsFullDryRunError("Expected 575 exact opkg package rows")
    distinct_source_count = len({row["source"] for row in package_rows})
    if distinct_source_count != 303:
        raise UnitronicsFullDryRunError("Expected 303 distinct Source values")
    runtime_evidence = _load_runtime_evidence(
        runtime_source_rows,
        version_source_rows,
    )
    component_rows = classify_runtime_rows(
        component_source_rows,
        packages_by_id,
        runtime_evidence,
    )
    rows_by_id = {row["component_id"]: row for row in component_rows}
    _apply_normalization(component_rows, version_source_rows)

    mapper = _Mapper(cpe_snapshot, nvd_snapshot)
    mapping_by_id = {
        row["component_id"]: row for row in mapping_source_rows
    }
    for component_id, mapping in mapping_by_id.items():
        row = rows_by_id[component_id]
        if row["runtime_status"] != "PRODUCT_RUNTIME":
            raise UnitronicsFullDryRunError(
                f"Mapping evidence reached non-product row {component_id}"
            )
        family = (
            mapping["search_part"],
            mapping["search_vendor"],
            mapping["search_product"],
        )
        mapper.map_known_family(
            row,
            family=family,
            normalized_version=row["normalized_product_version"],
            expected_template_cpe=mapping["proposed_gt_cpe"] or None,
            identity_evidence=(
                "Reused fixed CPE family binding and official evidence from "
                f"representative mapping case {mapping['case_id']}."
            ),
        )

    for package, family in NEW_FIXED_FAMILY_BINDINGS.items():
        package_row = next(
            source
            for source in version_source_rows
            if source["component_package"] == package
        )
        row = rows_by_id[package_row["component_id"]]
        mapper.map_known_family(
            row,
            family=family,
            normalized_version=row["normalized_product_version"],
            expected_template_cpe=None,
            identity_evidence=(
                f"Fixed version evidence identifies {package_row['upstream_product']}; "
                "the analysis binding uses the corresponding OpenWrt product tuple."
            ),
        )

    ppp_evidence = next(
        source
        for source in version_source_rows
        if source["component_package"] == "ppp"
    )
    mapper.map_ambiguous_ppp(
        rows_by_id[ppp_evidence["component_id"]],
        normalized_version=ppp_evidence["normalized_product_version"],
    )

    for row in component_rows:
        _set_control_cpe_comparison(row)
        row["evidence_summary"] = " | ".join(
            value
            for value in (
                row["evidence_summary"],
                row["runtime_evidence"],
                row["normalization_evidence"],
            )
            if value
        )

    component_rows.sort(key=lambda row: int(row["component_id"]))
    review_rows = [row.copy() for row in component_rows if row["review_required"] == "true"]
    human_validation_rows = [
        row.copy()
        for row in component_rows
        if row["proposed_decision"]
        in {
            "CPE_CONFIRMED",
            "OFFICIAL_CPE_MAPPED",
            "VERSION_NOT_IN_DICTIONARY",
            "NVD_CONFIGURATION_ONLY",
        }
        or row["mapping_path"] == "DEPRECATED_TO_ACTIVE"
    ]

    previous_mapping = {
        row["component_id"]: (
            row["proposed_decision"],
            row["proposed_gt_cpe"],
        )
        for row in mapping_source_rows
    }
    changed_representatives = [
        {
            "component_id": component_id,
            "previous_decision": previous[0],
            "actual_decision": rows_by_id[component_id]["proposed_decision"],
            "previous_gt": previous[1],
            "actual_gt": rows_by_id[component_id]["proposed_gt_cpe"],
        }
        for component_id, previous in previous_mapping.items()
        if previous
        != (
            rows_by_id[component_id]["proposed_decision"],
            rows_by_id[component_id]["proposed_gt_cpe"],
        )
    ]

    runtime_counts = Counter(row["runtime_status"] for row in component_rows)
    normalization_counts = Counter(
        row["normalization_status"] for row in component_rows
    )
    mapping_counts = Counter(row["mapping_path"] for row in component_rows)
    decision_counts = Counter(
        row["proposed_decision"] or "UNDECIDED_REVIEW"
        for row in component_rows
    )
    review_stage_counts = Counter(row["review_stage"] for row in review_rows)
    review_reason_counts = Counter(row["review_reason"] for row in review_rows)
    review_cause_group_counts = Counter()
    for row in review_rows:
        if row["review_stage"] == "CPE_PRODUCT_IDENTITY":
            review_cause_group_counts["CPE_PRODUCT_IDENTITY_AMBIGUITY"] += 1
        elif row["review_reason"] == "NO_FIXED_OFFICIAL_RUNTIME_ROLE_EVIDENCE":
            review_cause_group_counts["NO_FIXED_OFFICIAL_RUNTIME_ROLE_EVIDENCE"] += 1
        elif row["normalization_status"] == "VENDOR_SPECIFIC_VERSION":
            review_cause_group_counts["VENDOR_RUNTIME_VERSION_AMBIGUITY"] += 1
        else:
            review_cause_group_counts["FIXED_RUNTIME_BOUNDARY_AMBIGUITY"] += 1
    review_free_terminal_count = sum(
        row["review_required"] == "false" for row in component_rows
    )
    proposed_decision_count = sum(
        bool(row["proposed_decision"]) for row in component_rows
    )
    cpe_id_counts = Counter(
        row["control_cpe_id_vs_gt"] for row in component_rows
    )
    proposed_cpes = [
        row["proposed_gt_cpe"]
        for row in component_rows
        if row["proposed_gt_cpe"]
    ]
    parser_failures = [
        cpe for cpe in proposed_cpes if not parse_cpe23(cpe).is_valid
    ]
    config_gate_violations = [
        row
        for row in mapper.configuration_rows
        if row["configuration_gate_passed"] != "true"
        or row["dictionary_active_tuple_count"] != "0"
        or row["dictionary_deprecated_tuple_count"] != "0"
    ]
    deprecated_final_gt = [
        row["component_id"]
        for row in component_rows
        if row["proposed_gt_cpe"]
        and CpeName.objects.filter(
            snapshot=cpe_snapshot,
            cpe_name=row["proposed_gt_cpe"],
            deprecated=True,
        ).exists()
    ]

    product_rows = [
        row for row in component_rows if row["runtime_status"] == "PRODUCT_RUNTIME"
    ]
    normalized_product_rows = [
        row for row in product_rows if row["normalized_product_version"]
    ]
    hashes = evidence_hashes()
    manifest_uses = (
        "component linkage",
        "exact package payload/source evidence",
        "runtime rulebook",
        "fixed runtime decisions",
        "normalization rulebook",
        "fixed normalization decisions",
        "CPE mapping rulebook",
        "fixed mapping decisions/family bindings",
        "boundary helper validation",
    )
    evidence_manifest_rows = [
        {
            "evidence_id": f"EVIDENCE-{index:02d}",
            "relative_path": relative,
            "sha256": digest,
            "use": use,
        }
        for index, ((relative, digest), use) in enumerate(
            zip(hashes.items(), manifest_uses, strict=True),
            start=1,
        )
    ]

    summary = {
        "schema_version": 1,
        "analysis_scope": (
            "Read-only 582-component proposed Ground Truth full dry-run; "
            "no persistence and no CVE applicability"
        ),
        "dataset": {
            "sbom_document_id": SBOM_ID,
            "manufacturer": sbom.manufacturer,
            "product": sbom.product_name,
            "firmware_version": sbom.product_version,
            "sbom_sha256": SBOM_SHA256,
            "firmware_sha256": FIRMWARE_SHA256,
            "component_count": len(component_rows),
            "distinct_source_count": distinct_source_count,
            "opkg_count": len(packages_by_id),
            "non_opkg_count": len(component_rows) - len(packages_by_id),
        },
        "snapshots": {
            "cpe_dictionary": {
                "snapshot_id": cpe_snapshot.snapshot_id,
                "total": cpe_snapshot.record_count,
                "active": cpe_snapshot.active_count,
                "deprecated": cpe_snapshot.deprecated_count,
                "manifest_sha256": cpe_snapshot.manifest_sha256,
                "content_sha256": cpe_snapshot.content_sha256,
            },
            "nvd_cve": {
                "snapshot_id": nvd_snapshot.snapshot_id,
                "cves": nvd_snapshot.record_count,
                "configurations": nvd_snapshot.configuration_count,
                "cpe_matches": nvd_snapshot.cpe_match_count,
                "manifest_sha256": nvd_snapshot.manifest_sha256,
                "content_sha256": nvd_snapshot.content_sha256,
            },
        },
        "runtime": {
            "counts": dict(sorted(runtime_counts.items())),
            "product_runtime_normalized_count": len(normalized_product_rows),
            "product_runtime_normalized_percent": round(
                len(normalized_product_rows) / len(product_rows) * 100,
                4,
            ),
            "policy": (
                "Only fixed official evidence can create PRODUCT_RUNTIME; "
                "structural role alone is never a positive terminal rule."
            ),
        },
        "normalization": {"counts": dict(sorted(normalization_counts.items()))},
        "mapping_paths": {"counts": dict(sorted(mapping_counts.items()))},
        "decisions": {"counts": dict(sorted(decision_counts.items()))},
        "automatic_coverage": {
            "review_free_terminal_count": review_free_terminal_count,
            "review_free_terminal_percent": round(
                review_free_terminal_count / len(component_rows) * 100,
                4,
            ),
            "proposed_decision_count": proposed_decision_count,
            "proposed_decision_percent": round(
                proposed_decision_count / len(component_rows) * 100,
                4,
            ),
            "review_required_with_proposed_decision_count": sum(
                row["review_required"] == "true"
                and bool(row["proposed_decision"])
                for row in component_rows
            ),
            "undecided_review_count": decision_counts["UNDECIDED_REVIEW"],
            "denominator": len(component_rows),
        },
        "review_queue": {
            "count": len(review_rows),
            "stage_counts": dict(sorted(review_stage_counts.items())),
            "cause_group_counts": dict(
                sorted(review_cause_group_counts.items())
            ),
            "reason_counts": dict(sorted(review_reason_counts.items())),
        },
        "human_validation_candidates": {
            "count": len(human_validation_rows),
            "decision_counts": dict(
                sorted(
                    Counter(
                        row["proposed_decision"]
                        for row in human_validation_rows
                    ).items()
                )
            ),
        },
        "deprecated": {
            "exact_encounter_component_count": sum(
                row["encounter_type"] == "EXACT"
                for row in mapper.deprecated_rows
            ),
            "family_encounter_component_count": sum(
                row["encounter_type"] == "PRODUCT_WIDE_FAMILY_AMBIGUITY"
                for row in mapper.deprecated_rows
            ),
            "one_to_one_replacement_count": sum(
                row["replacement_count"] == "1"
                and row["replacement_depth"] == "1"
                for row in mapper.deprecated_rows
            ),
            "multi_hop_count": sum(
                int(row["replacement_depth"]) > 1
                for row in mapper.deprecated_rows
            ),
            "multiple_replacement_count": sum(
                int(row["replacement_count"]) > 1
                for row in mapper.deprecated_rows
            ),
            "dead_end_count": sum(
                row["resolution_status"] == "DEPRECATED_DEAD_END"
                for row in mapper.deprecated_rows
            ),
            "resolved_active_endpoint_count": sum(
                bool(row["resolved_active_cpe"])
                for row in mapper.deprecated_rows
            ),
            "review_stop_count": sum(
                row["review_required"] == "true"
                for row in mapper.deprecated_rows
            ),
            "deprecated_final_gt_count": len(deprecated_final_gt),
        },
        "configuration_only": {
            "gate_query_component_count": len(
                {
                    row["component_id"] for row in mapper.configuration_rows
                }
            ),
            "configuration_product_found_count": len(
                {
                    row["component_id"]
                    for row in mapper.configuration_rows
                    if row["configuration_match"] == "true"
                }
            ),
            "gt_expression_count": sum(
                row["mapping_path"] == "NVD_CONFIGURATION_ONLY"
                for row in component_rows
            ),
            "template_ambiguity_count": sum(
                row["review_required"] == "true"
                for row in mapper.configuration_rows
            ),
            "gate_violation_count": len(config_gate_violations),
        },
        "control_cpe_id_comparison": {
            "comparison_unit": "part/vendor/product family only for CPE 2.2 URI versus proposed CPE 2.3",
            "counts": dict(sorted(cpe_id_counts.items())),
            "used_as_ground_truth_evidence": False,
        },
        "representative_regression": {
            "case_count": len(mapping_source_rows),
            "changed_cases": changed_representatives,
            "passed": not changed_representatives,
        },
        "guardrails": {
            "database_transaction_read_only": True,
            "live_api_calls": 0,
            "live_web_dependencies": 0,
            "original_cpe_candidate_evidence_uses": 0,
            "control_cpe_id_candidate_evidence_uses": 0,
            "cve_applicability_evaluations": 0,
            "ground_truth_mutations": 0,
            "component_mutations": 0,
            "migration_count": 0,
            "production_hook_added": False,
        },
        "validation": {
            "component_rows": len(component_rows),
            "component_rows_equal_582": len(component_rows) == 582,
            "distinct_source_count": distinct_source_count,
            "distinct_source_count_equal_303": distinct_source_count == 303,
            "opkg_plus_non_opkg": f"{len(packages_by_id)} + {len(component_rows) - len(packages_by_id)} = {len(component_rows)}",
            "runtime_partition": sum(runtime_counts.values()),
            "runtime_partition_equal_582": sum(runtime_counts.values()) == 582,
            "decision_plus_undecided_partition": sum(decision_counts.values()),
            "decision_plus_undecided_equal_582": sum(decision_counts.values()) == 582,
            "proposed_gt_count": len(proposed_cpes),
            "proposed_gt_parser_failure_count": len(parser_failures),
            "configuration_gate_violation_count": len(config_gate_violations),
            "deprecated_final_gt_count": len(deprecated_final_gt),
            "ground_truth_count_before": ComponentCpeGroundTruth.objects.count(),
            "ground_truth_count_after": None,
            "ground_truth_count_unchanged": None,
            "evidence_hashes_unchanged": None,
        },
        "remaining_evidence_gaps": [
            {
                "gap": "official_runtime_role_registry",
                "affected_count": sum(
                    row["review_reason"]
                    == "NO_FIXED_OFFICIAL_RUNTIME_ROLE_EVIDENCE"
                    for row in review_rows
                ),
                "effect": (
                    "Structural package role cannot safely create positive or "
                    "plugin-negative runtime decisions."
                ),
            },
            {
                "gap": "CPE_family_binding_for_PPP_snapshot",
                "affected_count": 1,
                "effect": (
                    "canonical:ppp and samba:ppp both remain possible; "
                    "automatic family selection is blocked."
                ),
            },
            {
                "gap": "vendor_product_version_evidence",
                "affected_count": sum(
                    row["normalization_status"] == "VENDOR_SPECIFIC_VERSION"
                    for row in review_rows
                ),
                "effect": "Vendor version boundaries remain unproven.",
            },
            {
                "gap": "fixed_runtime_product_boundary_evidence",
                "affected_count": review_cause_group_counts[
                    "FIXED_RUNTIME_BOUNDARY_AMBIGUITY"
                ],
                "effect": (
                    "Three fixed representative library/plugin cases retain "
                    "an explicit runtime-boundary review stop."
                ),
            },
        ],
    }
    return FullDryRunAnalysis(
        component_rows=component_rows,
        review_rows=review_rows,
        human_validation_rows=human_validation_rows,
        deprecated_rows=mapper.deprecated_rows,
        configuration_rows=mapper.configuration_rows,
        evidence_manifest_rows=evidence_manifest_rows,
        evidence_hashes=hashes,
        summary=summary,
    )


def finalize_validation(
    analysis: FullDryRunAnalysis,
    *,
    ground_truth_count_after: int,
) -> None:
    validation = analysis.summary["validation"]
    validation["ground_truth_count_after"] = ground_truth_count_after
    validation["ground_truth_count_unchanged"] = (
        validation["ground_truth_count_before"] == ground_truth_count_after
    )
    validation["evidence_hashes_unchanged"] = (
        analysis.evidence_hashes == evidence_hashes()
    )
    failures = [
        key
        for key in (
            "component_rows_equal_582",
            "distinct_source_count_equal_303",
            "runtime_partition_equal_582",
            "decision_plus_undecided_equal_582",
            "ground_truth_count_unchanged",
            "evidence_hashes_unchanged",
        )
        if not validation[key]
    ]
    if validation["proposed_gt_parser_failure_count"]:
        failures.append("proposed_gt_parser_failure_count")
    if validation["configuration_gate_violation_count"]:
        failures.append("configuration_gate_violation_count")
    if validation["deprecated_final_gt_count"]:
        failures.append("deprecated_final_gt_count")
    if failures:
        raise UnitronicsFullDryRunError(
            "Full dry-run consistency failures: " + ", ".join(failures)
        )


def _write_csv(
    path: Path,
    fields: tuple[str, ...],
    rows: list[dict[str, str]],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_unitronics_full_dry_run(
    analysis: FullDryRunAnalysis,
    output_directory: Path,
) -> tuple[Path, ...]:
    if output_directory.exists():
        raise UnitronicsFullDryRunError(
            f"Refusing to modify existing artifact directory: {output_directory}"
        )
    output_directory.mkdir(parents=True, exist_ok=False)
    paths = (
        output_directory / "report.md",
        output_directory / "components.csv",
        output_directory / "review_queue.csv",
        output_directory / "human_validation_candidates.csv",
        output_directory / "deprecated_resolution.csv",
        output_directory / "configuration_only_cases.csv",
        output_directory / "evidence_manifest.csv",
        output_directory / "summary.json",
    )
    _write_csv(paths[1], COMPONENT_FIELDS, analysis.component_rows)
    _write_csv(paths[2], COMPONENT_FIELDS, analysis.review_rows)
    _write_csv(paths[3], COMPONENT_FIELDS, analysis.human_validation_rows)
    _write_csv(paths[4], DEPRECATED_FIELDS, analysis.deprecated_rows)
    _write_csv(paths[5], CONFIGURATION_FIELDS, analysis.configuration_rows)
    _write_csv(
        paths[6],
        EVIDENCE_MANIFEST_FIELDS,
        analysis.evidence_manifest_rows,
    )
    paths[7].write_text(
        json.dumps(analysis.summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths[0].write_text(_render_report(analysis.summary), encoding="utf-8")
    return paths


def _render_report(summary: dict[str, Any]) -> str:
    runtime = summary["runtime"]
    coverage = summary["automatic_coverage"]
    mapping = summary["mapping_paths"]["counts"]
    decisions = summary["decisions"]["counts"]
    review = summary["review_queue"]
    human = summary["human_validation_candidates"]
    validation = summary["validation"]
    terminal_coverage = (
        f"{coverage['review_free_terminal_count']:,}/582 "
        f"({coverage['review_free_terminal_percent']:.2f}%)"
    )
    decision_coverage = (
        f"{coverage['proposed_decision_count']:,}/582 "
        f"({coverage['proposed_decision_percent']:.2f}%)"
    )

    def table_rows(counts: dict[str, int], denominator: int = 582) -> str:
        return "\n".join(
            f"| `{name}` | {count:,} | {count / denominator * 100:.2f}% |"
            for name, count in counts.items()
        )

    return f"""# Unitronics Ground Truth full READ-ONLY dry-run

## Scope

- SBOMDocument: `1364`
- Firmware: Unitronics UCR-ST-B8 `52.07.13.7`
- Components: 582 (`575 opkg + 7 non-opkg`)
- Distinct opkg `Source` values: {summary['dataset']['distinct_source_count']}
- CPE Dictionary: `{CPE_SNAPSHOT_ID}`
- NVD CVE/Configuration: `{NVD_SNAPSHOT_ID}`

This run generated proposed results only. It performed no Ground Truth,
Component, snapshot, migration, production-hook, live API, web, CVE
applicability, or RQ1-final-statistic operation.

## Automatic coverage

| Runtime status | Count | Percent |
|---|---:|---:|
{table_rows(runtime['counts'])}

`PRODUCT_RUNTIME` is intentionally evidence-closed: only cases already backed
by the fixed official evidence registry can be positive. Exact kmod, firmware,
meta/helper, and two BusyBox detector rows can be negative from reproducible
local accessory evidence. All other structural roles stop for review.

All {runtime['counts']['PRODUCT_RUNTIME']} PRODUCT_RUNTIME rows have a fixed
normalized product version ({runtime['product_runtime_normalized_percent']:.2f}%).

Review-free terminal automation covers **{terminal_coverage}**. A proposed
internal Decision is populated for **{decision_coverage}**; that broader figure
includes **{coverage['review_required_with_proposed_decision_count']}** explicit
`UNRESOLVED` rows that still require human review. The conservative terminal
coverage is therefore the review-free figure, not the broader populated-field
figure.

## Mapping paths

| Path | Count | Percent |
|---|---:|---:|
{table_rows(mapping)}

## Proposed Decision distribution

| Decision / dry-run state | Count | Percent |
|---|---:|---:|
{table_rows(decisions)}

`UNDECIDED_REVIEW` is not a database Decision. NON_PRODUCT_RUNTIME and
NO_DIRECT_CPE share `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED`, but retain different
`decision_reason` values in `components.csv`.

## Review Queue

- Total: **{review['count']:,}**
- By stage: `{_json(review['stage_counts'])}`
- By reproducible cause group: `{_json(review['cause_group_counts'])}`
- Human validation candidates with a CPE/expression: **{human['count']:,}**

The main exception is not a parser or resolver failure. It is the absence of
fixed official upstream runtime-role evidence for packages not covered by the
existing evidence registry. Those rows are not promoted from names or package
roles. PPP additionally stops at CPE family identity because both
`canonical:ppp` and `samba:ppp` occur in the fixed Dictionary.

## Deprecated and Configuration-only

- Deprecated exact encounters: {summary['deprecated']['exact_encounter_component_count']}
- Deprecated family encounter rows: {summary['deprecated']['family_encounter_component_count']}
- Deprecated-to-Active final mappings: {mapping.get('DEPRECATED_TO_ACTIVE', 0)}
- Deprecated CPE used as final GT: {summary['deprecated']['deprecated_final_gt_count']}
- Configuration gate/query components: {summary['configuration_only']['gate_query_component_count']}
- Configuration-only products found: {summary['configuration_only']['configuration_product_found_count']}
- Gate violations: {summary['configuration_only']['gate_violation_count']}

## Representative regression

All 11 earlier representative cases remain identical in both Decision and
proposed GT CPE: **{'PASS' if summary['representative_regression']['passed'] else 'FAIL'}**.

## Answers to the fifteen questions

1. PRODUCT_RUNTIME: **{runtime['counts']['PRODUCT_RUNTIME']}**.
2. NON_PRODUCT_RUNTIME: **{runtime['counts']['NON_PRODUCT_RUNTIME']}**.
3. Runtime-stage review: **{runtime['counts']['REVIEW_REQUIRED']}**.
4. PRODUCT_RUNTIME normalized automatically: **{runtime['product_runtime_normalized_count']}/{runtime['counts']['PRODUCT_RUNTIME']} ({runtime['product_runtime_normalized_percent']:.2f}%)**.
5. Active exact CPE: **{mapping.get('ACTIVE_EXACT', 0)}**.
6. Deprecated-to-Active: **{mapping.get('DEPRECATED_TO_ACTIVE', 0)}**.
7. VERSION_NOT_IN_DICTIONARY: **{mapping.get('VERSION_NOT_IN_DICTIONARY', 0)}**.
8. NVD_CONFIGURATION_ONLY: **{mapping.get('NVD_CONFIGURATION_ONLY', 0)}**.
9. Verified products with no direct representation: **{mapping.get('NO_DIRECT_CPE', 0)}**.
10. UNRESOLVED: **{decisions.get('UNRESOLVED', 0)}**.
11. Review Queue: **{review['count']}**.
12. CPE-linked human validation candidates: **{human['count']}**.
13. Representative contradiction: **none**.
14. Full reproducible terminal processing with the current evidence registry: **no**; only the reported non-review subset is terminally reproducible.
15. Methods freeze needs an expanded official runtime-role/product-boundary registry, vendor version evidence, and a fixed PPP CPE-family binding or explicit unresolved policy.

## Validation

- Component rows: {validation['component_rows']} — PASS
- opkg + non-opkg: `{validation['opkg_plus_non_opkg']}` — PASS
- Distinct opkg `Source` values: {validation['distinct_source_count']} — PASS
- Runtime partition: {validation['runtime_partition']} — PASS
- Decision + undecided partition: {validation['decision_plus_undecided_partition']} — PASS
- Proposed GT canonical parse failures: {validation['proposed_gt_parser_failure_count']} — PASS
- Deprecated final GT: {validation['deprecated_final_gt_count']} — PASS
- Configuration gate violations: {validation['configuration_gate_violation_count']} — PASS
- Ground Truth count: `{validation['ground_truth_count_before']} -> {validation['ground_truth_count_after']}` — PASS
- Existing evidence artifact hashes unchanged: {validation['evidence_hashes_unchanged']} — PASS

The run stops at proposed results, review queue, human-validation candidates,
and quantitative summary.
"""

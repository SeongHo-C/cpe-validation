from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from django.conf import settings

from cpe.cpe23_canonical import (
    CPE23CanonicalizationError,
    canonicalize_cpe23,
    parse_cpe23,
)
from sboms.models import Component, ComponentCpeGroundTruth
from sboms.unitronics_ground_truth_db_application import (
    AUDIT_RESULTS_RELATIVE,
    CANDIDATE_COMPONENTS_RELATIVE,
    CPE_SNAPSHOT_ID,
    DATASET_KEY,
    EXPECTED_ARTIFACT_HASHES,
    SBOM_DOCUMENT_ID,
    _component_fingerprint,
    load_application_plan,
)


OUTPUT_RELATIVE = (
    "analysis/results/unitronics-ground-truth-duplicate-cpe-audit/"
    f"{DATASET_KEY}"
)
SOURCE_PACKAGES_RELATIVE = (
    "analysis/results/unitronics-source-package-analysis/"
    f"{DATASET_KEY}/packages.csv"
)
PREANALYSIS_RELATIVE = (
    "analysis/results/unitronics-ground-truth-preanalysis/"
    f"{DATASET_KEY}/components.csv"
)

KEEP_GT_CPE = "KEEP_GT_CPE"
REMOVE_DUPLICATED_GT_CPE = "REMOVE_DUPLICATED_GT_CPE"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
NO_DIRECT_CPE = "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"


class UnitronicsDuplicateCpeAuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class GroupDecision:
    group_id: str
    status: str
    representative: str
    remove: tuple[str, ...]
    review: tuple[str, ...]
    same_source_upstream: str
    boundary_finding: str
    representative_basis: str
    derived_packages: str
    independent_cpe_products: str
    evidence_summary: str


GROUP_DECISIONS = {
    "cpe:2.3:a:libcap_project:libcap:2.69:*:*:*:*:*:*:*": GroupDecision(
        group_id="DUP-01",
        status="KEEP_SINGLE_REPRESENTATIVE",
        representative="libcap",
        remove=("libcap-bin",),
        review=(),
        same_source_upstream=(
            "YES: both packages are version 2.69-1 from package/libs/libcap "
            "and identify upstream libcap 2.69."
        ),
        boundary_finding=(
            "libcap owns the core libcap shared library; libcap-bin is an "
            "explicit utility split containing setcap/getcap/getpcaps/capsh."
        ),
        representative_basis=(
            "libcap aligns with the upstream product name and provides "
            "libcap.so.2.69; libcap-bin depends on libcap."
        ),
        derived_packages="libcap-bin: utility/CLI split",
        independent_cpe_products=(
            "NO: no evidence identifies libcap-bin as a separate CPE product."
        ),
        evidence_summary=(
            "Exact control/list evidence gives libcap three library paths and "
            "libcap-bin four utility executables; Source and normalized version "
            "are identical."
        ),
    ),
    "cpe:2.3:a:lua:lua:5.1.5:*:*:*:*:*:*:*": GroupDecision(
        group_id="DUP-02",
        status="KEEP_SINGLE_REPRESENTATIVE",
        representative="lua",
        remove=("liblua5.1.5",),
        review=(),
        same_source_upstream=(
            "YES: both packages are version 5.1.5-9 from package/utils/lua "
            "and identify upstream Lua 5.1.5."
        ),
        boundary_finding=(
            "lua is the upstream-name-aligned language interpreter package; "
            "liblua5.1.5 is the shared-library split used by other programs."
        ),
        representative_basis=(
            "lua owns /usr/bin/lua and /usr/bin/lua5.1, is name-aligned, and "
            "depends on liblua5.1.5."
        ),
        derived_packages="liblua5.1.5: library split",
        independent_cpe_products=(
            "NO: the fixed Dictionary evidence identifies Lua, not a separate "
            "liblua5.1.5 CPE product."
        ),
        evidence_summary=(
            "Exact control/list evidence distinguishes the interpreter package "
            "from its one-file shared-library dependency."
        ),
    ),
    "cpe:2.3:a:netfilter:ipset:7.6:*:*:*:*:*:*:*": GroupDecision(
        group_id="DUP-03",
        status="KEEP_SINGLE_REPRESENTATIVE",
        representative="ipset",
        remove=("libipset13",),
        review=(),
        same_source_upstream=(
            "YES: both packages are version 7.6-1 from "
            "package/network/utils/ipset and identify upstream ipset 7.6."
        ),
        boundary_finding=(
            "ipset is the name-aligned administration utility; libipset13 is "
            "the shared-library split."
        ),
        representative_basis=(
            "ipset owns /usr/sbin/ipset and depends on libipset13; its name and "
            "payload directly represent the CPE product."
        ),
        derived_packages="libipset13: library split",
        independent_cpe_products=(
            "NO: no separate libipset13 CPE product was established."
        ),
        evidence_summary=(
            "The package pair consists of one canonical executable and two "
            "libipset.so paths from the same Source/version."
        ),
    ),
    "cpe:2.3:a:netfilter:iptables:1.8.7:*:*:*:*:*:*:*": GroupDecision(
        group_id="DUP-04",
        status="KEEP_SINGLE_REPRESENTATIVE",
        representative="iptables",
        remove=("ip6tables",),
        review=(),
        same_source_upstream=(
            "YES: both packages are version 1.8.7-3 from "
            "package/network/utils/iptables and identify upstream iptables 1.8.7."
        ),
        boundary_finding=(
            "iptables is the name-aligned primary firewall administration "
            "package; ip6tables is the IPv6 utility split and depends on iptables."
        ),
        representative_basis=(
            "iptables owns the canonical iptables/xtables executables and is "
            "the Source-name-aligned package."
        ),
        derived_packages="ip6tables: IPv6 utility/CLI split",
        independent_cpe_products=(
            "NO: the exact CPE product is iptables and no independent ip6tables "
            "CPE product was established."
        ),
        evidence_summary=(
            "Exact lists separate iptables executables from ip6tables executables; "
            "dependency and naming identify the latter as a split."
        ),
    ),
    "cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*": GroupDecision(
        group_id="DUP-05",
        status="REPRESENTATIVE_AMBIGUOUS",
        representative="",
        remove=(),
        review=("libopenssl3", "openssl-util"),
        same_source_upstream=(
            "YES: both packages are version 3.0.14-3 from package/libs/openssl "
            "and identify upstream OpenSSL 3.0.14."
        ),
        boundary_finding=(
            "libopenssl3 contains the core libssl/libcrypto runtime while "
            "openssl-util contains the canonical /usr/bin/openssl CLI; no "
            "installed package named openssl represents both halves."
        ),
        representative_basis=(
            "AMBIGUOUS: the core shared libraries and canonical executable are "
            "both central upstream product payloads, and neither package alone "
            "represents the complete toolkit."
        ),
        derived_packages=(
            "libopenssl3: core library split; openssl-util: canonical CLI split"
        ),
        independent_cpe_products=(
            "NO separate CPE products were established, but evidence is "
            "insufficient to choose one representative component."
        ),
        evidence_summary=(
            "Exact lists show libssl.so.3/libcrypto.so.3 versus /usr/bin/openssl. "
            "openssl-util depends on libopenssl3; both are classified as partial "
            "splits and there is no main package."
        ),
    ),
    "cpe:2.3:a:sqlite:sqlite:3.41.2:*:*:*:*:*:*:*": GroupDecision(
        group_id="DUP-06",
        status="KEEP_SINGLE_REPRESENTATIVE",
        representative="sqlite",
        remove=("libsqlite3-0",),
        review=(),
        same_source_upstream=(
            "PARTIAL: both identify SQLite 3.41.2, but sqlite is a direct "
            "non-opkg artifact while libsqlite3-0 is the owning opkg package."
        ),
        boundary_finding=(
            "Both components point to the same physical core payload, "
            "/usr/lib/libsqlite3.so.0.8.6; libsqlite3-0 is the distribution "
            "library package and sqlite is the upstream-product-aligned direct "
            "artifact."
        ),
        representative_basis=(
            "sqlite directly names the upstream product and was independently "
            "identified from the exact shared-library artifact; retaining both "
            "would double count the same file/product instance."
        ),
        derived_packages="libsqlite3-0: distribution library package",
        independent_cpe_products=(
            "NO: both mappings resolve to the exact sqlite:sqlite CPE and the "
            "same installed library file."
        ),
        evidence_summary=(
            "The libsqlite3-0 .list owns libsqlite3.so.0.8.6, which is the exact "
            "source_path used by the non-opkg sqlite detector component."
        ),
    ),
    "cpe:2.3:a:strongswan:strongswan:5.9.14:-:*:*:*:*:*:*": GroupDecision(
        group_id="DUP-07",
        status="KEEP_SINGLE_REPRESENTATIVE",
        representative="strongswan",
        remove=("strongswan-charon", "strongswan-swanctl"),
        review=(),
        same_source_upstream=(
            "YES: all three packages are version 5.9.14-24 from "
            "package/network/services/strongswan and identify strongSwan 5.9.14."
        ),
        boundary_finding=(
            "strongswan is the Source-name-aligned main package with core "
            "libstrongswan libraries/configuration; strongswan-charon is a split "
            "daemon runtime and strongswan-swanctl is a CLI split."
        ),
        representative_basis=(
            "strongswan is explicitly classified PRODUCT_OR_MAIN_PACKAGE and "
            "DIRECT_PRODUCT_CANDIDATE; both duplicate siblings depend on it."
        ),
        derived_packages=(
            "strongswan-charon: split runtime/daemon; strongswan-swanctl: "
            "utility/CLI split"
        ),
        independent_cpe_products=(
            "NO: neither charon nor swanctl was established as a separate CPE "
            "product in the fixed evidence."
        ),
        evidence_summary=(
            "The 28-package Source has one main package, one split runtime, one "
            "CLI split, and plugin modules; exact dependencies point back to "
            "strongswan."
        ),
    ),
}


def _fail(message: str) -> NoReturn:
    raise UnitronicsDuplicateCpeAuditError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except OSError as error:
        _fail(f"Cannot read {path}: {error}")


def _effective_cpe(record: ComponentCpeGroundTruth) -> str:
    if record.ground_truth_cpe is not None:
        return record.ground_truth_cpe.cpe_name
    return record.manual_ground_truth_cpe


def _ground_truth_fingerprint(
    records: list[ComponentCpeGroundTruth],
) -> str:
    payload = [
        {
            "id": record.id,
            "component_id": record.component_id,
            "snapshot_id": record.snapshot_id,
            "ground_truth_cpe_id": record.ground_truth_cpe_id,
            "manual_ground_truth_cpe": record.manual_ground_truth_cpe,
            "resolution_outcome": record.resolution_outcome,
            "decision": record.decision,
            "note": record.note,
            "created_at": record.created_at.isoformat(),
            "updated_at": record.updated_at.isoformat(),
            "discrepancy_ids": list(
                record.discrepancy_types.values_list("id", flat=True)
            ),
            "correction_ids": list(
                record.correction_types.values_list("id", flat=True)
            ),
        }
        for record in records
    ]
    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def current_database_state() -> dict[str, Any]:
    components = list(
        Component.objects.filter(sbom_document_id=SBOM_DOCUMENT_ID).order_by(
            "id"
        )
    )
    records = list(
        ComponentCpeGroundTruth.objects.filter(
            component__sbom_document_id=SBOM_DOCUMENT_ID,
            snapshot__snapshot_id=CPE_SNAPSHOT_ID,
        )
        .select_related("ground_truth_cpe")
        .prefetch_related("discrepancy_types", "correction_types")
        .order_by("id")
    )
    return {
        "component_count": len(components),
        "component_fingerprint": _component_fingerprint(components),
        "ground_truth_count": len(records),
        "cpe_bearing_count": sum(bool(_effective_cpe(row)) for row in records),
        "ground_truth_fingerprint": _ground_truth_fingerprint(records),
        "records": records,
    }


def _artifact_hashes(repository_root: Path) -> dict[str, str]:
    relative_paths = (
        CANDIDATE_COMPONENTS_RELATIVE,
        AUDIT_RESULTS_RELATIVE,
        SOURCE_PACKAGES_RELATIVE,
        PREANALYSIS_RELATIVE,
    )
    return {
        relative: _sha256(repository_root / relative)
        for relative in relative_paths
    }


def _group_rows(
    group: list[dict[str, Any]],
    decision: GroupDecision,
) -> dict[str, str | int]:
    names = [item["candidate"].name for item in group]
    representative = next(
        (
            item
            for item in group
            if item["candidate"].name == decision.representative
        ),
        None,
    )
    return {
        "group_id": decision.group_id,
        "canonical_gt_cpe": group[0]["canonical_gt_cpe"],
        "component_count": len(group),
        "component_ids": " | ".join(
            str(item["candidate"].component_id) for item in group
        ),
        "component_names": " | ".join(names),
        "versions": " | ".join(
            item["candidate"].observed_version for item in group
        ),
        "sources": " | ".join(
            sorted({item["source"] for item in group})
        ),
        "actual_product": " | ".join(
            sorted({item["candidate_raw"]["actual_product"] for item in group})
        ),
        "actual_product_version": " | ".join(
            sorted(
                {
                    item["candidate"].actual_product_version
                    for item in group
                }
            )
        ),
        "group_status": decision.status,
        "representative_component_id": (
            representative["candidate"].component_id if representative else ""
        ),
        "representative_component_name": decision.representative,
        "remove_candidate_ids": " | ".join(
            str(item["candidate"].component_id)
            for item in group
            if item["candidate"].name in decision.remove
        ),
        "remove_candidate_names": " | ".join(decision.remove),
        "review_component_ids": " | ".join(
            str(item["candidate"].component_id)
            for item in group
            if item["candidate"].name in decision.review
        ),
        "review_component_names": " | ".join(decision.review),
        "q1_same_source_upstream": decision.same_source_upstream,
        "q2_product_boundary": decision.boundary_finding,
        "q3_representative_basis": decision.representative_basis,
        "q4_derived_packages": decision.derived_packages,
        "q5_independent_cpe_product": decision.independent_cpe_products,
        "evidence_summary": decision.evidence_summary,
    }


def build_duplicate_cpe_audit(
    repository_root: Path | None = None,
) -> dict[str, Any]:
    root = repository_root or settings.REPOSITORY_ROOT
    plan = load_application_plan(root)
    before_state = current_database_state()
    if before_state["component_count"] != 582:
        _fail("Expected 582 Unitronics Components")
    if before_state["ground_truth_count"] != 582:
        _fail("Expected 582 applied Ground Truth records")
    if before_state["cpe_bearing_count"] != 48:
        _fail("Expected 48 CPE-bearing Ground Truth records")

    candidate_raw_rows = _read_csv(root / CANDIDATE_COMPONENTS_RELATIVE)
    candidate_raw_by_id = {
        int(row["component_id"]): row for row in candidate_raw_rows
    }
    source_by_name = {
        row["sbom_name"]: row
        for row in _read_csv(root / SOURCE_PACKAGES_RELATIVE)
    }
    preanalysis_by_name = {
        row["name"]: row for row in _read_csv(root / PREANALYSIS_RELATIVE)
    }
    records_by_component = {
        row.component_id: row for row in before_state["records"]
    }
    if set(records_by_component) != {row.component_id for row in plan.rows}:
        _fail("Candidate and DB Ground Truth component partitions differ")

    db_cpe_mismatches = 0
    db_decision_mismatches = 0
    parse_failure_count = 0
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    near_grouped: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for candidate in plan.rows:
        record = records_by_component[candidate.component_id]
        current_cpe = _effective_cpe(record)
        db_cpe_mismatches += current_cpe != candidate.proposed_gt_cpe
        db_decision_mismatches += record.decision != candidate.proposed_decision
        if not current_cpe:
            continue
        try:
            canonical = canonicalize_cpe23(current_cpe)
        except CPE23CanonicalizationError:
            parse_failure_count += 1
            continue
        parsed = parse_cpe23(canonical)
        if parsed.name is None:
            parse_failure_count += 1
            continue
        fields = parsed.name.fields
        near_grouped[
            (
                fields["part"],
                fields["vendor"],
                fields["product"],
                fields["version"],
            )
        ].add(canonical)
        raw = candidate_raw_by_id[candidate.component_id]
        grouped[canonical].append(
            {
                "candidate": candidate,
                "candidate_raw": raw,
                "record": record,
                "canonical_gt_cpe": canonical,
                "source": raw["source"],
            }
        )
    if db_cpe_mismatches or db_decision_mismatches:
        _fail(
            "Candidate-to-DB mismatch: "
            f"CPE={db_cpe_mismatches}, decision={db_decision_mismatches}"
        )
    if parse_failure_count:
        _fail(f"Canonical CPE parse failures: {parse_failure_count}")
    if sum(len(group) for group in grouped.values()) != 48:
        _fail("Canonical grouping did not cover all 48 CPE-bearing records")

    duplicate_groups = {
        cpe: group for cpe, group in grouped.items() if len(group) >= 2
    }
    if set(duplicate_groups) != set(GROUP_DECISIONS):
        _fail(
            "Duplicate group set differs from the reviewed registry: "
            f"actual={sorted(duplicate_groups)}, "
            f"expected={sorted(GROUP_DECISIONS)}"
        )
    for cpe, group in duplicate_groups.items():
        actual_names = {item["candidate"].name for item in group}
        decision = GROUP_DECISIONS[cpe]
        expected_names = {
            name
            for name in (
                decision.representative,
                *decision.remove,
                *decision.review,
            )
            if name
        }
        if actual_names != expected_names:
            _fail(
                f"Reviewed component boundary mismatch for {cpe}: "
                f"actual={actual_names}, expected={expected_names}"
            )

    group_rows = [
        _group_rows(duplicate_groups[cpe], GROUP_DECISIONS[cpe])
        for cpe in GROUP_DECISIONS
    ]
    component_rows: list[dict[str, Any]] = []
    for canonical, group in sorted(grouped.items()):
        decision = GROUP_DECISIONS.get(canonical)
        for item in sorted(
            group,
            key=lambda value: value["candidate"].component_id,
        ):
            candidate = item["candidate"]
            source = source_by_name.get(candidate.name, {})
            preanalysis = preanalysis_by_name.get(candidate.name, {})
            if decision is None:
                recommendation = KEEP_GT_CPE
                reason = "UNIQUE_CANONICAL_GT_CPE"
                recommended_cpe = canonical
                recommended_result = candidate.proposed_decision
                discrepancy_impact = "UNCHANGED"
                representative_name = candidate.name
                group_id = ""
                group_status = ""
                group_type = "UNIQUE_GT_CPE"
            elif candidate.name in decision.remove:
                recommendation = REMOVE_DUPLICATED_GT_CPE
                reason = "DERIVED_SPLIT_PACKAGE_NO_CPE_INHERITANCE"
                recommended_cpe = ""
                recommended_result = NO_DIRECT_CPE
                discrepancy_impact = "N/A"
                representative_name = decision.representative
                group_id = decision.group_id
                group_status = decision.status
                group_type = "DUPLICATED_GT_CPE"
            elif candidate.name in decision.review:
                recommendation = REVIEW_REQUIRED
                reason = "NO_UNIQUE_PRODUCT_REPRESENTATIVE_ESTABLISHED"
                recommended_cpe = canonical
                recommended_result = candidate.proposed_decision
                discrepancy_impact = "REVIEW_REQUIRED"
                representative_name = ""
                group_id = decision.group_id
                group_status = decision.status
                group_type = "DUPLICATED_GT_CPE"
            else:
                recommendation = KEEP_GT_CPE
                reason = "UPSTREAM_PRODUCT_REPRESENTATIVE"
                recommended_cpe = canonical
                recommended_result = candidate.proposed_decision
                discrepancy_impact = "UNCHANGED"
                representative_name = decision.representative
                group_id = decision.group_id
                group_status = decision.status
                group_type = "DUPLICATED_GT_CPE"
            component_rows.append(
                {
                    "component_id": candidate.component_id,
                    "component_name": candidate.name,
                    "sbom_version": candidate.observed_version,
                    "source": item["source"],
                    "source_name": item["candidate_raw"]["source_name"],
                    "description": item["candidate_raw"]["description"],
                    "depends": source.get(
                        "depends",
                        preanalysis.get("control_dependencies", ""),
                    ),
                    "representative_paths": source.get(
                        "representative_paths",
                        item["candidate_raw"]["payload_summary"],
                    ),
                    "sibling_packages": source.get("sibling_packages", ""),
                    "package_role": source.get(
                        "package_role",
                        preanalysis.get("package_role", "NON_OPKG_DIRECT_ARTIFACT"),
                    ),
                    "product_identity_status": source.get(
                        "product_identity_status",
                        preanalysis.get(
                            "product_identity_status",
                            "DIRECT_BINARY_EVIDENCE",
                        ),
                    ),
                    "actual_product": item["candidate_raw"]["actual_product"],
                    "actual_product_version": candidate.actual_product_version,
                    "canonical_gt_cpe": canonical,
                    "group_type": group_type,
                    "duplicate_group_id": group_id,
                    "duplicate_group_status": group_status,
                    "representative_component": representative_name,
                    "current_gt_cpe": canonical,
                    "recommended_gt_cpe": recommended_cpe,
                    "current_validation_result": candidate.proposed_decision,
                    "recommended_validation_result": recommended_result,
                    "recommendation": recommendation,
                    "reason": reason,
                    "expected_discrepancy_after_change": discrepancy_impact,
                    "exact_firmware_evidence": item["candidate_raw"][
                        "exact_firmware_evidence"
                    ],
                }
            )

    recommendation_counts = Counter(
        row["recommendation"] for row in component_rows
    )
    status_counts = Counter(decision.status for decision in GROUP_DECISIONS.values())
    semantic_near_duplicates = sum(
        len(canonical_values) > 1
        for canonical_values in near_grouped.values()
    )
    artifacts_before = _artifact_hashes(root)
    summary = {
        "schema_version": 1,
        "analysis_scope": (
            "Read-only cross-component duplicate Ground Truth CPE audit of "
            "the fixed 48 CPE-bearing Unitronics records"
        ),
        "dataset": {
            "sbom_document_id": SBOM_DOCUMENT_ID,
            "components": 582,
            "ground_truth_records": 582,
            "cpe_bearing_ground_truth": 48,
            "cpe_dictionary_snapshot": CPE_SNAPSHOT_ID,
        },
        "grouping": {
            "distinct_canonical_gt_cpes": len(grouped),
            "unique_gt_cpe_groups": sum(len(group) == 1 for group in grouped.values()),
            "duplicated_gt_cpe_groups": len(duplicate_groups),
            "components_in_duplicate_groups": sum(
                len(group) for group in duplicate_groups.values()
            ),
            "semantic_near_duplicate_groups": semantic_near_duplicates,
            "canonical_parse_failure_count": parse_failure_count,
        },
        "duplicate_group_status_counts": {
            status: status_counts.get(status, 0)
            for status in (
                "KEEP_SINGLE_REPRESENTATIVE",
                "KEEP_MULTIPLE",
                "REPRESENTATIVE_AMBIGUOUS",
                "DATA_INCONSISTENCY",
            )
        },
        "component_recommendation_counts": {
            recommendation: recommendation_counts.get(recommendation, 0)
            for recommendation in (
                KEEP_GT_CPE,
                REMOVE_DUPLICATED_GT_CPE,
                REVIEW_REQUIRED,
            )
        },
        "representative_components": [
            {
                "group_id": decision.group_id,
                "component": decision.representative,
                "canonical_gt_cpe": cpe,
            }
            for cpe, decision in GROUP_DECISIONS.items()
            if decision.representative
        ],
        "remove_recommendations": [
            {
                "group_id": decision.group_id,
                "components": list(decision.remove),
                "canonical_gt_cpe": cpe,
            }
            for cpe, decision in GROUP_DECISIONS.items()
            if decision.remove
        ],
        "projected_if_recommendations_applied": {
            "current_cpe_bearing_components": 48,
            "projected_cpe_bearing_components": (
                48 - recommendation_counts[REMOVE_DUPLICATED_GT_CPE]
            ),
            "projected_distinct_canonical_gt_cpes": len(grouped),
            "projected_removed_duplicate_mappings": recommendation_counts[
                REMOVE_DUPLICATED_GT_CPE
            ],
            "projected_remaining_duplicate_groups": status_counts[
                "REPRESENTATIVE_AMBIGUOUS"
            ],
        },
        "diagnostic_non_duplicate_cases": {
            "curl_libcurl": (
                "Not an exact or semantic near-duplicate: curl and libcurl use "
                "independently named CPE products."
            ),
            "e2fsprogs": (
                "Only e2fsprogs is CPE-bearing; libext2fs2 did not inherit the "
                "e2fsprogs CPE."
            ),
        },
        "methodology_recommendation": {
            "adopt_once_per_upstream_product_version_rule": True,
            "caveat": (
                "Do not remove exact duplicates mechanically. Require package-"
                "boundary evidence, allow independently identifiable CPE products, "
                "and retain REVIEW_REQUIRED when no unique representative exists."
            ),
        },
        "artifact_hashes_before": artifacts_before,
        "validation": {
            "input_cpe_bearing_equal_48": True,
            "db_ground_truth_equal_582": True,
            "canonical_grouping_coverage_equal_48": True,
            "canonical_parse_failure_count": 0,
            "candidate_db_cpe_mismatch_count": db_cpe_mismatches,
            "candidate_db_decision_mismatch_count": db_decision_mismatches,
            "component_fingerprint_before": before_state[
                "component_fingerprint"
            ],
            "ground_truth_fingerprint_before": before_state[
                "ground_truth_fingerprint"
            ],
        },
    }
    return {
        "summary": summary,
        "group_rows": group_rows,
        "component_rows": sorted(
            component_rows,
            key=lambda row: int(row["component_id"]),
        ),
        "before_state": before_state,
        "artifact_hashes_before": artifacts_before,
    }


def finalize_read_only_validation(
    analysis: dict[str, Any],
    repository_root: Path | None = None,
) -> None:
    root = repository_root or settings.REPOSITORY_ROOT
    after_state = current_database_state()
    before_state = analysis["before_state"]
    artifacts_after = _artifact_hashes(root)
    if (
        after_state["component_count"] != before_state["component_count"]
        or after_state["component_fingerprint"]
        != before_state["component_fingerprint"]
    ):
        _fail("Original Component state changed during the read-only audit")
    if (
        after_state["ground_truth_count"] != before_state["ground_truth_count"]
        or after_state["cpe_bearing_count"] != before_state["cpe_bearing_count"]
        or after_state["ground_truth_fingerprint"]
        != before_state["ground_truth_fingerprint"]
    ):
        _fail("Ground Truth DB state changed during the read-only audit")
    if artifacts_after != analysis["artifact_hashes_before"]:
        _fail("Source candidate/audit evidence changed during the audit")
    validation = analysis["summary"]["validation"]
    validation.update(
        {
            "component_fingerprint_after": after_state[
                "component_fingerprint"
            ],
            "ground_truth_fingerprint_after": after_state[
                "ground_truth_fingerprint"
            ],
            "original_component_mutation_count": 0,
            "ground_truth_db_mutation_count": 0,
            "candidate_artifact_modification_count": 0,
            "cpe_audit_artifact_modification_count": 0,
            "migration_count": 0,
        }
    )
    analysis["summary"]["artifact_hashes_after"] = artifacts_after


def _report(analysis: dict[str, Any]) -> str:
    summary = analysis["summary"]
    grouping = summary["grouping"]
    statuses = summary["duplicate_group_status_counts"]
    recommendations = summary["component_recommendation_counts"]
    projected = summary["projected_if_recommendations_applied"]
    group_sections: list[str] = []
    components_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in analysis["component_rows"]:
        if row["duplicate_group_id"]:
            components_by_group[row["duplicate_group_id"]].append(row)
    for group in analysis["group_rows"]:
        component_lines = "\n".join(
            (
                f"| {row['component_id']} | `{row['component_name']}` | "
                f"`{row['package_role']}` | `{row['current_validation_result']}` | "
                f"`{row['recommendation']}` | "
                f"`{row['recommended_validation_result']}` |"
            )
            for row in components_by_group[group["group_id"]]
        )
        group_sections.append(
            f"""### {group['group_id']} — `{group['canonical_gt_cpe']}`

- Status: `{group['group_status']}`
- Q1 — Same Source/upstream: {group['q1_same_source_upstream']}
- Q2 — Product boundary: {group['q2_product_boundary']}
- Q3 — Representative: {group['q3_representative_basis']}
- Q4 — Derived packages: {group['q4_derived_packages']}
- Q5 — Independent CPE product: {group['q5_independent_cpe_product']}
- Evidence: {group['evidence_summary']}

| ID | Component | Package role | Current result | Recommendation | Recommended result |
|---:|---|---|---|---|---|
{component_lines}
"""
        )
    representatives = ", ".join(
        f"`{item['component']}` ({item['group_id']})"
        for item in summary["representative_components"]
    )
    validation = summary["validation"]
    return f"""# Unitronics Ground Truth Duplicate CPE Audit

## Audit scope and result

This is a read-only cross-component audit of the 48 CPE-bearing Ground Truth
records for SBOMDocument `1364`. Original SBOM CPE and firmware control CPE-ID
were excluded from product-boundary reasoning. Existing candidate/audit results
were used for identity and provenance, but their prior `ACCEPTED` status was not
treated as an answer to cross-component duplication.

| Metric | Count |
|---|---:|
| CPE-bearing Ground Truth Components | 48 |
| Distinct canonical GT CPEs | {grouping['distinct_canonical_gt_cpes']} |
| Unique GT CPE groups | {grouping['unique_gt_cpe_groups']} |
| Duplicated GT CPE groups | {grouping['duplicated_gt_cpe_groups']} |
| Components in duplicate groups | {grouping['components_in_duplicate_groups']} |
| Semantic near-duplicate groups | {grouping['semantic_near_duplicate_groups']} |

Duplicate group status:

- `KEEP_SINGLE_REPRESENTATIVE`: {statuses['KEEP_SINGLE_REPRESENTATIVE']}
- `KEEP_MULTIPLE`: {statuses['KEEP_MULTIPLE']}
- `REPRESENTATIVE_AMBIGUOUS`: {statuses['REPRESENTATIVE_AMBIGUOUS']}
- `DATA_INCONSISTENCY`: {statuses['DATA_INCONSISTENCY']}

Component recommendations across all 48 records:

- `KEEP_GT_CPE`: {recommendations[KEEP_GT_CPE]}
- `REMOVE_DUPLICATED_GT_CPE`: {recommendations[REMOVE_DUPLICATED_GT_CPE]}
- `REVIEW_REQUIRED`: {recommendations[REVIEW_REQUIRED]}

## Duplicate group evidence and recommendations

{''.join(group_sections)}
## Required comparison cases

### libcap / libcap-bin

Keep the GT CPE on `libcap`; recommend removing it from `libcap-bin`. The latter
is an explicit utilities split, depends on `libcap`, and has no independently
identified CPE product. The proposed post-change result for `libcap-bin` is
`DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` with no GT CPE.

### OpenSSL

`libopenssl3` and `openssl-util` are an exact duplicate group, but no single
installed package represents both the core libraries and canonical CLI. Both
remain `REVIEW_REQUIRED`; this audit does not recommend a DB change for either.

### strongSwan

Keep `strongswan`, the Source-name-aligned main package. Recommend removing the
duplicate mapping from `strongswan-charon` (split daemon runtime) and
`strongswan-swanctl` (CLI split), both of which depend on the main package.

### curl / libcurl and e2fsprogs

`curl` and `libcurl4` are not duplicate or semantic near-duplicate groups: they
map to independently named CPE products `curl` and `libcurl`. `e2fsprogs` is the
only CPE-bearing member of its Source family; `libext2fs2` did not inherit its
parent CPE. No duplicate recommendation is created for these cases.

## Projected effect (recommendation only)

- Current CPE-bearing Components: {projected['current_cpe_bearing_components']}
- Projected CPE-bearing Components: {projected['projected_cpe_bearing_components']}
- Projected distinct canonical GT CPEs: {projected['projected_distinct_canonical_gt_cpes']}
- Projected removed duplicate mappings: {projected['projected_removed_duplicate_mappings']}
- Projected remaining duplicate groups: {projected['projected_remaining_duplicate_groups']} (OpenSSL, pending review)
- Clear representative Components: {representatives}

## Methodology conclusion

The evidence supports adding the once-per-upstream-product/version rule to the
Ground Truth methodology, with an explicit evidence gate. Exact duplicate CPEs
must not be removed mechanically: the audit must first establish package/product
boundaries, preserve independently identifiable CPE products, and use
`REVIEW_REQUIRED` when no unique representative exists.

Recommended rule:

> A Ground Truth CPE is assigned once per upstream product/version within a
> firmware SBOM. When the same upstream product is represented by multiple
> distribution-specific split packages, the CPE is retained only on the
> component that most directly represents the upstream product. Derived split
> packages do not inherit the same CPE unless they correspond to an independently
> identifiable CPE product.

## Read-only validation

- Canonical parse failures: `{grouping['canonical_parse_failure_count']}`
- Candidate-to-DB CPE/result mismatches: `0 / 0`
- Component fingerprint before/after: `{validation['component_fingerprint_before']}` / `{validation['component_fingerprint_after']}`
- Ground Truth fingerprint before/after: `{validation['ground_truth_fingerprint_before']}` / `{validation['ground_truth_fingerprint_after']}`
- Original Component mutations: `0`
- Ground Truth DB mutations: `0`
- Candidate/audit artifact modifications: `0 / 0`
- Migration: `0`
"""


def write_duplicate_cpe_audit(
    analysis: dict[str, Any],
    output_directory: Path,
) -> tuple[Path, ...]:
    if output_directory.exists():
        _fail(f"Refusing to overwrite existing audit directory: {output_directory}")
    output_directory.mkdir(parents=True)
    group_path = output_directory / "duplicate_groups.csv"
    component_path = output_directory / "component_recommendations.csv"
    report_path = output_directory / "audit_report.md"
    summary_path = output_directory / "summary.json"
    with group_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(analysis["group_rows"][0]),
        )
        writer.writeheader()
        writer.writerows(analysis["group_rows"])
    with component_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(analysis["component_rows"][0]),
        )
        writer.writeheader()
        writer.writerows(analysis["component_rows"])
    report_path.write_text(_report(analysis), encoding="utf-8")
    summary_path.write_text(
        json.dumps(analysis["summary"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report_path, group_path, component_path, summary_path

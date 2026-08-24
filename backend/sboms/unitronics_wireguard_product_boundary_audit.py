from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from django.conf import settings
from django.db.models import Q, TextField
from django.db.models.functions import Cast

from cpe.cpe23_canonical import parse_cpe23
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from nvd_cve.models import NvdCpeMatch, NvdCveSnapshot
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    GroundTruthDecision,
)


DATASET_KEY = "61602e128acb__52.07.13.7"
SBOM_DOCUMENT_ID = 1364
COMPONENT_ID = 200186
COMPONENT_NAME = "wireguard-tools"
OBSERVED_VERSION = "1.0.20210223-4"
AUDITED_PRODUCT = "wireguard-tools"
AUDITED_VERSION = "1.0.20210223"

CPE_SNAPSHOT_ID = "20260819T035002Z"
NVD_SNAPSHOT_ID = "20260820T110357Z"
WIREGUARD_FAMILY = ("a", "wireguard", "wireguard")
WINDOWS_CPE = "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
WINDOWS_PRODUCT_CPE = (
    "cpe:2.3:a:wireguard:wireguard:0.5.3:*:*:*:*:*:*:*"
)
DIRECT_PRODUCT_NAMES = (
    "wireguard-tools",
    "wireguard_tools",
    "wireguardtools",
    "wg",
)
DIRECT_PRODUCT_NORMALIZED = frozenset({"wireguardtools", "wg"})
EXPECTED_CVE_IDS = frozenset({"CVE-2021-46873", "CVE-2023-35838"})

OUTPUT_RELATIVE = Path(
    "analysis/results/unitronics-wireguard-product-boundary-audit/"
    f"{DATASET_KEY}"
)
CANDIDATE_DIRECTORY = Path(
    "analysis/results/unitronics-ground-truth-candidate-build/"
    f"{DATASET_KEY}"
)
CANDIDATE_COMPONENTS = CANDIDATE_DIRECTORY / "components.csv"

CPE_FIELDS = (
    "cpe_name_id",
    "cpe",
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
    "title",
    "status",
    "deprecated",
    "deprecated_by",
    "deprecates",
    "references",
    "product_boundary_signal",
)
CONFIGURATION_FIELDS = (
    "cve_id",
    "criteria",
    "match_criteria_id",
    "vulnerable",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "configuration_operator",
    "node_operator",
    "companion_criteria",
    "description",
    "platform_wording",
    "references",
    "raw_feed",
    "raw_feed_sha256",
)

OFFICIAL_PROJECTS = (
    {
        "project": "wireguard-tools",
        "purpose": (
            "Cross-platform userspace tools that configure WireGuard "
            "implementations"
        ),
        "canonical_artifacts": "wg(8), wg-quick(8)",
        "version_scheme": "1.0.YYYYMMDD",
        "release_examples": (
            "1.0.20210223, 1.0.20210315, 1.0.20210424, 1.0.20210914"
        ),
        "url": "https://git.zx2c4.com/wireguard-tools/",
    },
    {
        "project": "wireguard-linux",
        "purpose": "WireGuard implementation for the Linux kernel",
        "canonical_artifacts": "Linux kernel WireGuard driver/module",
        "version_scheme": "Linux kernel branches/releases",
        "release_examples": "devel, stable, backport branches",
        "url": "https://git.zx2c4.com/wireguard-linux/",
    },
    {
        "project": "wireguard-linux-compat",
        "purpose": "Out-of-tree Linux kernel module backport",
        "canonical_artifacts": "wireguard kernel module for Linux 3.10-5.5",
        "version_scheme": "Kernel compatibility releases",
        "release_examples": "separate compatibility repository",
        "url": "https://git.zx2c4.com/wireguard-linux-compat/",
    },
    {
        "project": "wireguard-windows",
        "purpose": "Official WireGuard client application for Windows",
        "canonical_artifacts": "wireguard.exe, manager service, UI",
        "version_scheme": "0.x semantic client releases in the audited era",
        "release_examples": "0.5, 0.5.1, 0.5.2, 0.5.3",
        "url": "https://git.zx2c4.com/wireguard-windows/refs/tags",
    },
    {
        "project": "wireguard-go",
        "purpose": "Cross-platform userspace WireGuard implementation",
        "canonical_artifacts": "wireguard-go userspace tunnel implementation",
        "version_scheme": "Independent repository history",
        "release_examples": "not the wireguard-tools release space",
        "url": "https://git.zx2c4.com/wireguard-go/",
    },
    {
        "project": "wireguard-android / wireguard-apple",
        "purpose": "Official platform-specific Android and Apple clients",
        "canonical_artifacts": "Android, macOS, and iOS applications",
        "version_scheme": "Platform-specific client releases",
        "release_examples": "independent platform repositories",
        "url": "https://www.wireguard.com/repositories/",
    },
)

OFFICIAL_EVIDENCE = {
    "accessed_at": "2026-08-25",
    "project_catalog": "https://www.wireguard.com/repositories/",
    "tools_repository": "https://git.zx2c4.com/wireguard-tools/",
    "tools_release_tag": (
        "https://git.zx2c4.com/wireguard-tools/tag/?h=v1.0.20210223"
    ),
    "tools_release_archive": (
        "https://git.zx2c4.com/wireguard-tools/snapshot/"
        "wireguard-tools-1.0.20210223.tar.xz"
    ),
    "tools_readme": (
        "https://git.zx2c4.com/wireguard-tools/tree/README.md?"
        "h=v1.0.20210223"
    ),
    "windows_repository": "https://git.zx2c4.com/wireguard-windows/",
    "windows_tags": "https://git.zx2c4.com/wireguard-windows/refs/tags",
    "openwrt_version_commit": (
        "https://git.openwrt.org/e0f7f5bbce0d03e5192b5dad5a24fcb8566da97f"
    ),
    "openwrt_release_semantics": (
        "https://github.com/openwrt/packages/blob/master/CONTRIBUTING.md"
    ),
}


class UnitronicsWireguardAuditError(Exception):
    pass


@dataclass
class WireguardAuditAnalysis:
    cpe_rows: list[dict[str, str]]
    configuration_rows: list[dict[str, str]]
    summary: dict[str, Any]


def _fail(message: str) -> NoReturn:
    raise UnitronicsWireguardAuditError(message)


def default_output_directory() -> Path:
    return settings.REPOSITORY_ROOT / OUTPUT_RELATIVE


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _normalized_product(value: str) -> str:
    return re.sub(r"[-_\s]", "", value).lower()


def _snapshot_metadata(
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
) -> dict[str, dict[str, Any]]:
    expected_cpe = {
        "snapshot_id": CPE_SNAPSHOT_ID,
        "status": CpeDictionarySnapshot.Status.COMPLETE,
        "manifest_sha256": (
            "d0353e020f67a19070ebf297615cba0a91b636f3f89bd580f73fd786719fddce"
        ),
        "content_sha256": (
            "9035416631831f5f50d3c723d813370532e7ceee0c5a93c8473897d5a97bfd7a"
        ),
        "record_count": 1811261,
        "active_count": 1711630,
        "deprecated_count": 99631,
    }
    expected_nvd = {
        "snapshot_id": NVD_SNAPSHOT_ID,
        "status": NvdCveSnapshot.Status.COMPLETE,
        "manifest_sha256": (
            "80b6107f5225923794d725b252527f575ad2b0c800765fc5ce6d0b07c18d94eb"
        ),
        "content_sha256": (
            "a8a1b6ca66a0383272a3ca035559229b1fc59535f029828b984a3998234c6eab"
        ),
        "record_count": 380865,
        "configuration_count": 760120,
        "cpe_match_count": 3170148,
    }
    for field, expected in expected_cpe.items():
        if getattr(cpe_snapshot, field) != expected:
            _fail(f"CPE snapshot mismatch for {field}")
    for field, expected in expected_nvd.items():
        if getattr(nvd_snapshot, field) != expected:
            _fail(f"NVD snapshot mismatch for {field}")
    return {
        "cpe_dictionary": expected_cpe,
        "nvd_cve": expected_nvd,
    }


def _candidate_artifact_hashes(root: Path) -> dict[str, str]:
    directory = root / CANDIDATE_DIRECTORY
    if not directory.is_dir():
        _fail(f"Candidate artifact directory is absent: {directory}")
    return {
        str(path.relative_to(root)): _sha256(path)
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def _model_fingerprint(rows: list[Any], *, include_m2m: bool = False) -> str:
    values: list[dict[str, Any]] = []
    for row in rows:
        value = {
            field.attname: getattr(row, field.attname)
            for field in row._meta.concrete_fields
        }
        if include_m2m:
            value["correction_type_ids"] = list(
                row.correction_types.order_by("id").values_list("id", flat=True)
            )
            value["discrepancy_type_ids"] = list(
                row.discrepancy_types.order_by("id").values_list("id", flat=True)
            )
        values.append(value)
    encoded = json.dumps(
        values,
        default=str,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _database_state() -> dict[str, Any]:
    components = list(
        Component.objects.filter(sbom_document_id=SBOM_DOCUMENT_ID).order_by("id")
    )
    records = list(
        ComponentCpeGroundTruth.objects.filter(
            component__sbom_document_id=SBOM_DOCUMENT_ID,
            snapshot__snapshot_id=CPE_SNAPSHOT_ID,
        )
        .prefetch_related("correction_types", "discrepancy_types")
        .order_by("id")
    )
    if len(components) != 582 or len(records) != 582:
        _fail("Fixed Unitronics dataset must contain 582 Components and GT rows")
    return {
        "component_count": len(components),
        "ground_truth_count": len(records),
        "component_fingerprint": _model_fingerprint(components),
        "ground_truth_fingerprint": _model_fingerprint(
            records,
            include_m2m=True,
        ),
    }


def _representative_title(titles: object) -> str:
    if not isinstance(titles, list):
        return ""
    for item in titles:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("title", ""))
    for item in titles:
        if isinstance(item, dict) and item.get("title"):
            return str(item["title"])
    return ""


def _cpe_family_evidence(
    snapshot: CpeDictionarySnapshot,
) -> tuple[list[dict[str, str]], list[dict[str, Any]], int]:
    family = list(
        CpeName.objects.filter(snapshot=snapshot, vendor="wireguard").order_by(
            "product", "version", "update", "cpe_name"
        )
    )
    rows: list[dict[str, str]] = []
    parse_failures = 0
    for item in family:
        parsed = parse_cpe23(item.cpe_name)
        if not parsed.is_valid:
            parse_failures += 1
        references = item.references if isinstance(item.references, list) else []
        windows_reference = any(
            isinstance(reference, dict)
            and "wireguard-windows" in str(reference.get("ref", "")).lower()
            for reference in references
        )
        rows.append(
            {
                "cpe_name_id": str(item.cpe_name_id),
                "cpe": item.cpe_name,
                "part": item.part,
                "vendor": item.vendor,
                "product": item.product,
                "version": item.version,
                "update": item.update,
                "edition": item.edition,
                "language": item.language,
                "sw_edition": item.sw_edition,
                "target_sw": item.target_sw,
                "target_hw": item.target_hw,
                "other": item.other,
                "title": _representative_title(item.titles),
                "status": "DEPRECATED" if item.deprecated else "ACTIVE",
                "deprecated": str(item.deprecated).lower(),
                "deprecated_by": _json(item.deprecated_by),
                "deprecates": _json(item.deprecates),
                "references": _json(references),
                "product_boundary_signal": (
                    "WIREGUARD_WINDOWS_VERSION_REFERENCE"
                    if windows_reference
                    else "NO_PLATFORM_REFERENCE"
                ),
            }
        )

    title_text = Cast("titles", output_field=TextField())
    direct = list(
        CpeName.objects.filter(snapshot=snapshot)
        .annotate(_title_text=title_text)
        .filter(
            Q(product__in=DIRECT_PRODUCT_NAMES)
            | Q(_title_text__icontains="wireguard-tools")
            | Q(_title_text__icontains="wireguard tools")
        )
        .order_by("vendor", "product", "version")
        .values(
            "cpe_name",
            "vendor",
            "product",
            "version",
            "titles",
            "deprecated",
        )
    )
    return rows, direct, parse_failures


def _load_raw_cves(
    root: Path,
    cve_ids: set[str],
) -> tuple[dict[str, dict[str, Any]], dict[int, dict[str, str]]]:
    by_year: dict[int, set[str]] = {}
    for cve_id in cve_ids:
        try:
            year = int(cve_id.split("-")[1])
        except (IndexError, ValueError) as error:
            _fail(f"Invalid CVE ID: {cve_id}: {error}")
        by_year.setdefault(year, set()).add(cve_id)

    found: dict[str, dict[str, Any]] = {}
    feeds: dict[int, dict[str, str]] = {}
    for year, expected_ids in sorted(by_year.items()):
        relative = Path(
            f"data/nvd-cve/{NVD_SNAPSHOT_ID}/feeds/"
            f"nvdcve-2.0-{year}.json.gz"
        )
        path = root / relative
        if not path.is_file():
            _fail(f"Fixed NVD raw feed is absent: {relative}")
        feeds[year] = {
            "path": str(relative),
            "sha256": _sha256(path),
        }
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            _fail(f"Cannot read fixed NVD raw feed {relative}: {error}")
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve", {}) if isinstance(entry, dict) else {}
            cve_id = cve.get("id") if isinstance(cve, dict) else None
            if cve_id in expected_ids:
                found[str(cve_id)] = cve
    missing = cve_ids - set(found)
    if missing:
        _fail(f"CVE records missing from fixed raw feeds: {sorted(missing)}")
    return found, feeds


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value", ""))
    return ""


def _companion_criteria(match: NvdCpeMatch) -> list[str]:
    configurations = match.cve_record.configurations
    if not isinstance(configurations, list):
        return []
    try:
        configuration = configurations[match.configuration_index]
        nodes = configuration["nodes"]
    except (IndexError, KeyError, TypeError):
        return []
    companions: list[str] = []
    for node_index, node in enumerate(nodes):
        if node_index == match.node_index or not isinstance(node, dict):
            continue
        for item in node.get("cpeMatch", []):
            if isinstance(item, dict) and item.get("criteria"):
                companions.append(str(item["criteria"]))
    return sorted(companions)


def _nvd_evidence(
    snapshot: NvdCveSnapshot,
    root: Path,
) -> tuple[list[dict[str, str]], dict[str, Any], int]:
    related = list(
        NvdCpeMatch.objects.filter(cve_record__snapshot=snapshot)
        .filter(Q(criteria__icontains="wireguard") | Q(criteria__contains=":wg:"))
        .values_list("criteria", flat=True)
        .distinct()
        .order_by("criteria")
    )
    related_parse_failures = 0
    direct_expressions: list[str] = []
    for criteria in related:
        parsed = parse_cpe23(criteria)
        if not parsed.is_valid or parsed.name is None:
            related_parse_failures += 1
            continue
        if (
            _normalized_product(parsed.name.attribute("product").canonical)
            in DIRECT_PRODUCT_NORMALIZED
        ):
            direct_expressions.append(criteria)

    family_matches = list(
        NvdCpeMatch.objects.filter(
            cve_record__snapshot=snapshot,
            criteria__startswith="cpe:2.3:a:wireguard:wireguard:",
        )
        .select_related("cve_record")
        .order_by(
            "cve_record__cve_id",
            "configuration_index",
            "node_index",
            "match_index",
        )
    )
    cve_ids = {match.cve_record.cve_id for match in family_matches}
    raw_cves, feeds = _load_raw_cves(root, cve_ids)
    rows: list[dict[str, str]] = []
    family_parse_failures = 0
    for match in family_matches:
        parsed = parse_cpe23(match.criteria)
        if not parsed.is_valid:
            family_parse_failures += 1
        cve_id = match.cve_record.cve_id
        raw = raw_cves[cve_id]
        description = _english_description(raw)
        companions = _companion_criteria(match)
        windows_signal = (
            match.configuration_operator == "AND"
            and WINDOWS_CPE in companions
            and "windows" in description.lower()
        )
        feed = feeds[int(cve_id.split("-")[1])]
        rows.append(
            {
                "cve_id": cve_id,
                "criteria": match.criteria,
                "match_criteria_id": str(match.match_criteria_id),
                "vulnerable": str(match.vulnerable).lower(),
                "version_start_including": match.version_start_including or "",
                "version_start_excluding": match.version_start_excluding or "",
                "version_end_including": match.version_end_including or "",
                "version_end_excluding": match.version_end_excluding or "",
                "configuration_operator": match.configuration_operator or "",
                "node_operator": match.node_operator or "",
                "companion_criteria": _json(companions),
                "description": description,
                "platform_wording": (
                    "WINDOWS_CLIENT_AND_CONFIGURATION"
                    if windows_signal
                    else "PLATFORM_SIGNAL_INCOMPLETE"
                ),
                "references": _json(raw.get("references", [])),
                "raw_feed": feed["path"],
                "raw_feed_sha256": feed["sha256"],
            }
        )

    criteria_counts = Counter(match.criteria for match in family_matches)
    versions: list[str] = []
    for criteria in criteria_counts:
        parsed = parse_cpe23(criteria)
        if parsed.is_valid and parsed.name is not None:
            versions.append(parsed.name.attribute("version").canonical)
    versions.sort()
    range_tuples = sorted(
        {
            (
                match.version_start_including or "",
                match.version_start_excluding or "",
                match.version_end_including or "",
                match.version_end_excluding or "",
            )
            for match in family_matches
        }
    )
    stats = {
        "related_distinct_criteria": related,
        "wireguard_family_distinct_criteria": sorted(criteria_counts),
        "wireguard_family_criteria_count": len(criteria_counts),
        "wireguard_family_occurrence_count": len(family_matches),
        "wireguard_family_distinct_cve_count": len(cve_ids),
        "wireguard_family_cve_ids": sorted(cve_ids),
        "wireguard_family_versions": versions,
        "wireguard_family_range_tuples": [list(item) for item in range_tuples],
        "direct_wireguard_tools_expressions": sorted(set(direct_expressions)),
        "direct_wireguard_tools_expression_count": len(set(direct_expressions)),
        "all_family_cases_windows_constrained": bool(rows)
        and all(
            row["platform_wording"] == "WINDOWS_CLIENT_AND_CONFIGURATION"
            for row in rows
        ),
        "raw_feeds": {str(year): value for year, value in feeds.items()},
    }
    return rows, stats, related_parse_failures + family_parse_failures


def judge_product_boundary(
    *,
    cpe_rows: list[dict[str, str]],
    direct_dictionary_products: list[dict[str, Any]],
    configuration_rows: list[dict[str, str]],
    nvd_stats: dict[str, Any],
) -> dict[str, Any]:
    family_versions = {row["version"] for row in cpe_rows}
    windows_references = all(
        row["product_boundary_signal"]
        == "WIREGUARD_WINDOWS_VERSION_REFERENCE"
        for row in cpe_rows
    )
    windows_cases = bool(configuration_rows) and all(
        row["platform_wording"] == "WINDOWS_CLIENT_AND_CONFIGURATION"
        for row in configuration_rows
    )
    different_product = (
        len(cpe_rows) == 1
        and family_versions == {"0.5.3"}
        and windows_references
        and windows_cases
        and not direct_dictionary_products
        and nvd_stats["direct_wireguard_tools_expression_count"] == 0
    )
    if not different_product:
        _fail(
            "Fixed evidence no longer supports the approved deterministic "
            "DIFFERENT_PRODUCT conclusion"
        )
    return {
        "classification": "DIFFERENT_PRODUCT",
        "audited_actual_product": AUDITED_PRODUCT,
        "audited_actual_version": AUDITED_VERSION,
        "recommended_gt_cpe": "",
        "recommended_validation_result": (
            GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
        ),
        "recommended_validation_result_label": "No Direct CPE Found",
        "reason": (
            "The only wireguard:wireguard Dictionary version and every fixed "
            "NVD use align with the separately versioned Windows client, while "
            "wireguard-tools is an official userspace-tools product with its own "
            "1.0.YYYYMMDD release space and no direct Dictionary or Configuration "
            "expression."
        ),
    }


def _current_comparison(
    root: Path,
    snapshot: CpeDictionarySnapshot,
    judgment: dict[str, Any],
) -> dict[str, Any]:
    component = Component.objects.get(
        id=COMPONENT_ID,
        sbom_document_id=SBOM_DOCUMENT_ID,
        name=COMPONENT_NAME,
    )
    if component.version != OBSERVED_VERSION:
        _fail("wireguard-tools observed Component version changed")
    record = ComponentCpeGroundTruth.objects.select_related(
        "ground_truth_cpe"
    ).get(component=component, snapshot=snapshot)
    current_cpe = (
        record.ground_truth_cpe.cpe_name
        if record.ground_truth_cpe is not None
        else record.manual_ground_truth_cpe
    )

    candidate_path = root / CANDIDATE_COMPONENTS
    try:
        with candidate_path.open(newline="", encoding="utf-8") as handle:
            matches = [
                row
                for row in csv.DictReader(handle)
                if row.get("component_id") == str(COMPONENT_ID)
            ]
    except OSError as error:
        _fail(f"Cannot read current candidate artifact: {error}")
    if len(matches) != 1:
        _fail("Expected one wireguard-tools candidate artifact row")
    candidate = matches[0]
    current = {
        "component_id": component.id,
        "component_name": component.name,
        "observed_package_version": component.version,
        "current_actual_product": candidate["actual_product"],
        "current_actual_version": candidate["actual_product_version"],
        "current_gt_cpe": current_cpe,
        "current_validation_result": record.decision,
        "current_resolution_outcome": record.resolution_outcome,
        "ground_truth_record_id": record.id,
    }
    changed = (
        current_cpe != judgment["recommended_gt_cpe"]
        or record.decision != judgment["recommended_validation_result"]
        or candidate["actual_product"] != judgment["audited_actual_product"]
    )
    return {
        "current": current,
        "audited": {
            "audited_actual_product": judgment["audited_actual_product"],
            "audited_actual_version": judgment["audited_actual_version"],
            "recommended_gt_cpe": judgment["recommended_gt_cpe"],
            "recommended_validation_result": judgment[
                "recommended_validation_result"
            ],
        },
        "audit_status": "CHANGE_REQUIRED" if changed else "NO_CHANGE",
    }


def build_wireguard_product_boundary_audit(
    *,
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
    repository_root: Path | None = None,
) -> WireguardAuditAnalysis:
    root = repository_root or settings.REPOSITORY_ROOT
    snapshots = _snapshot_metadata(cpe_snapshot, nvd_snapshot)

    # Independent evidence is deliberately completed before current GT is read.
    cpe_rows, direct_dictionary, cpe_parse_failures = _cpe_family_evidence(
        cpe_snapshot
    )
    configuration_rows, nvd_stats, nvd_parse_failures = _nvd_evidence(
        nvd_snapshot,
        root,
    )
    judgment = judge_product_boundary(
        cpe_rows=cpe_rows,
        direct_dictionary_products=direct_dictionary,
        configuration_rows=configuration_rows,
        nvd_stats=nvd_stats,
    )

    candidate_hashes_before = _candidate_artifact_hashes(root)
    database_before = _database_state()
    comparison = _current_comparison(root, cpe_snapshot, judgment)
    database_after = _database_state()
    candidate_hashes_after = _candidate_artifact_hashes(root)

    if database_before != database_after:
        _fail("Database mutation detected during read-only WireGuard audit")
    if candidate_hashes_before != candidate_hashes_after:
        _fail("Candidate artifact mutation detected during WireGuard audit")
    if cpe_parse_failures or nvd_parse_failures:
        _fail("CPE canonical parse failure detected")
    if {row["cve_id"] for row in configuration_rows} != EXPECTED_CVE_IDS:
        _fail("Unexpected WireGuard CVE set in the fixed NVD snapshot")
    if [row["cpe"] for row in cpe_rows] != [WINDOWS_PRODUCT_CPE]:
        _fail("Unexpected vendor=wireguard Dictionary family")

    status_counts = Counter(row["status"] for row in cpe_rows)
    summary = {
        "schema_version": 1,
        "audit": "Unitronics wireguard-tools product-boundary audit",
        "mode": "READ_ONLY",
        "dataset": {
            "dataset_key": DATASET_KEY,
            "sbom_document_id": SBOM_DOCUMENT_ID,
            "component_id": COMPONENT_ID,
            "component_name": COMPONENT_NAME,
            "observed_package_version": OBSERVED_VERSION,
        },
        "snapshots": snapshots,
        "version_normalization": {
            "observed_package_version": OBSERVED_VERSION,
            "verified_upstream_version": AUDITED_VERSION,
            "upstream_tag": "v1.0.20210223",
            "upstream_archive": "wireguard-tools-1.0.20210223.tar.xz",
            "distribution_suffix": "-4",
            "distribution_suffix_meaning": (
                "OpenWrt package release/revision; not removed because it looks "
                "date-like, but because official upstream and package metadata "
                "separate PKG_VERSION from PKG_RELEASE."
            ),
        },
        "official_project_structure": list(OFFICIAL_PROJECTS),
        "official_evidence": OFFICIAL_EVIDENCE,
        "cpe_dictionary": {
            "vendor_family_record_count": len(cpe_rows),
            "vendor_family_versions": sorted({row["version"] for row in cpe_rows}),
            "status_counts": {
                "ACTIVE": status_counts["ACTIVE"],
                "DEPRECATED": status_counts["DEPRECATED"],
            },
            "direct_wireguard_tools_product_found": bool(direct_dictionary),
            "direct_wireguard_tools_matches": direct_dictionary,
            "canonical_parse_failure_count": cpe_parse_failures,
        },
        "nvd_configuration": {
            **nvd_stats,
            "canonical_parse_failure_count": nvd_parse_failures,
        },
        "version_space_comparison": [
            {
                "product": "wireguard-tools",
                "observed_or_known_versions": (
                    "1.0.20210223; 1.0.20210315; 1.0.20210424; 1.0.20210914"
                ),
                "scheme": "1.0.YYYYMMDD",
                "alignment": "AUDITED_COMPONENT",
            },
            {
                "product": "wireguard-windows",
                "observed_or_known_versions": "0.5; 0.5.1; 0.5.2; 0.5.3",
                "scheme": "0.x client releases",
                "alignment": "CPE_FAMILY",
            },
            {
                "product": "CPE wireguard:wireguard",
                "observed_or_known_versions": "; ".join(
                    sorted({row["version"] for row in cpe_rows})
                ),
                "scheme": "single fixed-snapshot version",
                "alignment": "WIREGUARD_WINDOWS",
            },
        ],
        "judgment": judgment,
        "comparison": comparison,
        "validation": {
            "fixed_snapshots_only": True,
            "cpe_family_export_count": len(cpe_rows),
            "configuration_case_export_count": len(configuration_rows),
            "cpe_canonical_parse_failure_count": (
                cpe_parse_failures + nvd_parse_failures
            ),
            "ground_truth_db_mutation_count": 0,
            "component_mutation_count": 0,
            "candidate_artifact_mutation_count": 0,
            "migration_count": 0,
            "commit_count": 0,
            "database_state_before": database_before,
            "database_state_after": database_after,
            "candidate_artifact_hashes_before": candidate_hashes_before,
            "candidate_artifact_hashes_after": candidate_hashes_after,
        },
    }
    return WireguardAuditAnalysis(cpe_rows, configuration_rows, summary)


def _report(analysis: WireguardAuditAnalysis) -> str:
    summary = analysis.summary
    dictionary = summary["cpe_dictionary"]
    nvd = summary["nvd_configuration"]
    judgment = summary["judgment"]
    comparison = summary["comparison"]
    validation = summary["validation"]
    projects = "\n".join(
        "| `{project}` | {purpose} | {canonical_artifacts} | "
        "{version_scheme} | {release_examples} | {url} |".format(**project)
        for project in summary["official_project_structure"]
    )
    cpe_table = "\n".join(
        f"| `{row['cpe']}` | `{row['version']}` | `{row['target_sw']}` | "
        f"{row['title']} | {row['status']} | {row['product_boundary_signal']} |"
        for row in analysis.cpe_rows
    )
    configuration_table = "\n".join(
        f"| `{row['cve_id']}` | `{row['criteria']}` | "
        f"`{row['configuration_operator']}` | "
        f"`{row['companion_criteria']}` | {row['platform_wording']} |"
        for row in analysis.configuration_rows
    )
    current = comparison["current"]
    audited = comparison["audited"]
    return f"""# Unitronics wireguard-tools product-boundary audit

## Scope and decision

- Mode: **READ-ONLY**
- Component: `{COMPONENT_NAME}` `{OBSERVED_VERSION}`
- CPE Dictionary snapshot: `{CPE_SNAPSHOT_ID}`
- NVD CVE/Configuration snapshot: `{NVD_SNAPSHOT_ID}`
- Product-boundary classification: **{judgment['classification']}**
- Current-result audit status: **{comparison['audit_status']}**

The fixed evidence identifies `wireguard-tools` as the separately released
userspace tooling project, not as the Windows client represented by the only
`wireguard:wireguard` CPE family entry. The current mapping should therefore not
be retained.

## Version verification

- Observed OpenWrt package version: `{OBSERVED_VERSION}`
- Verified upstream release: `{AUDITED_VERSION}`
- Official tag: `v1.0.20210223`
- Official archive: `wireguard-tools-1.0.20210223.tar.xz`
- `-4`: OpenWrt package release/revision, not part of the upstream version

The date-shaped `20210223` portion is retained because it is part of the
official upstream release version.

## Official project boundaries

| Official project | Purpose | Canonical artifacts | Release scheme | Release/tag examples | Official repository |
|---|---|---|---|---|---|
{projects}

The official WireGuard repository catalog explicitly separates the Linux kernel
implementation, cross-platform configuration tools, Windows client, and other
platform implementations.

## Fixed CPE Dictionary family

- `vendor=wireguard` records: **{dictionary['vendor_family_record_count']}**
- Versions: `{', '.join(dictionary['vendor_family_versions'])}`
- Direct `wireguard-tools` product/title matches: **{len(dictionary['direct_wireguard_tools_matches'])}**

| CPE | Version | target_sw | Title | Status | Boundary signal |
|---|---|---|---|---|---|
{cpe_table}

Although `target_sw=*` and the title are generic, the entry's version reference
points to `WireGuard/wireguard-windows/tags`. Its `0.5.3` version also matches
the official Windows-client release space and not the tools release space.

## Fixed NVD Configuration evidence

- Distinct `wireguard:wireguard` criteria: **{nvd['wireguard_family_criteria_count']}**
- Occurrences: **{nvd['wireguard_family_occurrence_count']}**
- Distinct CVEs: **{nvd['wireguard_family_distinct_cve_count']}**
- Versions: `{', '.join(nvd['wireguard_family_versions'])}`
- Version ranges: **none**
- Direct `wireguard-tools` expressions: **{nvd['direct_wireguard_tools_expression_count']}**

| CVE | Vulnerable criteria | Configuration | Companion criteria | Platform signal |
|---|---|---|---|---|
{configuration_table}

Both occurrences are vulnerable application criteria combined by `AND` with a
non-vulnerable Microsoft Windows platform criterion. `CVE-2021-46873` describes
WireGuard 0.5.3 on Windows; `CVE-2023-35838` explicitly describes the WireGuard
client 0.5.3 on Windows. No fixed-snapshot Configuration uses this family for
Linux `wireguard-tools` or `wg`.

## Version-space comparison

| Product/family | Version space | Alignment |
|---|---|---|
| `wireguard-tools` | `1.0.YYYYMMDD` | Audited Component |
| `wireguard-windows` | `0.x`, including `0.5.3` | CPE and NVD evidence |
| `wireguard:wireguard` CPE | only `0.5.3` | Windows client |

## Current result versus independent audit

| Field | Current | Audited/recommended |
|---|---|---|
| Actual product | `{current['current_actual_product']}` | `{audited['audited_actual_product']}` |
| Actual version | `{current['current_actual_version']}` | `{audited['audited_actual_version']}` |
| GT CPE | `{current['current_gt_cpe']}` | `null` |
| Validation Result | `{current['current_validation_result']}` | `{audited['recommended_validation_result']}` |

Recommendation:

```text
Ground Truth CPE = null
CPE Validation Result = DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
UI label = No Direct CPE Found
```

This report is advisory. It does not apply the recommendation to the candidate
artifact or database.

## Validation and provenance

- CPE canonical parse failures: **{validation['cpe_canonical_parse_failure_count']}**
- Ground Truth DB mutation: **{validation['ground_truth_db_mutation_count']}**
- Component mutation: **{validation['component_mutation_count']}**
- Candidate artifact mutation: **{validation['candidate_artifact_mutation_count']}**
- Migration: **{validation['migration_count']}**
- Commit: **{validation['commit_count']}**
- Component fingerprint unchanged: `{validation['database_state_before']['component_fingerprint']}`
- Ground Truth fingerprint unchanged: `{validation['database_state_before']['ground_truth_fingerprint']}`

Official upstream evidence:

- {OFFICIAL_EVIDENCE['project_catalog']}
- {OFFICIAL_EVIDENCE['tools_release_tag']}
- {OFFICIAL_EVIDENCE['tools_release_archive']}
- {OFFICIAL_EVIDENCE['windows_tags']}
- {OFFICIAL_EVIDENCE['openwrt_version_commit']}
- {OFFICIAL_EVIDENCE['openwrt_release_semantics']}

Fixed NVD descriptions, references, and full AND/OR Configuration structures
were read from the raw yearly feeds listed in `configuration_cases.csv`; counts
and positions were cross-checked against the imported fixed-snapshot schema.
"""


def write_wireguard_product_boundary_audit(
    analysis: WireguardAuditAnalysis,
    output_directory: Path,
) -> tuple[Path, ...]:
    if output_directory.exists():
        _fail(f"Refusing to overwrite existing audit directory: {output_directory}")
    output_directory.mkdir(parents=True)
    report_path = output_directory / "report.md"
    cpe_path = output_directory / "cpe_family.csv"
    configuration_path = output_directory / "configuration_cases.csv"
    summary_path = output_directory / "summary.json"

    report_path.write_text(_report(analysis), encoding="utf-8")
    with cpe_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CPE_FIELDS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(analysis.cpe_rows)
    with configuration_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CONFIGURATION_FIELDS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(analysis.configuration_rows)
    summary_path.write_text(
        json.dumps(analysis.summary, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return report_path, cpe_path, configuration_path, summary_path

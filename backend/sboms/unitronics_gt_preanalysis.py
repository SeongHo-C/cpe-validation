from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZipFile

from django.conf import settings
from django.db import connection

from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    SBOMDocument,
    SourceArtifact,
)


SCHEMA_VERSION = 1
EXPECTED_SBOM_ID = 1364
EXPECTED_MANUFACTURER = "Unitronics"
EXPECTED_PRODUCT = "UCR-ST-B8"
EXPECTED_VERSION = "52.07.13.7"
EXPECTED_COMPONENT_COUNT = 582
EXPECTED_SBOM_SHA256 = (
    "61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e"
)
EXPECTED_FIRMWARE_FILENAME = "UCRB8_R_52.07.13.7_WEBUI.bin"
EXPECTED_FIRMWARE_SHA256 = (
    "6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c"
)
OBSERVED_OFFICIAL_ZIP_SHA256 = (
    "711ed9fe0cb8eaa1f4ddb8dc9523ba288e0364063740c7985b355f91a33e13f7"
)
OFFICIAL_FIRMWARE_URL = (
    "https://downloads.unitronicsplc.com/Sites/plc/Technical_Library/"
    "Accessories/UCR-RUT%20OS-7.zip"
)

COMPONENTS_FILENAME = "components.csv"
PROPERTY_KEYS_FILENAME = "property_keys.csv"
SOURCE_PACKAGES_FILENAME = "source_packages.csv"
SUMMARY_FILENAME = "summary.json"
REPORT_FILENAME = "report.md"
OUTPUT_FILENAMES = (
    COMPONENTS_FILENAME,
    PROPERTY_KEYS_FILENAME,
    SOURCE_PACKAGES_FILENAME,
    SUMMARY_FILENAME,
    REPORT_FILENAME,
)

COMPONENT_FIELDS = (
    "component_id",
    "bom_ref",
    "name",
    "version",
    "version_form",
    "original_cpe",
    "purl",
    "group",
    "publisher",
    "supplier",
    "author",
    "type",
    "external_references",
    "evidence",
    "properties_keys",
    "properties_summary",
    "properties_paths",
    "firmware_traceability_status",
    "firmware_control_path",
    "sdk_match_status",
    "sdk_package_path",
    "makefile_path",
    "makefile_path_candidate",
    "pkg_name",
    "pkg_version",
    "pkg_release",
    "package_definition",
    "installed_package",
    "installed_package_version",
    "source_package",
    "pkg_source",
    "pkg_source_url",
    "pkg_source_version",
    "pkg_source_date",
    "control_source_name",
    "control_source_date_epoch",
    "control_cpe_id",
    "control_license",
    "control_section",
    "control_maintainer",
    "control_description",
    "control_dependencies",
    "installed_paths",
    "source_installed_package_count",
    "source_structure",
    "is_vendor_specific",
    "package_role",
    "product_identity_status",
    "upstream_product_candidate",
    "version_relationship",
    "installed_version_evidence",
    "version_release_decomposition",
    "properties_contribution_sdk",
    "properties_contribution_firmware",
    "matching_evidence",
    "product_identity_evidence",
    "notes",
)

PROPERTY_KEY_FIELDS = (
    "property_key",
    "semantic_key",
    "component_count",
    "coverage_percent",
    "occurrence_count",
    "distinct_value_count",
    "representative_values",
    "value_pattern",
    "firmware_path_related",
    "analysis_source_binary_path_related",
    "package_source_traceability_use",
    "sdk_makefile_traceability",
)

SOURCE_PACKAGE_FIELDS = (
    "source_package",
    "installed_component_count",
    "installed_packages",
    "source_structure",
    "is_vendor_specific",
    "makefile_path_candidate",
    "makefile_verified",
    "evidence_origin",
)

PACKAGE_ROLES = (
    "PRODUCT_OR_MAIN_PACKAGE",
    "SPLIT_RUNTIME_PACKAGE",
    "LIBRARY_PACKAGE",
    "UTILITY_OR_CLI_PACKAGE",
    "PLUGIN_OR_MODULE",
    "DEVELOPMENT_PACKAGE",
    "KERNEL_OR_KMOD",
    "FIRMWARE_OR_DRIVER_ARTIFACT",
    "BOARD_OR_CALIBRATION_DATA",
    "META_OR_VIRTUAL_PACKAGE",
    "VENDOR_SPECIFIC_PACKAGE",
    "UNKNOWN",
)

PRODUCT_IDENTITY_STATUSES = (
    "DIRECT_PRODUCT_EVIDENCE",
    "POSSIBLE_PRODUCT",
    "PARTIAL_OR_SPLIT_COMPONENT",
    "NON_PRODUCT_ARTIFACT",
    "AMBIGUOUS",
    "UNRESOLVED",
)

VERSION_RELATIONSHIPS = (
    "EXACT",
    "PACKAGE_RELEASE_SUFFIX",
    "SOURCE_VERSION_AVAILABLE",
    "DATE_BASED",
    "GIT_OR_REVISION_BASED",
    "VENDOR_TRANSFORMED",
    "AMBIGUOUS",
    "UNRESOLVED",
)

VERSION_FORMS = (
    "UPSTREAM_LIKE",
    "PACKAGE_RELEASE",
    "DATE_BASED",
    "GIT_OR_REVISION",
    "KERNEL_VERSION",
    "VENDOR_SPECIFIC",
    "UNKNOWN_OR_PLACEHOLDER",
    "OTHER",
)


class UnitronicsPreanalysisError(Exception):
    """Raised when analysis provenance or consistency checks fail."""


@dataclass(frozen=True)
class UnitronicsPreanalysis:
    summary: dict[str, Any]
    components: list[dict[str, Any]]
    property_keys: list[dict[str, Any]]
    source_packages: list[dict[str, Any]]
    report: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def _percent(count: int, total: int) -> float:
    return round(_ratio(count, total) * 100.0, 2)


def _present(value: Any) -> bool:
    return value not in (None, "", [], {})


def _json_cell(value: Any) -> str:
    if not _present(value):
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _strip_property_quotes(value: Any) -> str:
    text = "" if value is None else str(value)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text


def _semantic_property_key(raw_key: str) -> str:
    prefix = "EMBA:sbom:"
    if not raw_key.startswith(prefix):
        return raw_key
    key = raw_key[len(prefix) :]
    for location_prefix in ("source_location:", "location:"):
        if key.startswith(location_prefix):
            key = key[len(location_prefix) :]
            break
    return re.sub(r"^\d+:", "", key)


def _source_property_paths(component: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for item in component.get("properties") or []:
        semantic_key = _semantic_property_key(str(item.get("name", "")))
        if semantic_key in {"source_path", "additional_source_path", "path"}:
            value = _strip_property_quotes(item.get("value"))
            if value:
                paths.append(value)
    return list(dict.fromkeys(paths))


def _semantic_properties(component: dict[str, Any]) -> dict[str, list[str]]:
    values: defaultdict[str, list[str]] = defaultdict(list)
    for item in component.get("properties") or []:
        raw_key = str(item.get("name", ""))
        semantic_key = _semantic_property_key(raw_key)
        value = _strip_property_quotes(item.get("value"))
        if value not in values[semantic_key]:
            values[semantic_key].append(value)
    return dict(sorted(values.items()))


def _rootfs_relative_path(analysis_path: str) -> str | None:
    marker = "/squashfs-root"
    if marker not in analysis_path:
        return None
    relative = analysis_path.split(marker, 1)[1]
    return relative if relative.startswith("/") else f"/{relative}"


def _parse_control(path: Path, rootfs: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    current_key: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line[:1].isspace() and current_key is not None:
            fields[current_key] += "\n" + line.strip()
            continue
        if ": " not in line:
            current_key = None
            continue
        current_key, value = line.split(": ", 1)
        fields[current_key] = value
    fields["_relative_path"] = "/" + path.relative_to(rootfs).as_posix()
    return fields


def _read_controls(rootfs: Path) -> dict[str, dict[str, str]]:
    info_directory = rootfs / "usr/lib/opkg/info"
    if not info_directory.is_dir():
        raise UnitronicsPreanalysisError(
            f"Installed opkg metadata directory is missing: {info_directory}"
        )
    controls: dict[str, dict[str, str]] = {}
    for path in sorted(info_directory.glob("*.control")):
        control = _parse_control(path, rootfs)
        package = control.get("Package", "")
        if not package:
            raise UnitronicsPreanalysisError(
                f"Installed control has no Package field: {path}"
            )
        if package in controls:
            raise UnitronicsPreanalysisError(
                f"Duplicate installed Package control: {package}"
            )
        controls[package] = control
    return controls


def _field_coverage(
    components: list[dict[str, Any]], field: str
) -> dict[str, Any]:
    present_values = [
        component.get(field)
        for component in components
        if _present(component.get(field))
    ]
    serialized = [
        json.dumps(value, ensure_ascii=False, sort_keys=True)
        if isinstance(value, (dict, list))
        else str(value)
        for value in present_values
    ]
    if field == "properties":
        representative_values = [
            f"{len(value)} properties: "
            + ", ".join(
                str(item.get("name", "")) for item in value[:5]
            )
            + (" ..." if len(value) > 5 else "")
            for value in present_values[:5]
        ]
    else:
        representative_values = list(dict.fromkeys(serialized))[:5]
    return {
        "present_count": len(present_values),
        "coverage_percent": _percent(len(present_values), len(components)),
        "distinct_value_count": len(set(serialized)),
        "representative_values": representative_values,
    }


def _classify_version_form(name: str, version: str) -> str:
    lowered = version.lower().strip()
    if lowered in {"", "unknown", "n/a", "na", "none", "-", "*"}:
        return "UNKNOWN_OR_PLACEHOLDER"
    if name == "linux_kernel" or re.fullmatch(r"5\.15\.176(?:-\d+)?", version):
        return "KERNEL_VERSION"
    if re.match(r"^\d{4}-\d{2}-\d{2}", version):
        if re.search(r"-[0-9a-f]{7,}(?:-|$)", lowered):
            return "GIT_OR_REVISION"
        return "DATE_BASED"
    if re.fullmatch(r"20\d{6}(?:-\d+(?:\.\d+)*)?", version):
        return "DATE_BASED"
    if (
        "git" in lowered
        or re.search(r"(?:^|[-+:])r\d+", lowered)
        or re.search(r"(?:^|[-+])[0-9a-f]{7,}(?:-|$)", lowered)
    ):
        return "GIT_OR_REVISION"
    if ":" in version or name in {"base-files", "openwrt"}:
        return "VENDOR_SPECIFIC"
    if re.fullmatch(r"v?\d+(?:[._]\d+)*(?:[a-z]\d*)?-[0-9]+(?:\.[0-9]+)*", version):
        return "PACKAGE_RELEASE"
    if re.fullmatch(r"v?\d+(?:[._]\d+)*(?:[a-z]\d*)?", version):
        return "UPSTREAM_LIKE"
    return "OTHER"


def _is_vendor_source(control: dict[str, str]) -> bool:
    source = control.get("Source", "").lower()
    license_name = control.get("License", "").lower()
    return any(
        token in source
        for token in ("/teltonika/", "feeds/vuci", "custom_feeds/")
    ) or "teltonika" in license_name


def _source_basename(source: str) -> str:
    return source.rstrip("/").rsplit("/", 1)[-1] if source else ""


def _classify_package_role(
    component: dict[str, Any],
    control: dict[str, str] | None,
    source_package_count: int,
) -> str:
    name = str(component.get("name", ""))
    lowered = name.lower()
    group = str(component.get("group", ""))
    paths = _source_property_paths(component)
    if group == "linux_kernel" or lowered == "kernel" or lowered.startswith("kmod-"):
        return "KERNEL_OR_KMOD"
    if group == "static_distri_analysis":
        return "PRODUCT_OR_MAIN_PACKAGE"
    if group == "static_bin_analysis":
        if any("libsqlite" in path for path in paths):
            return "LIBRARY_PACKAGE"
        return "UTILITY_OR_CLI_PACKAGE"
    if control is None:
        return "UNKNOWN"
    section = control.get("Section", "").lower()
    description = control.get("Description", "").lower()
    source = control.get("Source", "")
    source_base = _source_basename(source).lower()
    if (
        "-mod-" in lowered
        or lowered.startswith(("rpcd-mod-", "ucode-mod-"))
        or "plugin" in lowered
        or section in {"vuci", "webui"}
    ):
        return "PLUGIN_OR_MODULE"
    if (
        "firmware" in lowered
        or lowered.endswith("-fw")
        or section == "firmware"
        or "firmware blob" in description
    ):
        return "FIRMWARE_OR_DRIVER_ARTIFACT"
    if any(token in lowered for token in ("caldata", "board-data", "boarddata")):
        return "BOARD_OR_CALIBRATION_DATA"
    if lowered.endswith(("-dev", "-devel", "-headers", "-src")):
        return "DEVELOPMENT_PACKAGE"
    if section == "libs" or lowered.startswith("lib"):
        return "LIBRARY_PACKAGE"
    installed_size = control.get("Installed-Size", "")
    if (
        section == "meta"
        or "virtual package" in description
        or installed_size == "0"
    ):
        return "META_OR_VIRTUAL_PACKAGE"
    if section in {"utils", "admin"} or any(
        token in description
        for token in (" command line ", " utility", " administration tool")
    ):
        return "UTILITY_OR_CLI_PACKAGE"
    if _is_vendor_source(control):
        return "VENDOR_SPECIFIC_PACKAGE"
    normalized_source = source_base.replace("_", "-")
    if source_package_count > 1 and lowered != normalized_source:
        return "SPLIT_RUNTIME_PACKAGE"
    return "PRODUCT_OR_MAIN_PACKAGE"


def _classify_product_identity(
    component: dict[str, Any], package_role: str
) -> str:
    name = str(component.get("name", ""))
    group = str(component.get("group", ""))
    paths = _source_property_paths(component)
    if group in {"linux_kernel", "static_distri_analysis"}:
        return "DIRECT_PRODUCT_EVIDENCE"
    if group == "static_bin_analysis":
        if name in {"sed", "udhcp"} and any(
            path.endswith("/bin/busybox") for path in paths
        ):
            return "PARTIAL_OR_SPLIT_COMPONENT"
        return "POSSIBLE_PRODUCT"
    if package_role in {
        "FIRMWARE_OR_DRIVER_ARTIFACT",
        "BOARD_OR_CALIBRATION_DATA",
        "META_OR_VIRTUAL_PACKAGE",
    }:
        return "NON_PRODUCT_ARTIFACT"
    if package_role == "KERNEL_OR_KMOD":
        return (
            "POSSIBLE_PRODUCT"
            if name == "kernel"
            else "PARTIAL_OR_SPLIT_COMPONENT"
        )
    if package_role in {
        "SPLIT_RUNTIME_PACKAGE",
        "LIBRARY_PACKAGE",
        "PLUGIN_OR_MODULE",
        "DEVELOPMENT_PACKAGE",
    }:
        return "PARTIAL_OR_SPLIT_COMPONENT"
    if package_role == "VENDOR_SPECIFIC_PACKAGE":
        return "UNRESOLVED"
    if package_role in {
        "PRODUCT_OR_MAIN_PACKAGE",
        "UTILITY_OR_CLI_PACKAGE",
    }:
        return "POSSIBLE_PRODUCT"
    return "AMBIGUOUS"


def _property_value_pattern(values: list[str]) -> str:
    if not values:
        return "EMPTY"
    if all(value.startswith("/") or value.startswith("'/") for value in values):
        return "ABSOLUTE_PATH"
    if all("ELF " in value or value == "data" for value in values):
        return "BINARY_DESCRIPTOR"
    if all(re.fullmatch(r"'[A-Za-z0-9_.+:/\\ -]+'", value) for value in values):
        return "QUOTED_STRING"
    return "MIXED_STRING"


def _property_traceability_use(semantic_key: str) -> str:
    return {
        "source_path": (
            "Maps a component to an exact installed control file or detected "
            "firmware binary path."
        ),
        "additional_source_path": (
            "Adds exact kernel-module artifact paths to the kernel component."
        ),
        "path": (
            "Lists installed firmware files; useful for role evidence, not a "
            "source Makefile path."
        ),
        "dependency": (
            "Provides installed-package dependency evidence; source linkage "
            "is indirect."
        ),
        "minimal_identifier": "Repeats detector identity and version.",
        "vendor_name": "Detector identity hint only.",
        "product_name": "Detector identity hint only.",
        "confidence": "Detector confidence, not source provenance.",
        "source_arch": "Binary architecture evidence.",
        "source_details": "Binary format evidence.",
        "identifer_detected": "Binary/distribution version-string evidence.",
    }.get(semantic_key, "Contextual detector metadata.")


def _property_key_rows(
    components: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_stats: defaultdict[str, dict[str, Any]] = defaultdict(
        lambda: {"component_refs": set(), "values": []}
    )
    semantic_stats: defaultdict[str, dict[str, Any]] = defaultdict(
        lambda: {"component_refs": set(), "values": [], "raw_keys": set()}
    )
    for component in components:
        bom_ref = str(component.get("bom-ref", ""))
        for item in component.get("properties") or []:
            raw_key = str(item.get("name", ""))
            value = str(item.get("value", ""))
            semantic_key = _semantic_property_key(raw_key)
            raw_stats[raw_key]["component_refs"].add(bom_ref)
            raw_stats[raw_key]["values"].append(value)
            semantic_stats[semantic_key]["component_refs"].add(bom_ref)
            semantic_stats[semantic_key]["values"].append(value)
            semantic_stats[semantic_key]["raw_keys"].add(raw_key)

    total = len(components)
    rows: list[dict[str, Any]] = []
    for raw_key, stats in sorted(raw_stats.items()):
        semantic_key = _semantic_property_key(raw_key)
        values = stats["values"]
        path_related = semantic_key in {
            "source_path",
            "additional_source_path",
            "path",
        }
        rows.append(
            {
                "property_key": raw_key,
                "semantic_key": semantic_key,
                "component_count": len(stats["component_refs"]),
                "coverage_percent": _percent(
                    len(stats["component_refs"]), total
                ),
                "occurrence_count": len(values),
                "distinct_value_count": len(set(values)),
                "representative_values": " | ".join(
                    list(dict.fromkeys(values))[:5]
                ),
                "value_pattern": _property_value_pattern(values),
                "firmware_path_related": path_related,
                "analysis_source_binary_path_related": semantic_key
                in {
                    "source_path",
                    "additional_source_path",
                    "source_arch",
                    "source_details",
                    "identifer_detected",
                },
                "package_source_traceability_use": (
                    _property_traceability_use(semantic_key)
                ),
                "sdk_makefile_traceability": (
                    "Not testable: no exact-version SDK/GPL artifact was "
                    "available."
                ),
            }
        )

    semantic_summary = {}
    for key, stats in sorted(
        semantic_stats.items(),
        key=lambda item: (-len(item[1]["component_refs"]), item[0]),
    ):
        values = stats["values"]
        semantic_summary[key] = {
            "component_count": len(stats["component_refs"]),
            "coverage_percent": _percent(
                len(stats["component_refs"]), total
            ),
            "occurrence_count": len(values),
            "distinct_value_count": len(set(values)),
            "raw_key_count": len(stats["raw_keys"]),
            "representative_values": list(dict.fromkeys(values))[:5],
        }
    return rows, semantic_summary


def _counter_dict(values: Iterable[str], expected: Iterable[str]) -> dict[str, int]:
    counts = Counter(values)
    return {value: counts.get(value, 0) for value in expected}


def _distribution(values: Iterable[str]) -> list[dict[str, Any]]:
    counts = Counter(values)
    return [
        {"value": value, "component_count": count}
        for value, count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]


def _select_examples(
    rows: list[dict[str, Any]],
    preferred_names: tuple[str, ...],
    predicate: Any,
    limit: int = 5,
) -> list[dict[str, Any]]:
    matches = {row["name"]: row for row in rows if predicate(row)}
    selected: list[dict[str, Any]] = []
    for name in preferred_names:
        row = matches.pop(name, None)
        if row is not None:
            selected.append(row)
            if len(selected) == limit:
                return selected
    selected.extend(matches[name] for name in sorted(matches)[: limit - len(selected)])
    return selected


def _example_view(row: dict[str, Any]) -> dict[str, Any]:
    view = {
        key: row[key]
        for key in (
            "component_id",
            "name",
            "version",
            "properties_paths",
            "firmware_control_path",
            "makefile_path",
            "source_package",
            "installed_package",
            "installed_package_version",
            "pkg_name",
            "pkg_version",
            "pkg_release",
            "package_definition",
            "source_installed_package_count",
            "package_role",
            "product_identity_status",
            "version_relationship",
            "matching_evidence",
            "product_identity_evidence",
            "notes",
        )
    }
    paths = [
        value.strip()
        for value in str(view["properties_paths"]).split(" | ")
        if value.strip()
    ]
    if len(paths) > 5:
        view["properties_paths"] = (
            " | ".join(paths[:5]) + f" | ... (+{len(paths) - 5} more)"
        )
    return view


def _build_examples(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    categories = {
        "component_and_source_name_align": _select_examples(
            rows,
            ("busybox", "curl", "dnsmasq", "dropbear", "openwrt"),
            lambda row: bool(row["source_package"])
            and _source_basename(row["source_package"])
            .lower()
            .replace("_", "-")
            == row["name"].lower().replace("_", "-")
            and row["package_role"]
            in {"PRODUCT_OR_MAIN_PACKAGE", "UTILITY_OR_CLI_PACKAGE"}
            and row["product_identity_status"]
            in {"DIRECT_PRODUCT_EVIDENCE", "POSSIBLE_PRODUCT"},
        ),
        "multiple_installed_packages_same_source": _select_examples(
            rows,
            ("curl", "libcurl4", "strongswan", "ppp", "data-sender"),
            lambda row: int(row["source_installed_package_count"] or 0) > 1,
        ),
        "library_split": _select_examples(
            rows,
            ("libcurl4", "libopenssl3", "libuci20130104", "libubus20210630", "libgps"),
            lambda row: row["package_role"] == "LIBRARY_PACKAGE",
        ),
        "utility_or_cli": _select_examples(
            rows,
            ("curl", "openssl-util", "iwinfo", "gpsctl", "point-to-point_protocol"),
            lambda row: row["package_role"] == "UTILITY_OR_CLI_PACKAGE",
        ),
        "kernel_or_kmod": _select_examples(
            rows,
            ("linux_kernel", "kernel", "kmod-wireguard", "kmod-cfg80211_515", "kmod-mt7603_515"),
            lambda row: row["package_role"] == "KERNEL_OR_KMOD",
        ),
        "firmware_or_driver_artifact": _select_examples(
            rows,
            ("wireless-regdb", "ath10k-firmware-qca9887", "kmod-mt7603_515"),
            lambda row: row["package_role"]
            in {"FIRMWARE_OR_DRIVER_ARTIFACT", "BOARD_OR_CALIBRATION_DATA"},
        ),
        "vendor_specific": _select_examples(
            rows,
            ("data-sender", "api-core", "gsmctl", "unicloud", "vuci"),
            lambda row: bool(row["is_vendor_specific"]),
        ),
        "version_requires_decomposition": _select_examples(
            rows,
            ("base-files", "kernel", "curl", "libubox20240329", "avl"),
            lambda row: row["version_form"]
            in {
                "PACKAGE_RELEASE",
                "DATE_BASED",
                "GIT_OR_REVISION",
                "VENDOR_SPECIFIC",
            },
        ),
        "identity_unresolved_or_ambiguous": _select_examples(
            rows,
            ("sed", "udhcp", "wpa_supplicant", "api-core", "apn_db"),
            lambda row: row["product_identity_status"]
            in {"AMBIGUOUS", "UNRESOLVED", "PARTIAL_OR_SPLIT_COMPONENT"},
        ),
    }
    return {
        category: [_example_view(row) for row in selected]
        for category, selected in categories.items()
    }


def _validate_target(document: SBOMDocument, components: list[Component]) -> None:
    observed = (
        document.id,
        document.manufacturer,
        document.product_name,
        document.product_version,
        document.file_sha256,
        len(components),
    )
    expected = (
        EXPECTED_SBOM_ID,
        EXPECTED_MANUFACTURER,
        EXPECTED_PRODUCT,
        EXPECTED_VERSION,
        EXPECTED_SBOM_SHA256,
        EXPECTED_COMPONENT_COUNT,
    )
    if observed != expected:
        raise UnitronicsPreanalysisError(
            f"Unexpected Unitronics analysis target: {observed!r} != {expected!r}"
        )


def _validate_raw_components(
    raw_components: list[dict[str, Any]], components: list[Component]
) -> dict[str, Component]:
    if len(raw_components) != EXPECTED_COMPONENT_COUNT:
        raise UnitronicsPreanalysisError(
            "Raw CycloneDX component count differs from the expected 582."
        )
    by_ref = {component.bom_ref: component for component in components}
    if len(by_ref) != len(components):
        raise UnitronicsPreanalysisError("Database bom-ref values are not unique.")
    for raw in raw_components:
        bom_ref = str(raw.get("bom-ref", ""))
        component = by_ref.get(bom_ref)
        if component is None:
            raise UnitronicsPreanalysisError(
                f"Raw component bom-ref is absent from the database: {bom_ref}"
            )
        if (
            component.name,
            component.version,
            component.cpe,
            component.group,
            component.publisher,
            component.purl,
            component.component_type,
        ) != (
            raw.get("name", ""),
            raw.get("version", ""),
            raw.get("cpe", ""),
            raw.get("group", ""),
            raw.get("publisher", ""),
            raw.get("purl", ""),
            raw.get("type", ""),
        ):
            raise UnitronicsPreanalysisError(
                f"Raw/DB component fields differ for bom-ref {bom_ref}."
            )
    return by_ref


def _read_openwrt_provenance(rootfs: Path) -> dict[str, str]:
    release_path = rootfs / "etc/openwrt_release"
    values: dict[str, str] = {}
    for line in release_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip("'\"")
    return values


def _build_source_rows(
    controls: dict[str, dict[str, str]]
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    source_packages: defaultdict[str, list[str]] = defaultdict(list)
    source_controls: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
    for package, control in controls.items():
        source = control.get("Source", "")
        source_packages[source].append(package)
        source_controls[source].append(control)
    rows = []
    for source, packages in sorted(source_packages.items()):
        sorted_packages = sorted(packages)
        vendor_specific = any(
            _is_vendor_source(control) for control in source_controls[source]
        )
        rows.append(
            {
                "source_package": source,
                "installed_component_count": len(sorted_packages),
                "installed_packages": " | ".join(sorted_packages),
                "source_structure": (
                    "ONE_SOURCE_ONE_INSTALLED_PACKAGE"
                    if len(sorted_packages) == 1
                    else "ONE_SOURCE_MULTIPLE_INSTALLED_PACKAGES"
                ),
                "is_vendor_specific": vendor_specific,
                "makefile_path_candidate": (
                    f"{source}/Makefile" if source else ""
                ),
                "makefile_verified": False,
                "evidence_origin": (
                    "Exact firmware installed control Source fields; exact "
                    "SDK/Makefile unavailable."
                ),
            }
        )
    return rows, dict(source_packages)


def _render_report(summary: dict[str, Any]) -> str:
    total = summary["dataset"]["total_components"]
    metadata = summary["metadata_coverage"]
    sdk = summary["sdk_linkage"]
    firmware = summary["firmware_traceability"]
    source = summary["source_structure"]
    properties = summary["properties"]
    roles = summary["package_roles"]
    identities = summary["product_identity"]
    versions = summary["version_relationship"]
    installed_versions = summary["installed_version_evidence"]

    def count_table(counts: dict[str, int]) -> str:
        lines = ["| Category | Count | Percent |", "|---|---:|---:|"]
        for category, count in counts.items():
            lines.append(
                f"| {category} | {count:,} | {_percent(count, total):.2f}% |"
            )
        return "\n".join(lines)

    lines = [
        "# Unitronics UCR-ST-B8 Ground Truth pre-analysis",
        "",
        "This report is empirical pre-analysis for designing later Ground Truth ",
        "decision rules. It does **not** assign, validate, replace, or reject any CPE.",
        "Original SBOM CPE values and installed-control `CPE-ID` fields are retained ",
        "only as uninterpreted metadata and are excluded from matching and identity ",
        "classification.",
        "",
        "## Dataset and provenance",
        "",
        f"- SBOMDocument: `{summary['dataset']['sbom_document_id']}`",
        f"- Product: `{summary['dataset']['manufacturer']} {summary['dataset']['product']} {summary['dataset']['firmware_version']}`",
        f"- Components: `{total}` (expected `{EXPECTED_COMPONENT_COUNT}`)",
        f"- CycloneDX SHA-256: `{summary['provenance']['sbom_sha256']}`",
        f"- Official Unitronics ZIP URL: {OFFICIAL_FIRMWARE_URL}",
        f"- Observed ZIP SHA-256: `{summary['provenance']['official_zip_sha256']}`",
        f"- Exact firmware SHA-256: `{summary['provenance']['firmware_sha256']}`",
        "- The exact firmware SHA-256 equals the hash embedded in CycloneDX metadata.",
        f"- Existing DB SourceArtifact: `{summary['provenance']['database_source_artifact']}`",
        "- Exact-version SDK/GPL artifact: **not available** in the repository, DB, ",
        "  Unitronics firmware ZIP, or the checked official public download paths.",
        "- Other products' SDK/GPL archives were not substituted.",
        "",
        "## Exact firmware build evidence",
        "",
        f"- OpenWrt release: `{summary['firmware_build']['openwrt_release']}`",
        f"- OpenWrt revision: `{summary['firmware_build']['openwrt_revision']}`",
        f"- Target / architecture: `{summary['firmware_build']['target']}` / `{summary['firmware_build']['architecture']}`",
        f"- Kernel: `{summary['firmware_build']['kernel_version']}`",
        f"- Installed opkg controls: `{summary['firmware_build']['installed_control_count']}`",
        "- SDK root, feeds configuration, Makefile count, `PKG_*` assignments, ",
        "  `Package/<name>` blocks, install rules, and `BuildPackage` calls are ",
        "  **not observable without the exact SDK/GPL source**.",
        "",
        "## Metadata coverage",
        "",
        "| Field | Present | Coverage | Distinct |",
        "|---|---:|---:|---:|",
    ]
    for field, values in metadata.items():
        lines.append(
            f"| {field} | {values['present_count']:,} | "
            f"{values['coverage_percent']:.2f}% | "
            f"{values['distinct_value_count']:,} |"
        )
    lines.extend(
        [
            "",
            "Representative values for requested discriminating fields:",
            "",
        ]
    )
    for field in ("group", "publisher", "type", "purl", "supplier"):
        values = metadata[field]["representative_values"]
        lines.append(
            f"- {field}: `{values if values else ['(no values)']}`"
        )
    lines.extend(
        [
            "",
            "Observed distributions:",
            "",
            f"- group: `{summary['distributions']['group']}`",
            f"- type: `{summary['distributions']['type']}`",
            f"- publisher: `{summary['distributions']['publisher']}`",
            f"- purl ecosystems: `{summary['distributions']['purl_ecosystem']}`",
            "",
            "`name` identifies the installed package key; `version` is complete for ",
            "all rows but often combines upstream/date/revision and package release; ",
            "`properties` provides exact firmware paths. PURL adds opkg/binary ecosystem, ",
            "OpenWrt namespace, distro, and sometimes architecture, but not an upstream ",
            "source identity beyond name/version. `group` and `type` are almost constant; ",
            "publisher is empty. Supplier provides maintainer/vendor hints but is not ",
            "source provenance.",
            "",
            "## Properties",
            "",
            f"- Raw property keys: `{properties['raw_property_key_count']}`",
            f"- Semantic property keys after removing EMBA indices: `{properties['semantic_property_key_count']}`",
            f"- Property occurrences: `{properties['property_occurrence_count']}`",
            "- All 582 rows contain `source_path`, `minimal_identifier`, and confidence.",
            "- 575 `source_path` values identify installed opkg control files; seven ",
            "  identify kernel, ELF, BusyBox multicall, shared-library, or distribution ",
            "  artifacts. Installed-file `path` values cover 455 components.",
            "- The raw-key-level inventory is in `property_keys.csv`.",
            "",
            "Properties contribution to exact-firmware traceability:",
            "",
            count_table(properties["firmware_traceability_contribution"]),
            "",
            "Properties contribution to SDK/Makefile linkage:",
            "",
            count_table(properties["sdk_makefile_contribution"]),
            "",
            "The second table is all `E` because no exact SDK exists; it must not be ",
            "read as evidence that properties are intrinsically useless.",
            "",
            "## Version forms",
            "",
            count_table(summary["version_forms"]),
            "",
            "No version was corrected. Exact control matching verifies the installed ",
            "package version string but does not reliably decompose `PKG_VERSION` and ",
            "`PKG_RELEASE` without Makefiles.",
            "",
            "## SDK/Makefile linkage",
            "",
            count_table(sdk),
            "",
            "## Exact-firmware traceability (separate denominator and evidence)",
            "",
            count_table(firmware),
            "",
            "All 582 components are traceable inside the exact firmware; this is not ",
            "equivalent to SDK/Makefile linkage.",
            "",
            "## Observed source structure",
            "",
            f"- Distinct installed-control `Source` paths: `{source['distinct_source_packages']}`",
            f"- One Source -> one installed package: `{source['one_source_one_installed_package_sources']}` sources / `{source['one_source_one_installed_package_components']}` components",
            f"- One Source -> multiple installed packages: `{source['one_source_multiple_installed_packages_sources']}` sources / `{source['components_sharing_multi_package_source']}` components",
            f"- Maximum installed packages sharing one Source: `{source['maximum_installed_packages_per_source']}`",
            "- Largest observed multi-package Source groups:",
        ]
    )
    for item in source["largest_multi_package_sources"]:
        lines.append(
            f"  - `{item['source_package']}`: "
            f"`{item['installed_component_count']}` installed packages"
        )
    lines.extend(
        [
            "",
            "These counts describe installed controls in this firmware, not every ",
            "`Package/<name>` potentially emitted by an unavailable Makefile.",
            "",
            "## Package roles",
            "",
            count_table(roles),
            "",
            "Roles are structural review aids inferred from exact control Section/Source/",
            "Description, installed paths, and naming. They are not CPE decisions.",
            f"An orthogonal vendor-source flag covers `{summary['vendor_specific_flag']['component_count']}` components across `{summary['vendor_specific_flag']['source_package_count']}` Source paths. The exclusive `VENDOR_SPECIFIC_PACKAGE` role is assigned only after more specific library/plugin/kernel/utility roles.",
            "",
            "## Product identity status",
            "",
            count_table(identities),
            "",
            "`DIRECT_PRODUCT_EVIDENCE` is limited to the separately detected OpenWrt ",
            "release and Linux kernel banner. `POSSIBLE_PRODUCT` does not authorize a CPE.",
            "",
            "## Version relationship",
            "",
            count_table(versions),
            "",
            "Exact-firmware installed version evidence (separate observation):",
            "",
            count_table(installed_versions),
            "",
            "All 582 SDK/Makefile version relationships remain `UNRESOLVED`. ",
            "Separately, 575 SBOM versions equal the exact installed-control Version ",
            "and seven static rows have detector version strings from exact artifacts. ",
            "Neither observation decomposes `PKG_VERSION` and `PKG_RELEASE`.",
            "",
            "## Original CPE inventory (statistics only)",
            "",
            f"- Present: `{summary['original_cpe']['present_count']}`",
            f"- Missing: `{summary['original_cpe']['missing_count']}`",
            f"- Distinct: `{summary['original_cpe']['distinct_count']}`",
            "- No Dictionary, status, NVD Configuration, correctness, or correction ",
            "  analysis was performed.",
            "",
            "## Representative cases",
            "",
        ]
    )
    for category, examples in summary["representative_examples"].items():
        lines.append(f"### {category}")
        lines.append("")
        for example in examples:
            lines.extend(
                [
                    f"- `{example['name']} {example['version']}` ",
                    f"  - properties paths: `{example['properties_paths'] or '(none)'}`",
                    f"  - firmware control: `{example['firmware_control_path'] or '(none)'}`",
                    f"  - Makefile: `{example['makefile_path'] or '(not available)'}`",
                    f"  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `{example['pkg_name'] or '(not available)'}` / `{example['pkg_version'] or '(not available)'}` / `{example['pkg_release'] or '(not available)'}`",
                    f"  - Package definition: `{example['package_definition'] or '(not available)'}`",
                    f"  - source / installed package: `{example['source_package'] or '(unresolved)'}` / `{example['installed_package'] or '(binary evidence only)'}`",
                    f"  - role / identity: `{example['package_role']}` / `{example['product_identity_status']}`",
                    f"  - interpretation: {example['product_identity_evidence']}",
                    f"  - GT-rule relevance: {example['notes']}",
                ]
            )
        lines.append("")
    lines.extend(
        [
            "## Answers for next-step rule design",
            "",
            "1. **Useful metadata:** name, version, source/control paths, installed paths, ",
            "   dependencies, exact control Source/Section/Description, and binary version ",
            "   strings. Original CPE is excluded from evidence.",
            "2. **name/version/properties:** name locates the installed package; version ",
            "   supports exact installed-version comparison but often needs decomposition; ",
            "   properties prove where the package/artifact was observed.",
            "3. **PURL/group/publisher/type:** PURL adds ecosystem/distro/arch context; group ",
            "   and type have low discrimination; publisher adds none. Supplier is a hint.",
            f"4. **SDK/Makefile traceable:** `{sdk['DIRECT'] + sdk['INDIRECT']}` / `{total}`. ",
            f"   **Exact firmware traceable:** `{firmware['CONTROL_DIRECT'] + firmware['BINARY_DIRECT']}` / `{total}`.",
            "5. **Properties contribution:** properties strengthen 575 control links and ",
            "   enable seven binary/artifact links, but cannot improve unavailable SDK linkage.",
            f"6. **Multi-package Source:** `{source['one_source_multiple_installed_packages_sources']}` Source paths cover `{source['components_sharing_multi_package_source']}` installed components.",
            "7. **Roles:** see the exhaustive role table; kernel/kmod, libraries, plugins, ",
            "   vendor packages, utilities, main packages, and artifact/meta classes dominate.",
            "8. **Strong upstream-product evidence:** only separately detected OS/kernel ",
            "   identities are marked direct. Main/CLI package rows remain possible.",
            "9. **Split/library/utility/module:** shared Source paths and installed paths ",
            "   expose structure, but CPE inheritance is not inferred.",
            "10. **Kernel/kmod/firmware/meta:** control Section/name, Source, and installed ",
            "    artifact paths provide the distinction; all remain policy-neutral.",
            "11. **Versions:** installed control Version is exact for 575; seven detector ",
            "    versions are available; upstream/release decomposition needs Makefiles.",
            "12. **Hardest cases:** vendor packages, split runtime/plugin/library packages, ",
            "    BusyBox multicall detections, and components whose source product differs ",
            "    from the binary package name.",
            "13. **Next rule design:** require independent product-identity evidence; treat ",
            "    source sharing as relationship evidence only; review split/library/utility/",
            "    module and artifact classes separately; require exact version provenance; ",
            "    keep an unresolved path when exact SDK evidence is absent.",
            "",
            "## Policy questions requiring human decision",
            "",
            "- Whether and when a split/subpackage represents the same software product as ",
            "  its source package.",
            "- Whether a runtime library, CLI utility, or plugin/module is an independent ",
            "  product identity, a partial identity, or only packaging structure.",
            "- How BusyBox multicall applets should be represented when detector identity ",
            "  and artifact identity differ.",
            "- How vendor-specific closed/NDA-source packages should be handled without an ",
            "  exact public SDK.",
            "- Whether installed package release suffixes are part of the product version ",
            "  after exact Makefile evidence becomes available.",
            "",
            "## Validation",
            "",
            f"- Component rows: `{summary['validation']['component_row_count']}` == `{total}`",
            f"- Package-role partition: `{summary['validation']['package_role_sum']}` == `{total}`",
            f"- Product-identity partition: `{summary['validation']['product_identity_sum']}` == `{total}`",
            f"- SDK-linkage partition: `{summary['validation']['sdk_linkage_sum']}` == `{total}`",
            f"- Firmware-traceability partition: `{summary['validation']['firmware_traceability_sum']}` == `{total}`",
            f"- Version-relationship partition: `{summary['validation']['version_relationship_sum']}` == `{total}`",
            f"- Installed-version-evidence partition: `{summary['validation']['installed_version_evidence_sum']}` == `{total}`",
            f"- Ground Truth records before/after: `{summary['safety']['ground_truth_records_before']}` / `{summary['safety']['ground_truth_records_after']}`",
            "",
        ]
    )
    return "\n".join(lines)


def build_unitronics_preanalysis(
    *,
    sbom_id: int,
    official_zip_path: Path,
    firmware_binary_path: Path,
    firmware_rootfs: Path,
) -> UnitronicsPreanalysis:
    """Build the target-specific analysis without modifying database records."""

    with connection.cursor() as cursor:
        cursor.execute("SET default_transaction_read_only = on")

    document = SBOMDocument.objects.get(pk=sbom_id)
    database_components = list(
        Component.objects.filter(sbom_document=document).order_by("id")
    )
    _validate_target(document, database_components)
    ground_truth_before = ComponentCpeGroundTruth.objects.filter(
        component__sbom_document=document
    ).count()

    sbom_path = Path(document.uploaded_file.path)
    if _sha256(sbom_path) != EXPECTED_SBOM_SHA256:
        raise UnitronicsPreanalysisError("Stored CycloneDX SHA-256 changed.")
    raw_document = json.loads(sbom_path.read_text(encoding="utf-8"))
    raw_components = raw_document.get("components") or []
    database_by_ref = _validate_raw_components(
        raw_components, database_components
    )

    zip_sha256 = _sha256(official_zip_path)
    if zip_sha256 != OBSERVED_OFFICIAL_ZIP_SHA256:
        raise UnitronicsPreanalysisError(
            "Official firmware ZIP differs from the observed pinned artifact."
        )
    with ZipFile(official_zip_path) as archive:
        names = archive.namelist()
        if EXPECTED_FIRMWARE_FILENAME not in names:
            raise UnitronicsPreanalysisError(
                "Official Unitronics ZIP lacks the expected UCR-B8 firmware."
            )

    firmware_sha256 = _sha256(firmware_binary_path)
    if firmware_sha256 != EXPECTED_FIRMWARE_SHA256:
        raise UnitronicsPreanalysisError("Exact firmware SHA-256 changed.")
    metadata_hashes = {
        item.get("alg"): item.get("content")
        for item in raw_document.get("metadata", {})
        .get("component", {})
        .get("hashes", [])
    }
    if metadata_hashes.get("SHA-256") != firmware_sha256:
        raise UnitronicsPreanalysisError(
            "Official firmware SHA-256 does not match CycloneDX metadata."
        )

    controls = _read_controls(firmware_rootfs)
    source_rows, source_packages = _build_source_rows(controls)
    property_rows, semantic_property_summary = _property_key_rows(
        raw_components
    )

    component_rows: list[dict[str, Any]] = []
    direct_control_count = 0
    direct_binary_count = 0
    for raw in sorted(
        raw_components,
        key=lambda value: (
            str(value.get("name", "")),
            str(value.get("version", "")),
            str(value.get("bom-ref", "")),
        ),
    ):
        component = database_by_ref[str(raw["bom-ref"])]
        name = str(raw.get("name", ""))
        version = str(raw.get("version", ""))
        properties = _semantic_properties(raw)
        all_paths = _source_property_paths(raw)
        source_path_values = properties.get("source_path", [])
        source_path = source_path_values[0] if source_path_values else ""
        relative_source_path = _rootfs_relative_path(source_path)
        control = controls.get(name)
        firmware_traceability_status = ""
        matching_evidence = ""
        notes = ""
        if control is not None:
            expected_control_path = control["_relative_path"]
            if relative_source_path != expected_control_path:
                raise UnitronicsPreanalysisError(
                    f"Property/control path mismatch for {name}: "
                    f"{relative_source_path!r} != {expected_control_path!r}"
                )
            if version != control.get("Version", ""):
                raise UnitronicsPreanalysisError(
                    f"SBOM/control version mismatch for {name}."
                )
            firmware_traceability_status = "CONTROL_DIRECT"
            direct_control_count += 1
            matching_evidence = (
                f"properties source_path -> {expected_control_path}; "
                f"control Package={name}; control Version={version}; "
                f"control Source={control.get('Source', '')}"
            )
        else:
            if relative_source_path is None and name != "linux_kernel":
                raise UnitronicsPreanalysisError(
                    f"Static component has no exact firmware path: {name}"
                )
            if relative_source_path is not None:
                candidate = firmware_rootfs / relative_source_path.lstrip("/")
                if not candidate.exists():
                    raise UnitronicsPreanalysisError(
                        "Static component artifact is missing: "
                        f"{relative_source_path}"
                    )
            firmware_traceability_status = "BINARY_DIRECT"
            direct_binary_count += 1
            if name == "linux_kernel":
                matching_evidence = (
                    f"properties source_path -> {source_path}; exact firmware "
                    "uImage identifies Linux 5.15.176; module paths are present "
                    "under /lib/modules/5.15.176"
                )
            else:
                matching_evidence = (
                    f"properties source_path -> {relative_source_path}; "
                    "detector identity/version evidence retained from exact firmware"
                )

        source_package = control.get("Source", "") if control else ""
        source_count = len(source_packages.get(source_package, [])) if control else 0
        role = _classify_package_role(raw, control, source_count)
        identity_status = _classify_product_identity(raw, role)
        vendor_specific = bool(control and _is_vendor_source(control))
        source_candidate = (
            _source_basename(source_package) if source_package else ""
        )
        if control:
            product_identity_evidence = (
                f"Exact installed control identifies Source={source_package}, "
                f"Section={control.get('Section', '')}, and "
                f"Description={control.get('Description', '').strip()}; "
                "the exact Makefile and upstream release metadata are absent."
            )
            notes = (
                "Review whether this installed binary package represents its "
                "Source product; source sharing does not imply CPE inheritance."
            )
            version_relationship = "UNRESOLVED"
            installed_version_evidence = "SBOM_EQUALS_CONTROL_VERSION"
        else:
            detected = properties.get("identifer_detected", [])
            product_identity_evidence = (
                f"Exact artifact path and detector string {detected!r}; no "
                "installed control or exact source Makefile."
            )
            notes = (
                "Binary/distribution identity requires independent review; "
                "multicall or bundled artifacts may not equal the detected product."
            )
            version_relationship = "UNRESOLVED"
            installed_version_evidence = "DETECTOR_VERSION_AVAILABLE"

        raw_property_keys = sorted(
            {
                str(item.get("name", ""))
                for item in raw.get("properties") or []
            }
        )
        installed_paths = properties.get("path", [])
        component_rows.append(
            {
                "component_id": component.id,
                "bom_ref": component.bom_ref,
                "name": name,
                "version": version,
                "version_form": _classify_version_form(name, version),
                "original_cpe": str(raw.get("cpe", "")),
                "purl": str(raw.get("purl", "")),
                "group": str(raw.get("group", "")),
                "publisher": str(raw.get("publisher", "")),
                "supplier": str((raw.get("supplier") or {}).get("name", "")),
                "author": str(raw.get("author", "")),
                "type": str(raw.get("type", "")),
                "external_references": _json_cell(
                    raw.get("externalReferences")
                ),
                "evidence": _json_cell(raw.get("evidence")),
                "properties_keys": " | ".join(raw_property_keys),
                "properties_summary": json.dumps(
                    properties, ensure_ascii=False, sort_keys=True
                ),
                "properties_paths": " | ".join(all_paths),
                "firmware_traceability_status": firmware_traceability_status,
                "firmware_control_path": (
                    control.get("_relative_path", "") if control else ""
                ),
                "sdk_match_status": "NO_MATCH",
                "sdk_package_path": "",
                "makefile_path": "",
                "makefile_path_candidate": (
                    f"{source_package}/Makefile" if source_package else ""
                ),
                "pkg_name": "",
                "pkg_version": "",
                "pkg_release": "",
                "package_definition": "",
                "installed_package": control.get("Package", "") if control else "",
                "installed_package_version": (
                    control.get("Version", "") if control else ""
                ),
                "source_package": source_package,
                "pkg_source": "",
                "pkg_source_url": "",
                "pkg_source_version": "",
                "pkg_source_date": "",
                "control_source_name": (
                    control.get("SourceName", "") if control else ""
                ),
                "control_source_date_epoch": (
                    control.get("SourceDateEpoch", "") if control else ""
                ),
                "control_cpe_id": (
                    control.get("CPE-ID", "") if control else ""
                ),
                "control_license": (
                    control.get("License", "") if control else ""
                ),
                "control_section": (
                    control.get("Section", "") if control else ""
                ),
                "control_maintainer": (
                    control.get("Maintainer", "") if control else ""
                ),
                "control_description": (
                    control.get("Description", "").strip() if control else ""
                ),
                "control_dependencies": (
                    control.get("Depends", "") if control else ""
                ),
                "installed_paths": " | ".join(installed_paths),
                "source_installed_package_count": source_count,
                "source_structure": (
                    "ONE_SOURCE_ONE_INSTALLED_PACKAGE"
                    if source_count == 1
                    else (
                        "ONE_SOURCE_MULTIPLE_INSTALLED_PACKAGES"
                        if source_count > 1
                        else "SOURCE_UNRESOLVED"
                    )
                ),
                "is_vendor_specific": vendor_specific,
                "package_role": role,
                "product_identity_status": identity_status,
                "upstream_product_candidate": source_candidate,
                "version_relationship": version_relationship,
                "installed_version_evidence": installed_version_evidence,
                "version_release_decomposition": "UNRESOLVED",
                "properties_contribution_sdk": "E",
                "properties_contribution_firmware": (
                    "B" if control else "C"
                ),
                "matching_evidence": matching_evidence,
                "product_identity_evidence": product_identity_evidence,
                "notes": notes,
            }
        )

    if direct_control_count != 575 or direct_binary_count != 7:
        raise UnitronicsPreanalysisError(
            "Unexpected exact-firmware traceability partition: "
            f"{direct_control_count} controls, {direct_binary_count} binaries."
        )

    total = len(component_rows)
    field_names = (
        "bom-ref",
        "name",
        "version",
        "cpe",
        "properties",
        "purl",
        "group",
        "publisher",
        "supplier",
        "author",
        "type",
        "externalReferences",
        "evidence",
    )
    metadata_coverage = {
        field: _field_coverage(raw_components, field) for field in field_names
    }
    original_cpes = [
        str(component.get("cpe", ""))
        for component in raw_components
        if component.get("cpe")
    ]
    source_counts = [row["installed_component_count"] for row in source_rows]
    source_prefix_counts = Counter()
    for row in source_rows:
        source = str(row["source_package"])
        prefix = (
            "package/teltonika"
            if source.startswith("package/teltonika/")
            else (
                "feeds/vuci"
                if source.startswith("feeds/vuci")
                else source.split("/", 2)[0]
            )
        )
        source_prefix_counts[prefix] += 1

    role_counts = _counter_dict(
        (row["package_role"] for row in component_rows), PACKAGE_ROLES
    )
    identity_counts = _counter_dict(
        (row["product_identity_status"] for row in component_rows),
        PRODUCT_IDENTITY_STATUSES,
    )
    relationship_counts = _counter_dict(
        (row["version_relationship"] for row in component_rows),
        VERSION_RELATIONSHIPS,
    )
    installed_version_counts = _counter_dict(
        (row["installed_version_evidence"] for row in component_rows),
        ("SBOM_EQUALS_CONTROL_VERSION", "DETECTOR_VERSION_AVAILABLE"),
    )
    version_form_counts = _counter_dict(
        (row["version_form"] for row in component_rows), VERSION_FORMS
    )
    examples = _build_examples(component_rows)
    openwrt = _read_openwrt_provenance(firmware_rootfs)

    try:
        source_artifact = document.source_artifact
        database_source_artifact: dict[str, Any] | None = {
            "id": source_artifact.id,
            "filename": source_artifact.original_filename,
            "sha256": source_artifact.file_sha256,
        }
    except SourceArtifact.DoesNotExist:
        database_source_artifact = None

    raw_property_occurrences = sum(
        len(component.get("properties") or []) for component in raw_components
    )
    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analysis_scope": (
            "Ground Truth rule-design pre-analysis; no CPE determination"
        ),
        "dataset": {
            "sbom_document_id": document.id,
            "manufacturer": document.manufacturer,
            "product": document.product_name,
            "firmware_version": document.product_version,
            "total_components": total,
        },
        "provenance": {
            "sbom_original_filename": document.original_filename,
            "sbom_stored_path": document.uploaded_file.name,
            "sbom_sha256": document.file_sha256,
            "cyclonedx_serial_number": raw_document.get("serialNumber", ""),
            "cyclonedx_spec_version": raw_document.get("specVersion", ""),
            "generated_at": raw_document.get("metadata", {}).get(
                "timestamp", ""
            ),
            "generator": (
                f"{document.generator_name} {document.generator_version}"
            ),
            "official_firmware_url": OFFICIAL_FIRMWARE_URL,
            "official_zip_filename": official_zip_path.name,
            "official_zip_sha256": zip_sha256,
            "firmware_filename": firmware_binary_path.name,
            "firmware_sha256": firmware_sha256,
            "firmware_sha256_matches_cyclonedx": True,
            "database_source_artifact": database_source_artifact,
            "exact_sdk_gpl_available": False,
            "exact_sdk_gpl_reason": (
                "No SourceArtifact is linked to SBOMDocument 1364; no exact "
                "archive is stored locally; the official Unitronics firmware "
                "ZIP contains four firmware binaries and no SDK/GPL source; "
                "checked official exact-version filename candidates returned "
                "404."
            ),
        },
        "firmware_build": {
            "openwrt_based": openwrt.get("DISTRIB_ID") == "OpenWrt",
            "openwrt_release": openwrt.get("DISTRIB_RELEASE", ""),
            "openwrt_revision": openwrt.get("DISTRIB_REVISION", ""),
            "target": openwrt.get("DISTRIB_TARGET", ""),
            "architecture": openwrt.get("DISTRIB_ARCH", ""),
            "kernel_version": "5.15.176",
            "installed_control_count": len(controls),
            "distinct_control_source_count": len(source_rows),
            "control_source_prefix_counts": dict(
                sorted(source_prefix_counts.items())
            ),
            "sdk_root": None,
            "feeds": None,
            "makefile_count": 0,
            "package_makefile_count": 0,
            "makefile_count_interpretation": (
                "Not observable because the exact SDK/GPL source is absent; "
                "zero means zero verified files, not that the build used none."
            ),
        },
        "metadata_coverage": metadata_coverage,
        "distributions": {
            "group": _distribution(
                str(component.get("group", "")) for component in raw_components
            ),
            "type": _distribution(
                str(component.get("type", "")) for component in raw_components
            ),
            "publisher": _distribution(
                str(component.get("publisher", ""))
                for component in raw_components
            ),
            "supplier": _distribution(
                str((component.get("supplier") or {}).get("name", ""))
                for component in raw_components
            ),
            "purl_ecosystem": _distribution(
                "pkg:opkg/openwrt"
                if str(component.get("purl", "")).startswith(
                    "pkg:opkg/openwrt/"
                )
                else "pkg:binary"
                for component in raw_components
            ),
        },
        "properties": {
            "raw_property_key_count": len(property_rows),
            "semantic_property_key_count": len(semantic_property_summary),
            "property_occurrence_count": raw_property_occurrences,
            "semantic_keys": semantic_property_summary,
            "firmware_traceability_contribution": {
                "A_NAME_VERSION_ONLY": 0,
                "B_PROPERTIES_STRENGTHEN": direct_control_count,
                "C_PROPERTIES_ENABLE_LINK": direct_binary_count,
                "D_PROPERTIES_RESOLVE_AMBIGUITY": 0,
                "E_STILL_UNLINKED": 0,
            },
            "sdk_makefile_contribution": {
                "A_NAME_VERSION_ONLY": 0,
                "B_PROPERTIES_STRENGTHEN": 0,
                "C_PROPERTIES_ENABLE_LINK": 0,
                "D_PROPERTIES_RESOLVE_AMBIGUITY": 0,
                "E_STILL_UNLINKED": total,
            },
        },
        "version_forms": version_form_counts,
        "sdk_linkage": {
            "DIRECT": 0,
            "INDIRECT": 0,
            "AMBIGUOUS": 0,
            "NO_MATCH": total,
        },
        "firmware_traceability": {
            "CONTROL_DIRECT": direct_control_count,
            "BINARY_DIRECT": direct_binary_count,
            "AMBIGUOUS": 0,
            "NO_MATCH": 0,
        },
        "source_structure": {
            "distinct_source_packages": len(source_rows),
            "one_source_one_installed_package_sources": sum(
                count == 1 for count in source_counts
            ),
            "one_source_one_installed_package_components": sum(
                count for count in source_counts if count == 1
            ),
            "one_source_multiple_installed_packages_sources": sum(
                count > 1 for count in source_counts
            ),
            "components_sharing_multi_package_source": sum(
                count for count in source_counts if count > 1
            ),
            "maximum_installed_packages_per_source": max(source_counts),
            "largest_multi_package_sources": [
                {
                    "source_package": row["source_package"],
                    "installed_component_count": row[
                        "installed_component_count"
                    ],
                }
                for row in sorted(
                    source_rows,
                    key=lambda value: (
                        -value["installed_component_count"],
                        value["source_package"],
                    ),
                )[:10]
                if row["installed_component_count"] > 1
            ],
            "unresolved_source_components": direct_binary_count,
            "denominator_note": (
                "Source counts use 575 installed opkg component rows; the "
                "seven detector-only rows have no installed-control Source."
            ),
        },
        "package_roles": role_counts,
        "vendor_specific_flag": {
            "component_count": sum(
                bool(row["is_vendor_specific"]) for row in component_rows
            ),
            "source_package_count": sum(
                bool(row["is_vendor_specific"]) for row in source_rows
            ),
        },
        "product_identity": identity_counts,
        "version_relationship": relationship_counts,
        "installed_version_evidence": installed_version_counts,
        "version_release_decomposition": {
            "UNRESOLVED": total,
            "reason": (
                "Installed control Version is not enough to separate exact "
                "PKG_VERSION and PKG_RELEASE without Makefile assignments."
            ),
        },
        "original_cpe": {
            "present_count": len(original_cpes),
            "missing_count": total - len(original_cpes),
            "distinct_count": len(set(original_cpes)),
            "used_as_matching_evidence": False,
        },
        "representative_examples": examples,
        "limitations": [
            "No exact-version SDK/GPL archive or Makefiles were available.",
            "Installed-control Source fields describe build source paths but do "
            "not enumerate every binary package a Makefile can generate.",
            "Package roles and product identity statuses are pre-review evidence "
            "classes, not Ground Truth CPE decisions.",
            "Original CPE and installed-control CPE-ID values were not used for "
            "matching, role classification, or identity classification.",
            "No CPE Dictionary or NVD Configuration data was queried.",
        ],
        "safety": {
            "database_session_read_only": True,
            "ground_truth_records_before": ground_truth_before,
            "ground_truth_records_after": None,
            "database_mutations": 0,
        },
    }

    ground_truth_after = ComponentCpeGroundTruth.objects.filter(
        component__sbom_document=document
    ).count()
    summary["safety"]["ground_truth_records_after"] = ground_truth_after
    if ground_truth_before != ground_truth_after:
        raise UnitronicsPreanalysisError(
            "Ground Truth record count changed during read-only analysis."
        )

    summary["validation"] = {
        "component_row_count": len(component_rows),
        "expected_component_count": EXPECTED_COMPONENT_COUNT,
        "package_role_sum": sum(role_counts.values()),
        "product_identity_sum": sum(identity_counts.values()),
        "sdk_linkage_sum": sum(summary["sdk_linkage"].values()),
        "firmware_traceability_sum": sum(
            summary["firmware_traceability"].values()
        ),
        "version_relationship_sum": sum(relationship_counts.values()),
        "installed_version_evidence_sum": sum(
            installed_version_counts.values()
        ),
        "version_form_sum": sum(version_form_counts.values()),
        "source_component_sum": (
            summary["source_structure"][
                "one_source_one_installed_package_components"
            ]
            + summary["source_structure"][
                "components_sharing_multi_package_source"
            ]
            + summary["source_structure"]["unresolved_source_components"]
        ),
        "all_partitions_equal_total": all(
            value == total
            for value in (
                sum(role_counts.values()),
                sum(identity_counts.values()),
                sum(summary["sdk_linkage"].values()),
                sum(summary["firmware_traceability"].values()),
                sum(relationship_counts.values()),
                sum(installed_version_counts.values()),
                sum(version_form_counts.values()),
                summary["source_structure"][
                    "one_source_one_installed_package_components"
                ]
                + summary["source_structure"][
                    "components_sharing_multi_package_source"
                ]
                + summary["source_structure"]["unresolved_source_components"],
            )
        ),
    }
    if not summary["validation"]["all_partitions_equal_total"]:
        raise UnitronicsPreanalysisError(
            "One or more component partitions do not sum to 582."
        )

    report = _render_report(summary)
    return UnitronicsPreanalysis(
        summary=summary,
        components=component_rows,
        property_keys=property_rows,
        source_packages=source_rows,
        report=report,
    )


def _render_csv(
    fieldnames: tuple[str, ...], rows: Iterable[dict[str, Any]]
) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=fieldnames, lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def render_unitronics_preanalysis(
    analysis: UnitronicsPreanalysis,
) -> dict[str, str]:
    return {
        COMPONENTS_FILENAME: _render_csv(
            COMPONENT_FIELDS, analysis.components
        ),
        PROPERTY_KEYS_FILENAME: _render_csv(
            PROPERTY_KEY_FIELDS, analysis.property_keys
        ),
        SOURCE_PACKAGES_FILENAME: _render_csv(
            SOURCE_PACKAGE_FIELDS, analysis.source_packages
        ),
        SUMMARY_FILENAME: json.dumps(
            analysis.summary, ensure_ascii=False, indent=2
        )
        + "\n",
        REPORT_FILENAME: analysis.report,
    }


def write_unitronics_preanalysis(
    analysis: UnitronicsPreanalysis,
    output_directory: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, ...]:
    output_directory.mkdir(parents=True, exist_ok=True)
    output_paths = tuple(
        output_directory / filename for filename in OUTPUT_FILENAMES
    )
    existing = [path for path in output_paths if path.exists()]
    if existing and not overwrite:
        raise UnitronicsPreanalysisError(
            "Refusing to replace existing analysis files without --overwrite: "
            + ", ".join(str(path) for path in existing)
        )
    rendered = render_unitronics_preanalysis(analysis)
    temporary_paths: dict[str, Path] = {}
    try:
        for filename in OUTPUT_FILENAMES:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{filename}.",
                suffix=".tmp",
                dir=output_directory,
            )
            temporary_path = Path(temporary_name)
            temporary_paths[filename] = temporary_path
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="",
            ) as stream:
                stream.write(rendered[filename])
                stream.flush()
                os.fsync(stream.fileno())
        for filename, output_path in zip(
            OUTPUT_FILENAMES, output_paths, strict=True
        ):
            os.replace(temporary_paths[filename], output_path)
        return output_paths
    finally:
        for path in temporary_paths.values():
            path.unlink(missing_ok=True)


def default_output_directory() -> Path:
    return (
        settings.REPOSITORY_ROOT
        / "analysis"
        / "results"
        / "unitronics-ground-truth-preanalysis"
        / "61602e128acb__52.07.13.7"
    )

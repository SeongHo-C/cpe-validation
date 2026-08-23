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

from django.conf import settings
from django.db import connection

from sboms.models import Component, ComponentCpeGroundTruth, SBOMDocument
from sboms.unitronics_gt_preanalysis import (
    EXPECTED_COMPONENT_COUNT,
    EXPECTED_FIRMWARE_SHA256,
    EXPECTED_MANUFACTURER,
    EXPECTED_PRODUCT,
    EXPECTED_SBOM_ID,
    EXPECTED_SBOM_SHA256,
    EXPECTED_VERSION,
)


SCHEMA_VERSION = 1
EXPECTED_INSTALLED_PACKAGES = 575
EXPECTED_SOURCE_COUNT = 303
EXPECTED_SINGLE_SOURCE_COUNT = 261
EXPECTED_MULTI_SOURCE_COUNT = 42

PACKAGES_FILENAME = "packages.csv"
SOURCES_FILENAME = "sources.csv"
MULTI_SOURCES_FILENAME = "multi_package_sources.csv"
CPE_PROPAGATION_FILENAME = "cpe_id_propagation.csv"
SUMMARY_FILENAME = "summary.json"
REPORT_FILENAME = "report.md"
OUTPUT_FILENAMES = (
    PACKAGES_FILENAME,
    SOURCES_FILENAME,
    MULTI_SOURCES_FILENAME,
    CPE_PROPAGATION_FILENAME,
    SUMMARY_FILENAME,
    REPORT_FILENAME,
)

PACKAGE_ROLES = (
    "PRODUCT_OR_MAIN_PACKAGE",
    "SPLIT_RUNTIME_PACKAGE",
    "LIBRARY_PACKAGE",
    "UTILITY_OR_CLI_PACKAGE",
    "PLUGIN_OR_MODULE",
    "KERNEL_OR_KMOD",
    "FIRMWARE_OR_DRIVER_ARTIFACT",
    "META_OR_HELPER_PACKAGE",
    "VENDOR_SPECIFIC_PACKAGE",
    "UNKNOWN",
)

PRODUCT_IDENTITY_STATUSES = (
    "DIRECT_PRODUCT_CANDIDATE",
    "POSSIBLE_PRODUCT_CANDIDATE",
    "PARTIAL_OR_SPLIT_COMPONENT",
    "NON_PRODUCT_ARTIFACT",
    "AMBIGUOUS",
    "UNRESOLVED",
)

PATH_CATEGORIES = (
    "executable",
    "library",
    "plugin_module",
    "kernel_module",
    "firmware_file",
    "config_file",
    "data_script",
    "development_artifact",
    "other",
)

PACKAGE_FIELDS = (
    "component_id",
    "sbom_name",
    "sbom_version",
    "package",
    "version",
    "source",
    "source_name",
    "source_date_epoch",
    "description",
    "depends",
    "provides",
    "architecture",
    "license",
    "maintainer",
    "section",
    "cpe_id",
    "control_path",
    "list_path",
    "status_version_matches",
    "status_architecture_matches",
    "control_fields_json",
    "installed_file_count",
    "existing_regular_file_count",
    "existing_symlink_count",
    "missing_listed_path_count",
    "executable_count",
    "library_count",
    "plugin_module_count",
    "kernel_module_count",
    "firmware_file_count",
    "config_file_count",
    "data_script_count",
    "development_artifact_count",
    "other_path_count",
    "representative_paths",
    "executable_paths",
    "library_paths",
    "plugin_module_paths",
    "kernel_module_paths",
    "firmware_paths",
    "config_paths",
    "data_script_paths",
    "development_paths",
    "installed_paths_json",
    "source_package_count",
    "sibling_packages",
    "single_or_multi",
    "source_name_aligned",
    "is_vendor_specific",
    "package_role",
    "product_identity_status",
    "role_evidence_basis",
    "role_evidence",
    "product_identity_evidence",
    "notes",
)

SOURCE_FIELDS = (
    "source",
    "package_count",
    "packages",
    "single_or_multi",
    "source_name_values",
    "version_values",
    "cpe_id_values",
    "cpe_id_package_count",
    "cpe_id_consistency",
    "product_candidate_count",
    "direct_product_candidate_count",
    "possible_product_candidate_count",
    "partial_component_count",
    "non_product_count",
    "ambiguous_count",
    "unresolved_count",
    "role_distribution",
    "main_package_candidate",
    "has_main_product_like_package",
    "has_library_split",
    "has_utility_split",
    "has_plugin_module_split",
    "has_kernel_package",
    "is_vendor_specific",
    "source_structure_summary",
)

MULTI_SOURCE_FIELDS = SOURCE_FIELDS + (
    "package_details_json",
)

CPE_PROPAGATION_FIELDS = (
    "cpe_id",
    "global_package_count",
    "global_source_count",
    "source",
    "source_package_count",
    "cpe_id_package_count_within_source",
    "cpe_id_coverage_percent_within_source",
    "packages",
    "propagation_status",
    "source_cpe_id_consistency",
)


class UnitronicsSourceAnalysisError(Exception):
    """Raised when exact-firmware evidence or a partition is inconsistent."""


@dataclass(frozen=True)
class UnitronicsSourceAnalysis:
    summary: dict[str, Any]
    packages: list[dict[str, Any]]
    sources: list[dict[str, Any]]
    multi_sources: list[dict[str, Any]]
    cpe_propagation: list[dict[str, Any]]
    report: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _percent(count: int, total: int) -> float:
    return round((count / total * 100.0) if total else 0.0, 2)


def _parse_stanzas(text: str) -> list[dict[str, str]]:
    stanzas: list[dict[str, str]] = []
    stanza: dict[str, str] = {}
    current_key: str | None = None
    for line in [*text.splitlines(), ""]:
        if line[:1].isspace() and current_key:
            stanza[current_key] += "\n" + line.strip()
        elif ": " in line:
            current_key, value = line.split(": ", 1)
            stanza[current_key] = value
        elif not line.strip():
            if stanza:
                stanzas.append(stanza)
                stanza = {}
            current_key = None
        else:
            current_key = None
    return stanzas


def _read_control(path: Path) -> dict[str, str]:
    stanzas = _parse_stanzas(path.read_text(encoding="utf-8", errors="replace"))
    if len(stanzas) != 1 or not stanzas[0].get("Package"):
        raise UnitronicsSourceAnalysisError(f"Invalid control file: {path}")
    return stanzas[0]


def _source_basename(source: str) -> str:
    return source.rstrip("/").rsplit("/", 1)[-1] if source else ""


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.lower()).strip("-")


def _source_name_aligned(package: str, source: str) -> bool:
    return _normalized_name(package) == _normalized_name(
        _source_basename(source)
    )


def _is_vendor_source(control: dict[str, str]) -> bool:
    source = control.get("Source", "").lower()
    return any(
        token in source
        for token in ("/teltonika/", "feeds/vuci", "custom_feeds/")
    )


def _path_category(path: str, rootfs: Path) -> str:
    lowered = path.lower()
    suffix = Path(lowered).suffix
    if lowered.startswith("/lib/modules/") or lowered.endswith(".ko"):
        return "kernel_module"
    if lowered.startswith(("/lib/firmware/", "/usr/lib/firmware/")):
        return "firmware_file"
    if (
        lowered.startswith("/usr/include/")
        or suffix in {".h", ".hpp", ".a", ".pc", ".la"}
    ):
        return "development_artifact"
    plugin_markers = (
        "/plugins/",
        "/plugin/",
        "/usr/lib/lua/",
        "/usr/lib/ucode/",
        "/usr/lib/iptables/",
        "/usr/lib/xtables/",
        "/usr/lib/pppd/",
        "/usr/lib/ipsec/plugins/",
        "/ossl-modules/",
    )
    if any(marker in lowered for marker in plugin_markers):
        return "plugin_module"
    if re.search(r"\.so(?:\..*)?$", lowered) and lowered.startswith(
        ("/lib/", "/usr/lib/")
    ):
        return "library"
    if lowered.startswith(
        ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/")
    ):
        return "executable"
    if lowered.startswith("/etc/"):
        return "config_file"
    candidate = rootfs / path.lstrip("/")
    try:
        executable_mode = bool(candidate.stat().st_mode & 0o111)
    except FileNotFoundError:
        executable_mode = False
    if executable_mode and candidate.is_file():
        return "executable"
    if lowered.startswith(("/usr/share/", "/www/")) or suffix in {
        ".lua",
        ".js",
        ".sh",
        ".uc",
        ".py",
    }:
        return "data_script"
    return "other"


def _path_state(rootfs: Path, path: str) -> str:
    candidate = rootfs / path.lstrip("/")
    if candidate.is_symlink():
        return "symlink"
    if candidate.is_file():
        return "regular_file"
    return "missing"


def _representative(values: list[str], limit: int = 5) -> str:
    return " | ".join(values[:limit])


def _description_excerpt(value: str, limit: int = 180) -> str:
    cleaned = " ".join(value.split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def _role_for_package(
    control: dict[str, str],
    category_counts: Counter[str],
    installed_path_count: int,
    source_package_count: int,
) -> tuple[str, str]:
    package = control["Package"]
    lowered = package.lower()
    source = control["Source"]
    section = control.get("Section", "").lower()
    description = control.get("Description", "").lower()
    aligned = _source_name_aligned(package, source)
    vendor = _is_vendor_source(control)
    executable_count = category_counts["executable"]
    library_count = category_counts["library"]
    plugin_count = category_counts["plugin_module"]
    kernel_count = category_counts["kernel_module"]
    firmware_count = category_counts["firmware_file"]
    development_count = category_counts["development_artifact"]
    payload_count = sum(category_counts[value] for value in PATH_CATEGORIES[:-1])

    if section == "kernel" or lowered.startswith("kmod-") or (
        source == "package/kernel/linux" and lowered == "kernel"
    ):
        return "KERNEL_OR_KMOD", (
            f"Section={section}; kernel paths={kernel_count}; "
            f"listed paths={installed_path_count}."
        )
    if section == "firmware" or (
        firmware_count > 0 and kernel_count == 0
    ):
        return "FIRMWARE_OR_DRIVER_ARTIFACT", (
            f"Section={section}; firmware paths={firmware_count}; "
            f"listed paths={installed_path_count}."
        )
    if development_count > 0 and payload_count == development_count:
        return "META_OR_HELPER_PACKAGE", (
            f"Development-only payload={development_count}; no runtime path."
        )

    web_section = section in {"vuci", "webui", "luci"}
    module_named = (
        "-mod-" in lowered
        or lowered.startswith(("rpcd-mod-", "ucode-mod-"))
        or lowered.endswith(("-module", "-plugin"))
    )
    utility_hint = (
        section in {"utils", "lang"}
        or lowered.endswith(("ctl", "-tools", "-util", "-utils", "-bin"))
        or any(
            token in description
            for token in (
                "command line",
                "command-line",
                "console line interface",
                " utility",
                "utilities",
                "administration tool",
                "client tool",
                "client-side url transfer",
            )
        )
    )
    source_aligned_main = (
        aligned
        and source_package_count > 1
        and installed_path_count > 0
        and not web_section
        and not utility_hint
        and not lowered.startswith("lib")
        and not module_named
    )
    if source_aligned_main:
        return "PRODUCT_OR_MAIN_PACKAGE", (
            "Package name aligns with control Source basename; it has "
            f"{installed_path_count} listed paths and "
            f"{source_package_count - 1} siblings."
        )
    if web_section or module_named or plugin_count > 0:
        return "PLUGIN_OR_MODULE", (
            f"Section={section}; plugin/module paths={plugin_count}; "
            f"module-style name={module_named}; listed paths={installed_path_count}."
        )
    if installed_path_count == 0:
        return "META_OR_HELPER_PACKAGE", (
            "The exact .list is empty; role relies on control metadata and "
            "sibling structure."
        )

    if utility_hint and executable_count > 0:
        return "UTILITY_OR_CLI_PACKAGE", (
            f"Section={section}; executables={executable_count}; control "
            "description identifies utility/tool behavior."
        )
    if source_package_count > 1 and executable_count > 0:
        return "SPLIT_RUNTIME_PACKAGE", (
            f"Non-aligned executable/runtime package with {source_package_count - 1} "
            "siblings; no utility or module signature."
        )
    if (
        executable_count == 0
        and library_count == 0
        and plugin_count == 0
        and kernel_count == 0
        and firmware_count == 0
        and installed_path_count > 0
    ):
        return "META_OR_HELPER_PACKAGE", (
            "The .list contains only configuration/data/other helper paths; "
            f"listed paths={installed_path_count}."
        )
    if section == "libs" or (library_count > 0 and executable_count == 0):
        return "LIBRARY_PACKAGE", (
            f"Section={section}; libraries={library_count}; executables="
            f"{executable_count}; listed paths={installed_path_count}."
        )
    if aligned and (executable_count > 0 or payload_count > 0):
        if utility_hint:
            return "UTILITY_OR_CLI_PACKAGE", (
                f"Source-aligned utility/CLI with {executable_count} executables; "
                "role and product identity are assessed separately."
            )
        return "PRODUCT_OR_MAIN_PACKAGE", (
            "Package name aligns with control Source basename and the .list "
            f"contains {installed_path_count} paths ({executable_count} executables)."
        )
    if source_package_count > 1:
        return "SPLIT_RUNTIME_PACKAGE", (
            f"Package has {source_package_count - 1} siblings and does not match "
            "a more specific library/plugin/utility/kernel/artifact signature."
        )
    if vendor:
        return "VENDOR_SPECIFIC_PACKAGE", (
            f"Vendor Source={source}; content signature is not more specific."
        )
    if executable_count > 0:
        return "POSSIBLE_PRODUCT_PACKAGE", ""
    return "UNKNOWN", (
        f"No decisive role signature; Section={section}; listed paths="
        f"{installed_path_count}."
    )


def _normalize_role(role: str, control: dict[str, str]) -> tuple[str, str | None]:
    if role == "POSSIBLE_PRODUCT_PACKAGE":
        return (
            "PRODUCT_OR_MAIN_PACKAGE",
            "Executable-bearing single package without source-name alignment.",
        )
    return role, None


def _identity_for_package(
    row: dict[str, Any], source_rows: list[dict[str, Any]]
) -> tuple[str, str]:
    role = row["package_role"]
    aligned = bool(row["source_name_aligned"])
    vendor = bool(row["is_vendor_specific"])
    source_count = int(row["source_package_count"])
    installed_count = int(row["installed_file_count"])
    executable_count = int(row["executable_count"])
    library_count = int(row["library_count"])
    sibling_roles = Counter(value["package_role"] for value in source_rows)
    sibling_main = [
        value["package"]
        for value in source_rows
        if value["package_role"] == "PRODUCT_OR_MAIN_PACKAGE"
        and value["package"] != row["package"]
    ]
    shared = (
        f"name/source alignment={aligned}; source packages={source_count}; "
        f"executables={executable_count}; libraries={library_count}; "
        f"sibling roles={dict(sorted(sibling_roles.items()))}"
    )

    if role == "FIRMWARE_OR_DRIVER_ARTIFACT":
        return "NON_PRODUCT_ARTIFACT", shared + "; firmware/data artifact role."
    if role == "META_OR_HELPER_PACKAGE":
        return "NON_PRODUCT_ARTIFACT", (
            shared + "; empty/development/helper payload does not itself show a "
            "complete runtime product."
        )
    if role == "KERNEL_OR_KMOD":
        if row["package"] == "kernel" and installed_count == 0:
            return "NON_PRODUCT_ARTIFACT", shared + "; virtual kernel package."
        return "PARTIAL_OR_SPLIT_COMPONENT", shared + "; kernel/module scope."
    if role == "PRODUCT_OR_MAIN_PACKAGE":
        if aligned and not vendor and installed_count > 0:
            return "DIRECT_PRODUCT_CANDIDATE", (
                shared
                + "; control Source name and installed core payload align. This is "
                "a product candidate, not a CPE decision."
            )
        return "POSSIBLE_PRODUCT_CANDIDATE", (
            shared + "; main-like runtime evidence exists but source/vendor identity "
            "needs independent confirmation."
        )
    if role in {"LIBRARY_PACKAGE", "PLUGIN_OR_MODULE", "SPLIT_RUNTIME_PACKAGE"}:
        if source_count > 1:
            return "PARTIAL_OR_SPLIT_COMPONENT", (
                shared
                + f"; sibling main candidates={sibling_main or '(none)'}. The "
                "package exposes only a structural subset of its Source."
            )
        return "AMBIGUOUS", (
            shared
            + "; single-package library/plugin scope may or may not represent an "
            "independent upstream product."
        )
    if role == "UTILITY_OR_CLI_PACKAGE":
        if aligned:
            return "POSSIBLE_PRODUCT_CANDIDATE", (
                shared + "; the installed CLI aligns with Source name, but CLI "
                "scope versus the complete upstream product remains unresolved."
            )
        if source_count > 1:
            return "PARTIAL_OR_SPLIT_COMPONENT", (
                shared
                + f"; utility split with sibling main candidates="
                f"{sibling_main or '(none)'}."
            )
        return "POSSIBLE_PRODUCT_CANDIDATE", (
            shared + "; executable utility is the installed runtime unit, but "
            "upstream product scope is not independently verified."
        )
    if role == "VENDOR_SPECIFIC_PACKAGE":
        return "UNRESOLVED", shared + "; exact vendor source is unavailable."
    return "UNRESOLVED", shared + "; insufficient role/product evidence."


def _counter(values: Iterable[str], expected: Iterable[str]) -> dict[str, int]:
    observed = Counter(values)
    return {value: observed.get(value, 0) for value in expected}


def _read_first_analysis(
    path: Path,
) -> tuple[dict[str, dict[str, str]], list[dict[str, str]]]:
    components_path = path / "components.csv"
    if not components_path.is_file():
        raise UnitronicsSourceAnalysisError(
            f"First-pass components.csv is missing: {components_path}"
        )
    with components_path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != EXPECTED_COMPONENT_COUNT:
        raise UnitronicsSourceAnalysisError(
            "First-pass component count differs from 582."
        )
    installed = {
        row["installed_package"]: row
        for row in rows
        if row.get("installed_package")
    }
    if len(installed) != EXPECTED_INSTALLED_PACKAGES:
        raise UnitronicsSourceAnalysisError(
            "First-pass installed-package mapping differs from 575."
        )
    non_opkg = [row for row in rows if not row.get("installed_package")]
    if len(non_opkg) != EXPECTED_COMPONENT_COUNT - EXPECTED_INSTALLED_PACKAGES:
        raise UnitronicsSourceAnalysisError(
            "First-pass non-opkg artifact count differs from seven."
        )
    return installed, non_opkg


def _read_exact_evidence(
    rootfs: Path,
) -> tuple[
    dict[str, dict[str, str]],
    dict[str, list[str]],
    dict[str, dict[str, str]],
]:
    info = rootfs / "usr/lib/opkg/info"
    control_paths = {path.stem: path for path in info.glob("*.control")}
    list_paths = {path.stem: path for path in info.glob("*.list")}
    if len(control_paths) != EXPECTED_INSTALLED_PACKAGES:
        raise UnitronicsSourceAnalysisError(
            f"Expected 575 controls, found {len(control_paths)}."
        )
    if set(control_paths) != set(list_paths):
        raise UnitronicsSourceAnalysisError(
            "Exact .control and .list package sets differ."
        )
    controls = {name: _read_control(path) for name, path in control_paths.items()}
    for filename, control in controls.items():
        if control["Package"] != filename:
            raise UnitronicsSourceAnalysisError(
                f"Control filename/Package mismatch: {filename}"
            )
    lists = {
        name: [
            line.strip()
            for line in path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            if line.strip()
        ]
        for name, path in list_paths.items()
    }
    status_path = rootfs / "usr/lib/opkg/status"
    statuses = {
        stanza["Package"]: stanza
        for stanza in _parse_stanzas(
            status_path.read_text(encoding="utf-8", errors="replace")
        )
    }
    if set(statuses) != set(controls):
        raise UnitronicsSourceAnalysisError(
            "opkg status and control package sets differ."
        )
    for package, control in controls.items():
        status = statuses[package]
        for field in ("Package", "Version", "Architecture"):
            if control.get(field, "") != status.get(field, ""):
                raise UnitronicsSourceAnalysisError(
                    f"Control/status {field} mismatch for {package}."
                )
    return controls, lists, statuses


def _package_rows(
    rootfs: Path,
    controls: dict[str, dict[str, str]],
    lists: dict[str, list[str]],
    statuses: dict[str, dict[str, str]],
    first_analysis: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    by_source: defaultdict[str, list[str]] = defaultdict(list)
    for package, control in controls.items():
        by_source[control["Source"]].append(package)
    if len(by_source) != EXPECTED_SOURCE_COUNT:
        raise UnitronicsSourceAnalysisError(
            f"Expected 303 Source paths, found {len(by_source)}."
        )

    rows: list[dict[str, Any]] = []
    for package in sorted(controls):
        control = controls[package]
        prior = first_analysis.get(package)
        if prior is None:
            raise UnitronicsSourceAnalysisError(
                f"Package missing from first-pass analysis: {package}"
            )
        if (
            prior["sbom_name" if "sbom_name" in prior else "name"],
            prior["installed_package_version"],
            prior["source_package"],
        ) != (package, control["Version"], control["Source"]):
            raise UnitronicsSourceAnalysisError(
                f"First-pass/control mismatch for {package}."
            )
        paths = lists[package]
        categorized: defaultdict[str, list[str]] = defaultdict(list)
        states = Counter()
        for value in paths:
            categorized[_path_category(value, rootfs)].append(value)
            states[_path_state(rootfs, value)] += 1
        category_counts = Counter(
            {category: len(categorized[category]) for category in PATH_CATEGORIES}
        )
        siblings = sorted(by_source[control["Source"]])
        role, role_evidence = _role_for_package(
            control, category_counts, len(paths), len(siblings)
        )
        role, normalization_note = _normalize_role(role, control)
        if normalization_note:
            role_evidence = role_evidence + " " + normalization_note
        role_basis = (
            "CONTROL_ONLY_EMPTY_LIST"
            if not paths
            else "CONTROL_AND_LIST"
        )
        representative_paths = []
        for category in PATH_CATEGORIES:
            representative_paths.extend(categorized[category][:2])
        representative_paths = list(dict.fromkeys(representative_paths))[:8]
        row: dict[str, Any] = {
            "component_id": prior["component_id"],
            "sbom_name": prior.get("name", package),
            "sbom_version": prior["version"],
            "package": package,
            "version": control["Version"],
            "source": control["Source"],
            "source_name": control.get("SourceName", ""),
            "source_date_epoch": control.get("SourceDateEpoch", ""),
            "description": control.get("Description", "").strip(),
            "depends": control.get("Depends", ""),
            "provides": control.get("Provides", ""),
            "architecture": control.get("Architecture", ""),
            "license": control.get("License", ""),
            "maintainer": control.get("Maintainer", ""),
            "section": control.get("Section", ""),
            "cpe_id": control.get("CPE-ID", ""),
            "control_path": f"/usr/lib/opkg/info/{package}.control",
            "list_path": f"/usr/lib/opkg/info/{package}.list",
            "status_version_matches": (
                statuses[package].get("Version", "") == control["Version"]
            ),
            "status_architecture_matches": (
                statuses[package].get("Architecture", "")
                == control.get("Architecture", "")
            ),
            "control_fields_json": json.dumps(
                control, ensure_ascii=False, sort_keys=True
            ),
            "installed_file_count": len(paths),
            "existing_regular_file_count": states["regular_file"],
            "existing_symlink_count": states["symlink"],
            "missing_listed_path_count": states["missing"],
            "representative_paths": _representative(representative_paths, 8),
            "installed_paths_json": json.dumps(paths, ensure_ascii=False),
            "source_package_count": len(siblings),
            "sibling_packages": " | ".join(siblings),
            "single_or_multi": (
                "SINGLE_PACKAGE_SOURCE"
                if len(siblings) == 1
                else "MULTI_PACKAGE_SOURCE"
            ),
            "source_name_aligned": _source_name_aligned(
                package, control["Source"]
            ),
            "is_vendor_specific": _is_vendor_source(control),
            "package_role": role,
            "product_identity_status": "",
            "role_evidence_basis": role_basis,
            "role_evidence": (
                role_evidence
                + " Description: "
                + _description_excerpt(control.get("Description", ""))
            ),
            "product_identity_evidence": "",
            "notes": (
                "CPE-ID and Original CPE are retained separately and were not "
                "used for role or product-identity classification."
            ),
        }
        for category in PATH_CATEGORIES:
            field = {
                "executable": "executable_count",
                "library": "library_count",
                "plugin_module": "plugin_module_count",
                "kernel_module": "kernel_module_count",
                "firmware_file": "firmware_file_count",
                "config_file": "config_file_count",
                "data_script": "data_script_count",
                "development_artifact": "development_artifact_count",
                "other": "other_path_count",
            }[category]
            row[field] = category_counts[category]
        for category, field in (
            ("executable", "executable_paths"),
            ("library", "library_paths"),
            ("plugin_module", "plugin_module_paths"),
            ("kernel_module", "kernel_module_paths"),
            ("firmware_file", "firmware_paths"),
            ("config_file", "config_paths"),
            ("data_script", "data_script_paths"),
            ("development_artifact", "development_paths"),
        ):
            row[field] = _representative(categorized[category])
        rows.append(row)

    rows_by_source: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        rows_by_source[row["source"]].append(row)
    for source_rows in rows_by_source.values():
        for row in source_rows:
            identity, evidence = _identity_for_package(row, source_rows)
            row["product_identity_status"] = identity
            row["product_identity_evidence"] = evidence
    return rows


def _source_cpe_consistency(rows: list[dict[str, Any]]) -> str:
    values = [row["cpe_id"] for row in rows if row["cpe_id"]]
    if not values:
        return "NO_CPE_ID"
    if len(set(values)) > 1:
        return "MULTIPLE_CPE_IDS"
    if len(values) == len(rows):
        return "ALL_PACKAGES_SAME_CPE_ID"
    return "PARTIAL_PACKAGES_SAME_CPE_ID"


def _source_rows(
    package_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in package_rows:
        grouped[row["source"]].append(row)
    sources: list[dict[str, Any]] = []
    multi_sources: list[dict[str, Any]] = []
    for source, source_rows in sorted(grouped.items()):
        source_rows.sort(key=lambda value: value["package"])
        roles = Counter(row["package_role"] for row in source_rows)
        identities = Counter(
            row["product_identity_status"] for row in source_rows
        )
        main_candidates = [
            row["package"]
            for row in source_rows
            if row["package_role"] == "PRODUCT_OR_MAIN_PACKAGE"
        ]
        cpe_values = sorted(
            {row["cpe_id"] for row in source_rows if row["cpe_id"]}
        )
        package_details = [
            {
                "package": row["package"],
                "version": row["version"],
                "description": row["description"],
                "role": row["package_role"],
                "product_identity_status": row[
                    "product_identity_status"
                ],
                "executable_count": row["executable_count"],
                "library_count": row["library_count"],
                "plugin_module_count": row["plugin_module_count"],
                "kernel_module_count": row["kernel_module_count"],
                "firmware_file_count": row["firmware_file_count"],
                "representative_paths": row["representative_paths"],
                "cpe_id": row["cpe_id"],
            }
            for row in source_rows
        ]
        flags = {
            "has_library_split": roles["LIBRARY_PACKAGE"] > 0,
            "has_utility_split": roles["UTILITY_OR_CLI_PACKAGE"] > 0,
            "has_plugin_module_split": roles["PLUGIN_OR_MODULE"] > 0,
            "has_kernel_package": roles["KERNEL_OR_KMOD"] > 0,
        }
        structure_parts = [
            "single installed package"
            if len(source_rows) == 1
            else f"{len(source_rows)} installed packages"
        ]
        for label, key in (
            ("main/product-like", "PRODUCT_OR_MAIN_PACKAGE"),
            ("library", "LIBRARY_PACKAGE"),
            ("utility", "UTILITY_OR_CLI_PACKAGE"),
            ("plugin/module", "PLUGIN_OR_MODULE"),
            ("kernel/kmod", "KERNEL_OR_KMOD"),
            ("meta/helper", "META_OR_HELPER_PACKAGE"),
        ):
            if roles[key]:
                structure_parts.append(f"{label}={roles[key]}")
        source_row: dict[str, Any] = {
            "source": source,
            "package_count": len(source_rows),
            "packages": " | ".join(row["package"] for row in source_rows),
            "single_or_multi": (
                "SINGLE_PACKAGE_SOURCE"
                if len(source_rows) == 1
                else "MULTI_PACKAGE_SOURCE"
            ),
            "source_name_values": " | ".join(
                sorted({row["source_name"] for row in source_rows})
            ),
            "version_values": " | ".join(
                sorted({row["version"] for row in source_rows})
            ),
            "cpe_id_values": " | ".join(cpe_values),
            "cpe_id_package_count": sum(
                bool(row["cpe_id"]) for row in source_rows
            ),
            "cpe_id_consistency": _source_cpe_consistency(source_rows),
            "product_candidate_count": (
                identities["DIRECT_PRODUCT_CANDIDATE"]
                + identities["POSSIBLE_PRODUCT_CANDIDATE"]
            ),
            "direct_product_candidate_count": identities[
                "DIRECT_PRODUCT_CANDIDATE"
            ],
            "possible_product_candidate_count": identities[
                "POSSIBLE_PRODUCT_CANDIDATE"
            ],
            "partial_component_count": identities[
                "PARTIAL_OR_SPLIT_COMPONENT"
            ],
            "non_product_count": identities["NON_PRODUCT_ARTIFACT"],
            "ambiguous_count": identities["AMBIGUOUS"],
            "unresolved_count": identities["UNRESOLVED"],
            "role_distribution": json.dumps(
                dict(sorted(roles.items())), ensure_ascii=False
            ),
            "main_package_candidate": " | ".join(main_candidates),
            "has_main_product_like_package": bool(main_candidates),
            **flags,
            "is_vendor_specific": any(
                bool(row["is_vendor_specific"]) for row in source_rows
            ),
            "source_structure_summary": "; ".join(structure_parts),
        }
        sources.append(source_row)
        if len(source_rows) > 1:
            multi_row = dict(source_row)
            multi_row["package_details_json"] = json.dumps(
                package_details, ensure_ascii=False, sort_keys=True
            )
            multi_sources.append(multi_row)
    return sources, multi_sources


def _cpe_propagation_rows(
    package_rows: list[dict[str, Any]], source_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    source_lookup = {row["source"]: row for row in source_rows}
    global_groups: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    source_groups: defaultdict[tuple[str, str], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    for row in package_rows:
        if row["cpe_id"]:
            global_groups[row["cpe_id"]].append(row)
            source_groups[(row["source"], row["cpe_id"])].append(row)
    rows = []
    for (source, cpe_id), values in sorted(source_groups.items()):
        source_count = int(source_lookup[source]["package_count"])
        within_count = len(values)
        global_values = global_groups[cpe_id]
        rows.append(
            {
                "cpe_id": cpe_id,
                "global_package_count": len(global_values),
                "global_source_count": len(
                    {value["source"] for value in global_values}
                ),
                "source": source,
                "source_package_count": source_count,
                "cpe_id_package_count_within_source": within_count,
                "cpe_id_coverage_percent_within_source": _percent(
                    within_count, source_count
                ),
                "packages": " | ".join(
                    sorted(value["package"] for value in values)
                ),
                "propagation_status": (
                    "PROPAGATED_TO_MULTIPLE_PACKAGES"
                    if within_count > 1
                    else "SINGLE_PACKAGE_ONLY"
                ),
                "source_cpe_id_consistency": source_lookup[source][
                    "cpe_id_consistency"
                ],
            }
        )
    return rows


def _select_package_examples(
    rows: list[dict[str, Any]],
    names: tuple[str, ...],
    predicate: Any,
    limit: int = 5,
) -> list[dict[str, Any]]:
    candidates = {row["package"]: row for row in rows if predicate(row)}
    selected: list[dict[str, Any]] = []
    for name in names:
        value = candidates.pop(name, None)
        if value:
            selected.append(value)
        if len(selected) == limit:
            break
    if len(selected) < limit:
        selected.extend(
            candidates[name]
            for name in sorted(candidates)[: limit - len(selected)]
        )
    return selected


def _example_view(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": row["source"],
        "package": row["package"],
        "version": row["version"],
        "description": _description_excerpt(row["description"]),
        "installed_paths": row["representative_paths"],
        "sibling_packages": row["sibling_packages"],
        "package_role": row["package_role"],
        "product_identity_status": row["product_identity_status"],
        "cpe_id": row["cpe_id"],
        "role_evidence": row["role_evidence"],
        "product_identity_evidence": row["product_identity_evidence"],
        "gt_rule_relevance": (
            "Source sharing and propagated CPE-ID are relationship metadata; "
            "binary product scope still requires a human rule."
        ),
    }


def _representative_examples(
    package_rows: list[dict[str, Any]], source_rows: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    sources_with_main_and_split = {
        row["source"]
        for row in source_rows
        if row["single_or_multi"] == "MULTI_PACKAGE_SOURCE"
        and row["has_main_product_like_package"]
        and int(row["package_count"])
        > len(str(row["main_package_candidate"]).split(" | "))
    }
    cases = {
        "A_main_plus_splits": _select_package_examples(
            package_rows,
            ("strongswan", "iptables", "data-sender", "ppp", "e2fsprogs"),
            lambda row: row["source"] in sources_with_main_and_split
            and row["package_role"] == "PRODUCT_OR_MAIN_PACKAGE",
        ),
        "B_library_only_package": _select_package_examples(
            package_rows,
            ("libcurl4", "libopenssl3", "libxml2", "libext2fs2", "libgps"),
            lambda row: row["package_role"] == "LIBRARY_PACKAGE",
        ),
        "C_cli_utility_only_package": _select_package_examples(
            package_rows,
            ("openssl-util", "iwinfo", "gpiod-tools", "gpsctl", "mctl"),
            lambda row: row["package_role"] == "UTILITY_OR_CLI_PACKAGE",
        ),
        "D_plugin_or_module": _select_package_examples(
            package_rows,
            (
                "strongswan-mod-openssl",
                "uhttpd-mod-lua",
                "data-sender-mod-http",
                "vuci-app-data-sender-api",
                "rpcd-mod-file",
            ),
            lambda row: row["package_role"] == "PLUGIN_OR_MODULE",
        ),
        "E_kernel_or_kmod": _select_package_examples(
            package_rows,
            (
                "kernel",
                "kmod-wireguard",
                "kmod-cfg80211_515",
                "kmod-mt7603_515",
                "kmod-usb-core",
            ),
            lambda row: row["package_role"] == "KERNEL_OR_KMOD",
        ),
        "F_vendor_multi_package": _select_package_examples(
            package_rows,
            ("data-sender", "gpsd", "gsmctl", "esim-lpac", "mctl"),
            lambda row: bool(row["is_vendor_specific"])
            and row["single_or_multi"] == "MULTI_PACKAGE_SOURCE",
        ),
        "G_propagated_cpe_id": _select_package_examples(
            package_rows,
            ("strongswan", "iptables", "openssl-util", "curl", "e2fsprogs"),
            lambda row: bool(row["cpe_id"])
            and int(row["source_package_count"]) > 1,
        ),
        "H_identity_ambiguous": _select_package_examples(
            package_rows,
            (
                "strongswan-minimal",
                "hostapd-common",
                "libpthread",
                "reboot_utils",
                "macchina_sdk",
            ),
            lambda row: row["product_identity_status"]
            in {"AMBIGUOUS", "UNRESOLVED", "NON_PRODUCT_ARTIFACT"},
        ),
    }
    return {
        category: [_example_view(row) for row in rows]
        for category, rows in cases.items()
    }


def _render_count_table(counts: dict[str, int], total: int) -> str:
    lines = ["| Category | Count | Percent |", "|---|---:|---:|"]
    for category, count in counts.items():
        lines.append(f"| {category} | {count:,} | {_percent(count, total):.2f}% |")
    return "\n".join(lines)


def _escape_table(value: Any, limit: int = 160) -> str:
    text = " ".join(str(value).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _render_report(summary: dict[str, Any], multi_rows: list[dict[str, Any]]) -> str:
    total = summary["packages"]["total"]
    sources = summary["sources"]
    multi = summary["multi_package_sources"]
    cpe = summary["cpe_id_propagation"]
    content = summary["list_content"]
    lines = [
        "# Unitronics UCR-ST-B8 source/package second-pass analysis",
        "",
        "This is a read-only empirical analysis of exact-firmware `.control` and ",
        "`.list` evidence. It does not assign or validate Ground Truth CPEs. Source ",
        "sharing and control `CPE-ID` propagation are never treated as proof of a ",
        "binary package's CPE product identity.",
        "",
        "## Dataset and evidence",
        "",
        f"- SBOMDocument: `{summary['dataset']['sbom_document_id']}`",
        f"- Product: `{summary['dataset']['manufacturer']} {summary['dataset']['product']} {summary['dataset']['firmware_version']}`",
        f"- Firmware SHA-256: `{summary['provenance']['firmware_sha256']}`",
        f"- Installed controls/lists/status stanzas: `{total}` / `{total}` / `{total}`",
        f"- Distinct control `Source`: `{sources['total']}`",
        "- Exact SDK/GPL and Makefiles remain unavailable. `Source` means the path ",
        "  recorded by installed control metadata, not a verified current Makefile.",
        "- The first-pass component mapping was reused and every one of its 575 opkg ",
        "  name/version/Source tuples was revalidated against exact controls.",
        "- Seven non-opkg SBOM artifacts are excluded from the 303-Source/575-package ",
        "  denominators and preserved separately below and in `summary.json`.",
        "",
        "## Source structure",
        "",
        "| Structure | Sources | Packages |",
        "|---|---:|---:|",
        f"| SINGLE_PACKAGE_SOURCE | {sources['single_package_sources']} | {sources['single_source_packages']} |",
        f"| MULTI_PACKAGE_SOURCE | {sources['multi_package_sources']} | {sources['multi_source_packages']} |",
        f"| Total | {sources['total']} | {total} |",
        "",
        "A 1:1 Source is not automatically a product. The role/identity partitions ",
        "below apply the same control/list rules to both single and multi Sources.",
        f"Among the 261 single-package Sources, `{summary['single_source_non_product']['count']}` are partial, non-product, ambiguous, or unresolved rather than direct/possible product candidates. Their role distribution is `{summary['single_source_non_product']['package_role_distribution']}`.",
        "",
        "### Separately retained non-opkg artifacts",
        "",
    ]
    for artifact in summary["non_opkg_artifacts"]:
        lines.append(
            f"- `{artifact['name']} {artifact['version']}` — "
            f"group `{artifact['group']}`, firmware traceability "
            f"`{artifact['firmware_traceability_status']}`"
        )
    lines.extend(
        [
        "",
        "## Exact `.list` content",
        "",
        f"- Declared paths: `{content['declared_path_count']}`",
        f"- Non-empty lists: `{content['nonempty_list_count']}` ({_percent(content['nonempty_list_count'], total):.2f}%)",
        f"- Empty lists: `{content['empty_list_count']}` ({_percent(content['empty_list_count'], total):.2f}%)",
        f"- Existing regular files / symlinks: `{content['existing_regular_file_count']}` / `{content['existing_symlink_count']}`",
        f"- Listed paths absent from extracted rootfs: `{content['missing_listed_path_count']}`",
        "",
        "The `.list` remains the installed-package ownership record even when a path ",
        "is absent after image assembly. Empty-list packages rely on Section, ",
        "Description, Source, dependency, naming, and sibling evidence.",
        "",
        "Path-category totals (path denominator):",
        "",
        _render_count_table(content["path_category_counts"], content["declared_path_count"]),
        "",
        "Role evidence basis (package denominator):",
        "",
        _render_count_table(summary["role_evidence_basis"], total),
        "",
        "## Package roles",
        "",
        _render_count_table(summary["package_roles"], total),
        "",
        "These are evidence classes, not CPE decisions. Vendor origin is also retained ",
        f"as an orthogonal flag on `{summary['vendor_specific']['package_count']}` packages and `{summary['vendor_specific']['source_count']}` Sources.",
        "",
        "## Product identity relationship",
        "",
        _render_count_table(summary["product_identity"], total),
        "",
        "`DIRECT_PRODUCT_CANDIDATE` means control Source basename and installed core ",
        "payload align. It does not confirm a CPE. Partial/library/plugin classifications ",
        "likewise do not decide that a CPE must be absent.",
        f"The explicit `AMBIGUOUS`/`UNRESOLVED` review set contains `{summary['additional_upstream_source_review']['package_count']}` packages with role distribution `{summary['additional_upstream_source_review']['role_distribution']}`. The complete package list is retained in `summary.json`.",
        "",
        "## Multi-package Source summary",
        "",
        f"- Sources: `{multi['source_count']}`; packages: `{multi['package_count']}`",
        f"- Package-count distribution: `{multi['package_count_distribution']}`",
        f"- With main/product-like package: `{multi['with_main_product_like']}`",
        f"- Without main/product-like package: `{multi['without_main_product_like']}`",
        f"- With library split: `{multi['with_library_split']}`",
        f"- With utility split: `{multi['with_utility_split']}`",
        f"- With plugin/module split: `{multi['with_plugin_module_split']}`",
        f"- Kernel-derived Sources: `{multi['kernel_source_count']}`",
        f"- Vendor-specific Sources: `{multi['vendor_specific_source_count']}`",
        "",
        "Multi-source package roles (314-package denominator):",
        "",
        _render_count_table(
            multi["package_role_distribution"], multi["package_count"]
        ),
        "",
        "Multi-source product identity (314-package denominator):",
        "",
        _render_count_table(
            multi["product_identity_distribution"], multi["package_count"]
        ),
        "",
        "## CPE-ID propagation (metadata observation only)",
        "",
        f"- CPE-ID package coverage: `{cpe['package_count']}` / `{total}` ({cpe['package_coverage_percent']:.2f}%)",
        f"- Distinct CPE-ID: `{cpe['distinct_cpe_id_count']}`",
        f"- CPE-IDs shared by multiple packages: `{cpe['shared_cpe_id_group_count']}`",
        f"- Packages in shared groups: `{cpe['packages_in_shared_groups']}`",
        f"- Multi-package Sources propagating one CPE-ID to 2+ packages: `{cpe['multi_sources_with_propagation']}` / `{sources['multi_package_sources']}`",
        f"- Maximum propagation: `{cpe['maximum_propagation_package_count']}` packages at `{cpe['maximum_propagation_source']}` (`{cpe['maximum_propagation_cpe_id']}`)",
        f"- Source-level consistency distribution: `{cpe['source_consistency_distribution']}`",
        "",
        "No correctness inference is made from these values.",
        "",
        "## Representative cases",
        "",
        ]
    )
    for category, examples in summary["representative_examples"].items():
        lines.extend([f"### {category}", ""])
        for example in examples:
            lines.extend(
                [
                    f"- Source / Package: `{example['source']}` / `{example['package']} {example['version']}`",
                    f"  - Description: {_escape_table(example['description'], 240)}",
                    f"  - Installed paths: `{example['installed_paths'] or '(empty .list)'}`",
                    f"  - Siblings: `{example['sibling_packages']}`",
                    f"  - Role / identity: `{example['package_role']}` / `{example['product_identity_status']}`",
                    f"  - CPE-ID (reference only): `{example['cpe_id'] or '(none)'}`",
                    f"  - Evidence: {example['role_evidence']} {example['product_identity_evidence']}",
                    f"  - GT-rule relevance: {example['gt_rule_relevance']}",
                ]
            )
        lines.append("")

    lines.extend(
        [
            "## Answers to the requested questions",
            "",
            f"1. `{sources['multi_package_sources']}` of `{sources['total']}` Sources are multi-package and contain `{sources['multi_source_packages']}` packages.",
            "2. The exhaustive role distribution is above and in `packages.csv`.",
            f"3. Among 42 multi Sources, main+split appears in `{multi['with_main_product_like']}`; library, utility, and plugin/module splits appear in `{multi['with_library_split']}`, `{multi['with_utility_split']}`, and `{multi['with_plugin_module_split']}` Sources respectively.",
            f"4. `{multi['without_main_product_like']}` multi Sources have no observed main/product-like package. In addition, all partial/ambiguous/unresolved rows require more than Source equality.",
            f"5. Description exists for all 575 controls. `.list` supplies content evidence for `{content['nonempty_list_count']}` packages; `{content['empty_list_count']}` empty lists require control/sibling evidence only.",
            f"6. Yes. `{summary['single_source_non_product']['count']}` single-package Sources are classified as non-product, partial, ambiguous, or unresolved rather than product candidates.",
            f"7. CPE-ID propagation occurs in `{cpe['multi_sources_with_propagation']}` multi Sources; the largest is StrongSwan with `{cpe['maximum_propagation_package_count']}` packages.",
            "8. OpenSSL has library/config/CLI splits and no main-role package; iptables has an aligned CLI candidate plus libraries/modules; StrongSwan has an aligned main candidate plus runtime/CLI/plugins; kernel/linux contains a virtual kernel package and kmod splits.",
            f"9. `{summary['product_identity']['DIRECT_PRODUCT_CANDIDATE']}` aligned, payload-bearing main packages have the strongest current candidate evidence, without constituting CPE assignments.",
            "10. Library-only, CLI-only, plugins/modules, kmods, firmware/meta/helper, vendor-only, and empty-list packages need separate human policy decisions.",
            f"11. The explicit ambiguous/unresolved set contains `{summary['product_identity']['AMBIGUOUS'] + summary['product_identity']['UNRESOLVED']}` packages; `packages.csv` records each package and why additional source/upstream evidence is needed.",
            "",
            "## All 42 multi-package Sources",
            "",
            "Each subsection is generated from exact control/list evidence. Descriptions ",
            "and paths are shortened here; their complete values are in `packages.csv` and ",
            "`multi_package_sources.csv`.",
            "",
        ]
    )
    for source in multi_rows:
        details = json.loads(source["package_details_json"])
        lines.extend(
            [
                f"### `{source['source']}`",
                "",
                f"- Packages: `{source['package_count']}`",
                f"- Main candidate(s): `{source['main_package_candidate'] or '(none)'}`",
                f"- Structure: {source['source_structure_summary']}",
                f"- CPE-ID consistency: `{source['cpe_id_consistency']}`; values: `{source['cpe_id_values'] or '(none)'}`",
                "",
                "| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |",
                "|---|---|---|---|---|---:|---:|---:|---:|---:|---|",
            ]
        )
        for value in details:
            lines.append(
                f"| {_escape_table(value['package'])} | {_escape_table(value['version'])} | "
                f"{_escape_table(value['description'])} | {value['role']} | "
                f"{value['product_identity_status']} | {value['executable_count']} | "
                f"{value['library_count']} | {value['plugin_module_count']} | "
                f"{value['kernel_module_count']} | {value['firmware_file_count']} | "
                f"{_escape_table(value['representative_paths'])} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Human-review issues before Ground Truth rules",
            "",
            "- Whether an aligned main runtime package and its Source have the same CPE ",
            "  product scope.",
            "- Whether library/CLI packages without a sibling main package represent an ",
            "  independently identifiable product or only packaging structure.",
            "- Whether empty-list meta/helper packages carry identity at all.",
            "- How plugin/module and kernel/kmod packages relate to a parent product.",
            "- How vendor-specific packages should be treated without exact source.",
            "- Whether propagated control CPE-ID should apply at binary granularity; this ",
            "  analysis observes propagation but does not accept or reject it.",
            "",
            "## Validation and safety",
            "",
            f"- Sources: `{summary['validation']['source_count']}` == `{EXPECTED_SOURCE_COUNT}`",
            f"- Installed packages: `{summary['validation']['package_count']}` == `{EXPECTED_INSTALLED_PACKAGES}`",
            f"- Single + multi packages: `{summary['validation']['source_package_partition_sum']}` == `{EXPECTED_INSTALLED_PACKAGES}`",
            f"- Role partition: `{summary['validation']['package_role_sum']}` == `{EXPECTED_INSTALLED_PACKAGES}`",
            f"- Product identity partition: `{summary['validation']['product_identity_sum']}` == `{EXPECTED_INSTALLED_PACKAGES}`",
            f"- Ground Truth records before/after: `{summary['safety']['ground_truth_records_before']}` / `{summary['safety']['ground_truth_records_after']}`",
            "- CPE Dictionary queries: `0`; NVD Configuration/CVE queries: `0`; DB mutations: `0`.",
            "",
            "## Stopping point",
            "",
            "The analysis stops at empirical package role and product-scope evidence. No ",
            "Ground Truth rule was generated or applied.",
            "",
        ]
    )
    return "\n".join(lines)


def build_unitronics_source_analysis(
    *,
    sbom_id: int,
    firmware_binary_path: Path,
    firmware_rootfs: Path,
    first_analysis_directory: Path,
) -> UnitronicsSourceAnalysis:
    with connection.cursor() as cursor:
        cursor.execute("SET default_transaction_read_only = on")

    document = SBOMDocument.objects.get(pk=sbom_id)
    observed_target = (
        document.id,
        document.manufacturer,
        document.product_name,
        document.product_version,
        document.file_sha256,
        Component.objects.filter(sbom_document=document).count(),
    )
    expected_target = (
        EXPECTED_SBOM_ID,
        EXPECTED_MANUFACTURER,
        EXPECTED_PRODUCT,
        EXPECTED_VERSION,
        EXPECTED_SBOM_SHA256,
        EXPECTED_COMPONENT_COUNT,
    )
    if observed_target != expected_target:
        raise UnitronicsSourceAnalysisError(
            f"Unexpected analysis target: {observed_target!r}"
        )
    ground_truth_before = ComponentCpeGroundTruth.objects.filter(
        component__sbom_document=document
    ).count()
    if _sha256(firmware_binary_path) != EXPECTED_FIRMWARE_SHA256:
        raise UnitronicsSourceAnalysisError("Exact firmware SHA-256 changed.")

    first_analysis, non_opkg = _read_first_analysis(first_analysis_directory)
    controls, lists, statuses = _read_exact_evidence(firmware_rootfs)
    packages = _package_rows(
        firmware_rootfs, controls, lists, statuses, first_analysis
    )
    sources, multi_sources = _source_rows(packages)
    cpe_rows = _cpe_propagation_rows(packages, sources)

    single_sources = [
        row for row in sources if row["single_or_multi"] == "SINGLE_PACKAGE_SOURCE"
    ]
    multi_source_rows = [
        row for row in sources if row["single_or_multi"] == "MULTI_PACKAGE_SOURCE"
    ]
    if len(single_sources) != EXPECTED_SINGLE_SOURCE_COUNT:
        raise UnitronicsSourceAnalysisError("Single Source count differs from 261.")
    if len(multi_source_rows) != EXPECTED_MULTI_SOURCE_COUNT:
        raise UnitronicsSourceAnalysisError("Multi Source count differs from 42.")

    role_counts = _counter(
        (row["package_role"] for row in packages), PACKAGE_ROLES
    )
    identity_counts = _counter(
        (row["product_identity_status"] for row in packages),
        PRODUCT_IDENTITY_STATUSES,
    )
    path_category_counts = {
        category: sum(
            int(
                row[
                    {
                        "executable": "executable_count",
                        "library": "library_count",
                        "plugin_module": "plugin_module_count",
                        "kernel_module": "kernel_module_count",
                        "firmware_file": "firmware_file_count",
                        "config_file": "config_file_count",
                        "data_script": "data_script_count",
                        "development_artifact": "development_artifact_count",
                        "other": "other_path_count",
                    }[category]
                ]
            )
            for row in packages
        )
        for category in PATH_CATEGORIES
    }
    cpe_values = [row["cpe_id"] for row in packages if row["cpe_id"]]
    cpe_counts = Counter(cpe_values)
    shared_cpes = {value: count for value, count in cpe_counts.items() if count > 1}
    propagated_rows = [
        row
        for row in cpe_rows
        if row["propagation_status"] == "PROPAGATED_TO_MULTIPLE_PACKAGES"
        and int(row["source_package_count"]) > 1
    ]
    maximum_propagation = max(
        propagated_rows,
        key=lambda row: int(row["cpe_id_package_count_within_source"]),
    )
    examples = _representative_examples(packages, sources)
    single_non_product_statuses = {
        "PARTIAL_OR_SPLIT_COMPONENT",
        "NON_PRODUCT_ARTIFACT",
        "AMBIGUOUS",
        "UNRESOLVED",
    }

    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analysis_scope": (
            "Exact-firmware installed Source/package empirical analysis; no "
            "Ground Truth CPE determination"
        ),
        "dataset": {
            "sbom_document_id": document.id,
            "manufacturer": document.manufacturer,
            "product": document.product_name,
            "firmware_version": document.product_version,
            "sbom_components": EXPECTED_COMPONENT_COUNT,
            "non_opkg_artifacts_excluded_from_source_analysis": (
                EXPECTED_COMPONENT_COUNT - EXPECTED_INSTALLED_PACKAGES
            ),
        },
        "non_opkg_artifacts": [
            {
                "component_id": row["component_id"],
                "name": row["name"],
                "version": row["version"],
                "group": row["group"],
                "firmware_traceability_status": row[
                    "firmware_traceability_status"
                ],
                "properties_paths": row["properties_paths"],
            }
            for row in non_opkg
        ],
        "provenance": {
            "sbom_sha256": document.file_sha256,
            "firmware_filename": firmware_binary_path.name,
            "firmware_sha256": EXPECTED_FIRMWARE_SHA256,
            "rootfs": str(firmware_rootfs),
            "first_analysis_directory": str(first_analysis_directory),
            "first_analysis_components_sha256": _sha256(
                first_analysis_directory / "components.csv"
            ),
            "exact_sdk_gpl_available": False,
            "makefiles_available": False,
        },
        "sources": {
            "total": len(sources),
            "single_package_sources": len(single_sources),
            "multi_package_sources": len(multi_source_rows),
            "single_source_packages": sum(
                int(row["package_count"]) for row in single_sources
            ),
            "multi_source_packages": sum(
                int(row["package_count"]) for row in multi_source_rows
            ),
        },
        "packages": {"total": len(packages)},
        "control_field_coverage": {
            field: {
                "package_count": sum(bool(control.get(field)) for control in controls.values()),
                "coverage_percent": _percent(
                    sum(bool(control.get(field)) for control in controls.values()),
                    len(packages),
                ),
                "distinct_value_count": len(
                    {control[field] for control in controls.values() if control.get(field)}
                ),
            }
            for field in (
                "Package",
                "Version",
                "Source",
                "SourceName",
                "SourceDateEpoch",
                "Architecture",
                "Description",
                "Depends",
                "Provides",
                "License",
                "Maintainer",
                "Section",
                "CPE-ID",
            )
        },
        "status_cross_check": {
            "package_set_matches": True,
            "version_matches": sum(
                bool(row["status_version_matches"]) for row in packages
            ),
            "architecture_matches": sum(
                bool(row["status_architecture_matches"]) for row in packages
            ),
        },
        "list_content": {
            "declared_path_count": sum(
                int(row["installed_file_count"]) for row in packages
            ),
            "nonempty_list_count": sum(
                int(row["installed_file_count"]) > 0 for row in packages
            ),
            "empty_list_count": sum(
                int(row["installed_file_count"]) == 0 for row in packages
            ),
            "existing_regular_file_count": sum(
                int(row["existing_regular_file_count"]) for row in packages
            ),
            "existing_symlink_count": sum(
                int(row["existing_symlink_count"]) for row in packages
            ),
            "missing_listed_path_count": sum(
                int(row["missing_listed_path_count"]) for row in packages
            ),
            "path_category_counts": path_category_counts,
        },
        "role_evidence_basis": _counter(
            (row["role_evidence_basis"] for row in packages),
            ("CONTROL_AND_LIST", "CONTROL_ONLY_EMPTY_LIST"),
        ),
        "package_roles": role_counts,
        "product_identity": identity_counts,
        "vendor_specific": {
            "package_count": sum(
                bool(row["is_vendor_specific"]) for row in packages
            ),
            "source_count": sum(
                bool(row["is_vendor_specific"]) for row in sources
            ),
        },
        "single_source_non_product": {
            "count": sum(
                row["product_identity_status"] in single_non_product_statuses
                for row in packages
                if row["single_or_multi"] == "SINGLE_PACKAGE_SOURCE"
            ),
            "definition": (
                "Single-source package with partial, non-product, ambiguous, "
                "or unresolved identity rather than a direct/possible candidate."
            ),
            "package_role_distribution": _counter(
                (
                    row["package_role"]
                    for row in packages
                    if row["single_or_multi"] == "SINGLE_PACKAGE_SOURCE"
                ),
                PACKAGE_ROLES,
            ),
            "product_identity_distribution": _counter(
                (
                    row["product_identity_status"]
                    for row in packages
                    if row["single_or_multi"] == "SINGLE_PACKAGE_SOURCE"
                ),
                PRODUCT_IDENTITY_STATUSES,
            ),
        },
        "multi_package_sources": {
            "source_count": len(multi_source_rows),
            "package_count": sum(
                int(row["package_count"]) for row in multi_source_rows
            ),
            "package_count_distribution": dict(
                sorted(
                    Counter(
                        int(row["package_count"]) for row in multi_source_rows
                    ).items()
                )
            ),
            "with_main_product_like": sum(
                bool(row["has_main_product_like_package"])
                for row in multi_source_rows
            ),
            "without_main_product_like": sum(
                not bool(row["has_main_product_like_package"])
                for row in multi_source_rows
            ),
            "with_library_split": sum(
                bool(row["has_library_split"]) for row in multi_source_rows
            ),
            "with_utility_split": sum(
                bool(row["has_utility_split"]) for row in multi_source_rows
            ),
            "with_plugin_module_split": sum(
                bool(row["has_plugin_module_split"])
                for row in multi_source_rows
            ),
            "kernel_source_count": sum(
                bool(row["has_kernel_package"]) for row in multi_source_rows
            ),
            "vendor_specific_source_count": sum(
                bool(row["is_vendor_specific"]) for row in multi_source_rows
            ),
            "package_role_distribution": _counter(
                (
                    row["package_role"]
                    for row in packages
                    if row["single_or_multi"] == "MULTI_PACKAGE_SOURCE"
                ),
                PACKAGE_ROLES,
            ),
            "product_identity_distribution": _counter(
                (
                    row["product_identity_status"]
                    for row in packages
                    if row["single_or_multi"] == "MULTI_PACKAGE_SOURCE"
                ),
                PRODUCT_IDENTITY_STATUSES,
            ),
        },
        "cpe_id_propagation": {
            "package_count": len(cpe_values),
            "package_coverage_percent": _percent(len(cpe_values), len(packages)),
            "distinct_cpe_id_count": len(cpe_counts),
            "shared_cpe_id_group_count": len(shared_cpes),
            "packages_in_shared_groups": sum(shared_cpes.values()),
            "multi_sources_with_propagation": len(propagated_rows),
            "maximum_propagation_package_count": int(
                maximum_propagation["cpe_id_package_count_within_source"]
            ),
            "maximum_propagation_source": maximum_propagation["source"],
            "maximum_propagation_cpe_id": maximum_propagation["cpe_id"],
            "source_consistency_distribution": dict(
                sorted(
                    Counter(
                        row["cpe_id_consistency"] for row in sources
                    ).items()
                )
            ),
            "used_for_role_or_identity": False,
        },
        "additional_upstream_source_review": {
            "statuses": ["AMBIGUOUS", "UNRESOLVED"],
            "package_count": sum(
                row["product_identity_status"] in {"AMBIGUOUS", "UNRESOLVED"}
                for row in packages
            ),
            "role_distribution": dict(
                sorted(
                    Counter(
                        row["package_role"]
                        for row in packages
                        if row["product_identity_status"]
                        in {"AMBIGUOUS", "UNRESOLVED"}
                    ).items()
                )
            ),
            "packages": [
                row["package"]
                for row in packages
                if row["product_identity_status"] in {"AMBIGUOUS", "UNRESOLVED"}
            ],
        },
        "representative_examples": examples,
        "limitations": [
            "Exact SDK/GPL source and Makefiles are unavailable.",
            "A .list records package ownership; 112 listed paths are absent from "
            "the final extracted rootfs and are retained as declared evidence.",
            "120 empty .list packages require control and sibling evidence.",
            "Role and identity classes are review aids, not CPE decisions.",
            "Control CPE-ID and Original CPE were not classification inputs.",
        ],
        "safety": {
            "database_session_read_only": True,
            "database_mutations": 0,
            "ground_truth_records_before": ground_truth_before,
            "ground_truth_records_after": None,
            "cpe_dictionary_queries": 0,
            "nvd_configuration_queries": 0,
            "cve_queries": 0,
            "ground_truth_rules_generated_or_applied": 0,
        },
    }

    ground_truth_after = ComponentCpeGroundTruth.objects.filter(
        component__sbom_document=document
    ).count()
    summary["safety"]["ground_truth_records_after"] = ground_truth_after
    if ground_truth_before != ground_truth_after:
        raise UnitronicsSourceAnalysisError(
            "Ground Truth record count changed during read-only analysis."
        )

    validation = {
        "source_count": len(sources),
        "package_count": len(packages),
        "single_source_count": len(single_sources),
        "multi_source_count": len(multi_source_rows),
        "source_package_partition_sum": (
            summary["sources"]["single_source_packages"]
            + summary["sources"]["multi_source_packages"]
        ),
        "package_role_sum": sum(role_counts.values()),
        "product_identity_sum": sum(identity_counts.values()),
        "path_category_sum": sum(path_category_counts.values()),
        "status_version_match_count": summary["status_cross_check"][
            "version_matches"
        ],
        "status_architecture_match_count": summary["status_cross_check"][
            "architecture_matches"
        ],
    }
    validation["all_checks_pass"] = (
        validation["source_count"] == EXPECTED_SOURCE_COUNT
        and validation["package_count"] == EXPECTED_INSTALLED_PACKAGES
        and validation["single_source_count"] == EXPECTED_SINGLE_SOURCE_COUNT
        and validation["multi_source_count"] == EXPECTED_MULTI_SOURCE_COUNT
        and validation["source_package_partition_sum"]
        == EXPECTED_INSTALLED_PACKAGES
        and validation["package_role_sum"] == EXPECTED_INSTALLED_PACKAGES
        and validation["product_identity_sum"] == EXPECTED_INSTALLED_PACKAGES
        and validation["path_category_sum"]
        == summary["list_content"]["declared_path_count"]
        and validation["status_version_match_count"]
        == EXPECTED_INSTALLED_PACKAGES
        and validation["status_architecture_match_count"]
        == EXPECTED_INSTALLED_PACKAGES
    )
    summary["validation"] = validation
    if not validation["all_checks_pass"]:
        raise UnitronicsSourceAnalysisError(
            "One or more source/package consistency checks failed."
        )

    report = _render_report(summary, multi_sources)
    return UnitronicsSourceAnalysis(
        summary=summary,
        packages=packages,
        sources=sources,
        multi_sources=multi_sources,
        cpe_propagation=cpe_rows,
        report=report,
    )


def _render_csv(fieldnames: tuple[str, ...], rows: Iterable[dict[str, Any]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def render_unitronics_source_analysis(
    analysis: UnitronicsSourceAnalysis,
) -> dict[str, str]:
    return {
        PACKAGES_FILENAME: _render_csv(PACKAGE_FIELDS, analysis.packages),
        SOURCES_FILENAME: _render_csv(SOURCE_FIELDS, analysis.sources),
        MULTI_SOURCES_FILENAME: _render_csv(
            MULTI_SOURCE_FIELDS, analysis.multi_sources
        ),
        CPE_PROPAGATION_FILENAME: _render_csv(
            CPE_PROPAGATION_FIELDS, analysis.cpe_propagation
        ),
        SUMMARY_FILENAME: json.dumps(
            analysis.summary, ensure_ascii=False, indent=2
        )
        + "\n",
        REPORT_FILENAME: analysis.report,
    }


def write_unitronics_source_analysis(
    analysis: UnitronicsSourceAnalysis,
    output_directory: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, ...]:
    output_directory.mkdir(parents=True, exist_ok=True)
    output_paths = tuple(output_directory / name for name in OUTPUT_FILENAMES)
    existing = [path for path in output_paths if path.exists()]
    if existing and not overwrite:
        raise UnitronicsSourceAnalysisError(
            "Refusing to replace existing files without --overwrite: "
            + ", ".join(str(path) for path in existing)
        )
    rendered = render_unitronics_source_analysis(analysis)
    temporary_paths: dict[str, Path] = {}
    try:
        for filename in OUTPUT_FILENAMES:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{filename}.", suffix=".tmp", dir=output_directory
            )
            temporary_path = Path(temporary_name)
            temporary_paths[filename] = temporary_path
            with os.fdopen(
                descriptor, "w", encoding="utf-8", newline=""
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


def default_first_analysis_directory() -> Path:
    return (
        settings.REPOSITORY_ROOT
        / "analysis/results/unitronics-ground-truth-preanalysis"
        / "61602e128acb__52.07.13.7"
    )


def default_output_directory() -> Path:
    return (
        settings.REPOSITORY_ROOT
        / "analysis/results/unitronics-source-package-analysis"
        / "61602e128acb__52.07.13.7"
    )

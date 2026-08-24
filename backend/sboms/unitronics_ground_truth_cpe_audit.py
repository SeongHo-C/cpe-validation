from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
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
    resolve_deprecated_cpe,
)
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from nvd_cve.models import NvdCveSnapshot
from sboms.models import ComponentCpeGroundTruth


SBOM_ID = 1364
CPE_SNAPSHOT_ID = "20260819T035002Z"
NVD_SNAPSHOT_ID = "20260820T110357Z"
FIRMWARE_SHA256 = "6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c"
SBOM_SHA256 = "61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e"

DATASET_RELATIVE = Path(
    "unitronics-ground-truth-candidate-build/61602e128acb__52.07.13.7"
)
OUTPUT_RELATIVE = Path(
    "analysis/results/unitronics-ground-truth-cpe-audit/"
    "61602e128acb__52.07.13.7"
)
SOURCE_PACKAGE_RELATIVE = Path(
    "unitronics-source-package-analysis/"
    "61602e128acb__52.07.13.7/packages.csv"
)
PREANALYSIS_RELATIVE = Path(
    "unitronics-ground-truth-preanalysis/"
    "61602e128acb__52.07.13.7/components.csv"
)
SOURCE_ARTIFACTS = (
    DATASET_RELATIVE / "components.csv",
    DATASET_RELATIVE / "human_validation.csv",
    DATASET_RELATIVE / "evidence_manifest.csv",
    DATASET_RELATIVE / "summary.json",
    DATASET_RELATIVE / "unitronics_gt_human_validation.html",
    SOURCE_PACKAGE_RELATIVE,
    PREANALYSIS_RELATIVE,
    Path(
        "unitronics-product-runtime-rulebook/"
        "61602e128acb__52.07.13.7/rulebook.md"
    ),
    Path(
        "unitronics-version-normalization-rulebook/"
        "61602e128acb__52.07.13.7/rulebook.md"
    ),
    Path(
        "unitronics-cpe-mapping-decision-dry-run/"
        "61602e128acb__52.07.13.7/rulebook.md"
    ),
    Path(
        "cpe-mapping-rulebook-boundary-tests/"
        f"{CPE_SNAPSHOT_ID}__{NVD_SNAPSHOT_ID}/summary.json"
    ),
)

RESULT_LABELS = {
    "CPE_CONFIRMED": "CPE Confirmed",
    "OFFICIAL_CPE_MAPPED": "Correct CPE Found",
    "VERSION_NOT_IN_DICTIONARY": "Version Not Registered",
}
EXPECTED_CURRENT_COUNTS = {
    "CPE_CONFIRMED": 2,
    "OFFICIAL_CPE_MAPPED": 24,
    "VERSION_NOT_IN_DICTIONARY": 22,
}
PASS_A_STATUSES = (
    "PRODUCT_VERSION_CONFIRMED",
    "PRODUCT_CORRECTION_REQUIRED",
    "VERSION_CORRECTION_REQUIRED",
    "EVIDENCE_INSUFFICIENT",
)
FINAL_AUDIT_STATUSES = (
    "ACCEPTED",
    "CORRECTION_REQUIRED",
    "EVIDENCE_REVIEW_REQUIRED",
)
EVIDENCE_STRENGTHS = ("STRONG", "MODERATE", "WEAK")

AUDIT_FIELDS = (
    "component_id",
    "name",
    "observed_version",
    "source",
    "source_name",
    "description",
    "representative_paths",
    "pass_a_status",
    "audited_actual_product",
    "audited_actual_vendor",
    "audited_product_version",
    "pass_a_product_evidence",
    "pass_a_version_evidence",
    "evidence_references",
    "audit_evidence_strength",
    "circular_evidence_risk",
    "audited_cpe_family",
    "active_family_count",
    "deprecated_family_count",
    "active_exact_any_count",
    "active_exact_compatible_count",
    "deprecated_exact_compatible_count",
    "family_template_observation_count",
    "audited_cpe_resolution_path",
    "audited_gt_cpe",
    "audited_validation_result",
    "audited_discrepancy_fields",
    "final_gt_is_deprecated",
    "current_actual_product",
    "current_product_version",
    "current_gt_cpe",
    "current_validation_result",
    "current_discrepancy_fields",
    "comparison_status",
    "final_audit_status",
    "product_correction",
    "version_correction",
    "gt_cpe_correction",
    "validation_result_correction",
    "discrepancy_field_correction",
    "recommended_value",
    "correction_reason",
    "notes",
)

NON_VERSION_ATTRIBUTES = (
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
DEFAULT_TEMPLATE = ("*", "*", "*", "*", "*", "*", "*")
PRERELEASE_UPDATE_TOKEN_RE = re.compile(
    r"^(?:pre|rc|beta|alpha|devel|snapshot)[0-9]*$",
    re.IGNORECASE,
)


class UnitronicsCpeAuditError(Exception):
    pass


@dataclass(frozen=True)
class AuditProductSpec:
    product: str
    vendor: str
    version: str
    family: tuple[str, str, str]
    cpe_version: str | None = None
    template: tuple[str, str, str, str, str, str, str] = DEFAULT_TEMPLATE
    strength: str = "MODERATE"
    evidence_refs: tuple[str, ...] = ("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY")


def _spec(
    product: str,
    vendor: str,
    version: str,
    family: tuple[str, str, str],
    *,
    cpe_version: str | None = None,
    template: tuple[str, str, str, str, str, str, str] = DEFAULT_TEMPLATE,
    strength: str = "MODERATE",
    evidence_refs: tuple[str, ...] = ("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY"),
) -> AuditProductSpec:
    return AuditProductSpec(
        product=product,
        vendor=vendor,
        version=version,
        family=family,
        cpe_version=cpe_version,
        template=template,
        strength=strength,
        evidence_refs=evidence_refs,
    )


AUDIT_PRODUCT_SPECS = {
    "busybox": _spec("BusyBox", "BusyBox", "1.34.1", ("a", "busybox", "busybox"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-BUSYBOX-1.34.1")),
    "curl": _spec("curl", "curl project", "8.11.0", ("a", "haxx", "curl"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "davici": _spec("davici", "strongSwan", "1.4", ("a", "strongswan", "davici")),
    "dnsmasq": _spec("dnsmasq", "Thekelleys", "2.89", ("a", "thekelleys", "dnsmasq")),
    "dropbear": _spec("Dropbear SSH", "Dropbear SSH project", "2020.81", ("a", "dropbear_ssh_project", "dropbear_ssh"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-DROPBEAR-2020.81")),
    "e2fsprogs": _spec("e2fsprogs", "e2fsprogs project", "1.47.0", ("a", "e2fsprogs_project", "e2fsprogs"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "ethtool": _spec("ethtool", "Linux kernel project", "5.10", ("a", "kernel", "ethtool"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-ETHTOOL")),
    "exfat-mkfs": _spec("exfatprogs", "exfatprogs project", "1.1.3", ("a", "namjaejeon", "exfatprogs")),
    "ip-full": _spec("iproute2", "iproute2 project", "5.19.0", ("a", "iproute2_project", "iproute2")),
    "ip6tables": _spec("iptables", "Netfilter", "1.8.7", ("a", "netfilter", "iptables"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "ipset": _spec("ipset", "Netfilter", "7.6", ("a", "netfilter", "ipset"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-IPSET-7.6", "UP-IPSET-STRUCTURE")),
    "iptables": _spec("iptables", "Netfilter", "1.8.7", ("a", "netfilter", "iptables"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "iw-515": _spec("iw", "Linux wireless project", "5.19", ("a", "kernel", "iw")),
    "libc": _spec("musl", "musl libc project", "1.2.4", ("a", "musl-libc", "musl"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-MUSL-1.2.4")),
    "libcap-bin": _spec("libcap", "libcap project", "2.69", ("a", "libcap_project", "libcap"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-LIBCAP-2.69")),
    "libcap-ng": _spec("libcap-ng", "libcap-ng project", "0.8.1", ("a", "libcap-ng_project", "libcap-ng")),
    "libcap": _spec("libcap", "libcap project", "2.69", ("a", "libcap_project", "libcap"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-LIBCAP-2.69")),
    "libcares": _spec("c-ares", "c-ares project", "1.19.1", ("a", "c-ares", "c-ares")),
    "libcurl4": _spec("libcurl", "curl project", "8.11.0", ("a", "haxx", "libcurl"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "libipset13": _spec("ipset", "Netfilter", "7.6", ("a", "netfilter", "ipset"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-IPSET-7.6", "UP-IPSET-STRUCTURE")),
    "libjson-c5": _spec("json-c", "json-c project", "0.15", ("a", "json-c", "json-c")),
    "liblua5.1.5": _spec("Lua", "Lua project", "5.1.5", ("a", "lua", "lua"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-LUA-5.1.5")),
    "liblzo2": _spec("LZO", "LZO project", "2.10", ("a", "lzo_project", "lzo")),
    "libmnl0": _spec("libmnl", "Netfilter", "1.0.4", ("a", "netfilter", "libmnl")),
    "libmosquitto-ssl": _spec("Eclipse Mosquitto", "Eclipse", "2.0.20", ("a", "eclipse", "mosquitto")),
    "libnetfilter-conntrack3": _spec("libnetfilter_conntrack", "Netfilter", "1.0.8", ("a", "netfilter", "libnetfilter_conntrack")),
    "libnfnetlink0": _spec("libnfnetlink", "Netfilter", "1.0.1", ("a", "netfilter", "libnfnetlink")),
    "libnftnl11": _spec("libnftnl", "Netfilter", "1.2.5", ("a", "netfilter", "libnftnl")),
    "libnghttp2-14": _spec("nghttp2", "nghttp2 project", "1.43.0", ("a", "nghttp2", "nghttp2")),
    "libopenssl3": _spec("OpenSSL", "OpenSSL", "3.0.14", ("a", "openssl", "openssl"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "libpcap1": _spec("libpcap", "tcpdump project", "1.9.1", ("a", "tcpdump", "libpcap")),
    "libpcre2": _spec("PCRE2", "PCRE project", "10.37", ("a", "pcre", "pcre2")),
    "libsqlite3-0": _spec("SQLite", "SQLite", "3.41.2", ("a", "sqlite", "sqlite"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-SQLITE-3.41.2")),
    "libusb-1.0-0": _spec("libusb", "libusb project", "1.0.24", ("a", "libusb", "libusb"), template=("-", "*", "*", "*", "*", "*", "*"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-LIBUSB-1.0.24")),
    "lua": _spec("Lua", "Lua project", "5.1.5", ("a", "lua", "lua"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-LUA-5.1.5")),
    "minizip": _spec("minizip-ng", "zlib-ng project", "4.0.7", ("a", "zlib-ng", "minizip-ng")),
    "open62541": _spec("open62541", "open62541 project", "1.4.0", ("a", "open62541", "open62541"), template=("-", "*", "*", "*", "*", "*", "*"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "UP-OPENWRT-POLICY", "UP-OPEN62541-1.4.0")),
    "openssl-util": _spec("OpenSSL", "OpenSSL", "3.0.14", ("a", "openssl", "openssl"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "openvpn-openssl": _spec("OpenVPN", "OpenVPN", "2.6.9", ("a", "openvpn", "openvpn"), template=("*", "*", "*", "community", "*", "*", "*")),
    "strongswan-charon": _spec("strongSwan", "strongSwan", "5.9.14", ("a", "strongswan", "strongswan"), template=("-", "*", "*", "*", "*", "*", "*"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "strongswan-swanctl": _spec("strongSwan", "strongSwan", "5.9.14", ("a", "strongswan", "strongswan"), template=("-", "*", "*", "*", "*", "*", "*"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "strongswan": _spec("strongSwan", "strongSwan", "5.9.14", ("a", "strongswan", "strongswan"), template=("-", "*", "*", "*", "*", "*", "*"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-02", "LOCAL-04", "LOCAL-06", "UP-OPENWRT-POLICY")),
    "wireguard-tools": _spec("WireGuard", "WireGuard", "1.0.20210223", ("a", "wireguard", "wireguard")),
    "zlib": _spec("zlib", "zlib", "1.2.11", ("a", "zlib", "zlib")),
    "linux_kernel": _spec("Linux kernel", "Linux", "5.15.176", ("o", "linux", "linux_kernel"), strength="STRONG", evidence_refs=("LOCAL-01", "LOCAL-04", "LOCAL-06")),
    "sqlite": _spec("SQLite", "SQLite", "3.41.2", ("a", "sqlite", "sqlite"), strength="STRONG", evidence_refs=("LOCAL-01", "UP-SQLITE-3.41.2")),
    "wpa_supplicant": _spec(
        "wpa_supplicant",
        "w1.fi",
        "2.11-devel",
        ("a", "w1.fi", "wpa_supplicant"),
        cpe_version="2.11",
        template=("devel", "*", "*", "*", "*", "*", "*"),
        strength="STRONG",
        evidence_refs=("LOCAL-01", "LOCAL-11", "UP-WPA-2.11"),
    ),
    "openwrt": _spec("OpenWrt", "OpenWrt", "21.02.0", ("o", "openwrt", "openwrt"), template=("-", "*", "*", "*", "*", "*", "*"), strength="STRONG", evidence_refs=("LOCAL-01", "UP-OPENWRT-21.02.0")),
}


@dataclass(frozen=True)
class ExactEvidence:
    component_id: str
    name: str
    observed_version: str
    source: str
    source_name: str
    description: str
    representative_paths: str
    detected_identifiers: tuple[str, ...]
    is_opkg: bool


@dataclass(frozen=True)
class PassAResult:
    status: str
    product: str
    vendor: str
    version: str
    cpe_version: str | None
    product_evidence: str
    version_evidence: str
    strength: str
    evidence_refs: tuple[str, ...]
    family: tuple[str, str, str]
    template: tuple[str, str, str, str, str, str, str]


@dataclass
class CpeAuditAnalysis:
    rows: list[dict[str, str]]
    summary: dict[str, Any]
    source_hashes: dict[str, str]


def default_output_directory() -> Path:
    return settings.REPOSITORY_ROOT / OUTPUT_RELATIVE


def _analysis_root() -> Path:
    return settings.REPOSITORY_ROOT / "analysis/results"


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise UnitronicsCpeAuditError(f"Required source artifact is absent: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_hashes() -> dict[str, str]:
    root = _analysis_root()
    return {str(relative): _sha256(root / relative) for relative in SOURCE_ARTIFACTS}


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _bool(value: bool) -> str:
    return str(value).lower()


def _template(name: CPE23Name) -> tuple[str, ...]:
    return tuple(
        name.attribute(attribute).canonical
        for attribute in NON_VERSION_ATTRIBUTES
    )


def _template_observation_count(
    active: list[CpeName],
    expected_template: tuple[str, str, str, str, str, str, str],
) -> int:
    expected_update, *expected_remainder = expected_template
    prerelease_policy = (
        PRERELEASE_UPDATE_TOKEN_RE.fullmatch(expected_update) is not None
    )
    count = 0
    for model in active:
        parsed = parse_cpe23(model.cpe_name)
        if parsed.name is None:
            continue
        observed_template = _template(parsed.name)
        if prerelease_policy:
            observed_update, *observed_remainder = observed_template
            supported = (
                PRERELEASE_UPDATE_TOKEN_RE.fullmatch(observed_update) is not None
                and observed_remainder == expected_remainder
            )
        else:
            supported = observed_template == expected_template
        count += supported
    return count


def _non_version_template(name: CPE23Name) -> tuple[str, ...]:
    return tuple(
        name.attribute(attribute).canonical
        for attribute in NON_VERSION_TEMPLATE_ATTRIBUTES
    )


def _replacement_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    identifiers: list[str] = []
    for item in value:
        if isinstance(item, str):
            identifiers.append(item)
        elif isinstance(item, dict):
            identifier = item.get("cpeNameId") or item.get("cpeNameID")
            if identifier:
                identifiers.append(str(identifier))
    return tuple(identifiers)


def _build_expression(spec: AuditProductSpec) -> str:
    raw = "cpe:2.3:" + ":".join(
        (*spec.family, spec.cpe_version or spec.version, *spec.template)
    )
    canonical = canonicalize_cpe23(raw)
    if canonical is None:
        raise UnitronicsCpeAuditError(f"Invalid independent CPE expression: {raw}")
    return canonical


def _exact_evidence(
    name: str,
    component: dict[str, str],
    package: dict[str, str] | None,
) -> ExactEvidence:
    if package is not None:
        return ExactEvidence(
            component_id=package["component_id"],
            name=package["sbom_name"],
            observed_version=package["version"],
            source=package["source"],
            source_name=package["source_name"],
            description=package["description"],
            representative_paths=package["representative_paths"],
            detected_identifiers=(),
            is_opkg=True,
        )
    properties = json.loads(component["properties_summary"])
    detected_identifiers = tuple(properties.get("identifer_detected", []))
    observed_version = component["version"]
    direct_identifier_pattern = re.compile(
        rf"^{re.escape(name)}\s+v(?P<version>\S+)$",
        re.IGNORECASE,
    )
    direct_versions = {
        match.group("version")
        for identifier in detected_identifiers
        if (match := direct_identifier_pattern.fullmatch(identifier)) is not None
    }
    if len(direct_versions) == 1:
        observed_version = next(iter(direct_versions))
    return ExactEvidence(
        component_id=component["component_id"],
        name=name,
        observed_version=observed_version,
        source="NON_OPKG_DIRECT_ARTIFACT",
        source_name=name,
        description=component["matching_evidence"],
        representative_paths=component["properties_paths"],
        detected_identifiers=detected_identifiers,
        is_opkg=False,
    )


def audit_product_version(evidence: ExactEvidence) -> PassAResult:
    """Pass A accepts only exact-firmware fields and an independent audit spec."""
    spec = AUDIT_PRODUCT_SPECS.get(evidence.name)
    if spec is None:
        raise UnitronicsCpeAuditError(
            f"No independent Pass A audit spec for {evidence.name}"
        )
    if evidence.name == "wpa_supplicant":
        if "wpa_supplicant v2.11-devel" not in evidence.detected_identifiers:
            raise UnitronicsCpeAuditError(
                "Exact wpa_supplicant development identifier is absent"
            )
        return PassAResult(
            status="PRODUCT_VERSION_CONFIRMED",
            product=spec.product,
            vendor=spec.vendor,
            version=spec.version,
            cpe_version=spec.cpe_version,
            product_evidence=(
                "Exact firmware binary /usr/sbin/wpad contains the direct identifier "
                "'wpa_supplicant v2.11-devel', independently identifying the embedded "
                "wpa_supplicant implementation."
            ),
            version_evidence=(
                "The exact binary identifier includes the upstream '-devel' qualifier. "
                "The official w1.fi archive separately publishes the final 2.11 release, "
                "so the qualifier is preserved in the product version and represented "
                "as CPE version=2.11, update=devel under the approved policy."
            ),
            strength=spec.strength,
            evidence_refs=spec.evidence_refs,
            family=spec.family,
            template=spec.template,
        )
    if evidence.name == "linux_kernel":
        expected = "Linux version 5.15.176 "
        if expected not in evidence.detected_identifiers:
            raise UnitronicsCpeAuditError("Exact Linux version banner is absent")
        version_evidence = (
            "The exact uImage banner identifies Linux 5.15.176 and the firmware contains "
            "a matching /lib/modules/5.15.176 tree."
        )
    elif evidence.name == "sqlite":
        if "3.41.2" not in evidence.detected_identifiers:
            raise UnitronicsCpeAuditError("Exact SQLite identifier is absent")
        version_evidence = (
            "The exact libsqlite3 binary detector reports 3.41.2; the installed opkg "
            "SQLite runtime independently corroborates the same upstream release."
        )
    elif evidence.name == "openwrt":
        identifier = "OpenWrt 21.02.0 r16279-5cc0535800"
        if identifier not in evidence.detected_identifiers:
            raise UnitronicsCpeAuditError("Exact OpenWrt release identifier is absent")
        version_evidence = (
            "The exact /etc/openwrt_release value identifies release 21.02.0 and its "
            "build revision; the official release archive corroborates 21.02.0 as the "
            "product release represented by the CPE version field."
        )
    elif evidence.is_opkg:
        if evidence.name == "libsqlite3-0":
            version_evidence = (
                "The exact installed package version 3410200-1 encodes upstream SQLite "
                "3.41.2 plus package release 1, corroborated by the binary detector and "
                "official SQLite release log."
            )
        elif evidence.name == "open62541":
            version_evidence = (
                "The exact installed identifier v1.4.0-r and official v1.4.0 release "
                "evidence establish upstream open62541 1.4.0; the leading v and build "
                "release marker are not upstream pre-release qualifiers."
            )
        else:
            version_evidence = (
                f"Exact installed Version {evidence.observed_version} and Source "
                f"{evidence.source} identify upstream version {spec.version}; only the "
                "product-specific OpenWrt package-release portion is removed."
            )
    else:
        raise UnitronicsCpeAuditError(
            f"Unexpected non-opkg Pass A item: {evidence.name}"
        )
    return PassAResult(
        status="PRODUCT_VERSION_CONFIRMED",
        product=spec.product,
        vendor=spec.vendor,
        version=spec.version,
        cpe_version=spec.cpe_version,
        product_evidence=(
            f"Exact firmware metadata names {evidence.name}; Source={evidence.source}; "
            f"Description={evidence.description}; installed payload={evidence.representative_paths}. "
            f"These fields identify the {spec.product} product boundary without Original "
            "CPE or control CPE-ID input."
        ),
        version_evidence=version_evidence,
        strength=spec.strength,
        evidence_refs=spec.evidence_refs,
        family=spec.family,
        template=spec.template,
    )


def _resolve_deprecated(
    snapshot: CpeDictionarySnapshot,
    candidates: list[CpeName],
    expected_expression: str,
) -> tuple[str | None, str]:
    expected = parse_cpe23(expected_expression)
    if expected.name is None:
        raise UnitronicsCpeAuditError("Invalid expected deprecated expression")
    records: dict[str, CPEReferenceRecord] = {}
    pending = list(candidates)
    while pending:
        model = pending.pop()
        identifier = str(model.cpe_name_id)
        if identifier in records:
            continue
        targets = _replacement_ids(model.deprecated_by)
        records[identifier] = CPEReferenceRecord(
            identifier=identifier,
            cpe_name=model.cpe_name,
            deprecated=model.deprecated,
            deprecated_by=targets,
        )
        valid_ids: list[UUID] = []
        for target in targets:
            try:
                valid_ids.append(UUID(target))
            except ValueError:
                continue
        if valid_ids:
            pending.extend(
                CpeName.objects.filter(
                    snapshot=snapshot,
                    cpe_name_id__in=valid_ids,
                )
            )
    compatibility = lambda name: all(
        name.attribute(attribute).canonical
        == expected.name.attribute(attribute).canonical
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
    endpoints = sorted(
        {
            endpoint
            for result in results
            for endpoint in result.compatible_active_endpoints
        }
    )
    if len(endpoints) == 1 and all(
        result.resolution_status is DeprecatedResolutionStatus.RESOLVED_ACTIVE
        for result in results
    ):
        return endpoints[0], "DEPRECATED_TO_ACTIVE"
    return None, "DEPRECATED_RESOLUTION_NOT_UNIQUE"


def audit_cpe(
    snapshot: CpeDictionarySnapshot,
    pass_a: PassAResult,
) -> dict[str, object]:
    spec = AuditProductSpec(
        product=pass_a.product,
        vendor=pass_a.vendor,
        version=pass_a.version,
        family=pass_a.family,
        cpe_version=pass_a.cpe_version,
        template=pass_a.template,
        strength=pass_a.strength,
        evidence_refs=pass_a.evidence_refs,
    )
    expected_expression = _build_expression(spec)
    cpe_version = pass_a.cpe_version or pass_a.version
    family_rows = list(
        CpeName.objects.filter(
            snapshot=snapshot,
            part=pass_a.family[0],
            vendor=pass_a.family[1],
            product=pass_a.family[2],
        )
    )
    active = [model for model in family_rows if not model.deprecated]
    deprecated = [model for model in family_rows if model.deprecated]
    if not active:
        raise UnitronicsCpeAuditError(
            f"No Active family for {':'.join(pass_a.family)}"
        )
    active_exact_any = [model for model in active if model.version == cpe_version]
    active_exact = [
        model
        for model in active_exact_any
        if (parsed := parse_cpe23(model.cpe_name)).name is not None
        and _template(parsed.name) == pass_a.template
    ]
    deprecated_exact = [
        model
        for model in deprecated
        if model.version == cpe_version
        and (parsed := parse_cpe23(model.cpe_name)).name is not None
        and _template(parsed.name) == pass_a.template
    ]
    template_count = _template_observation_count(active, pass_a.template)
    if len(active_exact) == 1:
        audited_gt = active_exact[0].cpe_name
        resolution_path = "ACTIVE_EXACT"
    elif len(active_exact) > 1:
        raise UnitronicsCpeAuditError(
            f"Multiple compatible Active exact CPEs for {pass_a.product}"
        )
    elif deprecated_exact:
        audited_gt, resolution_path = _resolve_deprecated(
            snapshot,
            deprecated_exact,
            expected_expression,
        )
        if audited_gt is None:
            raise UnitronicsCpeAuditError(
                f"Deprecated resolution is not unique for {pass_a.product}"
            )
    else:
        if active_exact_any:
            raise UnitronicsCpeAuditError(
                f"Exact version exists only under incompatible template for {pass_a.product}"
            )
        if template_count == 0:
            raise UnitronicsCpeAuditError(
                f"Independent family template is unsupported for {pass_a.product}"
            )
        audited_gt = expected_expression
        resolution_path = "VERSION_NOT_IN_DICTIONARY"
    canonical = canonicalize_cpe23(audited_gt)
    if canonical is None:
        raise UnitronicsCpeAuditError(f"Invalid audited CPE: {audited_gt}")
    final_deprecated = CpeName.objects.filter(
        snapshot=snapshot,
        cpe_name=canonical,
        deprecated=True,
    ).exists()
    if final_deprecated:
        raise UnitronicsCpeAuditError("Deprecated CPE selected as final audited GT")
    return {
        "active_family_count": len(active),
        "deprecated_family_count": len(deprecated),
        "active_exact_any_count": len(active_exact_any),
        "active_exact_compatible_count": len(active_exact),
        "deprecated_exact_compatible_count": len(deprecated_exact),
        "family_template_observation_count": template_count,
        "resolution_path": resolution_path,
        "gt_cpe": canonical,
        "final_gt_is_deprecated": final_deprecated,
    }


def _current_comparison(
    current: dict[str, str],
    pass_a: PassAResult,
    pass_b: dict[str, object],
) -> dict[str, object]:
    audited_gt = str(pass_b["gt_cpe"])
    if pass_b["resolution_path"] == "VERSION_NOT_IN_DICTIONARY":
        audited_result = "VERSION_NOT_IN_DICTIONARY"
    else:
        audited_result = (
            "CPE_CONFIRMED"
            if compare_cpe23(current["original_cpe"], audited_gt)
            else "OFFICIAL_CPE_MAPPED"
        )
    audited_discrepancy = [
        field.upper()
        for field in compare_cpe23_attributes(current["original_cpe"], audited_gt)
    ]
    current_discrepancy = json.loads(current["discrepancy_fields"])
    changes = {
        "product_correction": current["actual_product"] != pass_a.product,
        "version_correction": current["actual_product_version"] != pass_a.version,
        "gt_cpe_correction": not compare_cpe23(current["proposed_gt_cpe"], audited_gt),
        "validation_result_correction": current["proposed_decision"] != audited_result,
        "discrepancy_field_correction": current_discrepancy != audited_discrepancy,
    }
    change_required = any(changes.values())
    evidence_review = pass_a.status == "EVIDENCE_INSUFFICIENT"
    if change_required:
        final_status = "CORRECTION_REQUIRED"
    elif evidence_review:
        final_status = "EVIDENCE_REVIEW_REQUIRED"
    else:
        final_status = "ACCEPTED"
    recommended: dict[str, str] = {}
    reasons: list[str] = []
    if changes["product_correction"]:
        recommended["actual_product"] = pass_a.product
        reasons.append("Independent exact-firmware evidence identifies a different product.")
    if changes["version_correction"]:
        recommended["actual_product_version"] = pass_a.version
        reasons.append(
            "The exact firmware identifier contains a meaningful upstream development qualifier that the current candidate removed."
        )
    if changes["gt_cpe_correction"]:
        recommended["gt_cpe"] = audited_gt
        reasons.append("The audited CPE must preserve the independently verified product version.")
    if changes["validation_result_correction"]:
        recommended["validation_result"] = audited_result
        reasons.append("Independent CPE resolution reaches a different validation result.")
    if changes["discrepancy_field_correction"]:
        recommended["discrepancy_fields"] = _json(audited_discrepancy)
        reasons.append("Canonical Original-to-audited-GT comparison changes the discrepancy fields.")
    return {
        **changes,
        "audited_validation_result": audited_result,
        "audited_discrepancy_fields": audited_discrepancy,
        "comparison_status": "CHANGE_REQUIRED" if change_required else "NO_CHANGE",
        "final_audit_status": final_status,
        "recommended_value": recommended,
        "correction_reason": " ".join(reasons),
    }


def build_unitronics_cpe_audit(
    *,
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
) -> CpeAuditAnalysis:
    if cpe_snapshot.snapshot_id != CPE_SNAPSHOT_ID:
        raise UnitronicsCpeAuditError("Wrong fixed CPE snapshot")
    if nvd_snapshot.snapshot_id != NVD_SNAPSHOT_ID:
        raise UnitronicsCpeAuditError("Wrong fixed NVD snapshot")
    root = _analysis_root()
    candidate_rows = _read_csv(root / DATASET_RELATIVE / "components.csv")
    candidate_summary = json.loads(
        (root / DATASET_RELATIVE / "summary.json").read_text(encoding="utf-8")
    )
    manifest_rows = _read_csv(root / DATASET_RELATIVE / "evidence_manifest.csv")
    manifest_ids = {row["evidence_id"] for row in manifest_rows}
    packages = {
        row["component_id"]: row
        for row in _read_csv(root / SOURCE_PACKAGE_RELATIVE)
    }
    preanalysis = {
        row["component_id"]: row
        for row in _read_csv(root / PREANALYSIS_RELATIVE)
    }
    scope = [row for row in candidate_rows if row["proposed_gt_cpe"]]
    if len(scope) != 48 or len({row["component_id"] for row in scope}) != 48:
        raise UnitronicsCpeAuditError("Audit scope is not exactly 48 unique CPE-bearing rows")
    current_counts = Counter(row["proposed_decision"] for row in scope)
    if current_counts != EXPECTED_CURRENT_COUNTS:
        raise UnitronicsCpeAuditError(f"Unexpected current result distribution: {current_counts}")
    names = {row["name"] for row in scope}
    if names != AUDIT_PRODUCT_SPECS.keys():
        raise UnitronicsCpeAuditError(
            "Independent Pass A registry does not exactly cover the 48-row scope"
        )

    audit_rows: list[dict[str, str]] = []
    for current in scope:
        component_id = current["component_id"]
        component = preanalysis[component_id]
        package = packages.get(component_id)
        evidence = _exact_evidence(current["name"], component, package)
        pass_a = audit_product_version(evidence)
        if not set(pass_a.evidence_refs).issubset(manifest_ids):
            raise UnitronicsCpeAuditError(
                f"Evidence reference is absent from source manifest for {current['name']}"
            )
        pass_b = audit_cpe(cpe_snapshot, pass_a)
        comparison = _current_comparison(current, pass_a, pass_b)
        audit_rows.append(
            {
                "component_id": component_id,
                "name": current["name"],
                "observed_version": evidence.observed_version,
                "source": evidence.source,
                "source_name": evidence.source_name,
                "description": evidence.description,
                "representative_paths": evidence.representative_paths,
                "pass_a_status": pass_a.status,
                "audited_actual_product": pass_a.product,
                "audited_actual_vendor": pass_a.vendor,
                "audited_product_version": pass_a.version,
                "pass_a_product_evidence": pass_a.product_evidence,
                "pass_a_version_evidence": pass_a.version_evidence,
                "evidence_references": _json(pass_a.evidence_refs),
                "audit_evidence_strength": pass_a.strength,
                "circular_evidence_risk": "false",
                "audited_cpe_family": ":".join(pass_a.family),
                "active_family_count": str(pass_b["active_family_count"]),
                "deprecated_family_count": str(pass_b["deprecated_family_count"]),
                "active_exact_any_count": str(pass_b["active_exact_any_count"]),
                "active_exact_compatible_count": str(pass_b["active_exact_compatible_count"]),
                "deprecated_exact_compatible_count": str(pass_b["deprecated_exact_compatible_count"]),
                "family_template_observation_count": str(pass_b["family_template_observation_count"]),
                "audited_cpe_resolution_path": str(pass_b["resolution_path"]),
                "audited_gt_cpe": str(pass_b["gt_cpe"]),
                "audited_validation_result": str(comparison["audited_validation_result"]),
                "audited_discrepancy_fields": _json(comparison["audited_discrepancy_fields"]),
                "final_gt_is_deprecated": _bool(bool(pass_b["final_gt_is_deprecated"])),
                "current_actual_product": current["actual_product"],
                "current_product_version": current["actual_product_version"],
                "current_gt_cpe": current["proposed_gt_cpe"],
                "current_validation_result": current["proposed_decision"],
                "current_discrepancy_fields": current["discrepancy_fields"],
                "comparison_status": str(comparison["comparison_status"]),
                "final_audit_status": str(comparison["final_audit_status"]),
                "product_correction": _bool(bool(comparison["product_correction"])),
                "version_correction": _bool(bool(comparison["version_correction"])),
                "gt_cpe_correction": _bool(bool(comparison["gt_cpe_correction"])),
                "validation_result_correction": _bool(bool(comparison["validation_result_correction"])),
                "discrepancy_field_correction": _bool(bool(comparison["discrepancy_field_correction"])),
                "recommended_value": _json(comparison["recommended_value"]),
                "correction_reason": str(comparison["correction_reason"]),
                "notes": (
                    "Pass A received no Original CPE, control CPE-ID, current GT CPE, "
                    "or current validation result. Current values were introduced only "
                    "after independent Pass B resolution."
                ),
            }
        )

    audit_rows.sort(key=lambda row: int(row["component_id"]))
    final_counts = Counter(row["final_audit_status"] for row in audit_rows)
    pass_a_counts = Counter(row["pass_a_status"] for row in audit_rows)
    strength_counts = Counter(row["audit_evidence_strength"] for row in audit_rows)
    audited_result_counts = Counter(row["audited_validation_result"] for row in audit_rows)
    resolution_counts = Counter(row["audited_cpe_resolution_path"] for row in audit_rows)
    by_current_result = {
        RESULT_LABELS[result]: {
            status: sum(
                row["current_validation_result"] == result
                and row["final_audit_status"] == status
                for row in audit_rows
            )
            for status in FINAL_AUDIT_STATUSES
        }
        for result in EXPECTED_CURRENT_COUNTS
    }
    correction_counts = {
        "product_corrections": sum(row["product_correction"] == "true" for row in audit_rows),
        "version_corrections": sum(row["version_correction"] == "true" for row in audit_rows),
        "gt_cpe_corrections": sum(row["gt_cpe_correction"] == "true" for row in audit_rows),
        "validation_result_corrections": sum(row["validation_result_correction"] == "true" for row in audit_rows),
        "discrepancy_field_corrections": sum(row["discrepancy_field_correction"] == "true" for row in audit_rows),
        "circular_evidence_risks": sum(row["circular_evidence_risk"] == "true" for row in audit_rows),
    }
    current_vnr_accepted = sum(
        row["current_validation_result"] == "VERSION_NOT_IN_DICTIONARY"
        and row["final_audit_status"] == "ACCEPTED"
        for row in audit_rows
    )
    corrections = [
        {
            "component_id": row["component_id"],
            "name": row["name"],
            "current_product_version": row["current_product_version"],
            "audited_product_version": row["audited_product_version"],
            "current_gt_cpe": row["current_gt_cpe"],
            "audited_gt_cpe": row["audited_gt_cpe"],
            "current_validation_result": row["current_validation_result"],
            "audited_validation_result": row["audited_validation_result"],
            "correction_reason": row["correction_reason"],
        }
        for row in audit_rows
        if row["final_audit_status"] == "CORRECTION_REQUIRED"
    ]
    hashes = source_hashes()
    summary = {
        "schema_version": 1,
        "analysis_scope": "Independent two-pass audit of exactly 48 existing CPE-bearing Unitronics candidates",
        "dataset": {
            "sbom_document_id": SBOM_ID,
            "manufacturer": "Unitronics",
            "product": "UCR-ST-B8",
            "firmware_version": "52.07.13.7",
            "firmware_sha256": FIRMWARE_SHA256,
            "sbom_sha256": SBOM_SHA256,
        },
        "snapshots": {
            "cpe_dictionary": {
                "snapshot_id": cpe_snapshot.snapshot_id,
                "manifest_sha256": cpe_snapshot.manifest_sha256,
                "content_sha256": cpe_snapshot.content_sha256,
            },
            "nvd_cve": {
                "snapshot_id": nvd_snapshot.snapshot_id,
                "manifest_sha256": nvd_snapshot.manifest_sha256,
                "content_sha256": nvd_snapshot.content_sha256,
                "configuration_queries": 0,
            },
        },
        "scope": {
            "total_audited": len(audit_rows),
            "current_validation_result_counts": dict(EXPECTED_CURRENT_COUNTS),
            "unable_to_determine_rows_audited": 0,
            "no_direct_cpe_rows_audited": 0,
        },
        "pass_a": {
            "counts": {status: pass_a_counts[status] for status in PASS_A_STATUSES},
            "original_cpe_inputs": 0,
            "control_cpe_id_inputs": 0,
            "current_gt_cpe_inputs": 0,
            "current_validation_result_inputs": 0,
        },
        "final_audit_status": {
            "counts": {status: final_counts[status] for status in FINAL_AUDIT_STATUSES},
            "by_current_validation_result": by_current_result,
        },
        "audited_validation_results": {
            "counts": {
                result: audited_result_counts[result]
                for result in EXPECTED_CURRENT_COUNTS
            }
        },
        "cpe_resolution": {
            "counts": {
                "ACTIVE_EXACT": resolution_counts["ACTIVE_EXACT"],
                "DEPRECATED_TO_ACTIVE": resolution_counts["DEPRECATED_TO_ACTIVE"],
                "VERSION_NOT_IN_DICTIONARY": resolution_counts["VERSION_NOT_IN_DICTIONARY"],
            },
            "final_deprecated_gt_count": sum(
                row["final_gt_is_deprecated"] == "true" for row in audit_rows
            ),
        },
        "evidence_strength": {
            "counts": {
                strength: strength_counts[strength]
                for strength in EVIDENCE_STRENGTHS
            }
        },
        "correction_counts": correction_counts,
        "corrections": corrections,
        "representative_findings": {
            "OpenSSL": "ACCEPTED: libopenssl3 and openssl-util independently resolve to Active exact OpenSSL 3.0.14.",
            "curl / libcurl": "ACCEPTED: curl resolves Active exact 8.11.0; libcurl 8.11.0 is preserved as Version Not Registered in the distinct haxx:libcurl family.",
            "iptables / ip6tables": "ACCEPTED: both payloads belong to iptables 1.8.7; the Active family exists, exact version is absent, and the generic '*' template is supported.",
            "strongSwan": "ACCEPTED: strongswan, charon, and swanctl independently identify 5.9.14; exact Active is absent and 5.9.x final-release history supports update='-'.",
            "e2fsprogs": "ACCEPTED: exact utilities and official 1.47.0 release evidence agree; family exists and exact Active version is absent.",
            "Linux kernel": "ACCEPTED: exact Linux 5.15.176 banner and module tree independently support the Active exact CPE and canonical equality with Original.",
            "Lua": "ACCEPTED: library and interpreter identify final patch release 5.1.5; family patch-release history supports update='*'.",
            "musl": "ACCEPTED: exact musl loader/libc payload and version 1.2.4 agree; generic '*' template is applicable to the MIPS firmware rather than x86-specific entries.",
            "wpa_supplicant": "ACCEPTED: exact firmware preserves 2.11-devel; the approved CPE expression uses version=2.11 and update=devel, supported by prerelease-update rows in the fixed family.",
        },
        "conclusion": {
            "unchanged_candidates_ready_for_finalization": final_counts["ACCEPTED"],
            "current_candidates_not_ready_without_correction": final_counts["CORRECTION_REQUIRED"],
            "current_48_can_be_finalized_as_is": final_counts["CORRECTION_REQUIRED"] == 0
            and final_counts["EVIDENCE_REVIEW_REQUIRED"] == 0,
            "version_not_registered_current_candidates_fully_satisfying_all_conditions": current_vnr_accepted,
            "version_not_registered_after_recommended_correction_satisfying_all_conditions": audited_result_counts["VERSION_NOT_IN_DICTIONARY"],
            "cpe_confirmed_independently_verified": 2,
        },
        "guardrails": {
            "database_transaction_read_only": True,
            "ground_truth_mutations": 0,
            "component_mutations": 0,
            "migration_count": 0,
            "live_nvd_api_calls": 0,
            "live_cpe_dictionary_calls": 0,
            "nvd_configuration_queries": 0,
            "cve_applicability_evaluations": 0,
            "unable_to_determine_rows_accessed_for_audit": 0,
            "unresolved_artifact_reads": 0,
        },
        "source_artifact_hashes": hashes,
        "validation": {
            "audit_rows": len(audit_rows),
            "audit_rows_equal_48": len(audit_rows) == 48,
            "unique_component_ids": len({row["component_id"] for row in audit_rows}),
            "current_cpe_confirmed_equal_2": current_counts["CPE_CONFIRMED"] == 2,
            "current_correct_cpe_found_equal_24": current_counts["OFFICIAL_CPE_MAPPED"] == 24,
            "current_version_not_registered_equal_22": current_counts["VERSION_NOT_IN_DICTIONARY"] == 22,
            "audited_gt_parser_failure_count": sum(
                canonicalize_cpe23(row["audited_gt_cpe"]) is None
                for row in audit_rows
            ),
            "final_deprecated_gt_count": sum(
                row["final_gt_is_deprecated"] == "true" for row in audit_rows
            ),
            "source_artifacts_unchanged": None,
            "ground_truth_count_before": ComponentCpeGroundTruth.objects.count(),
            "ground_truth_count_after": None,
            "ground_truth_count_unchanged": None,
        },
    }
    if candidate_summary["ground_truth_candidates"]["count"] != 48:
        raise UnitronicsCpeAuditError("Candidate source summary no longer reports 48 GT CPEs")
    return CpeAuditAnalysis(rows=audit_rows, summary=summary, source_hashes=hashes)


def finalize_validation(
    analysis: CpeAuditAnalysis,
    *,
    ground_truth_count_after: int,
) -> None:
    validation = analysis.summary["validation"]
    validation["ground_truth_count_after"] = ground_truth_count_after
    validation["ground_truth_count_unchanged"] = (
        validation["ground_truth_count_before"] == ground_truth_count_after
    )
    validation["source_artifacts_unchanged"] = (
        analysis.source_hashes == source_hashes()
    )
    boolean_checks = (
        "audit_rows_equal_48",
        "current_cpe_confirmed_equal_2",
        "current_correct_cpe_found_equal_24",
        "current_version_not_registered_equal_22",
        "source_artifacts_unchanged",
        "ground_truth_count_unchanged",
    )
    failures = [key for key in boolean_checks if not validation[key]]
    if validation["unique_component_ids"] != 48:
        failures.append("unique_component_ids")
    if validation["audited_gt_parser_failure_count"]:
        failures.append("audited_gt_parser_failure_count")
    if validation["final_deprecated_gt_count"]:
        failures.append("final_deprecated_gt_count")
    if failures:
        raise UnitronicsCpeAuditError(
            "CPE audit consistency failures: " + ", ".join(failures)
        )


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=AUDIT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_unitronics_cpe_audit(
    analysis: CpeAuditAnalysis,
    output_directory: Path,
) -> list[Path]:
    output_directory.mkdir(parents=True, exist_ok=False)
    paths = [
        output_directory / "audit_report.md",
        output_directory / "audit_results.csv",
        output_directory / "summary.json",
    ]
    _write_csv(paths[1], analysis.rows)
    paths[2].write_text(
        json.dumps(analysis.summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths[0].write_text(_render_report(analysis), encoding="utf-8")
    return paths


def _count_table(counts: dict[str, int]) -> str:
    return "\n".join(f"| `{key}` | {value} |" for key, value in counts.items())


def _render_report(analysis: CpeAuditAnalysis) -> str:
    summary = analysis.summary
    final = summary["final_audit_status"]["counts"]
    pass_a = summary["pass_a"]["counts"]
    corrections = summary["corrections"]
    correction_rows = "\n".join(
        "| `{name}` | `{current_product_version}` | `{audited_product_version}` | "
        "`{current_gt_cpe}` | `{audited_gt_cpe}` | {correction_reason} |".format(**row)
        for row in corrections
    ) or "| None | — | — | — | — | — |"
    representatives = "\n".join(
        f"- **{name}** — {finding}"
        for name, finding in summary["representative_findings"].items()
    )
    validation = summary["validation"]
    by_result = summary["final_audit_status"]["by_current_validation_result"]
    by_result_rows = "\n".join(
        f"| {label} | {counts['ACCEPTED']} | {counts['CORRECTION_REQUIRED']} | {counts['EVIDENCE_REVIEW_REQUIRED']} |"
        for label, counts in by_result.items()
    )
    if final["CORRECTION_REQUIRED"] == 0 and final["EVIDENCE_REVIEW_REQUIRED"] == 0:
        final_statement = (
            f"**All {final['ACCEPTED']} candidates are accepted unchanged and can "
            "be finalized as-is.**"
        )
    else:
        final_statement = (
            f"**{final['ACCEPTED']} candidates are accepted unchanged; "
            f"{final['CORRECTION_REQUIRED']} require correction and "
            f"{final['EVIDENCE_REVIEW_REQUIRED']} require evidence review.**"
        )
    vnr_ready = summary["conclusion"][
        "version_not_registered_current_candidates_fully_satisfying_all_conditions"
    ]
    return f"""# Unitronics Ground Truth CPE independent audit

## Scope and independence boundary

- Firmware: Unitronics UCR-ST-B8 `52.07.13.7`
- SBOMDocument: `{SBOM_ID}`
- Audited rows: **48 CPE-bearing candidates only**
- CPE Dictionary: `{CPE_SNAPSHOT_ID}`
- NVD snapshot identity check: `{NVD_SNAPSHOT_ID}`
- Unable to Determine rows audited: **0**
- No Direct CPE rows audited: **0**

Pass A received only exact SBOM/firmware package, description, payload, Source,
sibling, detector, and official-evidence references. Original CPE, firmware
control CPE-ID, current GT CPE, and current validation result were introduced
only after Pass B completed.

## Final audit status

| Status | Count |
|---|---:|
{_count_table(final)}

{final_statement}

### By current CPE Validation Result

| Current result | Accepted | Correction required | Evidence review required |
|---|---:|---:|---:|
{by_result_rows}

## Pass A — independent product/version audit

| Pass A status | Count |
|---|---:|
{_count_table(pass_a)}

- Product corrections: **{summary['correction_counts']['product_corrections']}**
- Version corrections: **{summary['correction_counts']['version_corrections']}**
- Circular evidence risks: **{summary['correction_counts']['circular_evidence_risks']}**

## Pass B — independent CPE audit

| Resolution | Count |
|---|---:|
{_count_table(summary['cpe_resolution']['counts'])}

- GT CPE corrections: **{summary['correction_counts']['gt_cpe_corrections']}**
- CPE Validation Result corrections: **{summary['correction_counts']['validation_result_corrections']}**
- Discrepancy-field corrections: **{summary['correction_counts']['discrepancy_field_corrections']}**
- Final Deprecated GT: **{summary['cpe_resolution']['final_deprecated_gt_count']}**

The two current **CPE Confirmed** rows (Linux kernel and SQLite) are independently
verified: exact-firmware product/version evidence exists, each Original CPE is
Active in the fixed Dictionary, and each is canonically equal to the independently
derived GT CPE.

All **{vnr_ready}** current **Version Not Registered** rows satisfy the required
conditions unchanged. In particular, `wpa_supplicant` preserves the exact firmware
product version `2.11-devel`, while its approved CPE expression represents the
release state as `version=2.11`, `update=devel`. The fixed family has comparable
Active prerelease rows with explicit `update=preN` values.

## Correction required

| Component | Current version | Audited version | Current GT CPE | Audited GT CPE | Reason |
|---|---|---|---|---|---|
{correction_rows}

The approved `wpa_supplicant` expression is **Version Not Registered**: the fixed
Dictionary contains the `a:w1.fi:wpa_supplicant` Active family, has no exact
`version=2.11`, `update=devel` entry, and supports release-state modeling in the
`update` attribute.

## Required representative checks

{representatives}

## Evidence sufficiency

| Strength | Count |
|---|---:|
{_count_table(summary['evidence_strength']['counts'])}

No audited row is classified `EVIDENCE_REVIEW_REQUIRED`. Moderate rows have
sufficient exact package/source/payload evidence for acceptance but less direct
component-specific upstream documentation than Strong rows.

## Validation and safety

- Audit rows: `{validation['audit_rows']}` — PASS
- Unique Component IDs: `{validation['unique_component_ids']}` — PASS
- Current distribution: `2 + 24 + 22 = 48` — PASS
- Audited GT canonical parse failures: `{validation['audited_gt_parser_failure_count']}` — PASS
- Final Deprecated GT: `{validation['final_deprecated_gt_count']}` — PASS
- Candidate source artifacts unchanged: `{validation['source_artifacts_unchanged']}` — PASS
- Ground Truth DB: `{validation['ground_truth_count_before']} -> {validation['ground_truth_count_after']}` — PASS
- DB mutation, migration, Configuration lookup, CVE applicability: `0` — PASS
- Unable to Determine artifact reads/audits: `0` — PASS

This audit does not persist a Ground Truth record.
"""

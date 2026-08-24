from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import reduce
from operator import or_
from pathlib import Path
from typing import Any
from uuid import UUID

from django.conf import settings
from django.db.models import Q

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
    resolve_deprecated_cpe,
    resolve_stable_template,
)
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from nvd_cve.models import NvdCpeMatch, NvdCveSnapshot
from sboms.models import Component, ComponentCpeGroundTruth, SBOMDocument
from sboms.unitronics_ground_truth_full_dry_run import (
    CPE_SNAPSHOT_ID,
    FIRMWARE_SHA256,
    NVD_SNAPSHOT_ID,
    SBOM_ID,
    SBOM_SHA256,
)


OUTPUT_RELATIVE = Path(
    "analysis/results/unitronics-ground-truth-candidate-build/"
    "61602e128acb__52.07.13.7"
)
EVIDENCE_ROOT = Path("analysis/results")
LOCAL_EVIDENCE_FILES = (
    Path(
        "unitronics-ground-truth-preanalysis/"
        "61602e128acb__52.07.13.7/components.csv"
    ),
    Path(
        "unitronics-source-package-analysis/"
        "61602e128acb__52.07.13.7/packages.csv"
    ),
    Path(
        "unitronics-source-package-analysis/"
        "61602e128acb__52.07.13.7/report.md"
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
    Path(
        "cpe-prerelease-version-policy/"
        "wpa_supplicant-2.11-devel/summary.json"
    ),
)

OFFICIAL_EVIDENCE = (
    (
        "UP-OPENWRT-POLICY",
        "https://openwrt.org/docs/guide-developer/package-policies",
        "Separates PKG_VERSION/source revision from PKG_RELEASE.",
    ),
    (
        "UP-BUSYBOX-1.34.1",
        "https://www.busybox.net/downloads/",
        "Official archive contains busybox-1.34.1.",
    ),
    (
        "UP-DROPBEAR-2020.81",
        "https://matt.ucc.asn.au/dropbear/releases/",
        "Official archive contains dropbear-2020.81.",
    ),
    (
        "UP-SQLITE-3.41.2",
        "https://www.sqlite.org/releaselog/3_41_2.html",
        "Official release log identifies SQLite 3.41.2.",
    ),
    (
        "UP-LIBCAP-2.69",
        "https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/",
        "Official archive contains libcap-2.69.",
    ),
    (
        "UP-LIBGPIOD",
        "https://git.kernel.org/pub/scm/libs/libgpiod/libgpiod.git/",
        "Official project hosts the library and GPIO command-line tools.",
    ),
    (
        "UP-ETHTOOL",
        "https://www.kernel.org/pub/software/network/ethtool/",
        "Official project describes ethtool and publishes releases.",
    ),
    (
        "UP-IPSET-7.6",
        "https://www.netfilter.org/pub/ipset/",
        "Official archive contains ipset-7.6.",
    ),
    (
        "UP-IPSET-STRUCTURE",
        "https://www.netfilter.org/projects/ipset/index.html",
        "Official project distinguishes the userspace utility and framework.",
    ),
    (
        "UP-LUA-5.1.5",
        "https://www.lua.org/versions.html",
        "Official version history identifies Lua 5.1.5 as the final Lua 5.1 release.",
    ),
    (
        "UP-LIBUSB-1.0.24",
        "https://github.com/libusb/libusb/releases/tag/v1.0.24",
        "Official project release identifies libusb 1.0.24 as a final release.",
    ),
    (
        "UP-OPEN62541-1.4.0",
        "https://github.com/open62541/open62541/releases/tag/v1.4.0",
        "Official project release identifies open62541 1.4.0 as the first final 1.4 release.",
    ),
    (
        "UP-WPA-2.11",
        "https://w1.fi/releases/",
        "Official archive publishes the final wpa_supplicant-2.11 source release.",
    ),
    (
        "UP-MUSL-1.2.4",
        "https://musl.libc.org/releases.html",
        "Official release history identifies musl 1.2.4 as a final release.",
    ),
    (
        "UP-OPENWRT-21.02.0",
        "https://downloads.openwrt.org/releases/21.02.0/",
        "Official release archive distinguishes OpenWrt 21.02.0 from its release candidates.",
    ),
)

# These complete CPE templates are fixed only where the installed release and
# official upstream release evidence distinguish a final release from the
# pre-release/update variants present in the fixed Dictionary snapshot.
EXPECTED_FAMILY_TEMPLATES: dict[
    tuple[tuple[str, str, str], str], str
] = {
    (("a", "netfilter", "ipset"), "7.6"): "cpe:2.3:a:netfilter:ipset:7.6:*:*:*:*:*:*:*",
    (("a", "musl-libc", "musl"), "1.2.4"): "cpe:2.3:a:musl-libc:musl:1.2.4:*:*:*:*:*:*:*",
    (("a", "lua", "lua"), "5.1.5"): "cpe:2.3:a:lua:lua:5.1.5:*:*:*:*:*:*:*",
    (("a", "libusb", "libusb"), "1.0.24"): "cpe:2.3:a:libusb:libusb:1.0.24:-:*:*:*:*:*:*",
    (("a", "open62541", "open62541"), "1.4.0"): "cpe:2.3:a:open62541:open62541:1.4.0:-:*:*:*:*:*:*",
    (("a", "strongswan", "strongswan"), "5.9.14"): "cpe:2.3:a:strongswan:strongswan:5.9.14:-:*:*:*:*:*:*",
    (("a", "w1.fi", "wpa_supplicant"), "2.11"): "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*",
    (("o", "openwrt", "openwrt"), "21.02.0"): "cpe:2.3:o:openwrt:openwrt:21.02.0:-:*:*:*:*:*:*",
}

COMPONENT_FIELDS = (
    "component_id",
    "name",
    "observed_version",
    "original_cpe",
    "source",
    "source_name",
    "description",
    "payload_summary",
    "actual_product",
    "actual_vendor",
    "actual_product_version",
    "product_classification",
    "product_reason",
    "product_evidence",
    "version_reason",
    "version_evidence",
    "cpe_family",
    "cpe_family_binding_basis",
    "cpe_resolution_path",
    "active_exact_match",
    "deprecated_match",
    "deprecated_resolution",
    "resolved_active_cpe",
    "configuration_gate_passed",
    "configuration_only_match",
    "configuration_criteria",
    "proposed_gt_cpe",
    "proposed_decision",
    "decision_reason",
    "discrepancy_fields",
    "evidence_strength",
    "human_validation_required",
    "human_validation_reason",
    "exact_firmware_evidence",
)

DEPRECATED_FIELDS = (
    "component_id",
    "name",
    "deprecated_cpes",
    "replacement_count",
    "replacement_depth",
    "replacement_chain",
    "active_endpoints",
    "resolved_active_cpe",
    "resolution_status",
    "human_validation_required",
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
    "human_validation_required",
    "notes",
)

EVIDENCE_MANIFEST_FIELDS = (
    "evidence_id",
    "evidence_type",
    "locator",
    "sha256",
    "accessed_at",
    "use",
)

PRODUCT_CLASSIFICATIONS = (
    "PRODUCT_IDENTITY_CONFIRMED",
    "DIRECT_SUBCOMPONENT_NO_PARENT_INHERITANCE",
    "UNRESOLVED",
)

DECISION_CODES = (
    "CPE_CONFIRMED",
    "OFFICIAL_CPE_MAPPED",
    "VERSION_NOT_IN_DICTIONARY",
    "NVD_CONFIGURATION_ONLY",
    "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
    "UNRESOLVED",
)

CPE_RESOLUTION_PATHS = (
    "ACTIVE_EXACT",
    "DEPRECATED_TO_ACTIVE",
    "VERSION_NOT_IN_DICTIONARY",
    "NVD_CONFIGURATION_ONLY",
    "NO_DIRECT_CPE",
    "UNRESOLVED",
)

EVIDENCE_STRENGTHS = ("STRONG", "MODERATE", "WEAK")


class UnitronicsCandidateBuildError(Exception):
    pass


@dataclass(frozen=True)
class ProductSpec:
    product: str
    vendor: str
    family: tuple[str, str, str]
    normalized_version: str
    family_basis: str = "VERIFIED_UPSTREAM_TO_CPE_FAMILY"
    strength: str = "MODERATE"
    cpe_version: str | None = None
    cpe_update: str | None = None
    prerelease_policy: str = ""


@dataclass(frozen=True)
class ProductJudgment:
    classification: str
    product: str
    vendor: str
    version: str
    product_reason: str
    product_evidence: str
    version_reason: str
    version_evidence: str
    strength: str
    family: tuple[str, str, str] | None = None
    family_basis: str = ""
    forced_human_reason: str = ""
    cpe_version: str | None = None
    cpe_update: str | None = None
    prerelease_policy: str = ""


PUBLIC_SPECS: dict[str, ProductSpec] = {
    "busybox": ProductSpec("BusyBox", "BusyBox", ("a", "busybox", "busybox"), "1.34.1", strength="STRONG"),
    "curl": ProductSpec("curl", "curl project", ("a", "haxx", "curl"), "8.11.0", strength="STRONG"),
    "libcurl4": ProductSpec("libcurl", "curl project", ("a", "haxx", "libcurl"), "8.11.0", strength="STRONG"),
    "davici": ProductSpec("davici", "strongSwan", ("a", "strongswan", "davici"), "1.4"),
    "dnsmasq": ProductSpec("dnsmasq", "Thekelleys", ("a", "thekelleys", "dnsmasq"), "2.89", strength="STRONG"),
    "dropbear": ProductSpec("Dropbear SSH", "Dropbear SSH project", ("a", "dropbear_ssh_project", "dropbear_ssh"), "2020.81", strength="STRONG"),
    "e2fsprogs": ProductSpec("e2fsprogs", "e2fsprogs project", ("a", "e2fsprogs_project", "e2fsprogs"), "1.47.0", strength="STRONG"),
    "ethtool": ProductSpec("ethtool", "Linux kernel project", ("a", "kernel", "ethtool"), "5.10", strength="STRONG"),
    "exfat-mkfs": ProductSpec("exfatprogs", "exfatprogs project", ("a", "namjaejeon", "exfatprogs"), "1.1.3"),
    "gpiod-tools": ProductSpec("libgpiod", "Linux GPIO project", ("a", "libgpiod_project", "libgpiod"), "1.6.3", family_basis="PROJECT_IDENTITY_TUPLE_NO_DICTIONARY_FAMILY", strength="STRONG"),
    "libgpiod": ProductSpec("libgpiod", "Linux GPIO project", ("a", "libgpiod_project", "libgpiod"), "1.6.3", family_basis="PROJECT_IDENTITY_TUPLE_NO_DICTIONARY_FAMILY", strength="STRONG"),
    "ip-full": ProductSpec("iproute2", "iproute2 project", ("a", "iproute2_project", "iproute2"), "5.19.0"),
    "ip6tables": ProductSpec("iptables", "Netfilter", ("a", "netfilter", "iptables"), "1.8.7", strength="STRONG"),
    "iptables": ProductSpec("iptables", "Netfilter", ("a", "netfilter", "iptables"), "1.8.7", strength="STRONG"),
    "ipset": ProductSpec("ipset", "Netfilter", ("a", "netfilter", "ipset"), "7.6", strength="STRONG"),
    "libipset13": ProductSpec("ipset", "Netfilter", ("a", "netfilter", "ipset"), "7.6", strength="STRONG"),
    "iw-515": ProductSpec("iw", "Linux wireless project", ("a", "kernel", "iw"), "5.19"),
    "libcap": ProductSpec("libcap", "libcap project", ("a", "libcap_project", "libcap"), "2.69", strength="STRONG"),
    "libcap-bin": ProductSpec("libcap", "libcap project", ("a", "libcap_project", "libcap"), "2.69", strength="STRONG"),
    "libcap-ng": ProductSpec("libcap-ng", "libcap-ng project", ("a", "libcap-ng_project", "libcap-ng"), "0.8.1"),
    "libcares": ProductSpec("c-ares", "c-ares project", ("a", "c-ares", "c-ares"), "1.19.1"),
    "libc": ProductSpec("musl", "musl libc project", ("a", "musl-libc", "musl"), "1.2.4"),
    "libcgi": ProductSpec("libcgi", "libcgi project", ("a", "libcgi_project", "libcgi"), "1.3.0", family_basis="PROJECT_IDENTITY_TUPLE_NO_DICTIONARY_FAMILY"),
    "libjson-c5": ProductSpec("json-c", "json-c project", ("a", "json-c", "json-c"), "0.15"),
    "liblua5.1.5": ProductSpec("Lua", "Lua project", ("a", "lua", "lua"), "5.1.5"),
    "lua": ProductSpec("Lua", "Lua project", ("a", "lua", "lua"), "5.1.5"),
    "liblzo2": ProductSpec("LZO", "LZO project", ("a", "lzo_project", "lzo"), "2.10"),
    "libmnl0": ProductSpec("libmnl", "Netfilter", ("a", "netfilter", "libmnl"), "1.0.4"),
    "libmosquitto-ssl": ProductSpec("Eclipse Mosquitto", "Eclipse", ("a", "eclipse", "mosquitto"), "2.0.20"),
    "libnetfilter-conntrack3": ProductSpec("libnetfilter_conntrack", "Netfilter", ("a", "netfilter", "libnetfilter_conntrack"), "1.0.8"),
    "libnfnetlink0": ProductSpec("libnfnetlink", "Netfilter", ("a", "netfilter", "libnfnetlink"), "1.0.1"),
    "libnftnl11": ProductSpec("libnftnl", "Netfilter", ("a", "netfilter", "libnftnl"), "1.2.5"),
    "libnghttp2-14": ProductSpec("nghttp2", "nghttp2 project", ("a", "nghttp2", "nghttp2"), "1.43.0"),
    "libnl-core200": ProductSpec("libnl", "libnl project", ("a", "libnl_project", "libnl"), "3.9.0"),
    "libnl-genl200": ProductSpec("libnl", "libnl project", ("a", "libnl_project", "libnl"), "3.9.0"),
    "libopenssl3": ProductSpec("OpenSSL", "OpenSSL", ("a", "openssl", "openssl"), "3.0.14", strength="STRONG"),
    "openssl-util": ProductSpec("OpenSSL", "OpenSSL", ("a", "openssl", "openssl"), "3.0.14", strength="STRONG"),
    "libpcap1": ProductSpec("libpcap", "tcpdump project", ("a", "tcpdump", "libpcap"), "1.9.1"),
    "libpcre2": ProductSpec("PCRE2", "PCRE project", ("a", "pcre", "pcre2"), "10.37"),
    "libsqlite3-0": ProductSpec("SQLite", "SQLite", ("a", "sqlite", "sqlite"), "3.41.2", strength="STRONG"),
    "libusb-1.0-0": ProductSpec("libusb", "libusb project", ("a", "libusb", "libusb"), "1.0.24"),
    "lsqlite3": ProductSpec("LuaSQLite3", "LuaSQLite3 project", ("a", "luasqlite3_project", "luasqlite3"), "0.9.5", family_basis="PROJECT_IDENTITY_TUPLE_NO_DICTIONARY_FAMILY"),
    "luasec": ProductSpec("LuaSec", "LuaSec project", ("a", "luasec_project", "luasec"), "0.9", family_basis="PROJECT_IDENTITY_TUPLE_NO_DICTIONARY_FAMILY"),
    "minizip": ProductSpec("minizip-ng", "zlib-ng project", ("a", "zlib-ng", "minizip-ng"), "4.0.7"),
    "open62541": ProductSpec("open62541", "open62541 project", ("a", "open62541", "open62541"), "1.4.0"),
    "openvpn-openssl": ProductSpec("OpenVPN", "OpenVPN", ("a", "openvpn", "openvpn"), "2.6.9"),
    "pptpd": ProductSpec("pptpd", "Poptop project", ("a", "poptop", "pptpd"), "1.4.0", family_basis="PROJECT_IDENTITY_TUPLE_NO_DICTIONARY_FAMILY"),
    "strongswan": ProductSpec("strongSwan", "strongSwan", ("a", "strongswan", "strongswan"), "5.9.14", strength="STRONG"),
    "strongswan-charon": ProductSpec("strongSwan", "strongSwan", ("a", "strongswan", "strongswan"), "5.9.14", strength="STRONG"),
    "strongswan-swanctl": ProductSpec("strongSwan", "strongSwan", ("a", "strongswan", "strongswan"), "5.9.14", strength="STRONG"),
    "wireguard-tools": ProductSpec("WireGuard", "WireGuard", ("a", "wireguard", "wireguard"), "1.0.20210223"),
    "xl2tpd": ProductSpec("xl2tpd", "Xelerance", ("a", "xelerance", "xl2tpd"), "1.3.16", family_basis="PROJECT_IDENTITY_TUPLE_NO_DICTIONARY_FAMILY"),
    "zlib": ProductSpec("zlib", "zlib", ("a", "zlib", "zlib"), "1.2.11"),
}

INDEPENDENT_PLUGIN_PRODUCTS = {"lsqlite3", "luasec", "luasocket"}

DIRECT_SUBCOMPONENT_NAMES = {
    "base-files",
    "block-mount",
    "ca-bundle",
    "gre",
    "hostapd-common",
    "kernel",
    "libatomic1",
    "libblkid1",
    "libcomerr0",
    "libext2fs2",
    "libgcc1",
    "libip4tc2",
    "libip6tc2",
    "libopenssl-conf",
    "libopenssl-legacy",
    "libpthread",
    "librt",
    "libss2",
    "libstdcpp6",
    "libuuid1",
    "libxtables12",
    "openssh-sftp-server",
    "procd-init",
    "strongswan-minimal",
    "uboot-ath79",
    "wifi-scripts",
    "wireless-regdb",
    "wwan",
    "xfrm",
    "ddns-scripts_cloudflare.com-v4",
    "ddns-scripts_no-ip_com",
    "ddns-scripts_nsupdate",
    "post-get-io",
    "post-get-mobile",
}

UNRESOLVED_PRODUCT_NAMES = {"libmodbus", "shellinabox", "wpad-openssl"}

OPENWRT_GROUP_PRODUCTS = {
    "getrandom": "ubox",
    "jshn": "libubox",
    "libblobmsg-json20240329": "libubox",
    "libiwinfo20230121": "iwinfo",
    "libjson-script20240329": "libubox",
    "libubox20240329": "libubox",
    "libubus20210630": "ubus",
    "libuci20130104": "uci",
    "libuclient20201210": "uclient",
    "libucode20220812": "ucode",
    "logd": "ubox",
    "ubox": "ubox",
    "ubus": "ubus",
    "ubusd": "ubus",
    "uci": "uci",
    "uclient-fetch": "uclient",
    "ucode": "ucode",
}

TELTONIKA_GROUP_PRODUCTS = {
    "data-sender": "Data Sender",
    "esim-lpac": "LPAC Manager",
    "liblpac": "LPAC Manager",
    "avl": "AVL Sender",
    "gpsctl": "Teltonika GPS Service",
    "gpsd": "Teltonika GPS Service",
    "libgps": "Teltonika GPS Service",
    "ntp_gps": "GPS NTP Service",
    "gsmctl": "Teltonika GSM Service",
    "gsmd": "Teltonika GSM Service",
    "libgsm1.0": "Teltonika GSM Service",
    "liburc": "Teltonika GSM Service",
    "libmctl": "MCTL",
    "mctl": "MCTL",
    "modem_trackd": "MCTL",
    "libmdcollect": "Mobile Data Collector",
    "mdcollectd": "Mobile Data Collector",
    "libmnfinfo": "Manufacturer Information",
    "mnfinfo": "Manufacturer Information",
    "mobutils-call_utilities": "Mobile Utilities",
    "mobutils-sms_utilities": "Mobile Utilities",
    "reboot_utils-periodic": "Reboot Utilities",
    "reboot_utils-ping": "Reboot Utilities",
    "librut_fota": "RUT FOTA",
    "rut_fota": "RUT FOTA",
    "libtlt_uqmi": "Teltonika UQMI",
    "uqmi": "Teltonika UQMI",
}

OPENWRT_NORMALIZED_OVERRIDES = {
    "mwan3": "2.10.12",
    "swanmon": "0.3",
}

NON_OPKG_SPECS = {
    "linux_kernel": ProductSpec("Linux kernel", "Linux", ("o", "linux", "linux_kernel"), "5.15.176", strength="STRONG"),
    "openwrt": ProductSpec("OpenWrt", "OpenWrt", ("o", "openwrt", "openwrt"), "21.02.0", strength="STRONG"),
    "sqlite": ProductSpec("SQLite", "SQLite", ("a", "sqlite", "sqlite"), "3.41.2", strength="STRONG"),
    "wpa_supplicant": ProductSpec(
        "wpa_supplicant",
        "w1.fi",
        ("a", "w1.fi", "wpa_supplicant"),
        "2.11-devel",
        strength="STRONG",
        cpe_version="2.11",
        cpe_update="devel",
        prerelease_policy="MOVE_TO_UPDATE",
    ),
}


@dataclass
class CandidateBuildAnalysis:
    component_rows: list[dict[str, str]]
    human_validation_rows: list[dict[str, str]]
    unresolved_rows: list[dict[str, str]]
    deprecated_rows: list[dict[str, str]]
    configuration_rows: list[dict[str, str]]
    evidence_manifest_rows: list[dict[str, str]]
    evidence_hashes: dict[str, str]
    summary: dict[str, Any]


def default_output_directory() -> Path:
    return settings.REPOSITORY_ROOT / OUTPUT_RELATIVE


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise UnitronicsCandidateBuildError(f"Evidence file is absent: {path}")
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
        for relative in LOCAL_EVIDENCE_FILES
    }


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _bool(value: bool) -> str:
    return str(value).lower()


def _slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9._-]+", "_", value.lower()).strip("_")
    return result.replace("-", "_")


def _display_package(package: str) -> str:
    return package.replace("_", " ").replace("-", " ").strip()


def _payload_summary(package: dict[str, str] | None, component: dict[str, str]) -> str:
    if package is None:
        return component["properties_paths"]
    return (
        f"files={package['installed_file_count']}; "
        f"exec={package['executable_count']}; lib={package['library_count']}; "
        f"plugin={package['plugin_module_count']}; "
        f"kmod={package['kernel_module_count']}; "
        f"paths={package['representative_paths']}"
    )


def _direct_subcomponent(
    package: dict[str, str],
    *,
    reason: str,
    strength: str,
) -> ProductJudgment:
    evidence = (
        f"Exact control/list/status: Source={package['source']}; "
        f"role={package['package_role']}; Description={package['description']}; "
        f"paths={package['representative_paths']}"
    )
    vendor = "Teltonika" if package["is_vendor_specific"] == "True" else "OpenWrt/upstream source"
    return ProductJudgment(
        classification="DIRECT_SUBCOMPONENT_NO_PARENT_INHERITANCE",
        product=_display_package(package["package"]),
        vendor=vendor,
        version=package["version"],
        product_reason=reason,
        product_evidence=evidence,
        version_reason="OBSERVED_COMPONENT_VERSION_PRESERVED_NO_PARENT_MAPPING",
        version_evidence="Exact installed control Version equals the SBOM version; no parent product version is inferred.",
        strength=strength,
    )


def _public_product_judgment(package: dict[str, str], spec: ProductSpec) -> ProductJudgment:
    return ProductJudgment(
        classification="PRODUCT_IDENTITY_CONFIRMED",
        product=spec.product,
        vendor=spec.vendor,
        version=spec.normalized_version,
        product_reason=(
            "The exact package description and installed core executable/library "
            "identify the named upstream product; package role was not used as a hard gate."
        ),
        product_evidence=(
            f"Source={package['source']}; Description={package['description']}; "
            f"paths={package['representative_paths']}; siblings={package['sibling_packages']}"
        ),
        version_reason="PRODUCT_SPECIFIC_UPSTREAM_VERSION_NORMALIZATION",
        version_evidence=(
            f"Observed {package['version']} was normalized to {spec.normalized_version} "
            "using the exact package/source structure and product-specific official release evidence."
        ),
        strength=spec.strength,
        family=spec.family,
        family_basis=spec.family_basis,
        cpe_version=spec.cpe_version,
        cpe_update=spec.cpe_update,
        prerelease_policy=spec.prerelease_policy,
    )


def _normalize_openwrt_version(package: dict[str, str]) -> tuple[str, str, str]:
    if package["package"] in OPENWRT_NORMALIZED_OVERRIDES:
        normalized = OPENWRT_NORMALIZED_OVERRIDES[package["package"]]
        return (
            normalized,
            "PRODUCT_SPECIFIC_PACKAGE_RELEASE_REMOVED",
            "Exact Source identity, official OpenWrt package-release policy, and the known project release establish the removed suffix.",
        )
    observed = package["version"]
    snapshot_match = re.fullmatch(
        r"(.+(?:\d{4}-\d{2}-\d{2}|[0-9a-f]{7,40}).*)-(\d+(?:\.\d+)?)",
        observed,
    )
    if snapshot_match and package["source_date_epoch"]:
        return (
            snapshot_match.group(1),
            "DATE_OR_GIT_SOURCE_VERSION",
            "Date/hash structure, SourceDateEpoch, and official OpenWrt PKG_RELEASE policy jointly identify only the final suffix as packaging metadata.",
        )
    return (
        observed,
        "EXACT_INSTALLED_PRODUCT_IDENTIFIER",
        "No suffix was removed; the exact installed Version is preserved as the product identifier.",
    )


def adjudicate_component(
    component: dict[str, str],
    package: dict[str, str] | None,
) -> ProductJudgment:
    name = component["name"]
    if package is None:
        if name in {"sed", "udhcp"}:
            return ProductJudgment(
                classification="DIRECT_SUBCOMPONENT_NO_PARENT_INHERITANCE",
                product=f"BusyBox {name} applet",
                vendor="BusyBox",
                version=component["version"],
                product_reason="The detector path resolves to the BusyBox multicall binary, not an independently owned sed/udhcp product.",
                product_evidence=component["properties_paths"],
                version_reason="BUNDLED_APPLET_VERSION_ONLY",
                version_evidence="The detector version is retained for provenance but is not mapped as a standalone product version.",
                strength="STRONG",
            )
        if name == "point-to-point_protocol":
            return ProductJudgment(
                classification="PRODUCT_IDENTITY_CONFIRMED",
                product="PPP/pppd",
                vendor="PPP project",
                version=component["version"],
                product_reason="Direct binary analysis identifies the Point-to-Point Protocol daemon product.",
                product_evidence=component["properties_paths"],
                version_reason="EXACT_BINARY_PRODUCT_VERSION",
                version_evidence="The detector reports PPP 2.4.9 directly from the exact firmware.",
                strength="STRONG",
                forced_human_reason="CPE_PRODUCT_FAMILY_AMBIGUITY",
            )
        spec = NON_OPKG_SPECS.get(name)
        if spec is None:
            return ProductJudgment(
                classification="UNRESOLVED",
                product="",
                vendor="",
                version="",
                product_reason="No reproducible non-opkg product rule exists.",
                product_evidence=component["properties_paths"],
                version_reason="UNRESOLVED",
                version_evidence="",
                strength="WEAK",
                forced_human_reason="SOFTWARE_IDENTITY_OR_VERSION_UNRESOLVED",
            )
        return ProductJudgment(
            classification="PRODUCT_IDENTITY_CONFIRMED",
            product=spec.product,
            vendor=spec.vendor,
            version=spec.normalized_version,
            product_reason="Direct exact-firmware detector/banner evidence identifies the product independently of SBOM CPE metadata.",
            product_evidence=component["properties_paths"],
            version_reason=(
                "PRERELEASE_STATE_MOVED_TO_CPE_UPDATE"
                if spec.prerelease_policy == "MOVE_TO_UPDATE"
                else "EXACT_BINARY_PRODUCT_VERSION"
                if name != "openwrt"
                else "FIRMWARE_RELEASE_VERSION_WITH_REVISION_SEPARATED"
            ),
            version_evidence=(
                f"Exact firmware evidence identifies {spec.product} "
                f"{spec.normalized_version}; approved prerelease policy preserves "
                f"the product version and represents the release state as "
                f"CPE version={spec.cpe_version}, update={spec.cpe_update}."
                if spec.prerelease_policy == "MOVE_TO_UPDATE"
                else f"Exact firmware evidence identifies {spec.product} {spec.normalized_version}."
            ),
            strength=spec.strength,
            family=spec.family,
            family_basis=spec.family_basis,
            cpe_version=spec.cpe_version,
            cpe_update=spec.cpe_update,
            prerelease_policy=spec.prerelease_policy,
        )

    role = package["package_role"]
    source = package["source"]
    if role == "KERNEL_OR_KMOD":
        return _direct_subcomponent(
            package,
            reason="Kernel package/module is a bounded kernel subcomponent; the Linux parent CPE is not inherited.",
            strength="STRONG",
        )
    if source.startswith("feeds/vuci/"):
        return _direct_subcomponent(
            package,
            reason="VuCI API/UI package is a feature module of the firmware interface, not an independently versioned parent product.",
            strength="MODERATE",
        )
    if role == "PLUGIN_OR_MODULE" and name not in INDEPENDENT_PLUGIN_PRODUCTS:
        return _direct_subcomponent(
            package,
            reason="Exact naming, description, and payload identify a plugin/module; its Source parent CPE is not inherited.",
            strength="STRONG",
        )
    if role in {"META_OR_HELPER_PACKAGE", "FIRMWARE_OR_DRIVER_ARTIFACT"}:
        return _direct_subcomponent(
            package,
            reason="Exact metadata identifies a meta/helper/data artifact rather than an independently mapped software product.",
            strength="MODERATE",
        )
    if name in DIRECT_SUBCOMPONENT_NAMES:
        return _direct_subcomponent(
            package,
            reason="Package payload is a configuration, split support, suite library, or optional subsystem; no parent CPE is inherited.",
            strength="MODERATE",
        )
    if name in UNRESOLVED_PRODUCT_NAMES:
        return ProductJudgment(
            classification="UNRESOLVED",
            product=_display_package(name),
            vendor="Teltonika/upstream" if package["is_vendor_specific"] == "True" else "upstream project",
            version="",
            product_reason="Exact payload identifies software, but the upstream product boundary cannot be fixed reproducibly.",
            product_evidence=(
                f"Source={source}; Description={package['description']}; "
                f"paths={package['representative_paths']}"
            ),
            version_reason="PRODUCT_VERSION_BOUNDARY_UNRESOLVED",
            version_evidence=f"Observed package identifier {package['version']} is retained but not promoted to an upstream product version.",
            strength="WEAK",
            forced_human_reason="PRODUCT_BOUNDARY_OR_VERSION_UNRESOLVED",
        )
    if name == "ppp":
        return ProductJudgment(
            classification="PRODUCT_IDENTITY_CONFIRMED",
            product="PPP/pppd",
            vendor="PPP project",
            version="2.4.9.git-2021-01-04",
            product_reason="The exact package description and canonical pppd payload identify the PPP daemon product.",
            product_evidence=(
                f"Source={source}; Description={package['description']}; "
                f"paths={package['representative_paths']}; siblings={package['sibling_packages']}"
            ),
            version_reason="PRODUCT_SPECIFIC_UPSTREAM_VERSION_NORMALIZATION",
            version_evidence=(
                "Official OpenWrt metadata and the exact Source identifier establish the "
                "2.4.9.git-2021-01-04 source snapshot; only the final package release is removed."
            ),
            strength="STRONG",
            forced_human_reason="CPE_PRODUCT_FAMILY_AMBIGUITY",
        )
    spec = PUBLIC_SPECS.get(name)
    if spec is not None:
        return _public_product_judgment(package, spec)
    if name == "luasocket":
        normalized, status, evidence = _normalize_openwrt_version(package)
        return ProductJudgment(
            classification="PRODUCT_IDENTITY_CONFIRMED",
            product="LuaSocket",
            vendor="LuaSocket project",
            version=normalized,
            product_reason="The exact Lua networking module is the independently distributed LuaSocket product.",
            product_evidence=f"Source={source}; Description={package['description']}; paths={package['representative_paths']}",
            version_reason=status,
            version_evidence=evidence,
            strength="MODERATE",
            family=("a", "luasocket_project", "luasocket"),
            family_basis="PROJECT_IDENTITY_TUPLE_NO_DICTIONARY_FAMILY",
        )
    if source.startswith("package/teltonika/"):
        product = TELTONIKA_GROUP_PRODUCTS.get(name, _display_package(name))
        opaque = bool(re.fullmatch(r"[0-9a-f]{7,12}", package["version"]))
        family = ("a", "teltonika", _slug(product))
        return ProductJudgment(
            classification="PRODUCT_IDENTITY_CONFIRMED",
            product=product,
            vendor="Teltonika",
            version=package["version"],
            product_reason="Exact vendor control, description, and installed payload establish this internal software product/library without inheriting another Source product.",
            product_evidence=(
                f"Source={source}; Description={package['description']}; "
                f"paths={package['representative_paths']}; siblings={package['sibling_packages']}"
            ),
            version_reason="VENDOR_PRODUCT_IDENTIFIER_PRESERVED",
            version_evidence="The complete exact installed vendor Version is preserved; no unproved package-release suffix is removed.",
            strength="WEAK" if opaque else "MODERATE",
            family=family,
            family_basis="EXACT_VENDOR_AND_PRODUCT_IDENTITY_TUPLE",
            forced_human_reason=("OPAQUE_VENDOR_VERSION_IDENTIFIER" if opaque else ""),
        )

    product_slug = OPENWRT_GROUP_PRODUCTS.get(name, name)
    normalized, version_reason, version_evidence = _normalize_openwrt_version(package)
    return ProductJudgment(
        classification="PRODUCT_IDENTITY_CONFIRMED",
        product=_display_package(product_slug),
        vendor="OpenWrt",
        version=normalized,
        product_reason="Exact control Source, description, and core executable/library payload establish the OpenWrt software product independently of CPE metadata.",
        product_evidence=(
            f"Source={source}; Description={package['description']}; "
            f"paths={package['representative_paths']}; siblings={package['sibling_packages']}"
        ),
        version_reason=version_reason,
        version_evidence=version_evidence,
        strength="MODERATE",
        family=("a", "openwrt", _slug(product_slug)),
        family_basis="EXACT_OPENWRT_PROJECT_AND_PRODUCT_IDENTITY_TUPLE",
    )


def _non_version_template(name: CPE23Name) -> tuple[str, ...]:
    return tuple(
        name.attribute(attribute).canonical
        for attribute in NON_VERSION_TEMPLATE_ATTRIBUTES
    )


PRERELEASE_UPDATE_TOKEN_RE = re.compile(
    r"^(?:pre|rc|beta|alpha|devel|snapshot)[0-9]*$",
    re.IGNORECASE,
)
PRERELEASE_REMAINDER_ATTRIBUTES = (
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


def resolve_prerelease_update_expression(
    active_cpes: list[str],
    *,
    family: tuple[str, str, str],
    version: str,
    update: str,
    expected_template_cpe: str | None = None,
) -> tuple[str | None, str]:
    """Apply MOVE_TO_UPDATE only when the Active family models release states there."""
    if PRERELEASE_UPDATE_TOKEN_RE.fullmatch(update) is None:
        return None, "INVALID_PRERELEASE_UPDATE_TOKEN"

    expected_name: CPE23Name | None = None
    if expected_template_cpe:
        parsed_expected = parse_cpe23(expected_template_cpe)
        if parsed_expected.name is None:
            return None, "INVALID_EXPECTED_PRERELEASE_TEMPLATE"
        expected_name = parsed_expected.name
        expected_identity = tuple(
            expected_name.attribute(attribute).canonical
            for attribute in ("part", "vendor", "product")
        )
        if (
            expected_identity != family
            or expected_name.attribute("version").canonical != version
            or expected_name.attribute("update").canonical != update
        ):
            return None, "EXPECTED_PRERELEASE_TEMPLATE_MISMATCH"

    supported_remainders: set[tuple[str, ...]] = set()
    for cpe in active_cpes:
        parsed = parse_cpe23(cpe)
        if parsed.name is None:
            continue
        family_update = parsed.name.attribute("update").canonical
        if PRERELEASE_UPDATE_TOKEN_RE.fullmatch(family_update) is None:
            continue
        supported_remainders.add(
            tuple(
                parsed.name.attribute(attribute).canonical
                for attribute in PRERELEASE_REMAINDER_ATTRIBUTES
            )
        )

    if expected_name is not None:
        remainder = tuple(
            expected_name.attribute(attribute).canonical
            for attribute in PRERELEASE_REMAINDER_ATTRIBUTES
        )
        if remainder not in supported_remainders:
            return None, "PRERELEASE_TEMPLATE_NOT_SUPPORTED"
        canonical = canonicalize_cpe23(expected_template_cpe or "")
        return canonical, "UNIQUE_SUPPORTED_PRERELEASE_TEMPLATE"

    if len(supported_remainders) != 1:
        status = (
            "PRERELEASE_TEMPLATE_NOT_SUPPORTED"
            if not supported_remainders
            else "MULTIPLE_PRERELEASE_TEMPLATES"
        )
        return None, status
    remainder = next(iter(supported_remainders))
    raw = "cpe:2.3:" + ":".join((*family, version, update, *remainder))
    canonical = canonicalize_cpe23(raw)
    if canonical is None:
        return None, "INVALID_GENERATED_PRERELEASE_EXPRESSION"
    return canonical, "UNIQUE_SUPPORTED_PRERELEASE_TEMPLATE"


def _replacement_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    result: list[str] = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            identifier = item.get("cpeNameId") or item.get("cpeNameID")
            if identifier:
                result.append(str(identifier))
    return tuple(result)


class CandidateCpeResolver:
    def __init__(
        self,
        cpe_snapshot: CpeDictionarySnapshot,
        nvd_snapshot: NvdCveSnapshot,
        families: set[tuple[str, str, str]],
    ) -> None:
        self.cpe_snapshot = cpe_snapshot
        self.nvd_snapshot = nvd_snapshot
        self.deprecated_rows: list[dict[str, str]] = []
        self.configuration_rows: list[dict[str, str]] = []
        products = {family[2] for family in families} | {"ppp"}
        models = list(
            CpeName.objects.filter(
                snapshot=cpe_snapshot,
                product__in=products,
            )
        )
        self.cpe_cache: defaultdict[
            tuple[str, str, str], list[CpeName]
        ] = defaultdict(list)
        for model in models:
            self.cpe_cache[(model.part, model.vendor, model.product)].append(model)
        missing_families = {
            family for family in families if not self.cpe_cache[family]
        }
        self.configuration_cache = self._load_configurations(missing_families)

    def _load_configurations(
        self,
        families: set[tuple[str, str, str]],
    ) -> defaultdict[tuple[str, str, str], list[dict[str, Any]]]:
        cache: defaultdict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        if not families:
            return cache
        grouped: defaultdict[tuple[str, str], set[tuple[str, str, str]]] = defaultdict(set)
        for family in families:
            grouped[(family[0], family[1])].add(family)
        predicates: list[Q] = []
        for (part, vendor), vendor_families in grouped.items():
            if len(vendor_families) >= 3:
                predicates.append(Q(criteria__startswith=f"cpe:2.3:{part}:{vendor}:"))
            else:
                predicates.extend(
                    Q(criteria__startswith="cpe:2.3:" + ":".join(family) + ":")
                    for family in vendor_families
                )
        rows = NvdCpeMatch.objects.filter(
            reduce(or_, predicates),
            cve_record__snapshot=self.nvd_snapshot,
        ).values(
            "criteria",
            "match_criteria_id",
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
            "cve_record__cve_id",
        )
        for match in rows.iterator(chunk_size=5000):
            parsed = parse_cpe23(match["criteria"])
            if parsed.name is None:
                continue
            family = tuple(
                parsed.name.attribute(attribute).canonical
                for attribute in ("part", "vendor", "product")
            )
            if family in families:
                cache[family].append(match)
        return cache

    def map_row(
        self,
        row: dict[str, str],
        *,
        family: tuple[str, str, str],
        version: str,
        expected_template_cpe: str | None,
        prerelease_update: str | None = None,
    ) -> None:
        expected_name: CPE23Name | None = None
        if expected_template_cpe:
            parsed = parse_cpe23(expected_template_cpe)
            if parsed.name is None:
                raise UnitronicsCandidateBuildError(
                    f"Invalid expected CPE template: {expected_template_cpe}"
                )
            expected_name = parsed.name
        family_models = self.cpe_cache[family]
        active = [model for model in family_models if not model.deprecated]
        deprecated = [model for model in family_models if model.deprecated]
        row["cpe_family"] = ":".join(family)
        exact_active = [
            model.cpe_name
            for model in active
            if model.version == version
        ]
        if expected_name is not None:
            expected_template = _non_version_template(expected_name)
            exact_active = [
                cpe
                for cpe in exact_active
                if parse_cpe23(cpe).name is not None
                and _non_version_template(parse_cpe23(cpe).name)
                == expected_template
            ]
        if len(exact_active) == 1:
            row["active_exact_match"] = exact_active[0]
            self._finish_with_cpe(row, exact_active[0], "ACTIVE_EXACT")
            return
        if len(exact_active) > 1:
            self._unresolved(row, "MULTIPLE_COMPATIBLE_ACTIVE_EXACT_CPE")
            return
        deprecated_exact = [model for model in deprecated if model.version == version]
        if deprecated_exact:
            row["deprecated_match"] = _json(
                [model.cpe_name for model in deprecated_exact]
            )
            self._resolve_deprecated(row, deprecated_exact, expected_name)
            return
        if active:
            if prerelease_update is not None:
                generated, status = resolve_prerelease_update_expression(
                    [model.cpe_name for model in active],
                    family=family,
                    version=version,
                    update=prerelease_update,
                    expected_template_cpe=expected_template_cpe,
                )
                if generated is None:
                    self._unresolved(row, status)
                    return
                self._finish_with_cpe(
                    row,
                    generated,
                    "VERSION_NOT_IN_DICTIONARY",
                )
                row["proposed_decision"] = "VERSION_NOT_IN_DICTIONARY"
                row["decision_reason"] = "ACTIVE_FAMILY_EXACT_PRERELEASE_ABSENT"
                return
            compatibility = None
            if expected_name is not None:
                expected_template = _non_version_template(expected_name)
                compatibility = lambda name: _non_version_template(name) == expected_template
            template = resolve_stable_template(
                [model.cpe_name for model in active],
                family=family,
                normalized_version=version,
                compatibility=compatibility,
            )
            if template.status is StableTemplateStatus.UNIQUE_STABLE_TEMPLATE:
                self._finish_with_cpe(
                    row,
                    template.generated_cpe or "",
                    "VERSION_NOT_IN_DICTIONARY",
                )
                row["proposed_decision"] = "VERSION_NOT_IN_DICTIONARY"
                row["decision_reason"] = "ACTIVE_FAMILY_EXACT_VERSION_ABSENT"
            else:
                self._unresolved(row, f"STABLE_TEMPLATE_{template.status.value}")
            return
        if deprecated:
            row["deprecated_match"] = f"FAMILY_CONTEXT:{len(deprecated)}"
            self._unresolved(
                row,
                "DEPRECATED_FAMILY_WITHOUT_EXACT_VERSION_OR_UNIQUE_ACTIVE_ALIAS",
            )
            return
        row["configuration_gate_passed"] = "true"
        self._configuration_or_no_direct(row, family, version)

    def _resolve_deprecated(
        self,
        row: dict[str, str],
        candidates: list[CpeName],
        expected_name: CPE23Name | None,
    ) -> None:
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
            valid_targets: list[UUID] = []
            for target in targets:
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
                name.attribute(attribute).canonical == expected_fields[attribute]
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
        for result in results:
            self.deprecated_rows.append(
                {
                    "component_id": row["component_id"],
                    "name": row["name"],
                    "deprecated_cpes": _json([candidate.cpe_name for candidate in candidates]),
                    "replacement_count": str(result.replacement_count),
                    "replacement_depth": str(result.replacement_depth),
                    "replacement_chain": _json(result.replacement_chains),
                    "active_endpoints": _json(result.compatible_active_endpoints),
                    "resolved_active_cpe": result.resolved_active_endpoint or "",
                    "resolution_status": result.resolution_status.value,
                    "human_validation_required": _bool(result.review_required),
                    "notes": result.review_reason,
                }
            )
        if len(endpoints) == 1 and all(
            result.resolution_status is DeprecatedResolutionStatus.RESOLVED_ACTIVE
            for result in results
        ):
            row["deprecated_resolution"] = "RESOLVED_ACTIVE"
            row["resolved_active_cpe"] = endpoints[0]
            self._finish_with_cpe(row, endpoints[0], "DEPRECATED_TO_ACTIVE")
        else:
            self._unresolved(row, "DEPRECATED_RESOLUTION_NOT_UNIQUE")

    def _configuration_or_no_direct(
        self,
        row: dict[str, str],
        family: tuple[str, str, str],
        version: str,
    ) -> None:
        matches = self.configuration_cache[family]
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
                    notes="Gate passed; fixed NVD snapshot contains no criteria for the verified tuple.",
                )
            )
            row["cpe_resolution_path"] = "NO_DIRECT_CPE"
            row["proposed_decision"] = "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
            row["decision_reason"] = "NO_CPE_REPRESENTATION"
            return
        template = resolve_stable_template(
            [match["criteria"] for match in matches],
            family=family,
            normalized_version=version,
        )
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
                notes="Product-expression existence only; version-range applicability was not evaluated.",
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
            row["configuration_criteria"] = _json(sorted(grouped))
            self._finish_with_cpe(
                row,
                template.generated_cpe or "",
                "NVD_CONFIGURATION_ONLY",
            )
            row["proposed_decision"] = "NVD_CONFIGURATION_ONLY"
            row["decision_reason"] = "CONFIGURATION_PRODUCT_EXPRESSION_ONLY"
        else:
            self._unresolved(row, f"CONFIGURATION_TEMPLATE_{template.status.value}")

    @staticmethod
    def _configuration_row(
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
            "human_validation_required": _bool(
                stable_status == StableTemplateStatus.MULTIPLE_COMPATIBLE_TEMPLATES.value
            ),
            "notes": notes,
        }

    @staticmethod
    def _finish_with_cpe(row: dict[str, str], cpe: str, path: str) -> None:
        canonical = canonicalize_cpe23(cpe)
        if canonical is None:
            raise UnitronicsCandidateBuildError(f"Generated invalid CPE: {cpe}")
        row["cpe_resolution_path"] = path
        row["proposed_gt_cpe"] = canonical
        if path == "VERSION_NOT_IN_DICTIONARY":
            row["proposed_decision"] = "VERSION_NOT_IN_DICTIONARY"
        elif path == "NVD_CONFIGURATION_ONLY":
            row["proposed_decision"] = "NVD_CONFIGURATION_ONLY"
        else:
            row["proposed_decision"] = (
                "CPE_CONFIRMED"
                if compare_cpe23(row["original_cpe"], canonical)
                else "OFFICIAL_CPE_MAPPED"
            )
        row["decision_reason"] = path
        row["discrepancy_fields"] = _json(
            [
                difference.upper()
                for difference in compare_cpe23_attributes(
                    row["original_cpe"], canonical
                )
            ]
        )

    @staticmethod
    def _unresolved(row: dict[str, str], reason: str) -> None:
        row["cpe_resolution_path"] = "UNRESOLVED"
        row["proposed_gt_cpe"] = ""
        row["proposed_decision"] = "UNRESOLVED"
        row["decision_reason"] = reason
        row["discrepancy_fields"] = "N/A"


def _blank_output_row(
    component: dict[str, str],
    package: dict[str, str] | None,
    judgment: ProductJudgment,
) -> dict[str, str]:
    row = {field: "" for field in COMPONENT_FIELDS}
    row.update(
        {
            "component_id": component["component_id"],
            "name": component["name"],
            "observed_version": component["version"],
            "original_cpe": component["original_cpe"],
            "source": package["source"] if package else "NON_OPKG_DIRECT_ARTIFACT",
            "source_name": package["source_name"] if package else component["name"],
            "description": package["description"] if package else component["matching_evidence"],
            "payload_summary": _payload_summary(package, component),
            "actual_product": judgment.product,
            "actual_vendor": judgment.vendor,
            "actual_product_version": judgment.version,
            "product_classification": judgment.classification,
            "product_reason": judgment.product_reason,
            "product_evidence": judgment.product_evidence,
            "version_reason": judgment.version_reason,
            "version_evidence": judgment.version_evidence,
            "cpe_family": ":".join(judgment.family) if judgment.family else "",
            "cpe_family_binding_basis": judgment.family_basis,
            "active_exact_match": "",
            "deprecated_match": "",
            "deprecated_resolution": "NOT_ENCOUNTERED",
            "configuration_gate_passed": "false",
            "configuration_only_match": "false",
            "discrepancy_fields": "N/A",
            "evidence_strength": judgment.strength,
            "human_validation_required": "false",
            "exact_firmware_evidence": (
                f"control={package['control_path']}; list={package['list_path']}; status_version_matches={package['status_version_matches']}"
                if package
                else component["properties_paths"]
            ),
        }
    )
    return row


def build_unitronics_candidate_build(
    *,
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
) -> CandidateBuildAnalysis:
    root = settings.REPOSITORY_ROOT / EVIDENCE_ROOT
    component_source_rows = _read_csv(root / LOCAL_EVIDENCE_FILES[0])
    package_rows = _read_csv(root / LOCAL_EVIDENCE_FILES[1])
    version_rows = _read_csv(root / LOCAL_EVIDENCE_FILES[6])
    mapping_rows = _read_csv(root / LOCAL_EVIDENCE_FILES[8])
    packages_by_id = {row["component_id"]: row for row in package_rows}
    components_by_id = {row["component_id"]: row for row in component_source_rows}

    sbom = SBOMDocument.objects.get(pk=SBOM_ID)
    if (
        sbom.file_sha256 != SBOM_SHA256
        or sbom.manufacturer != "Unitronics"
        or sbom.product_name != "UCR-ST-B8"
        or sbom.product_version != "52.07.13.7"
    ):
        raise UnitronicsCandidateBuildError("SBOM identity does not match fixed scope")
    database_component_ids = {
        str(component.id)
        for component in Component.objects.filter(sbom_document=sbom)
    }
    if len(components_by_id) != 582 or database_component_ids != components_by_id.keys():
        raise UnitronicsCandidateBuildError("Exact 582-component set mismatch")
    if len(packages_by_id) != 575 or len({row["source"] for row in package_rows}) != 303:
        raise UnitronicsCandidateBuildError("Expected 575 packages and 303 Source values")
    if cpe_snapshot.snapshot_id != CPE_SNAPSHOT_ID or nvd_snapshot.snapshot_id != NVD_SNAPSHOT_ID:
        raise UnitronicsCandidateBuildError("Wrong fixed snapshot")

    judgments = {
        component_id: adjudicate_component(
            component,
            packages_by_id.get(component_id),
        )
        for component_id, component in components_by_id.items()
    }
    families = {
        judgment.family
        for judgment in judgments.values()
        if judgment.family is not None
    }
    resolver = CandidateCpeResolver(cpe_snapshot, nvd_snapshot, families)
    expected_templates = {
        row["component_id"]: row["proposed_gt_cpe"]
        for row in mapping_rows
        if row["proposed_gt_cpe"]
    }
    fixed_normalizations = {
        row["component_id"]: row["normalized_product_version"]
        for row in version_rows
        if row["normalized_product_version"]
    }

    component_rows: list[dict[str, str]] = []
    for component_id, component in components_by_id.items():
        package = packages_by_id.get(component_id)
        judgment = judgments[component_id]
        if component_id in fixed_normalizations and judgment.classification == "PRODUCT_IDENTITY_CONFIRMED":
            if judgment.version != fixed_normalizations[component_id]:
                raise UnitronicsCandidateBuildError(
                    f"Normalization contradicts fixed evidence for {component_id}"
                )
        row = _blank_output_row(component, package, judgment)
        if judgment.classification == "DIRECT_SUBCOMPONENT_NO_PARENT_INHERITANCE":
            row["cpe_resolution_path"] = "NO_DIRECT_CPE"
            row["proposed_decision"] = "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
            row["decision_reason"] = "NON_DIRECT_SUBCOMPONENT"
        elif judgment.classification == "UNRESOLVED" or not judgment.version:
            row["cpe_resolution_path"] = "UNRESOLVED"
            row["proposed_decision"] = "UNRESOLVED"
            row["decision_reason"] = "PRODUCT_BOUNDARY_OR_VERSION_UNRESOLVED"
        elif judgment.product == "PPP/pppd":
            candidates = sorted(
                {
                    (model.part, model.vendor, model.product)
                    for model in resolver.cpe_cache[("a", "canonical", "ppp")]
                    + resolver.cpe_cache[("a", "samba", "ppp")]
                }
            )
            row["cpe_family"] = _json(candidates)
            row["cpe_family_binding_basis"] = "MULTIPLE_SEMANTICALLY_POSSIBLE_FAMILIES"
            row["cpe_resolution_path"] = "NO_DIRECT_CPE"
            row["proposed_decision"] = "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
            row["decision_reason"] = "CPE_PRODUCT_FAMILY_AMBIGUITY"
        elif judgment.family is None:
            row["cpe_resolution_path"] = "NO_DIRECT_CPE"
            row["proposed_decision"] = "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
            row["decision_reason"] = "NO_VERIFIED_CPE_FAMILY_BINDING"
        else:
            cpe_version = judgment.cpe_version or judgment.version
            approved_prerelease_template = (
                EXPECTED_FAMILY_TEMPLATES.get((judgment.family, cpe_version))
                if judgment.prerelease_policy == "MOVE_TO_UPDATE"
                else None
            )
            resolver.map_row(
                row,
                family=judgment.family,
                version=cpe_version,
                expected_template_cpe=(
                    approved_prerelease_template
                    or expected_templates.get(component_id)
                    or EXPECTED_FAMILY_TEMPLATES.get(
                        (judgment.family, cpe_version)
                    )
                ),
                prerelease_update=(
                    judgment.cpe_update
                    if judgment.prerelease_policy == "MOVE_TO_UPDATE"
                    else None
                ),
            )
        component_rows.append(row)

    rows_by_id = {row["component_id"]: row for row in component_rows}
    for component_id, judgment in judgments.items():
        row = rows_by_id[component_id]
        reasons: list[str] = []
        if row["proposed_gt_cpe"]:
            reasons.append("PROPOSED_GT_CPE_CONFIRMATION")
        if row["proposed_decision"] == "UNRESOLVED":
            reasons.append("UNRESOLVED")
        if row["evidence_strength"] == "WEAK":
            reasons.append("WEAK_EVIDENCE")
        if judgment.forced_human_reason:
            reasons.append(judgment.forced_human_reason)
        if (
            judgment.classification == "PRODUCT_IDENTITY_CONFIRMED"
            and row["proposed_decision"] == "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
        ):
            reasons.append("PRODUCT_WITHOUT_CONFIRMED_DIRECT_CPE")
        row["human_validation_required"] = _bool(bool(reasons))
        row["human_validation_reason"] = " | ".join(dict.fromkeys(reasons))

    component_rows.sort(key=lambda row: int(row["component_id"]))
    human_rows = [row for row in component_rows if row["human_validation_required"] == "true"]
    unresolved_rows = [row for row in component_rows if row["proposed_decision"] == "UNRESOLVED"]
    proposed_cpes = [row["proposed_gt_cpe"] for row in component_rows if row["proposed_gt_cpe"]]
    parser_failures = [cpe for cpe in proposed_cpes if parse_cpe23(cpe).name is None]
    deprecated_final = list(
        CpeName.objects.filter(
            snapshot=cpe_snapshot,
            deprecated=True,
            cpe_name__in=proposed_cpes,
        ).values_list("cpe_name", flat=True)
    )
    config_gate_violations = [
        row
        for row in resolver.configuration_rows
        if row["dictionary_active_tuple_count"] != "0"
        or row["dictionary_deprecated_tuple_count"] != "0"
        or row["configuration_gate_passed"] != "true"
    ]

    hashes = evidence_hashes()
    manifest_rows = [
        {
            "evidence_id": f"LOCAL-{index:02d}",
            "evidence_type": "LOCAL_IMMUTABLE_ARTIFACT",
            "locator": relative,
            "sha256": digest,
            "accessed_at": "",
            "use": "Exact firmware linkage, product boundary, version rule, or CPE boundary evidence",
        }
        for index, (relative, digest) in enumerate(hashes.items(), start=1)
    ]
    manifest_rows.extend(
        {
            "evidence_id": evidence_id,
            "evidence_type": "OFFICIAL_UPSTREAM_URL",
            "locator": url,
            "sha256": "",
            "accessed_at": "2026-08-23",
            "use": note,
        }
        for evidence_id, url, note in OFFICIAL_EVIDENCE
    )

    product_counter = Counter(row["product_classification"] for row in component_rows)
    decision_counter = Counter(row["proposed_decision"] for row in component_rows)
    resolution_counter = Counter(row["cpe_resolution_path"] for row in component_rows)
    strength_counter = Counter(row["evidence_strength"] for row in component_rows)
    human_strength_counter = Counter(row["evidence_strength"] for row in human_rows)
    product_counts = {
        classification: product_counter[classification]
        for classification in PRODUCT_CLASSIFICATIONS
    }
    decision_counts = {
        decision: decision_counter[decision]
        for decision in DECISION_CODES
    }
    resolution_counts = {
        path: resolution_counter[path]
        for path in CPE_RESOLUTION_PATHS
    }
    strength_counts = {
        strength: strength_counter[strength]
        for strength in EVIDENCE_STRENGTHS
    }
    human_strength_counts = {
        strength: human_strength_counter[strength]
        for strength in EVIDENCE_STRENGTHS
    }
    original_different_count = sum(
        bool(row["proposed_gt_cpe"])
        and row["proposed_decision"] != "CPE_CONFIRMED"
        for row in component_rows
    )
    summary = {
        "schema_version": 1,
        "analysis_scope": "First-pass 582-component Ground Truth candidate build; read-only and not final GT",
        "dataset": {
            "sbom_document_id": SBOM_ID,
            "manufacturer": sbom.manufacturer,
            "product": sbom.product_name,
            "firmware_version": sbom.product_version,
            "firmware_sha256": FIRMWARE_SHA256,
            "sbom_sha256": SBOM_SHA256,
            "component_count": len(component_rows),
            "opkg_count": len(packages_by_id),
            "non_opkg_count": len(component_rows) - len(packages_by_id),
            "distinct_source_count": len({row["source"] for row in package_rows}),
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
        "product_classification": {"counts": product_counts},
        "decisions": {"counts": decision_counts},
        "cpe_resolution": {"counts": resolution_counts},
        "ground_truth_candidates": {
            "count": len(proposed_cpes),
            "original_different_count": original_different_count,
            "original_same_count": decision_counts["CPE_CONFIRMED"],
        },
        "evidence_strength": {"counts": strength_counts},
        "human_validation": {
            "count": len(human_rows),
            "strength_counts": human_strength_counts,
            "cpe_mapped_count": sum(bool(row["proposed_gt_cpe"]) for row in human_rows),
            "unresolved_count": sum(row["proposed_decision"] == "UNRESOLVED" for row in human_rows),
            "reason_counts": dict(
                sorted(
                    Counter(
                        reason
                        for row in human_rows
                        for reason in row["human_validation_reason"].split(" | ")
                    ).items()
                )
            ),
        },
        "deprecated": {
            "encounter_count": len(resolver.deprecated_rows),
            "resolved_to_active_count": sum(
                row["resolution_status"] == DeprecatedResolutionStatus.RESOLVED_ACTIVE.value
                for row in resolver.deprecated_rows
            ),
            "final_deprecated_gt_count": len(deprecated_final),
        },
        "configuration_only": {
            "gate_entry_component_count": len({row["component_id"] for row in resolver.configuration_rows}),
            "product_found_component_count": len(
                {
                    row["component_id"]
                    for row in resolver.configuration_rows
                    if row["configuration_match"] == "true"
                }
            ),
            "gt_expression_count": resolution_counts["NVD_CONFIGURATION_ONLY"],
            "gate_violation_count": len(config_gate_violations),
        },
        "guardrails": {
            "database_transaction_read_only": True,
            "original_cpe_candidate_evidence_uses": 0,
            "control_cpe_id_candidate_evidence_uses": 0,
            "live_nvd_api_calls": 0,
            "live_cpe_dictionary_calls": 0,
            "cve_applicability_evaluations": 0,
            "ground_truth_mutations": 0,
            "component_mutations": 0,
            "migration_count": 0,
            "production_hook_added": False,
        },
        "validation": {
            "component_rows": len(component_rows),
            "component_rows_equal_582": len(component_rows) == 582,
            "opkg_plus_non_opkg": f"{len(packages_by_id)} + {len(component_rows) - len(packages_by_id)} = {len(component_rows)}",
            "decision_partition": sum(decision_counts.values()),
            "every_component_has_decision": all(row["proposed_decision"] for row in component_rows),
            "every_component_has_valid_decision": all(
                row["proposed_decision"] in DECISION_CODES
                for row in component_rows
            ),
            "proposed_gt_count": len(proposed_cpes),
            "proposed_gt_parser_failure_count": len(parser_failures),
            "deprecated_final_gt_count": len(deprecated_final),
            "configuration_gate_violation_count": len(config_gate_violations),
            "ground_truth_count_before": ComponentCpeGroundTruth.objects.count(),
            "ground_truth_count_after": None,
            "ground_truth_count_unchanged": None,
            "evidence_hashes_unchanged": None,
        },
        "new_ambiguity_types": [
            {
                "type": "MULTI_PRODUCT_BINARY_BOUNDARY",
                "examples": ["wpad-openssl"],
                "effect": "One package combines hostapd and wpa_supplicant roles; no single product CPE was selected.",
            },
            {
                "type": "UPSTREAM_VERSION_HIDDEN_BY_VENDOR_IDENTIFIER",
                "examples": ["libmodbus", "shellinabox"],
                "effect": "Exact installed Version does not reproducibly establish the public upstream release.",
            },
            {
                "type": "CPE_PRODUCT_FAMILY_AMBIGUITY",
                "examples": ["ppp", "point-to-point_protocol"],
                "effect": "canonical:ppp and samba:ppp remain semantically possible without using control/original CPE as truth.",
            },
            {
                "type": "OPAQUE_VENDOR_REVISION",
                "examples": ["gsmctl", "gsmd", "mobifd"],
                "effect": "Short vendor hashes are preserved and require human provenance confirmation.",
            },
        ],
        "method_limitations": [
            "The exact matching SDK/GPL Makefiles are unavailable, so non-representative package-release decompositions remain product-specific rather than globally inferred.",
            "Teltonika internal product names and complete installed Version strings are reproducible, but public release/tag semantics are often unavailable.",
            "A first-pass CPE family binding without a Dictionary hit remains a human-validation item; absence is not treated as proof of semantic correctness.",
            "This candidate set is not final Ground Truth and has not been persisted.",
        ],
    }
    return CandidateBuildAnalysis(
        component_rows=component_rows,
        human_validation_rows=human_rows,
        unresolved_rows=unresolved_rows,
        deprecated_rows=resolver.deprecated_rows,
        configuration_rows=resolver.configuration_rows,
        evidence_manifest_rows=manifest_rows,
        evidence_hashes=hashes,
        summary=summary,
    )


def finalize_validation(
    analysis: CandidateBuildAnalysis,
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
            "every_component_has_decision",
            "every_component_has_valid_decision",
            "ground_truth_count_unchanged",
            "evidence_hashes_unchanged",
        )
        if not validation[key]
    ]
    if validation["decision_partition"] != 582:
        failures.append("decision_partition")
    if validation["proposed_gt_parser_failure_count"]:
        failures.append("proposed_gt_parser_failure_count")
    if validation["deprecated_final_gt_count"]:
        failures.append("deprecated_final_gt_count")
    if validation["configuration_gate_violation_count"]:
        failures.append("configuration_gate_violation_count")
    if failures:
        raise UnitronicsCandidateBuildError(
            "Candidate-build consistency failures: " + ", ".join(failures)
        )


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_unitronics_candidate_build(
    analysis: CandidateBuildAnalysis,
    output_directory: Path,
) -> list[Path]:
    output_directory.mkdir(parents=True, exist_ok=False)
    paths = [
        output_directory / "report.md",
        output_directory / "components.csv",
        output_directory / "human_validation.csv",
        output_directory / "unresolved.csv",
        output_directory / "deprecated_resolution.csv",
        output_directory / "configuration_only_cases.csv",
        output_directory / "summary.json",
        output_directory / "evidence_manifest.csv",
    ]
    _write_csv(paths[1], COMPONENT_FIELDS, analysis.component_rows)
    _write_csv(paths[2], COMPONENT_FIELDS, analysis.human_validation_rows)
    _write_csv(paths[3], COMPONENT_FIELDS, analysis.unresolved_rows)
    _write_csv(paths[4], DEPRECATED_FIELDS, analysis.deprecated_rows)
    _write_csv(paths[5], CONFIGURATION_FIELDS, analysis.configuration_rows)
    paths[6].write_text(
        json.dumps(analysis.summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_csv(paths[7], EVIDENCE_MANIFEST_FIELDS, analysis.evidence_manifest_rows)
    paths[0].write_text(_render_report(analysis.summary), encoding="utf-8")
    return paths


def _table_rows(counts: dict[str, int], denominator: int = 582) -> str:
    return "\n".join(
        f"| `{name}` | {count:,} | {count / denominator * 100:.2f}% |"
        for name, count in counts.items()
    )


def _render_report(summary: dict[str, Any]) -> str:
    products = summary["product_classification"]["counts"]
    decisions = summary["decisions"]["counts"]
    resolution = summary["cpe_resolution"]["counts"]
    human = summary["human_validation"]
    validation = summary["validation"]
    gt = summary["ground_truth_candidates"]
    ambiguities = "\n".join(
        f"- `{item['type']}`: {item['effect']} Examples: {', '.join(item['examples'])}."
        for item in summary["new_ambiguity_types"]
    )
    limitations = "\n".join(
        f"- {item}" for item in summary["method_limitations"]
    )
    return f"""# Unitronics Ground Truth CPE candidate build

## Scope

- SBOMDocument: `1364`
- Firmware: Unitronics UCR-ST-B8 `52.07.13.7`
- Components: 582 (`575 opkg + 7 non-opkg`; 303 distinct `Source` values)
- CPE Dictionary: `{CPE_SNAPSHOT_ID}`
- NVD CVE/Configuration: `{NVD_SNAPSHOT_ID}`

This is a first-pass candidate build, not final or persisted Ground Truth.
Original CPE and control `CPE-ID` were excluded from product/version/CPE
candidate selection and used only for the final Original-versus-GT comparison.

## Product adjudication

| Classification | Count | Percent |
|---|---:|---:|
{_table_rows(products)}

The previous runtime status was not a hard gate. Exact control/list/status,
payload, sibling structure, prior rulebook evidence, and product-specific
official evidence were re-applied to every row. Clear kernel modules, VuCI
feature modules, plugins, helpers, and suite-only children were adjudicated as
direct subcomponents instead of being sent to a generic missing-registry queue.

## Decision distribution

| Decision | Count | Percent |
|---|---:|---:|
{_table_rows(decisions)}

Every component has one of the six existing internal Decisions.

## CPE resolution

| Resolution path | Count | Percent |
|---|---:|---:|
{_table_rows(resolution)}

- Proposed GT CPE/expression: **{gt['count']}**
- Original equals GT: **{gt['original_same_count']}**
- Original differs from GT: **{gt['original_different_count']}**
- Deprecated final GT: **{summary['deprecated']['final_deprecated_gt_count']}**
- Configuration gate violations: **{summary['configuration_only']['gate_violation_count']}**

## Human validation

- Total: **{human['count']}**
- Strength: `{_json(human['strength_counts'])}`
- CPE-mapped candidates: **{human['cpe_mapped_count']}**
- Unresolved candidates: **{human['unresolved_count']}**
- Reasons: `{_json(human['reason_counts'])}`

The list is focused on proposed CPEs, unresolved rows, weak evidence, CPE-family
ambiguity, and confirmed products for which no direct CPE was found. Clear
direct subcomponents are not automatically sent back for 582-row re-review.

## Newly observed ambiguity types

{ambiguities}

## Reproducibility limitations before Methods freeze

{limitations}

## Validation

- Component rows: {validation['component_rows']} — PASS
- opkg + non-opkg: `{validation['opkg_plus_non_opkg']}` — PASS
- Decision partition: {validation['decision_partition']} — PASS
- Every row has a Decision: {validation['every_component_has_decision']} — PASS
- Every Decision uses the fixed six-code taxonomy: {validation['every_component_has_valid_decision']} — PASS
- Proposed GT canonical parse failures: {validation['proposed_gt_parser_failure_count']} — PASS
- Deprecated final GT: {validation['deprecated_final_gt_count']} — PASS
- Configuration gate violations: {validation['configuration_gate_violation_count']} — PASS
- Ground Truth DB count: `{validation['ground_truth_count_before']} -> {validation['ground_truth_count_after']}` — PASS
- Existing local evidence hashes unchanged: {validation['evidence_hashes_unchanged']} — PASS

No Ground Truth, Component, CPE/NVD snapshot, migration, production hook, CVE
applicability, or final RQ1 state was created or modified.
"""

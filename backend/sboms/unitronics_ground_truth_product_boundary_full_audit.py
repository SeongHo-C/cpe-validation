from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from django.conf import settings
from django.db.models import Count, Q, TextField
from django.db.models.functions import Cast

from cpe.cpe23_canonical import canonicalize_cpe23, parse_cpe23
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from nvd_cve.models import NvdCpeMatch, NvdCveSnapshot
from sboms.models import Component, ComponentCpeGroundTruth


DATASET_KEY = "61602e128acb__52.07.13.7"
SBOM_DOCUMENT_ID = 1364
CPE_SNAPSHOT_ID = "20260819T035002Z"
NVD_SNAPSHOT_ID = "20260820T110357Z"
EXPECTED_COMPONENT_COUNT = 582
EXPECTED_CPE_BEARING_COUNT = 40
EXPECTED_CURRENT_DECISIONS = {
    "CPE_CONFIRMED": 2,
    "OFFICIAL_CPE_MAPPED": 21,
    "VERSION_NOT_IN_DICTIONARY": 17,
    "NVD_CONFIGURATION_ONLY": 0,
    "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED": 537,
    "UNRESOLVED": 5,
}
FINAL_CPE_BEARING_COUNT = 39
FINAL_CURRENT_DECISIONS = {
    "CPE_CONFIRMED": 2,
    "OFFICIAL_CPE_MAPPED": 21,
    "VERSION_NOT_IN_DICTIONARY": 16,
    "NVD_CONFIGURATION_ONLY": 0,
    "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED": 538,
    "UNRESOLVED": 5,
}

OUTPUT_RELATIVE = Path(
    "analysis/results/unitronics-ground-truth-product-boundary-full-audit/"
    f"{DATASET_KEY}"
)
RESULTS_ROOT = Path("analysis/results")
PACKAGE_RELATIVE = Path(
    "unitronics-source-package-analysis/"
    f"{DATASET_KEY}/packages.csv"
)
PREANALYSIS_RELATIVE = Path(
    "unitronics-ground-truth-preanalysis/"
    f"{DATASET_KEY}/components.csv"
)
PROTECTED_ARTIFACT_DIRECTORIES = (
    Path("unitronics-ground-truth-candidate-build") / DATASET_KEY,
    Path("unitronics-ground-truth-cpe-audit") / DATASET_KEY,
    Path("unitronics-ground-truth-duplicate-cpe-audit") / DATASET_KEY,
    Path("unitronics-ground-truth-representative-finalization") / DATASET_KEY,
    Path("unitronics-openssl-representative-audit") / DATASET_KEY,
    Path("unitronics-wireguard-product-boundary-audit") / DATASET_KEY,
)

AUDIT_FIELDS = (
    "component_id",
    "name",
    "observed_version",
    "audited_actual_vendor",
    "audited_actual_product",
    "audited_actual_version",
    "exact_firmware_evidence",
    "official_upstream_evidence",
    "official_product_boundary",
    "current_gt_cpe",
    "current_validation_result",
    "cpe_family_part",
    "cpe_family_vendor",
    "cpe_family_product",
    "cpe_family_entry_count",
    "cpe_family_active_count",
    "cpe_family_deprecated_count",
    "cpe_family_deprecated_by_edge_count",
    "cpe_family_active_exact_version_count",
    "cpe_family_active_exact_compatible_count",
    "cpe_family_template_compatible_count",
    "cpe_family_version_summary",
    "cpe_family_attribute_summary",
    "cpe_title_summary",
    "cpe_reference_summary",
    "nvd_configuration_occurrences",
    "nvd_configuration_cve_count",
    "nvd_distinct_criteria_count",
    "nvd_criteria_examples",
    "nvd_operator_summary",
    "nvd_usage_summary",
    "nvd_representative_case_review",
    "product_boundary_status",
    "version_space_status",
    "direct_actual_product_cpe_found",
    "configuration_only_actual_product_found",
    "risk_flags",
    "circular_evidence_risk",
    "audit_status",
    "recommended_gt_cpe",
    "recommended_validation_result",
    "audit_reason",
    "evidence_strength",
)

HIGH_RISK_FIELDS = (
    "component_id",
    "name",
    "observed_version",
    "audited_actual_product",
    "current_gt_cpe",
    "risk_flags",
    "official_product_boundary",
    "cpe_title_summary",
    "cpe_reference_summary",
    "nvd_usage_summary",
    "nvd_representative_case_review",
    "product_boundary_status",
    "version_space_status",
    "audit_status",
    "audit_reason",
    "evidence_strength",
)

AUDIT_STATUSES = ("KEEP", "CHANGE_CPE", "REMOVE_CPE", "REVIEW_REQUIRED")
EVIDENCE_STRENGTHS = ("STRONG", "MODERATE", "WEAK")
WIREGUARD_CURRENT_FAMILY = ("a", "wireguard", "wireguard")
DIRECT_WIREGUARD_PRODUCTS = (
    "wireguard-tools",
    "wireguard_tools",
    "wireguardtools",
    "wg",
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
PRERELEASE_UPDATE_RE = re.compile(
    r"^(?:pre|rc|beta|alpha|devel|snapshot)[0-9]*$",
    re.IGNORECASE,
)
REPRESENTATIVE_NVD_REVIEW_COMPONENTS = frozenset(
    {
        "curl",
        "libcurl4",
        "libmosquitto-ssl",
        "libnghttp2-14",
        "libopenssl3",
        "openvpn-openssl",
        "wireguard-tools",
        "wpa_supplicant",
    }
)
NVD_USAGE_INTERPRETATIONS = {
    "curl": (
        "MIXED_NVD_USAGE: representative fixed-Snapshot cases under "
        "haxx:curl describe libcurl. This is not used to infer the installed "
        "CLI boundary; official curl/libcurl separation and the distinct "
        "Dictionary families control the mapping."
    ),
    "libcurl4": (
        "DIRECT_LIBRARY_USAGE: representative cases explicitly describe "
        "libcurl APIs and behavior."
    ),
    "libmosquitto-ssl": (
        "PROJECT_WIDE_USAGE: representative cases include both broker and "
        "libmosquitto client-library behavior, matching the official project "
        "definition that comprises both."
    ),
    "libnghttp2-14": (
        "PROJECT_WIDE_USAGE: representative cases cover nghttpx and the "
        "nghttp2 library, both shipped by the official nghttp2 project."
    ),
    "libopenssl3": (
        "TOOLKIT_WIDE_USAGE: representative cases describe OpenSSL library "
        "APIs and command-line equivalents within the same toolkit."
    ),
    "openvpn-openssl": (
        "PRODUCT_AND_PLATFORM_USAGE: representative cases include general "
        "OpenVPN and Windows-service behavior; platform applicability is not "
        "inferred for this product-boundary audit."
    ),
    "wireguard-tools": (
        "WINDOWS_ONLY_FOR_FAMILY: both wireguard:wireguard cases identify "
        "WireGuard 0.5.3 on Windows and use Windows-constrained AND nodes."
    ),
    "wpa_supplicant": (
        "DIRECT_SUPPLICANT_USAGE: representative cases explicitly identify "
        "wpa_supplicant, with one shared hostapd/wpa_supplicant implementation "
        "case."
    ),
}


class UnitronicsProductBoundaryAuditError(Exception):
    pass


@dataclass(frozen=True)
class BoundarySpec:
    component_id: int
    name: str
    observed_version: str
    actual_vendor: str
    actual_product: str
    actual_version: str
    direct_family: tuple[str, str, str] | None
    official_urls: tuple[str, ...]
    boundary_reason: str
    version_reason: str
    risk_flags: tuple[str, ...] = ()
    evidence_strength: str = "MODERATE"
    excluded_families: tuple[tuple[str, str, str], ...] = ()


def _spec(
    component_id: int,
    name: str,
    observed_version: str,
    actual_vendor: str,
    actual_product: str,
    actual_version: str,
    direct_family: tuple[str, str, str] | None,
    official_urls: tuple[str, ...],
    boundary_reason: str,
    version_reason: str,
    *,
    risk_flags: tuple[str, ...] = (),
    evidence_strength: str = "MODERATE",
    excluded_families: tuple[tuple[str, str, str], ...] = (),
) -> BoundarySpec:
    return BoundarySpec(
        component_id=component_id,
        name=name,
        observed_version=observed_version,
        actual_vendor=actual_vendor,
        actual_product=actual_product,
        actual_version=actual_version,
        direct_family=direct_family,
        official_urls=official_urls,
        boundary_reason=boundary_reason,
        version_reason=version_reason,
        risk_flags=risk_flags,
        evidence_strength=evidence_strength,
        excluded_families=excluded_families,
    )


OPENWRT_VERSION_POLICY = (
    "https://github.com/openwrt/packages/blob/master/CONTRIBUTING.md"
)

BOUNDARY_SPECS = {
    spec.name: spec
    for spec in (
        _spec(199623, "busybox", "1.34.1-79.7", "BusyBox", "BusyBox", "1.34.1", ("a", "busybox", "busybox"), ("https://busybox.net/about.html", "https://busybox.net/downloads/"), "The installed multi-call binary and applets are the BusyBox product represented by the BusyBox family.", "The official archive contains 1.34.1; 79.7 is downstream package release data.", evidence_strength="STRONG"),
        _spec(199625, "curl", "8.11.0-23.2", "curl project", "curl", "8.11.0", ("a", "haxx", "curl"), ("https://curl.se/docs/faq.html", "https://curl.se/docs/versions.html"), "The curl project explicitly distinguishes the curl command-line product from the libcurl library; /usr/bin/curl maps to the curl family.", "curl and libcurl use the 8.11.0 upstream release; 23.2 is packaging data.", risk_flags=("UMBRELLA_PROJECT_SUBPRODUCT", "CLI_VS_LIBRARY", "MIXED_NVD_USAGE"), evidence_strength="MODERATE"),
        _spec(199653, "davici", "1.4-1", "strongSwan", "davici", "1.4", ("a", "strongswan", "davici"), ("https://github.com/strongswan/davici",), "davici is the separately released Decoupled Asynchronous VICI client library under the strongSwan organization, and has a direct davici CPE family.", "The package release 1.4-1 identifies upstream davici 1.4 plus package release 1.", risk_flags=("UMBRELLA_PROJECT_SUBPROJECT", "LIBRARY_PRODUCT"), evidence_strength="STRONG"),
        _spec(199659, "dnsmasq", "2.89-42.4", "Thekelleys", "dnsmasq", "2.89", ("a", "thekelleys", "dnsmasq"), ("https://thekelleys.org.uk/dnsmasq/doc.html",), "The installed dnsmasq daemon and the CPE family both identify Simon Kelley's dnsmasq product.", "2.89 is the upstream release; 42.4 is distribution packaging data."),
        _spec(199660, "dropbear", "2020.81-3", "Dropbear SSH project", "Dropbear SSH", "2020.81", ("a", "dropbear_ssh_project", "dropbear_ssh"), ("https://matt.ucc.asn.au/dropbear/dropbear.html", "https://matt.ucc.asn.au/dropbear/releases/"), "The installed Dropbear SSH executables and the dropbear_ssh family are the same compact SSH product.", "The official release archive contains 2020.81; 3 is package release data.", evidence_strength="STRONG"),
        _spec(199661, "e2fsprogs", "1.47.0-2", "e2fsprogs project", "e2fsprogs", "1.47.0", ("a", "e2fsprogs_project", "e2fsprogs"), ("https://e2fsprogs.sourceforge.net/", "https://github.com/tytso/e2fsprogs/tags"), "The installed filesystem utilities originate from and retain the e2fsprogs product boundary.", "1.47.0 is the upstream release and 2 is the package release.", evidence_strength="STRONG"),
        _spec(199663, "ethtool", "5.10-1", "Linux kernel networking project", "ethtool", "5.10", ("a", "kernel", "ethtool"), ("https://www.kernel.org/pub/software/network/ethtool/",), "ethtool is a separately released userspace networking utility hosted by kernel.org; the kernel:ethtool CPE references that release archive.", "The kernel.org archive uses ethtool 5.10; 1 is the package release.", risk_flags=("VENDOR_LABEL_DIFFERS", "USERSPACE_TOOL_IN_KERNEL_NAMESPACE"), evidence_strength="STRONG"),
        _spec(199665, "exfat-mkfs", "1.1.3-4", "exfatprogs project", "exfatprogs", "1.1.3", ("a", "namjaejeon", "exfatprogs"), ("https://github.com/exfatprogs/exfatprogs", "https://github.com/exfatprogs/exfatprogs/releases"), "exfat-mkfs is the mkfs utility built by the exfatprogs upstream project and the CPE family directly names exfatprogs.", "The project release is 1.1.3 and 4 is package release data.", risk_flags=("PACKAGE_NAME_DIFFERS", "UTILITY_WITHIN_PRODUCT"), evidence_strength="STRONG"),
        _spec(199683, "ip-full", "5.19.0-8", "iproute2 project", "iproute2", "5.19.0", ("a", "iproute2_project", "iproute2"), ("https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/", "https://www.kernel.org/pub/linux/utils/net/iproute2/"), "ip-full is OpenWrt's full ip utility package from the iproute2 source product; it is not a separate upstream product.", "5.19.0 is the iproute2 upstream release and 8 is the package release.", risk_flags=("DISTRIBUTION_PACKAGE_ALIAS", "UTILITY_WITHIN_PRODUCT"), evidence_strength="STRONG"),
        _spec(199686, "ipset", "7.6-1", "Netfilter", "ipset", "7.6", ("a", "netfilter", "ipset"), ("https://www.netfilter.org/projects/ipset/index.html", "https://www.netfilter.org/pub/ipset/"), "The installed ipset userspace utility and the Netfilter ipset family identify the same project.", "The official archive contains ipset 7.6 and 1 is package release data.", evidence_strength="STRONG"),
        _spec(199690, "iptables", "1.8.7-3", "Netfilter", "iptables", "1.8.7", ("a", "netfilter", "iptables"), ("https://www.netfilter.org/projects/iptables/index.html", "https://www.netfilter.org/projects/iptables/files/"), "The installed iptables command suite and the Netfilter iptables family identify the same product.", "1.8.7 is the upstream release and 3 is package release data.", evidence_strength="STRONG"),
        _spec(199691, "iw-515", "5.19-1", "Linux wireless project", "iw", "5.19", ("a", "kernel", "iw"), ("https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html", "https://www.kernel.org/pub/software/network/iw/"), "iw-515 is a distribution package name for the upstream iw userspace wireless utility; the kernel:iw CPE references the same release archive.", "The upstream iw release is 5.19 and 1 is package release data.", risk_flags=("DISTRIBUTION_PACKAGE_ALIAS", "USERSPACE_TOOL_IN_KERNEL_NAMESPACE"), evidence_strength="STRONG"),
        _spec(199845, "libc", "1.2.4-3", "musl libc project", "musl", "1.2.4", ("a", "musl-libc", "musl"), ("https://musl.libc.org/", "https://musl.libc.org/releases.html"), "The firmware loader/libc payload identifies musl rather than a generic libc product, and the CPE family directly identifies musl.", "The official release history identifies musl 1.2.4; 3 is package release data.", risk_flags=("GENERIC_PACKAGE_NAME", "LIBRARY_PRODUCT"), evidence_strength="STRONG"),
        _spec(199847, "libcap-ng", "0.8.1-1", "libcap-ng project", "libcap-ng", "0.8.1", ("a", "libcap-ng_project", "libcap-ng"), ("https://github.com/stevegrubb/libcap-ng", "https://github.com/stevegrubb/libcap-ng/releases"), "The installed libcap-ng library is the direct libcap-ng upstream product, distinct from libcap.", "0.8.1 is the upstream release and 1 is package release data.", risk_flags=("SIMILAR_PRODUCT_NAMES", "LIBRARY_PRODUCT")),
        _spec(199848, "libcap", "2.69-1", "libcap project", "libcap", "2.69", ("a", "libcap_project", "libcap"), ("https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/",), "The installed capability library and the libcap family are the same upstream product.", "The official archive contains libcap 2.69; 1 is package release data.", risk_flags=("LIBRARY_PRODUCT",), evidence_strength="STRONG"),
        _spec(199849, "libcares", "1.19.1-2", "c-ares project", "c-ares", "1.19.1", ("a", "c-ares", "c-ares"), ("https://c-ares.org/", "https://c-ares.org/changelog.html"), "libcares is the distribution package for the c-ares asynchronous DNS library and the CPE directly names c-ares.", "1.19.1 is the upstream release and 2 is package release data.", risk_flags=("PACKAGE_NAME_DIFFERS", "LIBRARY_PRODUCT")),
        _spec(199854, "libcurl4", "8.11.0-23.2", "curl project", "libcurl", "8.11.0", ("a", "haxx", "libcurl"), ("https://curl.se/docs/faq.html", "https://curl.se/libcurl/c/"), "The curl project explicitly defines libcurl as its client-side transfer library, separate from the curl CLI, and the CPE family directly names libcurl.", "libcurl follows upstream 8.11.0; 23.2 is distribution packaging data.", risk_flags=("UMBRELLA_PROJECT_SUBPRODUCT", "CLI_VS_LIBRARY"), evidence_strength="STRONG"),
        _spec(199866, "libjson-c5", "0.15-2", "json-c project", "json-c", "0.15", ("a", "json-c", "json-c"), ("https://github.com/json-c/json-c", "https://github.com/json-c/json-c/releases"), "The ABI-suffixed distribution package contains the json-c library and maps to the direct json-c family.", "0.15 is the upstream release and 2 is package release data.", risk_flags=("ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT")),
        _spec(199871, "liblzo2", "2.10-4", "LZO project", "LZO", "2.10", ("a", "lzo_project", "lzo"), ("https://www.oberhumer.com/opensource/lzo/",), "The ABI-suffixed package contains the LZO compression library represented by the LZO family.", "2.10 is the upstream release and 4 is package release data.", risk_flags=("ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT")),
        _spec(199875, "libmnl0", "1.0.4-2", "Netfilter", "libmnl", "1.0.4", ("a", "netfilter", "libmnl"), ("https://www.netfilter.org/projects/libmnl/",), "The installed library is Netfilter's separately released libmnl project and has a direct libmnl family.", "1.0.4 is the upstream release and 2 is package release data.", risk_flags=("ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT")),
        _spec(199877, "libmosquitto-ssl", "2.0.20-1", "Eclipse", "Eclipse Mosquitto", "2.0.20", ("a", "eclipse", "mosquitto"), ("https://mosquitto.org/man/mosquitto-7.html", "https://mosquitto.org/api/"), "The official Mosquitto project definition explicitly comprises the broker, clients, and libmosquitto client library; this SSL-enabled library package remains inside the Mosquitto product boundary.", "The library shares Mosquitto release 2.0.20; 1 is package release data.", risk_flags=("LIBRARY_VS_APPLICATION", "UMBRELLA_PROJECT_COMPONENT", "BUILD_FLAVOR"), evidence_strength="STRONG"),
        _spec(199878, "libnetfilter-conntrack3", "1.0.8-1", "Netfilter", "libnetfilter_conntrack", "1.0.8", ("a", "netfilter", "libnetfilter_conntrack"), ("https://www.netfilter.org/projects/libnetfilter_conntrack/",), "The ABI-suffixed package is the direct Netfilter libnetfilter_conntrack library product.", "1.0.8 is the upstream release and 1 is package release data.", risk_flags=("ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT")),
        _spec(199880, "libnfnetlink0", "1.0.1-4", "Netfilter", "libnfnetlink", "1.0.1", ("a", "netfilter", "libnfnetlink"), ("https://www.netfilter.org/projects/libnfnetlink/",), "The ABI-suffixed package is the direct Netfilter libnfnetlink library product.", "1.0.1 is the upstream release and 4 is package release data.", risk_flags=("ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT")),
        _spec(199881, "libnftnl11", "1.2.5-5", "Netfilter", "libnftnl", "1.2.5", ("a", "netfilter", "libnftnl"), ("https://www.netfilter.org/projects/libnftnl/",), "The ABI-suffixed package is the direct Netfilter libnftnl library product.", "1.2.5 is the upstream release and 5 is package release data.", risk_flags=("ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT")),
        _spec(199882, "libnghttp2-14", "1.43.0-1", "nghttp2 project", "nghttp2", "1.43.0", ("a", "nghttp2", "nghttp2"), ("https://nghttp2.org/documentation/package_README.html", "https://github.com/nghttp2/nghttp2/releases"), "The official nghttp2 project defines its reusable C library as the core framing implementation and also ships applications; the installed libnghttp2 remains within the nghttp2 product boundary.", "The library uses the nghttp2 1.43.0 release; 1 is package release data.", risk_flags=("LIBRARY_VS_APPLICATION", "UMBRELLA_PROJECT_COMPONENT", "ABI_SUFFIXED_PACKAGE"), evidence_strength="STRONG"),
        _spec(199888, "libopenssl3", "3.0.14-3", "OpenSSL Project", "OpenSSL", "3.0.14", ("a", "openssl", "openssl"), ("https://github.com/openssl/openssl", "https://openssl-library.org/source/"), "libssl.so.3 and libcrypto.so.3 are core OpenSSL libraries from the OpenSSL 3.0.14 source product; the family represents the OpenSSL toolkit rather than only its CLI.", "3.0.14 is the upstream OpenSSL release and 3 is package release data.", risk_flags=("LIBRARY_VS_APPLICATION", "SPLIT_UPSTREAM_PRODUCT"), evidence_strength="STRONG"),
        _spec(199890, "libpcap1", "1.9.1-3", "tcpdump project", "libpcap", "1.9.1", ("a", "tcpdump", "libpcap"), ("https://www.tcpdump.org/", "https://www.tcpdump.org/release/"), "The ABI-suffixed package contains the tcpdump project's separately named libpcap library, matching the direct libpcap family.", "1.9.1 is the upstream release and 3 is package release data.", risk_flags=("VENDOR_LABEL_DIFFERS", "LIBRARY_PRODUCT", "ABI_SUFFIXED_PACKAGE")),
        _spec(199891, "libpcre2", "10.37-5", "PCRE project", "PCRE2", "10.37", ("a", "pcre", "pcre2"), ("https://github.com/PCRE2Project/pcre2", "https://github.com/PCRE2Project/pcre2/releases"), "The installed PCRE2 library and the pcre:pcre2 family identify the same second-generation PCRE product.", "10.37 is the upstream release and 5 is package release data.", risk_flags=("LIBRARY_PRODUCT",)),
        _spec(199913, "libusb-1.0-0", "1.0.24-5", "libusb project", "libusb", "1.0.24", ("a", "libusb", "libusb"), ("https://libusb.info/", "https://github.com/libusb/libusb/releases/tag/v1.0.24"), "The ABI-suffixed package contains the direct libusb library product.", "The official project release is 1.0.24 and 5 is package release data.", risk_flags=("ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT"), evidence_strength="STRONG"),
        _spec(199920, "lua", "5.1.5-9", "Lua project", "Lua", "5.1.5", ("a", "lua", "lua"), ("https://www.lua.org/versions.html",), "The installed Lua interpreter/runtime represents the Lua product and maps directly to the Lua family.", "Lua 5.1.5 is the final 5.1 patch release; 9 is package release data.", evidence_strength="STRONG"),
        _spec(199933, "minizip", "4.0.7-2", "zlib-ng project", "minizip-ng", "4.0.7", ("a", "zlib-ng", "minizip-ng"), ("https://github.com/zlib-ng/minizip-ng", "https://github.com/zlib-ng/minizip-ng/releases/tag/4.0.7"), "The installed minizip payload comes from the independently released minizip-ng repository, not from the zlib or zlib-ng core product; the CPE family directly names minizip-ng.", "4.0.7 is the minizip-ng upstream release and 2 is package release data.", risk_flags=("UMBRELLA_PROJECT_SUBPROJECT", "HISTORICAL_FORK_NAME"), evidence_strength="STRONG"),
        _spec(199956, "open62541", "v1.4.0-r", "open62541 project", "open62541", "1.4.0", ("a", "open62541", "open62541"), ("https://github.com/open62541/open62541", "https://github.com/open62541/open62541/releases/tag/v1.4.0"), "The firmware library identifies the open62541 OPC UA project and the CPE family directly names it.", "The official final tag is v1.4.0; the firmware's v/r notation is normalized to 1.4.0 without discarding a prerelease qualifier.", risk_flags=("NON_OPKG_VERSION_FORM",), evidence_strength="STRONG"),
        _spec(199959, "openvpn-openssl", "2.6.9-5", "OpenVPN", "OpenVPN", "2.6.9", ("a", "openvpn", "openvpn"), ("https://community.openvpn.net/openvpn/wiki/OverviewOfOpenvpn", "https://github.com/OpenVPN/openvpn/releases/tag/v2.6.9"), "openvpn-openssl is the OpenSSL-linked build flavor of OpenVPN Community Edition, not a separate upstream product; the CPE's community sw_edition preserves that boundary.", "2.6.9 is the OpenVPN upstream release and 5 is package release data.", risk_flags=("BUILD_FLAVOR", "EDITION_SPECIFIC_CPE"), evidence_strength="STRONG"),
        _spec(200023, "strongswan", "5.9.14-24", "strongSwan", "strongSwan", "5.9.14", ("a", "strongswan", "strongswan"), ("https://www.strongswan.org/", "https://github.com/strongswan/strongswan/releases"), "The main package contains core libstrongswan and configuration from the strongSwan IPsec product; separately named subprojects such as davici retain separate families.", "5.9.14 is the upstream release and 24 is package release data.", risk_flags=("SPLIT_UPSTREAM_PRODUCT", "CLIENT_SERVER_PLUGIN_SUITE"), evidence_strength="STRONG"),
        _spec(200186, "wireguard-tools", "1.0.20210223-4", "WireGuard", "wireguard-tools", "1.0.20210223", None, ("https://www.wireguard.com/repositories/", "https://git.zx2c4.com/wireguard-tools/tag/?h=v1.0.20210223", "https://git.zx2c4.com/wireguard-windows/refs/tags"), "wireguard-tools is the separately released wg/wg-quick userspace-tools project. The wireguard:wireguard 0.5.3 family instead aligns with the separately versioned Windows client.", "The official tools tag is v1.0.20210223; 4 is OpenWrt package release data and the date-shaped upstream version is retained.", risk_flags=("KERNEL_VS_USERSPACE", "PLATFORM_SPECIFIC_CPE", "UMBRELLA_PROJECT_SUBPROJECT", "VERSION_SPACE_MISMATCH"), evidence_strength="STRONG", excluded_families=(WIREGUARD_CURRENT_FAMILY,)),
        _spec(200192, "zlib", "1.2.11-4", "zlib project", "zlib", "1.2.11", ("a", "zlib", "zlib"), ("https://zlib.net/", "https://zlib.net/fossils/"), "The installed compression library and zlib family identify the same upstream product.", "1.2.11 is the upstream release and 4 is package release data.", risk_flags=("LIBRARY_PRODUCT",)),
        _spec(200193, "linux_kernel", "5.15.176", "Linux", "Linux kernel", "5.15.176", ("o", "linux", "linux_kernel"), ("https://www.kernel.org/", "https://cdn.kernel.org/pub/linux/kernel/v5.x/"), "The exact kernel banner/module tree identifies the Linux kernel OS product represented by linux:linux_kernel, not a userspace utility.", "The exact firmware kernel release is 5.15.176 with no package suffix.", risk_flags=("OS_PLATFORM_CPE", "KERNEL_PRODUCT"), evidence_strength="STRONG"),
        _spec(200196, "sqlite", "3.41.2", "SQLite", "SQLite", "3.41.2", ("a", "sqlite", "sqlite"), ("https://www.sqlite.org/releaselog/3_41_2.html",), "The exact embedded SQLite identifier and the sqlite:sqlite family identify the same database engine.", "The exact identifier and official release log both identify 3.41.2.", evidence_strength="STRONG"),
        _spec(200198, "wpa_supplicant", "2.11", "w1.fi/hostap", "wpa_supplicant", "2.11-devel", ("a", "w1.fi", "wpa_supplicant"), ("https://w1.fi/wpa_supplicant/", "https://w1.fi/releases/"), "wpa_supplicant is the client/supplicant program within the hostap project and has its own direct CPE family distinct from hostapd.", "The SBOM reports 2.11, while the exact binary says 2.11-devel; the development qualifier is preserved as CPE version 2.11 and update devel.", risk_flags=("CLIENT_SERVER_SPLIT", "PRERELEASE_VERSION"), evidence_strength="STRONG"),
        _spec(200199, "openwrt", "21.02.0:r16279-5cc0535800", "OpenWrt", "OpenWrt", "21.02.0", ("o", "openwrt", "openwrt"), ("https://downloads.openwrt.org/releases/21.02.0/", "https://openwrt.org/about/history"), "The firmware release identifier represents the OpenWrt operating-system distribution and maps to the OpenWrt OS family.", "21.02.0 is the official release; r16279-5cc0535800 is the source revision, not a different upstream product version.", risk_flags=("OS_PLATFORM_CPE", "REVISION_SUFFIX"), evidence_strength="STRONG"),
    )
}


@dataclass
class ProductBoundaryAuditAnalysis:
    rows: list[dict[str, str]]
    high_risk_rows: list[dict[str, str]]
    summary: dict[str, Any]


def _fail(message: str) -> NoReturn:
    raise UnitronicsProductBoundaryAuditError(message)


def default_output_directory() -> Path:
    return settings.REPOSITORY_ROOT / OUTPUT_RELATIVE


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _bool(value: bool) -> str:
    return str(value).lower()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        _fail(f"Required evidence artifact is absent: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _protected_artifact_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative_directory in PROTECTED_ARTIFACT_DIRECTORIES:
        directory = root / RESULTS_ROOT / relative_directory
        if not directory.is_dir():
            _fail(f"Protected artifact directory is absent: {directory}")
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            relative = path.relative_to(root)
            hashes[str(relative)] = _sha256(path)
    return hashes


def _serializable(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_serializable(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _serializable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    return str(value)


def _fingerprint(rows: list[dict[str, object]]) -> str:
    payload = json.dumps(
        _serializable(rows),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _database_state(snapshot: CpeDictionarySnapshot) -> dict[str, Any]:
    components = list(
        Component.objects.filter(sbom_document_id=SBOM_DOCUMENT_ID)
        .order_by("id")
        .values()
    )
    records = list(
        ComponentCpeGroundTruth.objects.filter(
            component__sbom_document_id=SBOM_DOCUMENT_ID,
            snapshot=snapshot,
        )
        .order_by("id")
        .values()
    )
    record_ids = [int(row["id"]) for row in records]
    corrections: dict[int, list[int]] = defaultdict(list)
    discrepancies: dict[int, list[int]] = defaultdict(list)
    for record_id, correction_id in (
        ComponentCpeGroundTruth.correction_types.through.objects.filter(
            componentcpegroundtruth_id__in=record_ids
        ).values_list("componentcpegroundtruth_id", "groundtruthcorrectiontype_id")
    ):
        corrections[record_id].append(correction_id)
    for record_id, discrepancy_id in (
        ComponentCpeGroundTruth.discrepancy_types.through.objects.filter(
            componentcpegroundtruth_id__in=record_ids
        ).values_list("componentcpegroundtruth_id", "groundtruthdiscrepancytype_id")
    ):
        discrepancies[record_id].append(discrepancy_id)
    for row in records:
        record_id = int(row["id"])
        row["correction_type_ids"] = sorted(corrections[record_id])
        row["discrepancy_type_ids"] = sorted(discrepancies[record_id])
    cpe_bearing = sum(
        row["ground_truth_cpe_id"] is not None
        or bool(row["manual_ground_truth_cpe"])
        for row in records
    )
    return {
        "component_count": len(components),
        "ground_truth_count": len(records),
        "cpe_bearing_count": cpe_bearing,
        "component_fingerprint": _fingerprint(components),
        "ground_truth_fingerprint": _fingerprint(records),
    }


def _snapshot_metadata(
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
) -> dict[str, Any]:
    if cpe_snapshot.snapshot_id != CPE_SNAPSHOT_ID:
        _fail("Wrong fixed CPE Dictionary snapshot")
    if nvd_snapshot.snapshot_id != NVD_SNAPSHOT_ID:
        _fail("Wrong fixed NVD snapshot")
    if cpe_snapshot.status != CpeDictionarySnapshot.Status.COMPLETE:
        _fail("Fixed CPE Dictionary snapshot is not COMPLETE")
    if nvd_snapshot.status != NvdCveSnapshot.Status.COMPLETE:
        _fail("Fixed NVD snapshot is not COMPLETE")
    return {
        "cpe_dictionary": {
            "snapshot_id": cpe_snapshot.snapshot_id,
            "record_count": cpe_snapshot.record_count,
            "active_count": cpe_snapshot.active_count,
            "deprecated_count": cpe_snapshot.deprecated_count,
            "manifest_sha256": cpe_snapshot.manifest_sha256,
            "content_sha256": cpe_snapshot.content_sha256,
        },
        "nvd_cve": {
            "snapshot_id": nvd_snapshot.snapshot_id,
            "record_count": nvd_snapshot.record_count,
            "configuration_count": nvd_snapshot.configuration_count,
            "cpe_match_count": nvd_snapshot.cpe_match_count,
            "manifest_sha256": nvd_snapshot.manifest_sha256,
            "content_sha256": nvd_snapshot.content_sha256,
        },
    }


def _natural_key(value: str) -> tuple[object, ...]:
    return tuple(
        int(part) if part.isdigit() else part.lower()
        for part in re.split(r"([0-9]+)", value)
    )


def _english_title(titles: object) -> list[str]:
    if not isinstance(titles, list):
        return []
    english = [
        str(item["title"])
        for item in titles
        if isinstance(item, dict)
        and item.get("lang") == "en"
        and item.get("title")
    ]
    if english:
        return english
    return [
        str(item["title"])
        for item in titles
        if isinstance(item, dict) and item.get("title")
    ]


def _reference_urls(references: object) -> list[str]:
    if not isinstance(references, list):
        return []
    return [
        str(item["ref"])
        for item in references
        if isinstance(item, dict) and item.get("ref")
    ]


def _family_evidence(
    snapshot: CpeDictionarySnapshot,
    family: tuple[str, str, str],
) -> dict[str, Any]:
    models = list(
        CpeName.objects.filter(
            snapshot=snapshot,
            part=family[0],
            vendor=family[1],
            product=family[2],
        ).order_by("version", "update", "cpe_name")
    )
    titles: list[str] = []
    references: list[str] = []
    versions: set[str] = set()
    update_values: set[str] = set()
    target_sw_values: set[str] = set()
    target_hw_values: set[str] = set()
    edition_values: set[str] = set()
    parse_failures = 0
    deprecated_by_edges = 0
    for model in models:
        parsed = parse_cpe23(model.cpe_name)
        parse_failures += not parsed.is_valid
        versions.add(model.version)
        update_values.add(model.update)
        target_sw_values.add(model.target_sw)
        target_hw_values.add(model.target_hw)
        edition_values.add(model.edition)
        titles.extend(_english_title(model.titles))
        references.extend(_reference_urls(model.references))
        if isinstance(model.deprecated_by, list):
            deprecated_by_edges += len(model.deprecated_by)
    ordered_versions = sorted(versions, key=_natural_key)
    samples = ordered_versions
    if len(samples) > 12:
        samples = ordered_versions[:6] + ["..."] + ordered_versions[-5:]
    unique_titles = list(dict.fromkeys(titles))
    unique_references = list(dict.fromkeys(references))
    active_count = sum(not model.deprecated for model in models)
    deprecated_count = len(models) - active_count
    return {
        "family": family,
        "entry_count": len(models),
        "active_count": active_count,
        "deprecated_count": deprecated_count,
        "deprecated_by_edge_count": deprecated_by_edges,
        "version_count": len(versions),
        "versions": ordered_versions,
        "version_summary": (
            f"{len(versions)} distinct; samples={'; '.join(samples)}"
        ),
        "attribute_summary": _json(
            {
                "updates": sorted(update_values, key=_natural_key),
                "editions": sorted(edition_values),
                "target_sw": sorted(target_sw_values),
                "target_hw": sorted(target_hw_values),
            }
        ),
        "title_summary": " | ".join(unique_titles[:3]),
        "reference_summary": " | ".join(unique_references[:4]),
        "canonical_parse_failure_count": parse_failures,
        "cpe_names": [model.cpe_name for model in models],
        "active_cpe_names": [
            model.cpe_name for model in models if not model.deprecated
        ],
    }


def _non_version_template(cpe_name: object) -> tuple[str, ...]:
    return tuple(
        cpe_name.attribute(attribute).canonical
        for attribute in NON_VERSION_ATTRIBUTES
    )


def _template_compatible(
    observed: tuple[str, ...],
    expected: tuple[str, ...],
) -> bool:
    if observed == expected:
        return True
    expected_update, *expected_remainder = expected
    observed_update, *observed_remainder = observed
    return (
        PRERELEASE_UPDATE_RE.fullmatch(expected_update) is not None
        and PRERELEASE_UPDATE_RE.fullmatch(observed_update) is not None
        and observed_remainder == expected_remainder
    )


def _family_compatibility_counts(
    family_evidence: dict[str, Any],
    current_name: object,
) -> dict[str, int]:
    current_version = current_name.attribute("version").canonical
    current_template = _non_version_template(current_name)
    exact_version = 0
    exact_compatible = 0
    template_compatible = 0
    for cpe in family_evidence["active_cpe_names"]:
        parsed = parse_cpe23(cpe)
        if not parsed.is_valid or parsed.name is None:
            continue
        observed_version = parsed.name.attribute("version").canonical
        observed_template = _non_version_template(parsed.name)
        compatible = _template_compatible(observed_template, current_template)
        exact_version += observed_version == current_version
        exact_compatible += (
            observed_version == current_version
            and observed_template == current_template
        )
        template_compatible += compatible
    return {
        "active_exact_version_count": exact_version,
        "active_exact_compatible_count": exact_compatible,
        "template_compatible_count": template_compatible,
    }


def _nvd_family_evidence(
    snapshot: NvdCveSnapshot,
    family: tuple[str, str, str],
) -> dict[str, Any]:
    prefix = "cpe:2.3:" + ":".join(family) + ":"
    matches = NvdCpeMatch.objects.filter(
        cve_record__snapshot=snapshot,
        criteria__startswith=prefix,
    )
    aggregate = matches.aggregate(
        occurrences=Count("id"),
        cves=Count("cve_record__cve_id", distinct=True),
        criteria=Count("criteria", distinct=True),
        configuration_and=Count("id", filter=Q(configuration_operator="AND")),
        configuration_or=Count("id", filter=Q(configuration_operator="OR")),
        configuration_unset=Count(
            "id", filter=Q(configuration_operator__isnull=True)
        ),
        node_and=Count("id", filter=Q(node_operator="AND")),
        node_or=Count("id", filter=Q(node_operator="OR")),
        ranged=Count(
            "id",
            filter=(
                Q(version_start_including__isnull=False)
                | Q(version_start_excluding__isnull=False)
                | Q(version_end_including__isnull=False)
                | Q(version_end_excluding__isnull=False)
            ),
        ),
    )
    candidates = list(
        matches.select_related("cve_record")
        .order_by("-cve_record__published_at_nvd", "cve_record__cve_id")
        .values(
            "cve_record__cve_id",
            "criteria",
            "configuration_operator",
            "node_operator",
            "vulnerable",
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
        )[:100]
    )
    examples: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    for candidate in candidates:
        cve_id = str(candidate["cve_record__cve_id"])
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        examples.append(candidate)
        if len(examples) == 3:
            break
    operator_summary = {
        key: int(aggregate[key] or 0)
        for key in (
            "configuration_and",
            "configuration_or",
            "configuration_unset",
            "node_and",
            "node_or",
            "ranged",
        )
    }
    return {
        "occurrences": int(aggregate["occurrences"] or 0),
        "cve_count": int(aggregate["cves"] or 0),
        "criteria_count": int(aggregate["criteria"] or 0),
        "examples": examples,
        "operator_summary": operator_summary,
        "usage_summary": (
            f"occurrences={int(aggregate['occurrences'] or 0)}; "
            f"CVEs={int(aggregate['cves'] or 0)}; "
            f"distinct criteria={int(aggregate['criteria'] or 0)}; "
            f"configuration AND/OR/unset="
            f"{operator_summary['configuration_and']}/"
            f"{operator_summary['configuration_or']}/"
            f"{operator_summary['configuration_unset']}; "
            f"node AND/OR={operator_summary['node_and']}/"
            f"{operator_summary['node_or']}; "
            f"ranged={operator_summary['ranged']}"
        ),
    }


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value", ""))
    return ""


def _load_raw_cve_reviews(
    root: Path,
    requests: dict[str, list[str]],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, str]]]:
    requested_ids = {
        cve_id for cve_ids in requests.values() for cve_id in cve_ids
    }
    by_year: dict[int, set[str]] = defaultdict(set)
    for cve_id in requested_ids:
        try:
            by_year[int(cve_id.split("-")[1])].add(cve_id)
        except (IndexError, ValueError):
            _fail(f"Invalid representative CVE ID: {cve_id}")
    found: dict[str, dict[str, Any]] = {}
    feed_provenance: dict[str, dict[str, str]] = {}
    for year, expected in sorted(by_year.items()):
        relative = Path(
            f"data/nvd-cve/{NVD_SNAPSHOT_ID}/feeds/"
            f"nvdcve-2.0-{year}.json.gz"
        )
        path = root / relative
        if not path.is_file():
            _fail(f"Fixed raw NVD feed is absent: {relative}")
        feed_provenance[str(year)] = {
            "path": str(relative),
            "sha256": _sha256(path),
        }
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            _fail(f"Cannot read fixed raw NVD feed {relative}: {error}")
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {}) if isinstance(item, dict) else {}
            cve_id = cve.get("id") if isinstance(cve, dict) else None
            if cve_id in expected:
                references = cve.get("references", [])
                found[str(cve_id)] = {
                    "cve_id": str(cve_id),
                    "description": _english_description(cve),
                    "references": [
                        str(reference["url"])
                        for reference in references
                        if isinstance(reference, dict) and reference.get("url")
                    ][:4],
                }
    missing = requested_ids - set(found)
    if missing:
        _fail(f"Representative CVEs missing from fixed raw feeds: {sorted(missing)}")
    reviews = {
        component: [found[cve_id] for cve_id in cve_ids]
        for component, cve_ids in requests.items()
    }
    return reviews, feed_provenance


def _wireguard_direct_search(
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
) -> dict[str, Any]:
    title_text = Cast("titles", output_field=TextField())
    dictionary = list(
        CpeName.objects.filter(snapshot=cpe_snapshot)
        .annotate(_title_text=title_text)
        .filter(
            Q(product__in=DIRECT_WIREGUARD_PRODUCTS)
            | Q(_title_text__icontains="wireguard-tools")
            | Q(_title_text__icontains="wireguard tools")
        )
        .values_list("cpe_name", flat=True)
    )
    normalized = {"wireguardtools", "wg"}
    related = list(
        NvdCpeMatch.objects.filter(cve_record__snapshot=nvd_snapshot)
        .filter(Q(criteria__icontains="wireguard") | Q(criteria__contains=":wg:"))
        .values_list("criteria", flat=True)
        .distinct()
    )
    configuration: list[str] = []
    parse_failures = 0
    for criteria in related:
        parsed = parse_cpe23(criteria)
        if not parsed.is_valid or parsed.name is None:
            parse_failures += 1
            continue
        product = parsed.name.attribute("product").canonical
        if re.sub(r"[-_\s]", "", product).lower() in normalized:
            configuration.append(criteria)
    return {
        "dictionary_matches": sorted(dictionary),
        "configuration_matches": sorted(set(configuration)),
        "related_criteria": sorted(related),
        "canonical_parse_failure_count": parse_failures,
    }


def _exact_firmware_evidence(
    spec: BoundarySpec,
    packages: dict[int, dict[str, str]],
    preanalysis: dict[int, dict[str, str]],
) -> dict[str, str]:
    component = preanalysis.get(spec.component_id)
    if component is None or component["name"] != spec.name:
        _fail(f"Exact preanalysis evidence mismatch for {spec.name}")
    package = packages.get(spec.component_id)
    if package is not None:
        if (
            package["sbom_name"] != spec.name
            or package["version"] != spec.observed_version
            or package["status_version_matches"] != "True"
        ):
            _fail(f"Exact package evidence mismatch for {spec.name}")
        evidence = {
            "source": package["source"],
            "source_name": package["source_name"],
            "description": package["description"],
            "depends": package["depends"],
            "payload": package["representative_paths"],
            "control": package["control_path"],
            "list": package["list_path"],
        }
    else:
        if component["version"] != spec.observed_version:
            _fail(f"Exact non-opkg version mismatch for {spec.name}")
        if spec.name == "wpa_supplicant":
            properties = json.loads(component["properties_summary"])
            identifiers = properties.get("identifer_detected", [])
            if "wpa_supplicant v2.11-devel" not in identifiers:
                _fail("Exact wpa_supplicant 2.11-devel identifier is absent")
        evidence = {
            "source": component["source_package"] or "NON_OPKG_DIRECT_ARTIFACT",
            "source_name": component["upstream_product_candidate"],
            "description": component["matching_evidence"],
            "depends": "",
            "payload": component["properties_paths"],
            "control": component["firmware_control_path"],
            "list": "",
        }
    return evidence


def _current_cpe(record: ComponentCpeGroundTruth) -> str:
    if record.ground_truth_cpe is not None:
        return record.ground_truth_cpe.cpe_name
    return record.manual_ground_truth_cpe


def classify_boundary(
    *,
    spec: BoundarySpec,
    current_family: tuple[str, str, str],
    direct_family_found: bool,
    configuration_only_found: bool,
) -> dict[str, str]:
    if spec.direct_family is not None and current_family == spec.direct_family:
        return {
            "product_boundary_status": "SAME_PRODUCT",
            "version_space_status": "ALIGNED",
            "audit_status": "KEEP",
            "reason": (
                f"{spec.boundary_reason} {spec.version_reason}"
            ),
        }
    if current_family in spec.excluded_families:
        if direct_family_found:
            return {
                "product_boundary_status": "DIFFERENT_PRODUCT",
                "version_space_status": "MISMATCH",
                "audit_status": "CHANGE_CPE",
                "reason": (
                    f"{spec.boundary_reason} A separate direct Dictionary family "
                    "is available for the actual product."
                ),
            }
        if configuration_only_found:
            return {
                "product_boundary_status": "DIFFERENT_PRODUCT",
                "version_space_status": "MISMATCH",
                "audit_status": "CHANGE_CPE",
                "reason": (
                    f"{spec.boundary_reason} The actual product is represented "
                    "only in fixed NVD Configuration data."
                ),
            }
        return {
            "product_boundary_status": "DIFFERENT_PRODUCT",
            "version_space_status": "MISMATCH",
            "audit_status": "REMOVE_CPE",
            "reason": (
                f"{spec.boundary_reason} No direct Dictionary family or fixed "
                "NVD Configuration expression exists for the actual product."
            ),
        }
    return {
        "product_boundary_status": "AMBIGUOUS_PRODUCT_BOUNDARY",
        "version_space_status": "INCONCLUSIVE",
        "audit_status": "REVIEW_REQUIRED",
        "reason": (
            "The independently established product boundary does not establish "
            "that the current family is the same product or a known different product."
        ),
    }


def _recommendation(
    *,
    status: str,
    current_cpe: str,
    current_decision: str,
    spec: BoundarySpec,
    family_evidence: dict[str, Any] | None,
) -> tuple[str, str]:
    if status == "KEEP":
        return current_cpe, current_decision
    if status == "REMOVE_CPE":
        return "", "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
    if status == "REVIEW_REQUIRED":
        return "", "UNRESOLVED"
    if spec.direct_family is None or family_evidence is None:
        _fail(f"CHANGE_CPE has no direct family for {spec.name}")
    exact = [
        cpe
        for cpe in family_evidence["cpe_names"]
        if (
            (parsed := parse_cpe23(cpe)).is_valid
            and parsed.name is not None
            and parsed.name.attribute("version").canonical == spec.actual_version
        )
    ]
    if len(exact) != 1:
        _fail(f"CHANGE_CPE has no unique exact direct CPE for {spec.name}")
    return exact[0], "OFFICIAL_CPE_MAPPED"


def _semantic_duplicate_groups(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        key = (
            re.sub(r"[^a-z0-9]", "", row["audited_actual_vendor"].lower()),
            re.sub(r"[^a-z0-9]", "", row["audited_actual_product"].lower()),
            row["audited_actual_version"].lower(),
        )
        if row["recommended_gt_cpe"]:
            grouped[key].append(row)
    return [
        {
            "actual_product_key": list(key),
            "component_ids": [row["component_id"] for row in members],
            "component_names": [row["name"] for row in members],
            "recommended_gt_cpes": sorted(
                {row["recommended_gt_cpe"] for row in members}
            ),
        }
        for key, members in grouped.items()
        if len({row["recommended_gt_cpe"] for row in members}) > 1
    ]


def _projected_decisions(
    current_counts: Counter[str],
    rows: list[dict[str, str]],
) -> dict[str, int]:
    projected = Counter(current_counts)
    for row in rows:
        current = row["current_validation_result"]
        recommended = row["recommended_validation_result"]
        if current != recommended:
            projected[current] -= 1
            projected[recommended] += 1
    return {
        decision: projected[decision]
        for decision in EXPECTED_CURRENT_DECISIONS
    }


def build_product_boundary_full_audit(
    *,
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
    repository_root: Path | None = None,
    finalized: bool = False,
) -> ProductBoundaryAuditAnalysis:
    root = repository_root or settings.REPOSITORY_ROOT
    snapshots = _snapshot_metadata(cpe_snapshot, nvd_snapshot)
    if len(BOUNDARY_SPECS) != EXPECTED_CPE_BEARING_COUNT:
        _fail("Independent product-boundary registry must contain exactly 40 rows")
    boundary_specs = {
        name: spec
        for name, spec in BOUNDARY_SPECS.items()
        if not finalized or name != "wireguard-tools"
    }
    expected_cpe_bearing_count = (
        FINAL_CPE_BEARING_COUNT if finalized else EXPECTED_CPE_BEARING_COUNT
    )
    expected_decisions = (
        FINAL_CURRENT_DECISIONS if finalized else EXPECTED_CURRENT_DECISIONS
    )
    representative_nvd_components = (
        REPRESENTATIVE_NVD_REVIEW_COMPONENTS - {"wireguard-tools"}
        if finalized
        else REPRESENTATIVE_NVD_REVIEW_COMPONENTS
    )
    if len(boundary_specs) != expected_cpe_bearing_count:
        _fail("Product-boundary registry does not match the requested state")

    artifact_hashes_before = _protected_artifact_hashes(root)
    database_before = _database_state(cpe_snapshot)
    if (
        database_before["component_count"] != EXPECTED_COMPONENT_COUNT
        or database_before["ground_truth_count"] != EXPECTED_COMPONENT_COUNT
        or database_before["cpe_bearing_count"] != expected_cpe_bearing_count
    ):
        _fail("Unexpected current Unitronics DB topology")

    records = list(
        ComponentCpeGroundTruth.objects.filter(
            component__sbom_document_id=SBOM_DOCUMENT_ID,
            snapshot=cpe_snapshot,
        )
        .filter(
            Q(ground_truth_cpe__isnull=False)
            | ~Q(manual_ground_truth_cpe="")
        )
        .select_related("component", "ground_truth_cpe")
        .order_by("component_id")
    )
    scope_ids = {record.component_id for record in records}
    spec_ids = {spec.component_id for spec in boundary_specs.values()}
    if len(records) != expected_cpe_bearing_count or scope_ids != spec_ids:
        _fail(
            "Current CPE-bearing scope does not match the independent "
            f"{expected_cpe_bearing_count}-row registry"
        )

    packages = {
        int(row["component_id"]): row
        for row in _read_csv(root / RESULTS_ROOT / PACKAGE_RELATIVE)
    }
    preanalysis = {
        int(row["component_id"]): row
        for row in _read_csv(root / RESULTS_ROOT / PREANALYSIS_RELATIVE)
    }

    # Independent actual-product and direct-family evidence is completed here.
    # Current CPE strings and decisions are not read until these drafts exist.
    family_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
    nvd_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
    independent: dict[int, dict[str, Any]] = {}
    for spec in boundary_specs.values():
        exact = _exact_firmware_evidence(spec, packages, preanalysis)
        direct_family = None
        direct_nvd = None
        if spec.direct_family is not None:
            if spec.direct_family not in family_cache:
                family_cache[spec.direct_family] = _family_evidence(
                    cpe_snapshot, spec.direct_family
                )
            if spec.direct_family not in nvd_cache:
                nvd_cache[spec.direct_family] = _nvd_family_evidence(
                    nvd_snapshot, spec.direct_family
                )
            direct_family = family_cache[spec.direct_family]
            direct_nvd = nvd_cache[spec.direct_family]
        independent[spec.component_id] = {
            "spec": spec,
            "exact": exact,
            "direct_family": direct_family,
            "direct_nvd": direct_nvd,
        }
    wireguard_direct = _wireguard_direct_search(cpe_snapshot, nvd_snapshot)

    current_decisions = Counter(
        ComponentCpeGroundTruth.objects.filter(
            component__sbom_document_id=SBOM_DOCUMENT_ID,
            snapshot=cpe_snapshot,
        ).values_list("decision", flat=True)
    )
    if {
        decision: current_decisions[decision]
        for decision in expected_decisions
    } != expected_decisions:
        _fail("Unexpected current Ground Truth decision distribution")

    rows: list[dict[str, str]] = []
    nvd_review_requests: dict[str, list[str]] = {}
    current_parse_failures = 0
    for record in records:
        draft = independent[record.component_id]
        spec: BoundarySpec = draft["spec"]
        current_cpe = _current_cpe(record)
        parsed = parse_cpe23(current_cpe)
        if not parsed.is_valid or parsed.name is None:
            current_parse_failures += 1
            continue
        current_family = parsed.name.family
        if current_family not in family_cache:
            family_cache[current_family] = _family_evidence(
                cpe_snapshot, current_family
            )
        if current_family not in nvd_cache:
            nvd_cache[current_family] = _nvd_family_evidence(
                nvd_snapshot, current_family
            )
        current_family_evidence = family_cache[current_family]
        current_nvd = nvd_cache[current_family]
        compatibility = _family_compatibility_counts(
            current_family_evidence,
            parsed.name,
        )
        direct_found = bool(
            draft["direct_family"]
            and draft["direct_family"]["entry_count"]
        )
        configuration_only_found = False
        if spec.name == "wireguard-tools":
            direct_found = bool(wireguard_direct["dictionary_matches"])
            configuration_only_found = bool(
                wireguard_direct["configuration_matches"]
            )
        classification = classify_boundary(
            spec=spec,
            current_family=current_family,
            direct_family_found=direct_found,
            configuration_only_found=configuration_only_found,
        )
        recommended_cpe, recommended_decision = _recommendation(
            status=classification["audit_status"],
            current_cpe=current_cpe,
            current_decision=record.decision,
            spec=spec,
            family_evidence=draft["direct_family"],
        )
        exact = draft["exact"]
        if spec.name in representative_nvd_components:
            nvd_review_requests[spec.name] = [
                str(example["cve_record__cve_id"])
                for example in current_nvd["examples"]
            ]
        rows.append(
            {
                "component_id": str(spec.component_id),
                "name": spec.name,
                "observed_version": spec.observed_version,
                "audited_actual_vendor": spec.actual_vendor,
                "audited_actual_product": spec.actual_product,
                "audited_actual_version": spec.actual_version,
                "exact_firmware_evidence": _json(exact),
                "official_upstream_evidence": _json(spec.official_urls),
                "official_product_boundary": spec.boundary_reason,
                "current_gt_cpe": current_cpe,
                "current_validation_result": record.decision,
                "cpe_family_part": current_family[0],
                "cpe_family_vendor": current_family[1],
                "cpe_family_product": current_family[2],
                "cpe_family_entry_count": str(
                    current_family_evidence["entry_count"]
                ),
                "cpe_family_active_count": str(
                    current_family_evidence["active_count"]
                ),
                "cpe_family_deprecated_count": str(
                    current_family_evidence["deprecated_count"]
                ),
                "cpe_family_deprecated_by_edge_count": str(
                    current_family_evidence["deprecated_by_edge_count"]
                ),
                "cpe_family_active_exact_version_count": str(
                    compatibility["active_exact_version_count"]
                ),
                "cpe_family_active_exact_compatible_count": str(
                    compatibility["active_exact_compatible_count"]
                ),
                "cpe_family_template_compatible_count": str(
                    compatibility["template_compatible_count"]
                ),
                "cpe_family_version_summary": current_family_evidence[
                    "version_summary"
                ],
                "cpe_family_attribute_summary": current_family_evidence[
                    "attribute_summary"
                ],
                "cpe_title_summary": current_family_evidence["title_summary"],
                "cpe_reference_summary": current_family_evidence[
                    "reference_summary"
                ],
                "nvd_configuration_occurrences": str(
                    current_nvd["occurrences"]
                ),
                "nvd_configuration_cve_count": str(current_nvd["cve_count"]),
                "nvd_distinct_criteria_count": str(
                    current_nvd["criteria_count"]
                ),
                "nvd_criteria_examples": _json(current_nvd["examples"]),
                "nvd_operator_summary": _json(
                    current_nvd["operator_summary"]
                ),
                "nvd_usage_summary": (
                    current_nvd["usage_summary"]
                    + (
                        "; " + NVD_USAGE_INTERPRETATIONS[spec.name]
                        if spec.name in NVD_USAGE_INTERPRETATIONS
                        else ""
                    )
                ),
                "nvd_representative_case_review": "",
                "product_boundary_status": classification[
                    "product_boundary_status"
                ],
                "version_space_status": classification["version_space_status"],
                "direct_actual_product_cpe_found": _bool(direct_found),
                "configuration_only_actual_product_found": _bool(
                    configuration_only_found
                ),
                "risk_flags": _json(spec.risk_flags),
                "circular_evidence_risk": "false",
                "audit_status": classification["audit_status"],
                "recommended_gt_cpe": recommended_cpe,
                "recommended_validation_result": recommended_decision,
                "audit_reason": classification["reason"],
                "evidence_strength": spec.evidence_strength,
            }
        )

    if current_parse_failures or len(rows) != expected_cpe_bearing_count:
        _fail("Canonical current GT CPE parse failure detected")
    rows.sort(key=lambda row: int(row["component_id"]))
    nvd_reviews, nvd_raw_feeds = _load_raw_cve_reviews(
        root,
        nvd_review_requests,
    )
    if (
        set(nvd_review_requests) != representative_nvd_components
        or any(not cve_ids for cve_ids in nvd_review_requests.values())
    ):
        _fail("Representative high-risk NVD review coverage is incomplete")
    for row in rows:
        row["nvd_representative_case_review"] = _json(
            nvd_reviews.get(row["name"], [])
        )
    wireguard_rows = [row for row in rows if row["name"] == "wireguard-tools"]
    if finalized:
        wireguard_record = ComponentCpeGroundTruth.objects.select_related(
            "ground_truth_cpe"
        ).get(
            component_id=200186,
            snapshot=cpe_snapshot,
        )
        if (
            wireguard_rows
            or _current_cpe(wireguard_record)
            or wireguard_record.decision
            != "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
        ):
            _fail("Approved WireGuard product-boundary removal was not retained")
    elif (
        len(wireguard_rows) != 1
        or wireguard_rows[0]["audit_status"] != "REMOVE_CPE"
    ):
        _fail("Known WireGuard product-boundary defect was not re-detected")
    if wireguard_direct["dictionary_matches"]:
        _fail("Unexpected direct wireguard-tools Dictionary product")
    if wireguard_direct["configuration_matches"]:
        _fail("Unexpected direct wireguard-tools NVD Configuration expression")
    if wireguard_direct["canonical_parse_failure_count"]:
        _fail("Canonical parse failure in direct wireguard-tools NVD search")

    family_parse_failures = sum(
        evidence["canonical_parse_failure_count"]
        for evidence in family_cache.values()
    )
    if family_parse_failures:
        _fail("Canonical parse failure in an audited CPE family")
    version_not_registered_rows = [
        row
        for row in rows
        if row["current_validation_result"] == "VERSION_NOT_IN_DICTIONARY"
    ]
    expected_vnr_count = 16 if finalized else 17
    if len(version_not_registered_rows) != expected_vnr_count:
        _fail(
            "Version Not Registered scope is not exactly "
            f"{expected_vnr_count} rows"
        )
    for row in version_not_registered_rows:
        if row["audit_status"] != "KEEP":
            continue
        if (
            row["product_boundary_status"] != "SAME_PRODUCT"
            or int(row["cpe_family_active_count"]) == 0
            or int(row["cpe_family_active_exact_compatible_count"]) != 0
            or int(row["cpe_family_template_compatible_count"]) == 0
        ):
            _fail(
                "Version Not Registered invariants failed for "
                f"{row['name']}"
            )
    if any(
        row["recommended_gt_cpe"]
        and CpeName.objects.filter(
            snapshot=cpe_snapshot,
            cpe_name=row["recommended_gt_cpe"],
            deprecated=True,
        ).exists()
        for row in rows
    ):
        _fail("Deprecated CPE selected as a final recommendation")

    status_counts = Counter(row["audit_status"] for row in rows)
    strength_counts = Counter(row["evidence_strength"] for row in rows)
    boundary_mismatches = sum(
        row["product_boundary_status"] == "DIFFERENT_PRODUCT"
        for row in rows
    )
    version_mismatches = sum(
        row["version_space_status"] == "MISMATCH" for row in rows
    )
    direct_replacements = sum(
        row["audit_status"] == "CHANGE_CPE" for row in rows
    )
    no_direct = sum(
        row["direct_actual_product_cpe_found"] == "false"
        and row["configuration_only_actual_product_found"] == "false"
        for row in rows
    )
    configuration_gate_violations = sum(
        row["recommended_validation_result"] == "NVD_CONFIGURATION_ONLY"
        and (
            row["direct_actual_product_cpe_found"] != "false"
            or row["configuration_only_actual_product_found"] != "true"
        )
        for row in rows
    )
    if configuration_gate_violations:
        _fail("Configuration-only gate violation detected")
    semantic_duplicates = _semantic_duplicate_groups(rows)
    projected_decisions = _projected_decisions(current_decisions, rows)
    projected_cpes = [
        canonical
        for row in rows
        if row["recommended_gt_cpe"]
        and (canonical := canonicalize_cpe23(row["recommended_gt_cpe"]))
    ]
    canonical_current = [
        canonicalize_cpe23(row["current_gt_cpe"]) for row in rows
    ]
    high_risk_rows = [row for row in rows if row["risk_flags"] != "[]"]

    database_after = _database_state(cpe_snapshot)
    artifact_hashes_after = _protected_artifact_hashes(root)
    if database_before != database_after:
        _fail("Ground Truth or Component DB mutation detected")
    if artifact_hashes_before != artifact_hashes_after:
        _fail("Existing candidate/audit artifact mutation detected")

    summary = {
        "schema_version": 1,
        "audit": "Unitronics full CPE product-boundary audit",
        "mode": "READ_ONLY",
        "dataset": {
            "dataset_key": DATASET_KEY,
            "sbom_document_id": SBOM_DOCUMENT_ID,
            "manufacturer": "Unitronics",
            "product": "UCR-ST-B8",
            "firmware_version": "52.07.13.7",
            "component_count": EXPECTED_COMPONENT_COUNT,
        },
        "snapshots": snapshots,
        "scope": {
            "input_cpe_bearing_components": len(rows),
            "unique_component_ids": len({row["component_id"] for row in rows}),
            "excluded_no_direct_cpe_components": 538 if finalized else 537,
            "excluded_unresolved_components": 5,
            "current_cpe_bearing": len(canonical_current),
            "current_distinct_canonical_cpes": len(set(canonical_current)),
            "current_duplicate_groups": sum(
                count > 1 for count in Counter(canonical_current).values()
            ),
        },
        "audit_status": {
            status: status_counts[status] for status in AUDIT_STATUSES
        },
        "statistics": {
            "product_boundary_mismatch_count": boundary_mismatches,
            "version_space_mismatch_count": version_mismatches,
            "direct_replacement_cpe_found_count": direct_replacements,
            "no_direct_product_cpe_count": no_direct,
            "circular_evidence_risk_count": sum(
                row["circular_evidence_risk"] == "true" for row in rows
            ),
            "high_risk_case_count": len(high_risk_rows),
            "semantic_product_duplicate_count": len(semantic_duplicates),
            "semantic_product_duplicates": semantic_duplicates,
        },
        "by_current_validation_result": {
            decision: {
                status: sum(
                    row["current_validation_result"] == decision
                    and row["audit_status"] == status
                    for row in rows
                )
                for status in AUDIT_STATUSES
            }
            for decision in (
                "CPE_CONFIRMED",
                "OFFICIAL_CPE_MAPPED",
                "VERSION_NOT_IN_DICTIONARY",
            )
        },
        "evidence_strength": {
            strength: strength_counts[strength]
            for strength in EVIDENCE_STRENGTHS
        },
        "wireguard_regression": {
            "detected": not finalized,
            "approved_removal_retained": finalized,
            "audit_status": (
                "REMOVED_FROM_CPE_BEARING_SCOPE"
                if finalized
                else "REMOVE_CPE"
            ),
            "actual_product": "wireguard-tools",
            "actual_version": "1.0.20210223",
            "current_family": "a:wireguard:wireguard",
            "direct_dictionary_matches": wireguard_direct[
                "dictionary_matches"
            ],
            "direct_configuration_matches": wireguard_direct[
                "configuration_matches"
            ],
            "known_family_related_criteria": wireguard_direct[
                "related_criteria"
            ],
        },
        "representative_nvd_review": {
            "components": sorted(nvd_review_requests),
            "case_count": sum(len(cases) for cases in nvd_reviews.values()),
            "raw_feeds": nvd_raw_feeds,
        },
        "changes": [
            {
                key: row[key]
                for key in (
                    "component_id",
                    "name",
                    "current_gt_cpe",
                    "current_validation_result",
                    "audit_status",
                    "recommended_gt_cpe",
                    "recommended_validation_result",
                    "audit_reason",
                )
            }
            for row in rows
            if row["audit_status"] != "KEEP"
        ],
        "projection": {
            "current_cpe_bearing": len(canonical_current),
            "projected_cpe_bearing": len(projected_cpes),
            "projected_distinct_canonical_cpes": len(set(projected_cpes)),
            "projected_duplicate_groups": sum(
                count > 1 for count in Counter(projected_cpes).values()
            ),
            "current_validation_result_distribution": {
                decision: current_decisions[decision]
                for decision in expected_decisions
            },
            "projected_validation_result_distribution": projected_decisions,
        },
        "methodology_conclusion": {
            "add_explicit_product_boundary_verification": True,
            "reason": (
                "The final 39-row audit retains only mappings whose official "
                "upstream product boundaries agree with CPE family metadata and "
                "fixed-snapshot NVD usage context."
                if finalized
                else "The fixed 40-row audit re-detected one mapping that passed "
                "a family-existence/version-resolution workflow but failed "
                "official upstream product-boundary and NVD usage-context "
                "verification."
            ),
        },
        "validation": {
            "input_row_count": len(rows),
            "unique_component_id_count": len(
                {row["component_id"] for row in rows}
            ),
            "canonical_current_gt_parse_failure_count": current_parse_failures,
            "audited_family_canonical_parse_failure_count": family_parse_failures,
            "wireguard_known_defect_redetected": not finalized,
            "wireguard_approved_removal_retained": finalized,
            "finalized_state": finalized,
            "fixed_cpe_snapshot_only": True,
            "fixed_nvd_snapshot_only": True,
            "configuration_only_gate_violation_count": (
                configuration_gate_violations
            ),
            "deprecated_final_recommendation_count": 0,
            "version_not_registered_input_count": len(
                version_not_registered_rows
            ),
            "version_not_registered_keep_all_invariants_count": sum(
                row["audit_status"] == "KEEP"
                and row["product_boundary_status"] == "SAME_PRODUCT"
                and int(row["cpe_family_active_count"]) > 0
                and int(row["cpe_family_active_exact_compatible_count"]) == 0
                and int(row["cpe_family_template_compatible_count"]) > 0
                for row in version_not_registered_rows
            ),
            "ground_truth_db_mutation_count": 0,
            "component_mutation_count": 0,
            "candidate_artifact_mutation_count": 0,
            "existing_audit_artifact_mutation_count": 0,
            "migration_count": 0,
            "commit_count": 0,
            "database_state_before": database_before,
            "database_state_after": database_after,
            "protected_artifact_hashes_before": artifact_hashes_before,
            "protected_artifact_hashes_after": artifact_hashes_after,
        },
    }
    return ProductBoundaryAuditAnalysis(rows, high_risk_rows, summary)


def _report(analysis: ProductBoundaryAuditAnalysis) -> str:
    summary = analysis.summary
    statuses = summary["audit_status"]
    statistics = summary["statistics"]
    projection = summary["projection"]
    validation = summary["validation"]
    representative_review = summary["representative_nvd_review"]
    by_result = summary["by_current_validation_result"]
    changes = summary["changes"]
    change_table = "\n".join(
        f"| {row['component_id']} | `{row['name']}` | {row['audit_status']} | "
        f"`{row['recommended_gt_cpe'] or 'null'}` | "
        f"`{row['recommended_validation_result']}` | {row['audit_reason']} |"
        for row in changes
    ) or "| - | None | - | - | - | No changes required. |"
    risk_table = "\n".join(
        f"| {row['component_id']} | `{row['name']}` | "
        f"{row['risk_flags'].replace('|', '/')} | "
        f"{row['product_boundary_status']} | {row['audit_status']} | "
        f"{row['official_product_boundary']} |"
        for row in analysis.high_risk_rows
    )
    decision_rows = "\n".join(
        f"| `{decision}` | {counts['KEEP']} | {counts['CHANGE_CPE']} | "
        f"{counts['REMOVE_CPE']} | {counts['REVIEW_REQUIRED']} |"
        for decision, counts in by_result.items()
    )
    projected_rows = "\n".join(
        f"| `{decision}` | "
        f"{projection['current_validation_result_distribution'][decision]} | "
        f"{projection['projected_validation_result_distribution'][decision]} |"
        for decision in EXPECTED_CURRENT_DECISIONS
    )
    finalized = bool(validation.get("finalized_state"))
    distribution_finding = (
        "All 21 `OFFICIAL_CPE_MAPPED` rows, both `CPE_CONFIRMED` rows, and "
        "all 16 `VERSION_NOT_IN_DICTIONARY` rows remain KEEP."
        if finalized
        else "All 21 `OFFICIAL_CPE_MAPPED` rows and both `CPE_CONFIRMED` rows "
        "remain KEEP. Of the 17 `VERSION_NOT_IN_DICTIONARY` rows, 16 have an "
        "aligned upstream/CPE family and one (`wireguard-tools`) has a "
        "different product boundary."
    )
    wireguard_section = (
        """## WireGuard approved-removal regression

The final-state regression check **PASS**ed: `wireguard-tools` is absent from
the CPE-bearing scope, its GT CPE is null, and its result is
`DIRECT_OFFICIAL_CPE_NOT_CONFIRMED`. The approved pre-change audits remain
unchanged.
"""
        if finalized
        else """## WireGuard known-defect regression

The regression check **PASS**ed:

```text
Component: wireguard-tools
Actual product/version: wireguard-tools 1.0.20210223
Current family: wireguard:wireguard
Audit: REMOVE_CPE
Direct Dictionary product: none
Direct NVD Configuration expression: none
Recommended GT CPE: null
Recommended result: DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
```

The only fixed Dictionary `wireguard:wireguard` entry is version `0.5.3`, its
version reference points to `wireguard-windows`, and both fixed NVD occurrences
are Windows-constrained AND configurations. This is incompatible with the
officially separate `wireguard-tools` `1.0.YYYYMMDD` release space.
"""
    )
    methodology_statement = (
        "The final 39-row state satisfies the explicit official upstream "
        "product-boundary check for every retained CPE mapping."
        if finalized
        else "The final Ground Truth methodology should explicitly require "
        "official upstream product-boundary and fixed NVD usage-context "
        "verification. An Active CPE family or a compatible version template "
        "is insufficient by itself."
    )
    return f"""# Unitronics Ground Truth full product-boundary audit

## Scope and result

- Mode: **READ-ONLY**
- Firmware: `Unitronics UCR-ST-B8 52.07.13.7`
- SBOMDocument: `{SBOM_DOCUMENT_ID}`
- CPE Dictionary snapshot: `{CPE_SNAPSHOT_ID}`
- NVD CVE/Configuration snapshot: `{NVD_SNAPSHOT_ID}`
- Input CPE-bearing Components: **{summary['scope']['input_cpe_bearing_components']}**

| Audit status | Count |
|---|---:|
| KEEP | {statuses['KEEP']} |
| CHANGE_CPE | {statuses['CHANGE_CPE']} |
| REMOVE_CPE | {statuses['REMOVE_CPE']} |
| REVIEW_REQUIRED | {statuses['REVIEW_REQUIRED']} |

The audit independently reconstructed actual product/version from exact firmware
package, Source, description, dependency, and payload evidence before reading the
current GT CPE or validation result. Official upstream project boundaries were
then compared with complete fixed-Snapshot CPE families and their fixed NVD
Configuration usage.

## Findings by current validation result

| Current validation result | KEEP | CHANGE_CPE | REMOVE_CPE | REVIEW_REQUIRED |
|---|---:|---:|---:|---:|
{decision_rows}

- Product-boundary mismatches: **{statistics['product_boundary_mismatch_count']}**
- Version-space mismatches: **{statistics['version_space_mismatch_count']}**
- Direct replacement CPEs found: **{statistics['direct_replacement_cpe_found_count']}**
- Actual products with neither direct Dictionary nor Configuration expression: **{statistics['no_direct_product_cpe_count']}**
- Circular-evidence risks: **{statistics['circular_evidence_risk_count']}**
- Semantic product duplicates: **{statistics['semantic_product_duplicate_count']}**
- Representative raw-feed CVE reviews: **{representative_review['case_count']}** across **{len(representative_review['components'])}** high-risk families

{distribution_finding}

{wireguard_section}

## Recommended changes

| Component ID | Component | Audit | Recommended GT CPE | Recommended result | Reason |
|---:|---|---|---|---|---|
{change_table}

No additional incorrect product-boundary mapping was found.

## High-risk cases

The following rows were expanded because their package name, vendor label,
library/application role, build flavor, platform, or upstream subproject boundary
could otherwise invite a name-based mapping error. Full family metadata and NVD
criteria/operator examples are in `audit_results.csv`.

| ID | Component | Risk flags | Boundary | Audit | Finding |
|---:|---|---|---|---|---|
{risk_table}

Notable resolved boundaries include:

- `curl` and `libcurl` are two explicit products of one upstream project and
  correctly use separate `haxx:curl` and `haxx:libcurl` families. The fixed NVD
  usage of `haxx:curl` is nevertheless mixed and includes libcurl wording, so
  the curl KEEP result is MODERATE and is based on exact CLI payload plus the
  official/Dictionary product split, not on NVD wording alone.
- Official Mosquitto documentation explicitly includes the broker, clients, and
  libmosquitto client library in the Mosquitto project boundary.
- The nghttp2 project's reusable C library is its core HTTP/2 framing
  implementation, so `libnghttp2-14` remains within `nghttp2:nghttp2`.
- `davici` and `minizip-ng` are independently named/released subprojects and
  correctly use their direct families instead of their umbrella projects.
- `openvpn-openssl` is an OpenSSL-linked build flavor of OpenVPN Community
  Edition; it is not a separate upstream product.

## Projected state if recommendations are applied

- Current CPE-bearing: **{projection['current_cpe_bearing']}**
- Projected CPE-bearing: **{projection['projected_cpe_bearing']}**
- Projected distinct canonical CPEs: **{projection['projected_distinct_canonical_cpes']}**
- Projected duplicate groups: **{projection['projected_duplicate_groups']}**

| Validation result | Current | Projected |
|---|---:|---:|
{projected_rows}

These are projections only. No recommendation was applied.

## Methodology conclusion

{methodology_statement}

## Validation

- Input rows / unique Component IDs: **{validation['input_row_count']} / {validation['unique_component_id_count']}**
- Canonical current GT parse failures: **{validation['canonical_current_gt_parse_failure_count']}**
- Audited family canonical parse failures: **{validation['audited_family_canonical_parse_failure_count']}**
- Version Not Registered rows / KEEP rows satisfying every family invariant: **{validation['version_not_registered_input_count']} / {validation['version_not_registered_keep_all_invariants_count']}**
- WireGuard known defect re-detected: **{validation['wireguard_known_defect_redetected']}**
- WireGuard approved removal retained: **{validation['wireguard_approved_removal_retained']}**
- Configuration-only gate violations: **{validation['configuration_only_gate_violation_count']}**
- Deprecated final recommendations: **{validation['deprecated_final_recommendation_count']}**
- Ground Truth DB mutation: **{validation['ground_truth_db_mutation_count']}**
- Component mutation: **{validation['component_mutation_count']}**
- Candidate artifact mutation: **{validation['candidate_artifact_mutation_count']}**
- Existing audit artifact mutation: **{validation['existing_audit_artifact_mutation_count']}**
- Migration: **{validation['migration_count']}**
- Commit: **{validation['commit_count']}**

Official evidence URLs are recorded per Component in `audit_results.csv`.
Dictionary titles/references and fixed NVD criteria, ranges, and AND/OR contexts
are derived only from the two fixed snapshots named above.
"""


def _write_csv(
    path: Path,
    rows: list[dict[str, str]],
    fields: tuple[str, ...],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows({field: row[field] for field in fields} for row in rows)


def write_product_boundary_full_audit(
    analysis: ProductBoundaryAuditAnalysis,
    output_directory: Path,
) -> list[Path]:
    output_directory.mkdir(parents=True, exist_ok=False)
    audit_results = output_directory / "audit_results.csv"
    high_risk = output_directory / "high_risk_cases.csv"
    report = output_directory / "audit_report.md"
    summary = output_directory / "summary.json"
    _write_csv(audit_results, analysis.rows, AUDIT_FIELDS)
    _write_csv(high_risk, analysis.high_risk_rows, HIGH_RISK_FIELDS)
    report.write_text(_report(analysis), encoding="utf-8", newline="\n")
    summary.write_text(
        json.dumps(analysis.summary, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return [report, audit_results, high_risk, summary]

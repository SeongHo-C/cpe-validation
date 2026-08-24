# Unitronics Ground Truth full product-boundary audit

## Scope and result

- Mode: **READ-ONLY**
- Firmware: `Unitronics UCR-ST-B8 52.07.13.7`
- SBOMDocument: `1364`
- CPE Dictionary snapshot: `20260819T035002Z`
- NVD CVE/Configuration snapshot: `20260820T110357Z`
- Input CPE-bearing Components: **40**

| Audit status | Count |
|---|---:|
| KEEP | 39 |
| CHANGE_CPE | 0 |
| REMOVE_CPE | 1 |
| REVIEW_REQUIRED | 0 |

The audit independently reconstructed actual product/version from exact firmware
package, Source, description, dependency, and payload evidence before reading the
current GT CPE or validation result. Official upstream project boundaries were
then compared with complete fixed-Snapshot CPE families and their fixed NVD
Configuration usage.

## Findings by current validation result

| Current validation result | KEEP | CHANGE_CPE | REMOVE_CPE | REVIEW_REQUIRED |
|---|---:|---:|---:|---:|
| `CPE_CONFIRMED` | 2 | 0 | 0 | 0 |
| `OFFICIAL_CPE_MAPPED` | 21 | 0 | 0 | 0 |
| `VERSION_NOT_IN_DICTIONARY` | 16 | 0 | 1 | 0 |

- Product-boundary mismatches: **1**
- Version-space mismatches: **1**
- Direct replacement CPEs found: **0**
- Actual products with neither direct Dictionary nor Configuration expression: **1**
- Circular-evidence risks: **0**
- Semantic product duplicates: **0**
- Representative raw-feed CVE reviews: **23** across **8** high-risk families

All 21 `OFFICIAL_CPE_MAPPED` rows and both `CPE_CONFIRMED` rows remain KEEP.
Of the 17 `VERSION_NOT_IN_DICTIONARY` rows, 16 have an aligned upstream/CPE
family and one (`wireguard-tools`) has a different product boundary.

## WireGuard known-defect regression

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

## Recommended changes

| Component ID | Component | Audit | Recommended GT CPE | Recommended result | Reason |
|---:|---|---|---|---|---|
| 200186 | `wireguard-tools` | REMOVE_CPE | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` | wireguard-tools is the separately released wg/wg-quick userspace-tools project. The wireguard:wireguard 0.5.3 family instead aligns with the separately versioned Windows client. No direct Dictionary family or fixed NVD Configuration expression exists for the actual product. |

No additional incorrect product-boundary mapping was found.

## High-risk cases

The following rows were expanded because their package name, vendor label,
library/application role, build flavor, platform, or upstream subproject boundary
could otherwise invite a name-based mapping error. Full family metadata and NVD
criteria/operator examples are in `audit_results.csv`.

| ID | Component | Risk flags | Boundary | Audit | Finding |
|---:|---|---|---|---|---|
| 199625 | `curl` | ["UMBRELLA_PROJECT_SUBPRODUCT", "CLI_VS_LIBRARY", "MIXED_NVD_USAGE"] | SAME_PRODUCT | KEEP | The curl project explicitly distinguishes the curl command-line product from the libcurl library; /usr/bin/curl maps to the curl family. |
| 199653 | `davici` | ["UMBRELLA_PROJECT_SUBPROJECT", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | davici is the separately released Decoupled Asynchronous VICI client library under the strongSwan organization, and has a direct davici CPE family. |
| 199663 | `ethtool` | ["VENDOR_LABEL_DIFFERS", "USERSPACE_TOOL_IN_KERNEL_NAMESPACE"] | SAME_PRODUCT | KEEP | ethtool is a separately released userspace networking utility hosted by kernel.org; the kernel:ethtool CPE references that release archive. |
| 199665 | `exfat-mkfs` | ["PACKAGE_NAME_DIFFERS", "UTILITY_WITHIN_PRODUCT"] | SAME_PRODUCT | KEEP | exfat-mkfs is the mkfs utility built by the exfatprogs upstream project and the CPE family directly names exfatprogs. |
| 199683 | `ip-full` | ["DISTRIBUTION_PACKAGE_ALIAS", "UTILITY_WITHIN_PRODUCT"] | SAME_PRODUCT | KEEP | ip-full is OpenWrt's full ip utility package from the iproute2 source product; it is not a separate upstream product. |
| 199691 | `iw-515` | ["DISTRIBUTION_PACKAGE_ALIAS", "USERSPACE_TOOL_IN_KERNEL_NAMESPACE"] | SAME_PRODUCT | KEEP | iw-515 is a distribution package name for the upstream iw userspace wireless utility; the kernel:iw CPE references the same release archive. |
| 199845 | `libc` | ["GENERIC_PACKAGE_NAME", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The firmware loader/libc payload identifies musl rather than a generic libc product, and the CPE family directly identifies musl. |
| 199847 | `libcap-ng` | ["SIMILAR_PRODUCT_NAMES", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The installed libcap-ng library is the direct libcap-ng upstream product, distinct from libcap. |
| 199848 | `libcap` | ["LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The installed capability library and the libcap family are the same upstream product. |
| 199849 | `libcares` | ["PACKAGE_NAME_DIFFERS", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | libcares is the distribution package for the c-ares asynchronous DNS library and the CPE directly names c-ares. |
| 199854 | `libcurl4` | ["UMBRELLA_PROJECT_SUBPRODUCT", "CLI_VS_LIBRARY"] | SAME_PRODUCT | KEEP | The curl project explicitly defines libcurl as its client-side transfer library, separate from the curl CLI, and the CPE family directly names libcurl. |
| 199866 | `libjson-c5` | ["ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The ABI-suffixed distribution package contains the json-c library and maps to the direct json-c family. |
| 199871 | `liblzo2` | ["ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The ABI-suffixed package contains the LZO compression library represented by the LZO family. |
| 199875 | `libmnl0` | ["ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The installed library is Netfilter's separately released libmnl project and has a direct libmnl family. |
| 199877 | `libmosquitto-ssl` | ["LIBRARY_VS_APPLICATION", "UMBRELLA_PROJECT_COMPONENT", "BUILD_FLAVOR"] | SAME_PRODUCT | KEEP | The official Mosquitto project definition explicitly comprises the broker, clients, and libmosquitto client library; this SSL-enabled library package remains inside the Mosquitto product boundary. |
| 199878 | `libnetfilter-conntrack3` | ["ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The ABI-suffixed package is the direct Netfilter libnetfilter_conntrack library product. |
| 199880 | `libnfnetlink0` | ["ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The ABI-suffixed package is the direct Netfilter libnfnetlink library product. |
| 199881 | `libnftnl11` | ["ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The ABI-suffixed package is the direct Netfilter libnftnl library product. |
| 199882 | `libnghttp2-14` | ["LIBRARY_VS_APPLICATION", "UMBRELLA_PROJECT_COMPONENT", "ABI_SUFFIXED_PACKAGE"] | SAME_PRODUCT | KEEP | The official nghttp2 project defines its reusable C library as the core framing implementation and also ships applications; the installed libnghttp2 remains within the nghttp2 product boundary. |
| 199888 | `libopenssl3` | ["LIBRARY_VS_APPLICATION", "SPLIT_UPSTREAM_PRODUCT"] | SAME_PRODUCT | KEEP | libssl.so.3 and libcrypto.so.3 are core OpenSSL libraries from the OpenSSL 3.0.14 source product; the family represents the OpenSSL toolkit rather than only its CLI. |
| 199890 | `libpcap1` | ["VENDOR_LABEL_DIFFERS", "LIBRARY_PRODUCT", "ABI_SUFFIXED_PACKAGE"] | SAME_PRODUCT | KEEP | The ABI-suffixed package contains the tcpdump project's separately named libpcap library, matching the direct libpcap family. |
| 199891 | `libpcre2` | ["LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The installed PCRE2 library and the pcre:pcre2 family identify the same second-generation PCRE product. |
| 199913 | `libusb-1.0-0` | ["ABI_SUFFIXED_PACKAGE", "LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The ABI-suffixed package contains the direct libusb library product. |
| 199933 | `minizip` | ["UMBRELLA_PROJECT_SUBPROJECT", "HISTORICAL_FORK_NAME"] | SAME_PRODUCT | KEEP | The installed minizip payload comes from the independently released minizip-ng repository, not from the zlib or zlib-ng core product; the CPE family directly names minizip-ng. |
| 199956 | `open62541` | ["NON_OPKG_VERSION_FORM"] | SAME_PRODUCT | KEEP | The firmware library identifies the open62541 OPC UA project and the CPE family directly names it. |
| 199959 | `openvpn-openssl` | ["BUILD_FLAVOR", "EDITION_SPECIFIC_CPE"] | SAME_PRODUCT | KEEP | openvpn-openssl is the OpenSSL-linked build flavor of OpenVPN Community Edition, not a separate upstream product; the CPE's community sw_edition preserves that boundary. |
| 200023 | `strongswan` | ["SPLIT_UPSTREAM_PRODUCT", "CLIENT_SERVER_PLUGIN_SUITE"] | SAME_PRODUCT | KEEP | The main package contains core libstrongswan and configuration from the strongSwan IPsec product; separately named subprojects such as davici retain separate families. |
| 200186 | `wireguard-tools` | ["KERNEL_VS_USERSPACE", "PLATFORM_SPECIFIC_CPE", "UMBRELLA_PROJECT_SUBPROJECT", "VERSION_SPACE_MISMATCH"] | DIFFERENT_PRODUCT | REMOVE_CPE | wireguard-tools is the separately released wg/wg-quick userspace-tools project. The wireguard:wireguard 0.5.3 family instead aligns with the separately versioned Windows client. |
| 200192 | `zlib` | ["LIBRARY_PRODUCT"] | SAME_PRODUCT | KEEP | The installed compression library and zlib family identify the same upstream product. |
| 200193 | `linux_kernel` | ["OS_PLATFORM_CPE", "KERNEL_PRODUCT"] | SAME_PRODUCT | KEEP | The exact kernel banner/module tree identifies the Linux kernel OS product represented by linux:linux_kernel, not a userspace utility. |
| 200198 | `wpa_supplicant` | ["CLIENT_SERVER_SPLIT", "PRERELEASE_VERSION"] | SAME_PRODUCT | KEEP | wpa_supplicant is the client/supplicant program within the hostap project and has its own direct CPE family distinct from hostapd. |
| 200199 | `openwrt` | ["OS_PLATFORM_CPE", "REVISION_SUFFIX"] | SAME_PRODUCT | KEEP | The firmware release identifier represents the OpenWrt operating-system distribution and maps to the OpenWrt OS family. |

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

- Current CPE-bearing: **40**
- Projected CPE-bearing: **39**
- Projected distinct canonical CPEs: **39**
- Projected duplicate groups: **0**

| Validation result | Current | Projected |
|---|---:|---:|
| `CPE_CONFIRMED` | 2 | 2 |
| `OFFICIAL_CPE_MAPPED` | 21 | 21 |
| `VERSION_NOT_IN_DICTIONARY` | 17 | 16 |
| `NVD_CONFIGURATION_ONLY` | 0 | 0 |
| `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` | 537 | 538 |
| `UNRESOLVED` | 5 | 5 |

These are projections only. No recommendation was applied.

## Methodology conclusion

**Yes.** The final Ground Truth methodology should explicitly require official
upstream product-boundary and fixed NVD usage-context verification. An Active CPE
family or a compatible version template is insufficient by itself: this audit
re-detected a mapping that passed family-existence/version-resolution checks but
represented a different platform-specific upstream product.

## Validation

- Input rows / unique Component IDs: **40 / 40**
- Canonical current GT parse failures: **0**
- Audited family canonical parse failures: **0**
- Version Not Registered rows / KEEP rows satisfying every family invariant: **17 / 16**
- WireGuard known defect re-detected: **True**
- Configuration-only gate violations: **0**
- Deprecated final recommendations: **0**
- Ground Truth DB mutation: **0**
- Component mutation: **0**
- Candidate artifact mutation: **0**
- Existing audit artifact mutation: **0**
- Migration: **0**
- Commit: **0**

Official evidence URLs are recorded per Component in `audit_results.csv`.
Dictionary titles/references and fixed NVD criteria, ranges, and AND/OR contexts
are derived only from the two fixed snapshots named above.

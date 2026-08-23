# Unitronics UCR-ST-B8 Ground Truth pre-analysis

This report is empirical pre-analysis for designing later Ground Truth 
decision rules. It does **not** assign, validate, replace, or reject any CPE.
Original SBOM CPE values and installed-control `CPE-ID` fields are retained 
only as uninterpreted metadata and are excluded from matching and identity 
classification.

## Dataset and provenance

- SBOMDocument: `1364`
- Product: `Unitronics UCR-ST-B8 52.07.13.7`
- Components: `582` (expected `582`)
- CycloneDX SHA-256: `61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e`
- Official Unitronics ZIP URL: https://downloads.unitronicsplc.com/Sites/plc/Technical_Library/Accessories/UCR-RUT%20OS-7.zip
- Observed ZIP SHA-256: `711ed9fe0cb8eaa1f4ddb8dc9523ba288e0364063740c7985b355f91a33e13f7`
- Exact firmware SHA-256: `6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c`
- The exact firmware SHA-256 equals the hash embedded in CycloneDX metadata.
- Existing DB SourceArtifact: `None`
- Exact-version SDK/GPL artifact: **not available** in the repository, DB, 
  Unitronics firmware ZIP, or the checked official public download paths.
- Other products' SDK/GPL archives were not substituted.

## Exact firmware build evidence

- OpenWrt release: `21.02.0`
- OpenWrt revision: `r16279-5cc0535800`
- Target / architecture: `ramips/mt76x8` / `mipsel_24kc`
- Kernel: `5.15.176`
- Installed opkg controls: `575`
- SDK root, feeds configuration, Makefile count, `PKG_*` assignments, 
  `Package/<name>` blocks, install rules, and `BuildPackage` calls are 
  **not observable without the exact SDK/GPL source**.

## Metadata coverage

| Field | Present | Coverage | Distinct |
|---|---:|---:|---:|
| bom-ref | 582 | 100.00% | 582 |
| name | 582 | 100.00% | 582 |
| version | 582 | 100.00% | 160 |
| cpe | 582 | 100.00% | 582 |
| properties | 582 | 100.00% | 582 |
| purl | 582 | 100.00% | 582 |
| group | 582 | 100.00% | 4 |
| publisher | 0 | 0.00% | 0 |
| supplier | 582 | 100.00% | 36 |
| author | 0 | 0.00% | 0 |
| type | 582 | 100.00% | 2 |
| externalReferences | 0 | 0.00% | 0 |
| evidence | 0 | 0.00% | 0 |

Representative values for requested discriminating fields:

- group: `['OpenWRT', 'linux_kernel', 'static_bin_analysis', 'static_distri_analysis']`
- publisher: `['(no values)']`
- type: `['library', 'operating-system']`
- purl: `['pkg:opkg/openwrt/api-core@1&distro=openwrt-21.02.0', 'pkg:opkg/openwrt/apn_db@7.13.0.2&distro=openwrt-21.02.0', 'pkg:opkg/openwrt/avl@2025-04-29-2&distro=openwrt-21.02.0', 'pkg:opkg/openwrt/base-files@2606-r16279-5cc0535800&distro=openwrt-21.02.0', 'pkg:opkg/openwrt/block-mount@2022-05-03-9e11b372-28&distro=openwrt-21.02.0']`
- supplier: `['{"name": "Unknown"}', '{"name": "John Crispin <john@phrozen.org>"}', '{"name": "Felix Fietkau <nbd@nbd.name>"}', '{"name": "Stan Grishin <stangri@melmac.ca>"}', '{"name": "Lukas Voegl <lvoegl@tdt.de>"}']`

Observed distributions:

- group: `[{'value': 'OpenWRT', 'component_count': 575}, {'value': 'static_bin_analysis', 'component_count': 5}, {'value': 'linux_kernel', 'component_count': 1}, {'value': 'static_distri_analysis', 'component_count': 1}]`
- type: `[{'value': 'library', 'component_count': 581}, {'value': 'operating-system', 'component_count': 1}]`
- publisher: `[{'value': '', 'component_count': 582}]`
- purl ecosystems: `[{'value': 'pkg:opkg/openwrt', 'component_count': 575}, {'value': 'pkg:binary', 'component_count': 7}]`

`name` identifies the installed package key; `version` is complete for 
all rows but often combines upstream/date/revision and package release; 
`properties` provides exact firmware paths. PURL adds opkg/binary ecosystem, 
OpenWrt namespace, distro, and sometimes architecture, but not an upstream 
source identity beyond name/version. `group` and `type` are almost constant; 
publisher is empty. Supplier provides maintainer/vendor hints but is not 
source provenance.

## Properties

- Raw property keys: `216`
- Semantic property keys after removing EMBA indices: `11`
- Property occurrences: `6619`
- All 582 rows contain `source_path`, `minimal_identifier`, and confidence.
- 575 `source_path` values identify installed opkg control files; seven 
  identify kernel, ELF, BusyBox multicall, shared-library, or distribution 
  artifacts. Installed-file `path` values cover 455 components.
- The raw-key-level inventory is in `property_keys.csv`.

Properties contribution to exact-firmware traceability:

| Category | Count | Percent |
|---|---:|---:|
| A_NAME_VERSION_ONLY | 0 | 0.00% |
| B_PROPERTIES_STRENGTHEN | 575 | 98.80% |
| C_PROPERTIES_ENABLE_LINK | 7 | 1.20% |
| D_PROPERTIES_RESOLVE_AMBIGUITY | 0 | 0.00% |
| E_STILL_UNLINKED | 0 | 0.00% |

Properties contribution to SDK/Makefile linkage:

| Category | Count | Percent |
|---|---:|---:|
| A_NAME_VERSION_ONLY | 0 | 0.00% |
| B_PROPERTIES_STRENGTHEN | 0 | 0.00% |
| C_PROPERTIES_ENABLE_LINK | 0 | 0.00% |
| D_PROPERTIES_RESOLVE_AMBIGUITY | 0 | 0.00% |
| E_STILL_UNLINKED | 582 | 100.00% |

The second table is all `E` because no exact SDK exists; it must not be 
read as evidence that properties are intrinsically useless.

## Version forms

| Category | Count | Percent |
|---|---:|---:|
| UPSTREAM_LIKE | 133 | 22.85% |
| PACKAGE_RELEASE | 117 | 20.10% |
| DATE_BASED | 51 | 8.76% |
| GIT_OR_REVISION | 138 | 23.71% |
| KERNEL_VERSION | 137 | 23.54% |
| VENDOR_SPECIFIC | 0 | 0.00% |
| UNKNOWN_OR_PLACEHOLDER | 0 | 0.00% |
| OTHER | 6 | 1.03% |

No version was corrected. Exact control matching verifies the installed 
package version string but does not reliably decompose `PKG_VERSION` and 
`PKG_RELEASE` without Makefiles.

## SDK/Makefile linkage

| Category | Count | Percent |
|---|---:|---:|
| DIRECT | 0 | 0.00% |
| INDIRECT | 0 | 0.00% |
| AMBIGUOUS | 0 | 0.00% |
| NO_MATCH | 582 | 100.00% |

## Exact-firmware traceability (separate denominator and evidence)

| Category | Count | Percent |
|---|---:|---:|
| CONTROL_DIRECT | 575 | 98.80% |
| BINARY_DIRECT | 7 | 1.20% |
| AMBIGUOUS | 0 | 0.00% |
| NO_MATCH | 0 | 0.00% |

All 582 components are traceable inside the exact firmware; this is not 
equivalent to SDK/Makefile linkage.

## Observed source structure

- Distinct installed-control `Source` paths: `303`
- One Source -> one installed package: `261` sources / `261` components
- One Source -> multiple installed packages: `42` sources / `314` components
- Maximum installed packages sharing one Source: `134`
- Largest observed multi-package Source groups:
  - `package/kernel/linux`: `134` installed packages
  - `package/network/services/strongswan`: `28` installed packages
  - `package/teltonika/data_sender`: `15` installed packages
  - `feeds/vuci/applications/vuci-app-data-sender/vuci-app-data-sender-api`: `13` installed packages
  - `package/network/utils/iptables`: `8` installed packages
  - `package/utils/ucode`: `7` installed packages
  - `package/libs/toolchain`: `6` installed packages
  - `package/libs/libubox`: `5` installed packages
  - `package/teltonika/ddns-scripts`: `5` installed packages
  - `package/teltonika/gps`: `5` installed packages

These counts describe installed controls in this firmware, not every 
`Package/<name>` potentially emitted by an unavailable Makefile.

## Package roles

| Category | Count | Percent |
|---|---:|---:|
| PRODUCT_OR_MAIN_PACKAGE | 36 | 6.19% |
| SPLIT_RUNTIME_PACKAGE | 10 | 1.72% |
| LIBRARY_PACKAGE | 89 | 15.29% |
| UTILITY_OR_CLI_PACKAGE | 46 | 7.90% |
| PLUGIN_OR_MODULE | 206 | 35.40% |
| DEVELOPMENT_PACKAGE | 0 | 0.00% |
| KERNEL_OR_KMOD | 145 | 24.91% |
| FIRMWARE_OR_DRIVER_ARTIFACT | 1 | 0.17% |
| BOARD_OR_CALIBRATION_DATA | 0 | 0.00% |
| META_OR_VIRTUAL_PACKAGE | 0 | 0.00% |
| VENDOR_SPECIFIC_PACKAGE | 49 | 8.42% |
| UNKNOWN | 0 | 0.00% |

Roles are structural review aids inferred from exact control Section/Source/
Description, installed paths, and naming. They are not CPE decisions.
An orthogonal vendor-source flag covers `258` components across `205` Source paths. The exclusive `VENDOR_SPECIFIC_PACKAGE` role is assigned only after more specific library/plugin/kernel/utility roles.

## Product identity status

| Category | Count | Percent |
|---|---:|---:|
| DIRECT_PRODUCT_EVIDENCE | 2 | 0.34% |
| POSSIBLE_PRODUCT | 81 | 13.92% |
| PARTIAL_OR_SPLIT_COMPONENT | 449 | 77.15% |
| NON_PRODUCT_ARTIFACT | 1 | 0.17% |
| AMBIGUOUS | 0 | 0.00% |
| UNRESOLVED | 49 | 8.42% |

`DIRECT_PRODUCT_EVIDENCE` is limited to the separately detected OpenWrt 
release and Linux kernel banner. `POSSIBLE_PRODUCT` does not authorize a CPE.

## Version relationship

| Category | Count | Percent |
|---|---:|---:|
| EXACT | 0 | 0.00% |
| PACKAGE_RELEASE_SUFFIX | 0 | 0.00% |
| SOURCE_VERSION_AVAILABLE | 0 | 0.00% |
| DATE_BASED | 0 | 0.00% |
| GIT_OR_REVISION_BASED | 0 | 0.00% |
| VENDOR_TRANSFORMED | 0 | 0.00% |
| AMBIGUOUS | 0 | 0.00% |
| UNRESOLVED | 582 | 100.00% |

Exact-firmware installed version evidence (separate observation):

| Category | Count | Percent |
|---|---:|---:|
| SBOM_EQUALS_CONTROL_VERSION | 575 | 98.80% |
| DETECTOR_VERSION_AVAILABLE | 7 | 1.20% |

All 582 SDK/Makefile version relationships remain `UNRESOLVED`. 
Separately, 575 SBOM versions equal the exact installed-control Version 
and seven static rows have detector version strings from exact artifacts. 
Neither observation decomposes `PKG_VERSION` and `PKG_RELEASE`.

## Original CPE inventory (statistics only)

- Present: `582`
- Missing: `0`
- Distinct: `582`
- No Dictionary, status, NVD Configuration, correctness, or correction 
  analysis was performed.

## Representative cases

### component_and_source_name_align

- `busybox 1.34.1-79.7` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/busybox.control | /bin/dmesg | /usr/bin/id | /bin/login | /bin/rm | ... (+135 more)`
  - firmware control: `/usr/lib/opkg/info/busybox.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/utils/busybox` / `busybox`
  - role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/utils/busybox, Section=base, and Description=The Swiss Army Knife of embedded Linux.
It slices, it dices, it makes Julian Fries.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `curl 8.11.0-23.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/curl.control | /usr/bin/curl`
  - firmware control: `/usr/lib/opkg/info/curl.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/utils/curl` / `curl`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/utils/curl, Section=net, and Description=A client-side URL transfer utility; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `dnsmasq 2.89-42.4` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/dnsmasq.control | /lib/upgrade/keep.d/dnsmasq | /etc/dnsmasq.conf | /usr/sbin/dhcpinfo.sh | /usr/share/dnsmasq/rfc6761.conf | ... (+8 more)`
  - firmware control: `/usr/lib/opkg/info/dnsmasq.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/services/dnsmasq` / `dnsmasq`
  - role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/services/dnsmasq, Section=net, and Description=It is intended to provide coupled DNS and DHCP service to a LAN.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `dropbear 2020.81-3` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/dropbear.control | /lib/preinit/99_10_failsafe_dropbear | /usr/bin/dbclient | /etc/dropbear/dropbear_ed25519_host_key | /etc/init.d/dropbear | ... (+3 more)`
  - firmware control: `/usr/lib/opkg/info/dropbear.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/services/dropbear` / `dropbear`
  - role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/services/dropbear, Section=net, and Description=A small SSH2 server/client designed for small memory environments.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `apn_db 7.13.0.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/apn_db.control | /usr/local/bin/backup_apn_db | /usr/local/share/mobifd/apn.db.gz | /etc/uci-defaults/etc/99_apn_db`
  - firmware control: `/usr/lib/opkg/info/apn_db.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/apn_db` / `apn_db`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/teltonika/apn_db, Section=utils, and Description=One APN database for all projects; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

### multiple_installed_packages_same_source

- `curl 8.11.0-23.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/curl.control | /usr/bin/curl`
  - firmware control: `/usr/lib/opkg/info/curl.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/utils/curl` / `curl`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/utils/curl, Section=net, and Description=A client-side URL transfer utility; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `libcurl4 8.11.0-23.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/libcurl4.control | /usr/lib/libcurl.so.4 | /usr/lib/libcurl.so.4.8.0`
  - firmware control: `/usr/lib/opkg/info/libcurl4.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/utils/curl` / `libcurl4`
  - role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/network/utils/curl, Section=libs, and Description=A client-side URL transfer library; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `strongswan 5.9.14-24` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/strongswan.control | /usr/lib/ipsec/libstrongswan.so.0 | /usr/lib/ipsec/libstrongswan.so.0.0.0 | /etc/strongswan.conf | /etc/config/ipsec | ... (+1 more)`
  - firmware control: `/usr/lib/opkg/info/strongswan.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/services/strongswan` / `strongswan`
  - role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/services/strongswan, Section=net, and Description=StrongSwan is an OpenSource IPsec implementation for the Linux operating system.
This package contains shared libraries and scripts.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `ppp 2.4.9.git-2021-01-04-4` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/ppp.control | /lib/upgrade/keep.d/ppp | /usr/sbin/pppd | /etc/ppp/options.sstp | /etc/ppp/filter | ... (+11 more)`
  - firmware control: `/usr/lib/opkg/info/ppp.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/services/ppp` / `ppp`
  - role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/services/ppp, Section=net, and Description=This package contains the PPP (Point-to-Point Protocol) daemon.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `data-sender 1.15-1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/data-sender.control | /usr/share/acl.d/data_sender.json | /etc/init.d/data_sender | /usr/sbin/datasender | /lib/troubleshoot/data_sender.sh | ... (+2 more)`
  - firmware control: `/usr/lib/opkg/info/data-sender.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/data_sender` / `data-sender`
  - role / identity: `VENDOR_SPECIFIC_PACKAGE` / `UNRESOLVED`
  - interpretation: Exact installed control identifies Source=package/teltonika/data_sender, Section=net, and Description=Data sender daemon by Teltonika; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

### library_split

- `libcurl4 8.11.0-23.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/libcurl4.control | /usr/lib/libcurl.so.4 | /usr/lib/libcurl.so.4.8.0`
  - firmware control: `/usr/lib/opkg/info/libcurl4.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/utils/curl` / `libcurl4`
  - role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/network/utils/curl, Section=libs, and Description=A client-side URL transfer library; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `libopenssl3 3.0.14-3` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/libopenssl3.control | /usr/lib/libssl.so.3 | /usr/lib/libcrypto.so.3`
  - firmware control: `/usr/lib/opkg/info/libopenssl3.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/libs/openssl` / `libopenssl3`
  - role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/libs/openssl, Section=libs, and Description=The OpenSSL Project is a collaborative effort to develop a robust,
commercial-grade, full-featured, and Open Source toolkit implementing the
Transport Layer Security (TLS) protocol as well as a full-strength
general-purpose cryptography library.
This package contains the OpenSSL shared libraries, needed by other programs.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `libuci20130104 2021-10-22-f84f49f0-12-12` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/libuci20130104.control | /lib/libuci.so`
  - firmware control: `/usr/lib/opkg/info/libuci20130104.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/system/uci` / `libuci20130104`
  - role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/system/uci, Section=libs, and Description=C library for the Unified Configuration Interface (UCI); the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `libubus20210630 2021-06-30-4fc532c8-6` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/libubus20210630.control | /lib/libubus.so.20210630`
  - firmware control: `/usr/lib/opkg/info/libubus20210630.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/system/ubus` / `libubus20210630`
  - role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/system/ubus, Section=libs, and Description=OpenWrt RPC client library; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `libgps 2025-04-29-2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/libgps.control | /usr/lib/libgps.so`
  - firmware control: `/usr/lib/opkg/info/libgps.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/gps` / `libgps`
  - role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/teltonika/gps, Section=libs, and Description=Library for communication with the gpsd daemon.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

### utility_or_cli

- `curl 8.11.0-23.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/curl.control | /usr/bin/curl`
  - firmware control: `/usr/lib/opkg/info/curl.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/utils/curl` / `curl`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/utils/curl, Section=net, and Description=A client-side URL transfer utility; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `openssl-util 3.0.14-3` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/openssl-util.control | /usr/bin/openssl`
  - firmware control: `/usr/lib/opkg/info/openssl-util.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/libs/openssl` / `openssl-util`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/libs/openssl, Section=utils, and Description=The OpenSSL Project is a collaborative effort to develop a robust,
commercial-grade, full-featured, and Open Source toolkit implementing the
Transport Layer Security (TLS) protocol as well as a full-strength
general-purpose cryptography library.
This package contains the OpenSSL command-line utility.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `iwinfo 2023-05-17-c9f5c3f7-1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/iwinfo.control | /usr/bin/iwinfo`
  - firmware control: `/usr/lib/opkg/info/iwinfo.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/utils/iwinfo` / `iwinfo`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/utils/iwinfo, Section=utils, and Description=Command line frontend for the wireless information library.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `point-to-point_protocol 2.4.9` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/sbin/pppd`
  - firmware control: `(none)`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `(unresolved)` / `(binary evidence only)`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact artifact path and detector string ['2.4.9']; no installed control or exact source Makefile.
  - GT-rule relevance: Binary/distribution identity requires independent review; multicall or bundled artifacts may not equal the detected product.
- `apn_db 7.13.0.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/apn_db.control | /usr/local/bin/backup_apn_db | /usr/local/share/mobifd/apn.db.gz | /etc/uci-defaults/etc/99_apn_db`
  - firmware control: `/usr/lib/opkg/info/apn_db.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/apn_db` / `apn_db`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/teltonika/apn_db, Section=utils, and Description=One APN database for all projects; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

### kernel_or_kmod

- `linux_kernel 5.15.176` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/0/MIPS_OpenWrt_Linux-5.15.176.bin.extracted/0/decompressed.bin | /logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/lib/modules/5.15.176/compat.ko | /logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/lib/modules/5.15.176/ovpn-dco-v2.ko | /logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/lib/modules/5.15.176/cfg80211.ko | /logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/lib/modules/5.15.176/pulse_counter.ko | ... (+4 more)`
  - firmware control: `(none)`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `(unresolved)` / `(binary evidence only)`
  - role / identity: `KERNEL_OR_KMOD` / `DIRECT_PRODUCT_EVIDENCE`
  - interpretation: Exact artifact path and detector string ['Linux version 5.15.176 ']; no installed control or exact source Makefile.
  - GT-rule relevance: Binary/distribution identity requires independent review; multicall or bundled artifacts may not equal the detected product.
- `kernel 5.15.176-1-c87d2a600c553d5338b2de4b88b39f15` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/kernel.control`
  - firmware control: `/usr/lib/opkg/info/kernel.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/kernel/linux` / `kernel`
  - role / identity: `KERNEL_OR_KMOD` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/kernel/linux, Section=sys, and Description=Virtual kernel package; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `kmod-wireguard 5.15.176-1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/kmod-wireguard.control | /etc/modules.d/wireguard`
  - firmware control: `/usr/lib/opkg/info/kmod-wireguard.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/kernel/linux` / `kmod-wireguard`
  - role / identity: `KERNEL_OR_KMOD` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/kernel/linux, Section=kernel, and Description=WireGuard is a novel VPN that runs inside the Linux Kernel and utilizes
state-of-the-art cryptography. It aims to be faster, simpler, leaner, and
more useful than IPSec, while avoiding the massive headache. It intends to
be considerably more performant than OpenVPN.  WireGuard is designed as a
general purpose VPN for running on embedded interfaces and super computers
alike, fit for many different circumstances. It uses UDP.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `kmod-cfg80211_515 5.15.176+6.5-1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/kmod-cfg80211_515.control | /lib/modules/5.15.176/compat.ko | /lib/modules/5.15.176/cfg80211.ko`
  - firmware control: `/usr/lib/opkg/info/kmod-cfg80211_515.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/kernel/mac80211_515` / `kmod-cfg80211_515`
  - role / identity: `KERNEL_OR_KMOD` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/kernel/mac80211_515, Section=kernel, and Description=cfg80211 is the Linux wireless LAN (802.11) configuration API.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `kmod-mt7603_515 5.15.176+2023-09-18-2afc7285-2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/kmod-mt7603_515.control | /etc/modules.d/mt7603_515 | /lib/firmware/mt7628_e2.bin | /lib/modules/5.15.176/mt7603e.ko`
  - firmware control: `/usr/lib/opkg/info/kmod-mt7603_515.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/kernel/mt76_515` / `kmod-mt7603_515`
  - role / identity: `KERNEL_OR_KMOD` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/kernel/mt76_515, Section=kernel, and Description=MediaTek MT7603 wireless driver; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

### firmware_or_driver_artifact

- `wireless-regdb 2021.04.21-1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/wireless-regdb.control | /lib/firmware/regulatory.db`
  - firmware control: `/usr/lib/opkg/info/wireless-regdb.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/firmware/wireless-regdb` / `wireless-regdb`
  - role / identity: `FIRMWARE_OR_DRIVER_ARTIFACT` / `NON_PRODUCT_ARTIFACT`
  - interpretation: Exact installed control identifies Source=package/firmware/wireless-regdb, Section=firmware, and Description=Wireless Regulatory Database; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

### vendor_specific

- `data-sender 1.15-1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/data-sender.control | /usr/share/acl.d/data_sender.json | /etc/init.d/data_sender | /usr/sbin/datasender | /lib/troubleshoot/data_sender.sh | ... (+2 more)`
  - firmware control: `/usr/lib/opkg/info/data-sender.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/data_sender` / `data-sender`
  - role / identity: `VENDOR_SPECIFIC_PACKAGE` / `UNRESOLVED`
  - interpretation: Exact installed control identifies Source=package/teltonika/data_sender, Section=net, and Description=Data sender daemon by Teltonika; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `api-core 1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/api-core.control | /sbin/event_server | /usr/lib/lua/vuci/usb.lua | /usr/lib/lua/api/post_logic.lua | /usr/lib/lua/vuci/util.lua | ... (+73 more)`
  - firmware control: `/usr/lib/opkg/info/api-core.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `feeds/vuci/api-core` / `api-core`
  - role / identity: `PLUGIN_OR_MODULE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=feeds/vuci/api-core, Section=webui, and Description=Provides core API functionality; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `gsmctl f61d039a` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/gsmctl.control | /usr/sbin/gsmctl`
  - firmware control: `/usr/lib/opkg/info/gsmctl.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/gsm` / `gsmctl`
  - role / identity: `VENDOR_SPECIFIC_PACKAGE` / `UNRESOLVED`
  - interpretation: Exact installed control identifies Source=package/teltonika/gsm, Section=net, and Description=Simple executable application to execute and read GSM modem AT commands. Created by Teltonika; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `apn_db 7.13.0.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/apn_db.control | /usr/local/bin/backup_apn_db | /usr/local/share/mobifd/apn.db.gz | /etc/uci-defaults/etc/99_apn_db`
  - firmware control: `/usr/lib/opkg/info/apn_db.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/apn_db` / `apn_db`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/teltonika/apn_db, Section=utils, and Description=One APN database for all projects; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `avl 2025-04-29-2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/avl.control | /etc/config/avl | /etc/init.d/avl | /usr/sbin/avl`
  - firmware control: `/usr/lib/opkg/info/avl.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/gps` / `avl`
  - role / identity: `VENDOR_SPECIFIC_PACKAGE` / `UNRESOLVED`
  - interpretation: Exact installed control identifies Source=package/teltonika/gps, Section=base, and Description=Daemon for sending data to AVL server.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

### version_requires_decomposition

- `base-files 2606-r16279-5cc0535800` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/base-files.control | /etc/opkg/openwrt/distfeeds.conf | /etc/proprietary_keys/780b53e9434e73a6 | /etc/openwrt_version | /etc/resolv.conf | ... (+89 more)`
  - firmware control: `/usr/lib/opkg/info/base-files.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/base-files` / `base-files`
  - role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/base-files, Section=base, and Description=This package contains a base filesystem and system scripts for OpenWrt.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `kernel 5.15.176-1-c87d2a600c553d5338b2de4b88b39f15` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/kernel.control`
  - firmware control: `/usr/lib/opkg/info/kernel.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/kernel/linux` / `kernel`
  - role / identity: `KERNEL_OR_KMOD` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/kernel/linux, Section=sys, and Description=Virtual kernel package; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `curl 8.11.0-23.2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/curl.control | /usr/bin/curl`
  - firmware control: `/usr/lib/opkg/info/curl.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/network/utils/curl` / `curl`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT`
  - interpretation: Exact installed control identifies Source=package/network/utils/curl, Section=net, and Description=A client-side URL transfer utility; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `libubox20240329 2024-03-29-eb9bcb64-2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/libubox20240329.control | /lib/libubox.so.20240329`
  - firmware control: `/usr/lib/opkg/info/libubox20240329.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/libs/libubox` / `libubox20240329`
  - role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/libs/libubox, Section=libs, and Description=Basic utility library; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `avl 2025-04-29-2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/avl.control | /etc/config/avl | /etc/init.d/avl | /usr/sbin/avl`
  - firmware control: `/usr/lib/opkg/info/avl.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/gps` / `avl`
  - role / identity: `VENDOR_SPECIFIC_PACKAGE` / `UNRESOLVED`
  - interpretation: Exact installed control identifies Source=package/teltonika/gps, Section=base, and Description=Daemon for sending data to AVL server.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

### identity_unresolved_or_ambiguous

- `sed 4.0` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/bin/busybox`
  - firmware control: `(none)`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `(unresolved)` / `(binary evidence only)`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact artifact path and detector string ['GNU sed version 4.0']; no installed control or exact source Makefile.
  - GT-rule relevance: Binary/distribution identity requires independent review; multicall or bundled artifacts may not equal the detected product.
- `udhcp 1.34.1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/bin/busybox`
  - firmware control: `(none)`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `(unresolved)` / `(binary evidence only)`
  - role / identity: `UTILITY_OR_CLI_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact artifact path and detector string ['udhcp 1.34.1']; no installed control or exact source Makefile.
  - GT-rule relevance: Binary/distribution identity requires independent review; multicall or bundled artifacts may not equal the detected product.
- `api-core 1` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/api-core.control | /sbin/event_server | /usr/lib/lua/vuci/usb.lua | /usr/lib/lua/api/post_logic.lua | /usr/lib/lua/vuci/util.lua | ... (+73 more)`
  - firmware control: `/usr/lib/opkg/info/api-core.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `feeds/vuci/api-core` / `api-core`
  - role / identity: `PLUGIN_OR_MODULE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=feeds/vuci/api-core, Section=webui, and Description=Provides core API functionality; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `avl 2025-04-29-2` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/avl.control | /etc/config/avl | /etc/init.d/avl | /usr/sbin/avl`
  - firmware control: `/usr/lib/opkg/info/avl.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/teltonika/gps` / `avl`
  - role / identity: `VENDOR_SPECIFIC_PACKAGE` / `UNRESOLVED`
  - interpretation: Exact installed control identifies Source=package/teltonika/gps, Section=base, and Description=Daemon for sending data to AVL server.; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.
- `block-mount 2022-05-03-9e11b372-28` 
  - properties paths: `/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root/usr/lib/opkg/info/block-mount.control | /etc/hotplug.d/block/00-media-change | /usr/sbin/swapon | /lib/libblkid-tiny.so | /etc/uci-defaults/etc/10_fstab-fstools | ... (+5 more)`
  - firmware control: `/usr/lib/opkg/info/block-mount.control`
  - Makefile: `(not available)`
  - PKG_NAME / PKG_VERSION / PKG_RELEASE: `(not available)` / `(not available)` / `(not available)`
  - Package definition: `(not available)`
  - source / installed package: `package/system/fstools` / `block-mount`
  - role / identity: `SPLIT_RUNTIME_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - interpretation: Exact installed control identifies Source=package/system/fstools, Section=base, and Description=Block device mounting and checking; the exact Makefile and upstream release metadata are absent.
  - GT-rule relevance: Review whether this installed binary package represents its Source product; source sharing does not imply CPE inheritance.

## Answers for next-step rule design

1. **Useful metadata:** name, version, source/control paths, installed paths, 
   dependencies, exact control Source/Section/Description, and binary version 
   strings. Original CPE is excluded from evidence.
2. **name/version/properties:** name locates the installed package; version 
   supports exact installed-version comparison but often needs decomposition; 
   properties prove where the package/artifact was observed.
3. **PURL/group/publisher/type:** PURL adds ecosystem/distro/arch context; group 
   and type have low discrimination; publisher adds none. Supplier is a hint.
4. **SDK/Makefile traceable:** `0` / `582`. 
   **Exact firmware traceable:** `582` / `582`.
5. **Properties contribution:** properties strengthen 575 control links and 
   enable seven binary/artifact links, but cannot improve unavailable SDK linkage.
6. **Multi-package Source:** `42` Source paths cover `314` installed components.
7. **Roles:** see the exhaustive role table; kernel/kmod, libraries, plugins, 
   vendor packages, utilities, main packages, and artifact/meta classes dominate.
8. **Strong upstream-product evidence:** only separately detected OS/kernel 
   identities are marked direct. Main/CLI package rows remain possible.
9. **Split/library/utility/module:** shared Source paths and installed paths 
   expose structure, but CPE inheritance is not inferred.
10. **Kernel/kmod/firmware/meta:** control Section/name, Source, and installed 
    artifact paths provide the distinction; all remain policy-neutral.
11. **Versions:** installed control Version is exact for 575; seven detector 
    versions are available; upstream/release decomposition needs Makefiles.
12. **Hardest cases:** vendor packages, split runtime/plugin/library packages, 
    BusyBox multicall detections, and components whose source product differs 
    from the binary package name.
13. **Next rule design:** require independent product-identity evidence; treat 
    source sharing as relationship evidence only; review split/library/utility/
    module and artifact classes separately; require exact version provenance; 
    keep an unresolved path when exact SDK evidence is absent.

## Policy questions requiring human decision

- Whether and when a split/subpackage represents the same software product as 
  its source package.
- Whether a runtime library, CLI utility, or plugin/module is an independent 
  product identity, a partial identity, or only packaging structure.
- How BusyBox multicall applets should be represented when detector identity 
  and artifact identity differ.
- How vendor-specific closed/NDA-source packages should be handled without an 
  exact public SDK.
- Whether installed package release suffixes are part of the product version 
  after exact Makefile evidence becomes available.

## Validation

- Component rows: `582` == `582`
- Package-role partition: `582` == `582`
- Product-identity partition: `582` == `582`
- SDK-linkage partition: `582` == `582`
- Firmware-traceability partition: `582` == `582`
- Version-relationship partition: `582` == `582`
- Installed-version-evidence partition: `582` == `582`
- Ground Truth records before/after: `0` / `0`

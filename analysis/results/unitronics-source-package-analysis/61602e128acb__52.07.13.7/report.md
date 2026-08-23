# Unitronics UCR-ST-B8 source/package second-pass analysis

This is a read-only empirical analysis of exact-firmware `.control` and 
`.list` evidence. It does not assign or validate Ground Truth CPEs. Source 
sharing and control `CPE-ID` propagation are never treated as proof of a 
binary package's CPE product identity.

## Dataset and evidence

- SBOMDocument: `1364`
- Product: `Unitronics UCR-ST-B8 52.07.13.7`
- Firmware SHA-256: `6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c`
- Installed controls/lists/status stanzas: `575` / `575` / `575`
- Distinct control `Source`: `303`
- Exact SDK/GPL and Makefiles remain unavailable. `Source` means the path 
  recorded by installed control metadata, not a verified current Makefile.
- The first-pass component mapping was reused and every one of its 575 opkg 
  name/version/Source tuples was revalidated against exact controls.
- Seven non-opkg SBOM artifacts are excluded from the 303-Source/575-package 
  denominators and preserved separately below and in `summary.json`.

## Source structure

| Structure | Sources | Packages |
|---|---:|---:|
| SINGLE_PACKAGE_SOURCE | 261 | 261 |
| MULTI_PACKAGE_SOURCE | 42 | 314 |
| Total | 303 | 575 |

A 1:1 Source is not automatically a product. The role/identity partitions 
below apply the same control/list rules to both single and multi Sources.
Among the 261 single-package Sources, `197` are partial, non-product, ambiguous, or unresolved rather than direct/possible product candidates. Their role distribution is `{'PRODUCT_OR_MAIN_PACKAGE': 45, 'SPLIT_RUNTIME_PACKAGE': 0, 'LIBRARY_PACKAGE': 35, 'UTILITY_OR_CLI_PACKAGE': 19, 'PLUGIN_OR_MODULE': 147, 'KERNEL_OR_KMOD': 6, 'FIRMWARE_OR_DRIVER_ARTIFACT': 1, 'META_OR_HELPER_PACKAGE': 6, 'VENDOR_SPECIFIC_PACKAGE': 2, 'UNKNOWN': 0}`.

### Separately retained non-opkg artifacts

- `linux_kernel 5.15.176` — group `linux_kernel`, firmware traceability `BINARY_DIRECT`
- `openwrt 21.02.0:r16279-5cc0535800` — group `static_distri_analysis`, firmware traceability `BINARY_DIRECT`
- `point-to-point_protocol 2.4.9` — group `static_bin_analysis`, firmware traceability `BINARY_DIRECT`
- `sed 4.0` — group `static_bin_analysis`, firmware traceability `BINARY_DIRECT`
- `sqlite 3.41.2` — group `static_bin_analysis`, firmware traceability `BINARY_DIRECT`
- `udhcp 1.34.1` — group `static_bin_analysis`, firmware traceability `BINARY_DIRECT`
- `wpa_supplicant 2.11` — group `static_bin_analysis`, firmware traceability `BINARY_DIRECT`

## Exact `.list` content

- Declared paths: `1812`
- Non-empty lists: `455` (79.13%)
- Empty lists: `120` (20.87%)
- Existing regular files / symlinks: `1449` / `251`
- Listed paths absent from extracted rootfs: `112`

The `.list` remains the installed-package ownership record even when a path 
is absent after image assembly. Empty-list packages rely on Section, 
Description, Source, dependency, naming, and sibling evidence.

Path-category totals (path denominator):

| Category | Count | Percent |
|---|---:|---:|
| executable | 384 | 21.19% |
| library | 154 | 8.50% |
| plugin_module | 388 | 21.41% |
| kernel_module | 11 | 0.61% |
| firmware_file | 2 | 0.11% |
| config_file | 586 | 32.34% |
| data_script | 230 | 12.69% |
| development_artifact | 0 | 0.00% |
| other | 57 | 3.15% |

Role evidence basis (package denominator):

| Category | Count | Percent |
|---|---:|---:|
| CONTROL_AND_LIST | 455 | 79.13% |
| CONTROL_ONLY_EMPTY_LIST | 120 | 20.87% |

## Package roles

| Category | Count | Percent |
|---|---:|---:|
| PRODUCT_OR_MAIN_PACKAGE | 54 | 9.39% |
| SPLIT_RUNTIME_PACKAGE | 20 | 3.48% |
| LIBRARY_PACKAGE | 72 | 12.52% |
| UTILITY_OR_CLI_PACKAGE | 47 | 8.17% |
| PLUGIN_OR_MODULE | 221 | 38.43% |
| KERNEL_OR_KMOD | 144 | 25.04% |
| FIRMWARE_OR_DRIVER_ARTIFACT | 1 | 0.17% |
| META_OR_HELPER_PACKAGE | 14 | 2.43% |
| VENDOR_SPECIFIC_PACKAGE | 2 | 0.35% |
| UNKNOWN | 0 | 0.00% |

These are evidence classes, not CPE decisions. Vendor origin is also retained 
as an orthogonal flag on `257` packages and `204` Sources.

## Product identity relationship

| Category | Count | Percent |
|---|---:|---:|
| DIRECT_PRODUCT_CANDIDATE | 21 | 3.65% |
| POSSIBLE_PRODUCT_CANDIDATE | 67 | 11.65% |
| PARTIAL_OR_SPLIT_COMPONENT | 287 | 49.91% |
| NON_PRODUCT_ARTIFACT | 16 | 2.78% |
| AMBIGUOUS | 182 | 31.65% |
| UNRESOLVED | 2 | 0.35% |

`DIRECT_PRODUCT_CANDIDATE` means control Source basename and installed core 
payload align. It does not confirm a CPE. Partial/library/plugin classifications 
likewise do not decide that a CPE must be absent.
The explicit `AMBIGUOUS`/`UNRESOLVED` review set contains `184` packages with role distribution `{'LIBRARY_PACKAGE': 35, 'PLUGIN_OR_MODULE': 147, 'VENDOR_SPECIFIC_PACKAGE': 2}`. The complete package list is retained in `summary.json`.

## Multi-package Source summary

- Sources: `42`; packages: `314`
- Package-count distribution: `{2: 16, 3: 8, 4: 8, 5: 3, 6: 1, 7: 1, 8: 1, 13: 1, 15: 1, 28: 1, 134: 1}`
- With main/product-like package: `9`
- Without main/product-like package: `33`
- With library split: `25`
- With utility split: `24`
- With plugin/module split: `15`
- Kernel-derived Sources: `3`
- Vendor-specific Sources: `14`

Multi-source package roles (314-package denominator):

| Category | Count | Percent |
|---|---:|---:|
| PRODUCT_OR_MAIN_PACKAGE | 9 | 2.87% |
| SPLIT_RUNTIME_PACKAGE | 20 | 6.37% |
| LIBRARY_PACKAGE | 37 | 11.78% |
| UTILITY_OR_CLI_PACKAGE | 28 | 8.92% |
| PLUGIN_OR_MODULE | 74 | 23.57% |
| KERNEL_OR_KMOD | 138 | 43.95% |
| FIRMWARE_OR_DRIVER_ARTIFACT | 0 | 0.00% |
| META_OR_HELPER_PACKAGE | 8 | 2.55% |
| VENDOR_SPECIFIC_PACKAGE | 0 | 0.00% |
| UNKNOWN | 0 | 0.00% |

Multi-source product identity (314-package denominator):

| Category | Count | Percent |
|---|---:|---:|
| DIRECT_PRODUCT_CANDIDATE | 6 | 1.91% |
| POSSIBLE_PRODUCT_CANDIDATE | 18 | 5.73% |
| PARTIAL_OR_SPLIT_COMPONENT | 281 | 89.49% |
| NON_PRODUCT_ARTIFACT | 9 | 2.87% |
| AMBIGUOUS | 0 | 0.00% |
| UNRESOLVED | 0 | 0.00% |

## CPE-ID propagation (metadata observation only)

- CPE-ID package coverage: `89` / `575` (15.48%)
- Distinct CPE-ID: `39`
- CPE-IDs shared by multiple packages: `12`
- Packages in shared groups: `62`
- Multi-package Sources propagating one CPE-ID to 2+ packages: `12` / `42`
- Maximum propagation: `28` packages at `package/network/services/strongswan` (`cpe:/a:strongswan:strongswan`)
- Source-level consistency distribution: `{'ALL_PACKAGES_SAME_CPE_ID': 39, 'NO_CPE_ID': 264}`

No correctness inference is made from these values.

## Representative cases

### A_main_plus_splits

- Source / Package: `package/network/services/strongswan` / `strongswan 5.9.14-24`
  - Description: StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This package contains shared libraries and scripts.
  - Installed paths: `/usr/lib/ipsec/libstrongswan.so.0 | /usr/lib/ipsec/libstrongswan.so.0.0.0 | /etc/strongswan.conf | /etc/config/ipsec | /lib/upgrade/keep.d/strongswan`
  - Siblings: `strongswan | strongswan-charon | strongswan-minimal | strongswan-mod-connmark | strongswan-mod-constraints | strongswan-mod-des | strongswan-mod-eap-identity | strongswan-mod-eap-mschapv2 | strongswan-mod-kernel-netlink | strongswan-mod-md4 | strongswan-mod-mgf1 | strongswan-mod-nonce | strongswan-mod-openssl | strongswan-mod-pem | strongswan-mod-pgp | strongswan-mod-pkcs1 | strongswan-mod-pkcs8 | strongswan-mod-pubkey | strongswan-mod-random | strongswan-mod-revocation | strongswan-mod-sha1 | strongswan-mod-socket-default | strongswan-mod-updown | strongswan-mod-vici | strongswan-mod-x509 | strongswan-mod-xauth-generic | strongswan-mod-xcbc | strongswan-swanctl`
  - Role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `DIRECT_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `cpe:/a:strongswan:strongswan`
  - Evidence: Package name aligns with control Source basename; it has 5 listed paths and 27 siblings. Description: StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This package contains shared libraries and scripts. name/source alignment=True; source packages=28; executables=0; libraries=2; sibling roles={'META_OR_HELPER_PACKAGE': 1, 'PLUGIN_OR_MODULE': 24, 'PRODUCT_OR_MAIN_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; control Source name and installed core payload align. This is a product candidate, not a CPE decision.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/data_sender` / `data-sender 1.15-1`
  - Description: Data sender daemon by Teltonika
  - Installed paths: `/usr/sbin/datasender | /lib/troubleshoot/data_sender.sh | /etc/init.d/data_sender | /etc/config/data_sender | /usr/share/acl.d/data_sender.json | /lib/data_sender/libdata_sender.sh`
  - Siblings: `data-sender | data-sender-mod-base | data-sender-mod-format-custom | data-sender-mod-gsm | data-sender-mod-http | data-sender-mod-lua-in | data-sender-mod-lua_format | data-sender-mod-mdcollect | data-sender-mod-mnfinfo | data-sender-mod-modbus | data-sender-mod-modbus-alarm | data-sender-mod-mqtt-in | data-sender-mod-mqtt-out | data-sender-mod-opcua | data-sender-mod-ubus`
  - Role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `(none)`
  - Evidence: Package name aligns with control Source basename; it has 6 listed paths and 14 siblings. Description: Data sender daemon by Teltonika name/source alignment=True; source packages=15; executables=2; libraries=0; sibling roles={'PLUGIN_OR_MODULE': 14, 'PRODUCT_OR_MAIN_PACKAGE': 1}; main-like runtime evidence exists but source/vendor identity needs independent confirmation.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/network/services/ppp` / `ppp 2.4.9.git-2021-01-04-4`
  - Description: This package contains the PPP (Point-to-Point Protocol) daemon.
  - Installed paths: `/usr/sbin/pppd | /lib/netifd/ppp-up | /etc/ppp/options.sstp | /etc/ppp/filter | /lib/netifd/proto/pppoa.sh | /lib/netifd/proto/pptp.sh | /lib/upgrade/keep.d/ppp`
  - Siblings: `ppp | ppp-mod-pppoe | ppp-mod-pppol2tp | ppp-mod-pptp`
  - Role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `DIRECT_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `cpe:/a:samba:ppp`
  - Evidence: Package name aligns with control Source basename; it has 15 listed paths and 3 siblings. Description: This package contains the PPP (Point-to-Point Protocol) daemon. name/source alignment=True; source packages=4; executables=5; libraries=0; sibling roles={'PLUGIN_OR_MODULE': 3, 'PRODUCT_OR_MAIN_PACKAGE': 1}; control Source name and installed core payload align. This is a product candidate, not a CPE decision.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/ddns-scripts` / `ddns-scripts 2025-02-06-1`
  - Description: Dynamic DNS Client scripts (with IPv6 support) - Info: http://wiki.openwrt.org/doc/howto/ddns.client
  - Installed paths: `/usr/lib/ddns/dynamic_dns_updater.sh | /usr/lib/ddns/dynamic_dns_functions.sh | /etc/uci-defaults/ddns.defaults | /etc/ddns/services | /usr/share/acl.d/ddns.json`
  - Siblings: `ddns-scripts | ddns-scripts_cloudflare.com-v4 | ddns-scripts_no-ip_com | ddns-scripts_nsupdate | tlt-ddns`
  - Role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `(none)`
  - Evidence: Package name aligns with control Source basename; it has 10 listed paths and 4 siblings. Description: Dynamic DNS Client scripts (with IPv6 support) - Info: http://wiki.openwrt.org/doc/howto/ddns.client name/source alignment=True; source packages=5; executables=3; libraries=0; sibling roles={'META_OR_HELPER_PACKAGE': 1, 'PRODUCT_OR_MAIN_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 3}; main-like runtime evidence exists but source/vendor identity needs independent confirmation.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/system/fstools` / `fstools 2022-05-03-9e11b372-28`
  - Description: OpenWrt filesystem tools
  - Installed paths: `/sbin/mount_root | /sbin/jffs2reset | /lib/libfstools.so`
  - Siblings: `block-mount | fstools`
  - Role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `DIRECT_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `(none)`
  - Evidence: Package name aligns with control Source basename; it has 4 listed paths and 1 siblings. Description: OpenWrt filesystem tools name/source alignment=True; source packages=2; executables=3; libraries=1; sibling roles={'PRODUCT_OR_MAIN_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 1}; control Source name and installed core payload align. This is a product candidate, not a CPE decision.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.

### B_library_only_package

- Source / Package: `package/network/utils/curl` / `libcurl4 8.11.0-23.2`
  - Description: A client-side URL transfer library
  - Installed paths: `/usr/lib/libcurl.so.4 | /usr/lib/libcurl.so.4.8.0`
  - Siblings: `curl | libcurl4`
  - Role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `cpe:/a:haxx:libcurl`
  - Evidence: Section=libs; libraries=2; executables=0; listed paths=2. Description: A client-side URL transfer library name/source alignment=False; source packages=2; executables=0; libraries=2; sibling roles={'LIBRARY_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; sibling main candidates=(none). The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/libs/openssl` / `libopenssl3 3.0.14-3`
  - Description: The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer Security (TLS) proto...
  - Installed paths: `/usr/lib/libssl.so.3 | /usr/lib/libcrypto.so.3`
  - Siblings: `libopenssl-conf | libopenssl-legacy | libopenssl3 | openssl-util`
  - Role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `cpe:/a:openssl:openssl`
  - Evidence: Section=libs; libraries=2; executables=0; listed paths=2. Description: The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer Security (TLS) proto... name/source alignment=False; source packages=4; executables=0; libraries=2; sibling roles={'LIBRARY_PACKAGE': 1, 'META_OR_HELPER_PACKAGE': 1, 'PLUGIN_OR_MODULE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; sibling main candidates=(none). The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/utils/e2fsprogs` / `libext2fs2 1.47.0-2`
  - Description: libext2fs is a library which can access ext2, ext3 and ext4 filesystems.
  - Installed paths: `/usr/lib/libext2fs.so.2.4 | /usr/lib/libext2fs.so.2`
  - Siblings: `e2fsprogs | libcomerr0 | libext2fs2 | libss2`
  - Role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `cpe:/a:e2fsprogs_project:e2fsprogs`
  - Evidence: Section=libs; libraries=2; executables=0; listed paths=2. Description: libext2fs is a library which can access ext2, ext3 and ext4 filesystems. name/source alignment=False; source packages=4; executables=0; libraries=2; sibling roles={'LIBRARY_PACKAGE': 3, 'UTILITY_OR_CLI_PACKAGE': 1}; sibling main candidates=(none). The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/gps` / `libgps 2025-04-29-2`
  - Description: Library for communication with the gpsd daemon.
  - Installed paths: `/usr/lib/libgps.so`
  - Siblings: `avl | gpsctl | gpsd | libgps | ntp_gps`
  - Role / identity: `LIBRARY_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=libs; libraries=1; executables=0; listed paths=1. Description: Library for communication with the gpsd daemon. name/source alignment=False; source packages=5; executables=0; libraries=1; sibling roles={'LIBRARY_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 3, 'UTILITY_OR_CLI_PACKAGE': 1}; sibling main candidates=(none). The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/libs/davici` / `davici 1.4-1`
  - Description: The davici library provides a client implementation of the strongSwan VICI protocol for integration into external applications.
  - Installed paths: `/usr/lib/libdavici.so | /usr/lib/libdavici.so.0.1.0`
  - Siblings: `davici`
  - Role / identity: `LIBRARY_PACKAGE` / `AMBIGUOUS`
  - CPE-ID (reference only): `cpe:/a:strongswan:davici`
  - Evidence: Section=libs; libraries=3; executables=0; listed paths=3. Description: The davici library provides a client implementation of the strongSwan VICI protocol for integration into external applications. name/source alignment=True; source packages=1; executables=0; libraries=3; sibling roles={'LIBRARY_PACKAGE': 1}; single-package library/plugin scope may or may not represent an independent upstream product.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.

### C_cli_utility_only_package

- Source / Package: `package/libs/openssl` / `openssl-util 3.0.14-3`
  - Description: The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer Security (TLS) proto...
  - Installed paths: `/usr/bin/openssl`
  - Siblings: `libopenssl-conf | libopenssl-legacy | libopenssl3 | openssl-util`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `cpe:/a:openssl:openssl`
  - Evidence: Section=utils; executables=1; control description identifies utility/tool behavior. Description: The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer Security (TLS) proto... name/source alignment=False; source packages=4; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'META_OR_HELPER_PACKAGE': 1, 'PLUGIN_OR_MODULE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; utility split with sibling main candidates=(none).
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/network/utils/iwinfo` / `iwinfo 2023-05-17-c9f5c3f7-1`
  - Description: Command line frontend for the wireless information library.
  - Installed paths: `/usr/bin/iwinfo`
  - Siblings: `iwinfo | libiwinfo-data | libiwinfo-lua | libiwinfo20230121`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=utils; executables=1; control description identifies utility/tool behavior. Description: Command line frontend for the wireless information library. name/source alignment=True; source packages=4; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'META_OR_HELPER_PACKAGE': 1, 'PLUGIN_OR_MODULE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; the installed CLI aligns with Source name, but CLI scope versus the complete upstream product remains unresolved.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/libs/libgpiod` / `gpiod-tools 1.6.3-1`
  - Description: Tools for interacting with the linux GPIO character device (gpiod stands for GPIO device), minimal required version.
  - Installed paths: `/usr/bin/gpiofind | /usr/bin/gpioset`
  - Siblings: `gpiod-tools | libgpiod`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=utils; executables=3; control description identifies utility/tool behavior. Description: Tools for interacting with the linux GPIO character device (gpiod stands for GPIO device), minimal required version. name/source alignment=False; source packages=2; executables=3; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; utility split with sibling main candidates=(none).
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/gps` / `gpsctl 2025-04-29-2`
  - Description: Console line interface for gpsd daemon.
  - Installed paths: `/usr/sbin/gpsctl`
  - Siblings: `avl | gpsctl | gpsd | libgps | ntp_gps`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=base; executables=1; control description identifies utility/tool behavior. Description: Console line interface for gpsd daemon. name/source alignment=False; source packages=5; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 3, 'UTILITY_OR_CLI_PACKAGE': 1}; utility split with sibling main candidates=(none).
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/mctl` / `mctl 4.10`
  - Description: Simple executable application for modem restart. Created by Teltonika
  - Installed paths: `/sbin/mctl`
  - Siblings: `libmctl | mctl | modem_trackd`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=utils; executables=1; control description identifies utility/tool behavior. Description: Simple executable application for modem restart. Created by Teltonika name/source alignment=True; source packages=3; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 2}; the installed CLI aligns with Source name, but CLI scope versus the complete upstream product remains unresolved.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.

### D_plugin_or_module

- Source / Package: `package/network/services/strongswan` / `strongswan-mod-openssl 5.9.14-24`
  - Description: StrongSwan OpenSSL crypto plugin
  - Installed paths: `/usr/lib/ipsec/plugins/libstrongswan-openssl.so | /etc/strongswan.d/charon/openssl.conf`
  - Siblings: `strongswan | strongswan-charon | strongswan-minimal | strongswan-mod-connmark | strongswan-mod-constraints | strongswan-mod-des | strongswan-mod-eap-identity | strongswan-mod-eap-mschapv2 | strongswan-mod-kernel-netlink | strongswan-mod-md4 | strongswan-mod-mgf1 | strongswan-mod-nonce | strongswan-mod-openssl | strongswan-mod-pem | strongswan-mod-pgp | strongswan-mod-pkcs1 | strongswan-mod-pkcs8 | strongswan-mod-pubkey | strongswan-mod-random | strongswan-mod-revocation | strongswan-mod-sha1 | strongswan-mod-socket-default | strongswan-mod-updown | strongswan-mod-vici | strongswan-mod-x509 | strongswan-mod-xauth-generic | strongswan-mod-xcbc | strongswan-swanctl`
  - Role / identity: `PLUGIN_OR_MODULE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `cpe:/a:strongswan:strongswan`
  - Evidence: Section=net; plugin/module paths=1; module-style name=True; listed paths=2. Description: StrongSwan OpenSSL crypto plugin name/source alignment=False; source packages=28; executables=0; libraries=0; sibling roles={'META_OR_HELPER_PACKAGE': 1, 'PLUGIN_OR_MODULE': 24, 'PRODUCT_OR_MAIN_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; sibling main candidates=['strongswan']. The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/network/services/uhttpd` / `uhttpd-mod-lua 2021-03-21-15346de8-9`
  - Description: The Lua plugin adds a CGI-like Lua runtime interface to uHTTPd.
  - Installed paths: `/usr/lib/uhttpd_lua.so`
  - Siblings: `uhttpd | uhttpd-mod-lua | uhttpd-mod-ubus`
  - Role / identity: `PLUGIN_OR_MODULE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=net; plugin/module paths=0; module-style name=True; listed paths=1. Description: The Lua plugin adds a CGI-like Lua runtime interface to uHTTPd. name/source alignment=False; source packages=3; executables=0; libraries=1; sibling roles={'PLUGIN_OR_MODULE': 2, 'PRODUCT_OR_MAIN_PACKAGE': 1}; sibling main candidates=['uhttpd']. The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/data_sender` / `data-sender-mod-http 1.15-1`
  - Description: Output plugin for sending data over http
  - Installed paths: `(empty .list)`
  - Siblings: `data-sender | data-sender-mod-base | data-sender-mod-format-custom | data-sender-mod-gsm | data-sender-mod-http | data-sender-mod-lua-in | data-sender-mod-lua_format | data-sender-mod-mdcollect | data-sender-mod-mnfinfo | data-sender-mod-modbus | data-sender-mod-modbus-alarm | data-sender-mod-mqtt-in | data-sender-mod-mqtt-out | data-sender-mod-opcua | data-sender-mod-ubus`
  - Role / identity: `PLUGIN_OR_MODULE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=net; plugin/module paths=0; module-style name=True; listed paths=0. Description: Output plugin for sending data over http name/source alignment=False; source packages=15; executables=0; libraries=0; sibling roles={'PLUGIN_OR_MODULE': 14, 'PRODUCT_OR_MAIN_PACKAGE': 1}; sibling main candidates=['data-sender']. The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `feeds/vuci/applications/vuci-app-data-sender/vuci-app-data-sender-api` / `vuci-app-data-sender-api 1`
  - Description: VuCI API Support for Data Sender
  - Installed paths: `/usr/lib/lua/api/services/data_sender_format.lua | /usr/lib/lua/api/services/data_sender_collections.lua | /usr/share/rpcd/acl.d/datasender.json`
  - Siblings: `data-sender-api-mod-format-custom | data-sender-api-mod-gsm | data-sender-api-mod-http | data-sender-api-mod-lua-in | data-sender-api-mod-lua_format | data-sender-api-mod-mdcollect | data-sender-api-mod-modbus | data-sender-api-mod-modbus-alarm | data-sender-api-mod-mqtt-in | data-sender-api-mod-mqtt-out | data-sender-api-mod-opcua | data-sender-api-mod-ubus | vuci-app-data-sender-api`
  - Role / identity: `PLUGIN_OR_MODULE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=vuci; plugin/module paths=6; module-style name=False; listed paths=7. Description: VuCI API Support for Data Sender name/source alignment=True; source packages=13; executables=0; libraries=0; sibling roles={'PLUGIN_OR_MODULE': 13}; sibling main candidates=(none). The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/system/rpcd` / `rpcd-mod-file 2021-03-11-ccb75178-8`
  - Description: Provides ubus calls for file and directory operations.
  - Installed paths: `/usr/lib/rpcd/file.so`
  - Siblings: `rpcd | rpcd-mod-file | rpcd-mod-iwinfo | rpcd-mod-rpcsys`
  - Role / identity: `PLUGIN_OR_MODULE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=utils; plugin/module paths=0; module-style name=True; listed paths=1. Description: Provides ubus calls for file and directory operations. name/source alignment=False; source packages=4; executables=0; libraries=1; sibling roles={'PLUGIN_OR_MODULE': 3, 'UTILITY_OR_CLI_PACKAGE': 1}; sibling main candidates=(none). The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.

### E_kernel_or_kmod

- Source / Package: `package/kernel/linux` / `kernel 5.15.176-1-c87d2a600c553d5338b2de4b88b39f15`
  - Description: Virtual kernel package
  - Installed paths: `(empty .list)`
  - Siblings: `kernel | kmod-asn1-decoder | kmod-crypto-acompress | kmod-crypto-aead | kmod-crypto-arc4 | kmod-crypto-authenc | kmod-crypto-cbc | kmod-crypto-ccm | kmod-crypto-cmac | kmod-crypto-crc32c | kmod-crypto-ctr | kmod-crypto-deflate | kmod-crypto-des | kmod-crypto-ecb | kmod-crypto-echainiv | kmod-crypto-gcm | kmod-crypto-gf128 | kmod-crypto-ghash | kmod-crypto-hash | kmod-crypto-hmac | kmod-crypto-kpp | kmod-crypto-lib-blake2s | kmod-crypto-lib-chacha20 | kmod-crypto-lib-chacha20poly1305 | kmod-crypto-lib-curve25519 | kmod-crypto-lib-poly1305 | kmod-crypto-manager | kmod-crypto-md5 | kmod-crypto-null | kmod-crypto-pcompress | kmod-crypto-rng | kmod-crypto-seqiv | kmod-crypto-sha1 | kmod-crypto-sha256 | kmod-crypto-sha512 | kmod-fs-autofs4 | kmod-fs-ext4 | kmod-fs-msdos | kmod-fs-ntfs | kmod-fs-vfat | kmod-gpio-nxp-74hc164 | kmod-gre | kmod-gre6 | kmod-hwmon-core | kmod-hwmon-mcp3021 | kmod-hwmon-tla2021 | kmod-i2c-core | kmod-i2c-mt7628 | kmod-ip6-tunnel | kmod-ip6tables | kmod-ipsec | kmod-ipsec4 | kmod-ipsec6 | kmod-ipt-conntrack | kmod-ipt-conntrack-extra | kmod-ipt-core | kmod-ipt-ipopt | kmod-ipt-ipsec | kmod-ipt-ipset | kmod-ipt-nat | kmod-ipt-offload | kmod-ipt-raw | kmod-ipt-raw6 | kmod-iptunnel | kmod-iptunnel4 | kmod-iptunnel6 | kmod-l2tp | kmod-l2tp-eth | kmod-l2tp-ip | kmod-leds-gpio | kmod-lib-crc-ccitt | kmod-lib-crc16 | kmod-lib-crc32c | kmod-lib-textsearch | kmod-lib-zlib-deflate | kmod-lib-zlib-inflate | kmod-mii | kmod-mppe | kmod-nf-conntrack | kmod-nf-conntrack-netlink | kmod-nf-conntrack6 | kmod-nf-flow | kmod-nf-ipt | kmod-nf-ipt6 | kmod-nf-log | kmod-nf-log6 | kmod-nf-nat | kmod-nf-nathelper | kmod-nf-nathelper-extra | kmod-nf-reject | kmod-nf-reject6 | kmod-nfnetlink | kmod-nft-core | kmod-nft-netdev | kmod-nls-base | kmod-nls-cp437 | kmod-nls-iso8859-1 | kmod-nls-utf8 | kmod-ppp | kmod-pppoe | kmod-pppol2tp | kmod-pppox | kmod-pptp | kmod-scsi-core | kmod-slhc | kmod-spi-bitbang | kmod-spi-gpio | kmod-tun | kmod-udptunnel4 | kmod-udptunnel6 | kmod-usb-acm | kmod-usb-core | kmod-usb-ehci | kmod-usb-net | kmod-usb-net-cdc-ether | kmod-usb-net-cdc-ncm | kmod-usb-net-qmi-wwan | kmod-usb-net-rndis | kmod-usb-serial | kmod-usb-serial-ark3116 | kmod-usb-serial-belkin | kmod-usb-serial-ch341 | kmod-usb-serial-ch343 | kmod-usb-serial-cp210x | kmod-usb-serial-cypress-m8 | kmod-usb-serial-ftdi | kmod-usb-serial-option | kmod-usb-serial-pl2303 | kmod-usb-serial-wwan | kmod-usb-storage | kmod-usb-wdm | kmod-usb2 | kmod-wireguard | kmod-xfrm-interface`
  - Role / identity: `KERNEL_OR_KMOD` / `NON_PRODUCT_ARTIFACT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=sys; kernel paths=0; listed paths=0. Description: Virtual kernel package name/source alignment=False; source packages=134; executables=0; libraries=0; sibling roles={'KERNEL_OR_KMOD': 134}; virtual kernel package.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/kernel/linux` / `kmod-wireguard 5.15.176-1`
  - Description: WireGuard is a novel VPN that runs inside the Linux Kernel and utilizes state-of-the-art cryptography. It aims to be faster, simpler, leaner, and more useful than IPSec, while a...
  - Installed paths: `/etc/modules.d/wireguard`
  - Siblings: `kernel | kmod-asn1-decoder | kmod-crypto-acompress | kmod-crypto-aead | kmod-crypto-arc4 | kmod-crypto-authenc | kmod-crypto-cbc | kmod-crypto-ccm | kmod-crypto-cmac | kmod-crypto-crc32c | kmod-crypto-ctr | kmod-crypto-deflate | kmod-crypto-des | kmod-crypto-ecb | kmod-crypto-echainiv | kmod-crypto-gcm | kmod-crypto-gf128 | kmod-crypto-ghash | kmod-crypto-hash | kmod-crypto-hmac | kmod-crypto-kpp | kmod-crypto-lib-blake2s | kmod-crypto-lib-chacha20 | kmod-crypto-lib-chacha20poly1305 | kmod-crypto-lib-curve25519 | kmod-crypto-lib-poly1305 | kmod-crypto-manager | kmod-crypto-md5 | kmod-crypto-null | kmod-crypto-pcompress | kmod-crypto-rng | kmod-crypto-seqiv | kmod-crypto-sha1 | kmod-crypto-sha256 | kmod-crypto-sha512 | kmod-fs-autofs4 | kmod-fs-ext4 | kmod-fs-msdos | kmod-fs-ntfs | kmod-fs-vfat | kmod-gpio-nxp-74hc164 | kmod-gre | kmod-gre6 | kmod-hwmon-core | kmod-hwmon-mcp3021 | kmod-hwmon-tla2021 | kmod-i2c-core | kmod-i2c-mt7628 | kmod-ip6-tunnel | kmod-ip6tables | kmod-ipsec | kmod-ipsec4 | kmod-ipsec6 | kmod-ipt-conntrack | kmod-ipt-conntrack-extra | kmod-ipt-core | kmod-ipt-ipopt | kmod-ipt-ipsec | kmod-ipt-ipset | kmod-ipt-nat | kmod-ipt-offload | kmod-ipt-raw | kmod-ipt-raw6 | kmod-iptunnel | kmod-iptunnel4 | kmod-iptunnel6 | kmod-l2tp | kmod-l2tp-eth | kmod-l2tp-ip | kmod-leds-gpio | kmod-lib-crc-ccitt | kmod-lib-crc16 | kmod-lib-crc32c | kmod-lib-textsearch | kmod-lib-zlib-deflate | kmod-lib-zlib-inflate | kmod-mii | kmod-mppe | kmod-nf-conntrack | kmod-nf-conntrack-netlink | kmod-nf-conntrack6 | kmod-nf-flow | kmod-nf-ipt | kmod-nf-ipt6 | kmod-nf-log | kmod-nf-log6 | kmod-nf-nat | kmod-nf-nathelper | kmod-nf-nathelper-extra | kmod-nf-reject | kmod-nf-reject6 | kmod-nfnetlink | kmod-nft-core | kmod-nft-netdev | kmod-nls-base | kmod-nls-cp437 | kmod-nls-iso8859-1 | kmod-nls-utf8 | kmod-ppp | kmod-pppoe | kmod-pppol2tp | kmod-pppox | kmod-pptp | kmod-scsi-core | kmod-slhc | kmod-spi-bitbang | kmod-spi-gpio | kmod-tun | kmod-udptunnel4 | kmod-udptunnel6 | kmod-usb-acm | kmod-usb-core | kmod-usb-ehci | kmod-usb-net | kmod-usb-net-cdc-ether | kmod-usb-net-cdc-ncm | kmod-usb-net-qmi-wwan | kmod-usb-net-rndis | kmod-usb-serial | kmod-usb-serial-ark3116 | kmod-usb-serial-belkin | kmod-usb-serial-ch341 | kmod-usb-serial-ch343 | kmod-usb-serial-cp210x | kmod-usb-serial-cypress-m8 | kmod-usb-serial-ftdi | kmod-usb-serial-option | kmod-usb-serial-pl2303 | kmod-usb-serial-wwan | kmod-usb-storage | kmod-usb-wdm | kmod-usb2 | kmod-wireguard | kmod-xfrm-interface`
  - Role / identity: `KERNEL_OR_KMOD` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=kernel; kernel paths=0; listed paths=1. Description: WireGuard is a novel VPN that runs inside the Linux Kernel and utilizes state-of-the-art cryptography. It aims to be faster, simpler, leaner, and more useful than IPSec, while a... name/source alignment=False; source packages=134; executables=0; libraries=0; sibling roles={'KERNEL_OR_KMOD': 134}; kernel/module scope.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/kernel/mac80211_515` / `kmod-cfg80211_515 5.15.176+6.5-1`
  - Description: cfg80211 is the Linux wireless LAN (802.11) configuration API.
  - Installed paths: `/lib/modules/5.15.176/compat.ko | /lib/modules/5.15.176/cfg80211.ko`
  - Siblings: `kmod-cfg80211_515 | kmod-mac80211_515`
  - Role / identity: `KERNEL_OR_KMOD` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=kernel; kernel paths=2; listed paths=2. Description: cfg80211 is the Linux wireless LAN (802.11) configuration API. name/source alignment=False; source packages=2; executables=0; libraries=0; sibling roles={'KERNEL_OR_KMOD': 2}; kernel/module scope.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/kernel/mt76_515` / `kmod-mt7603_515 5.15.176+2023-09-18-2afc7285-2`
  - Description: MediaTek MT7603 wireless driver
  - Installed paths: `/lib/modules/5.15.176/mt7603e.ko | /lib/firmware/mt7628_e2.bin | /etc/modules.d/mt7603_515`
  - Siblings: `kmod-mt76-core_515 | kmod-mt7603_515`
  - Role / identity: `KERNEL_OR_KMOD` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=kernel; kernel paths=1; listed paths=3. Description: MediaTek MT7603 wireless driver name/source alignment=False; source packages=2; executables=0; libraries=0; sibling roles={'KERNEL_OR_KMOD': 2}; kernel/module scope.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/kernel/linux` / `kmod-usb-core 5.15.176-1`
  - Description: Kernel support for USB
  - Installed paths: `/etc/modules.d/20-usb-core | /etc/modules-boot.d/20-usb-core`
  - Siblings: `kernel | kmod-asn1-decoder | kmod-crypto-acompress | kmod-crypto-aead | kmod-crypto-arc4 | kmod-crypto-authenc | kmod-crypto-cbc | kmod-crypto-ccm | kmod-crypto-cmac | kmod-crypto-crc32c | kmod-crypto-ctr | kmod-crypto-deflate | kmod-crypto-des | kmod-crypto-ecb | kmod-crypto-echainiv | kmod-crypto-gcm | kmod-crypto-gf128 | kmod-crypto-ghash | kmod-crypto-hash | kmod-crypto-hmac | kmod-crypto-kpp | kmod-crypto-lib-blake2s | kmod-crypto-lib-chacha20 | kmod-crypto-lib-chacha20poly1305 | kmod-crypto-lib-curve25519 | kmod-crypto-lib-poly1305 | kmod-crypto-manager | kmod-crypto-md5 | kmod-crypto-null | kmod-crypto-pcompress | kmod-crypto-rng | kmod-crypto-seqiv | kmod-crypto-sha1 | kmod-crypto-sha256 | kmod-crypto-sha512 | kmod-fs-autofs4 | kmod-fs-ext4 | kmod-fs-msdos | kmod-fs-ntfs | kmod-fs-vfat | kmod-gpio-nxp-74hc164 | kmod-gre | kmod-gre6 | kmod-hwmon-core | kmod-hwmon-mcp3021 | kmod-hwmon-tla2021 | kmod-i2c-core | kmod-i2c-mt7628 | kmod-ip6-tunnel | kmod-ip6tables | kmod-ipsec | kmod-ipsec4 | kmod-ipsec6 | kmod-ipt-conntrack | kmod-ipt-conntrack-extra | kmod-ipt-core | kmod-ipt-ipopt | kmod-ipt-ipsec | kmod-ipt-ipset | kmod-ipt-nat | kmod-ipt-offload | kmod-ipt-raw | kmod-ipt-raw6 | kmod-iptunnel | kmod-iptunnel4 | kmod-iptunnel6 | kmod-l2tp | kmod-l2tp-eth | kmod-l2tp-ip | kmod-leds-gpio | kmod-lib-crc-ccitt | kmod-lib-crc16 | kmod-lib-crc32c | kmod-lib-textsearch | kmod-lib-zlib-deflate | kmod-lib-zlib-inflate | kmod-mii | kmod-mppe | kmod-nf-conntrack | kmod-nf-conntrack-netlink | kmod-nf-conntrack6 | kmod-nf-flow | kmod-nf-ipt | kmod-nf-ipt6 | kmod-nf-log | kmod-nf-log6 | kmod-nf-nat | kmod-nf-nathelper | kmod-nf-nathelper-extra | kmod-nf-reject | kmod-nf-reject6 | kmod-nfnetlink | kmod-nft-core | kmod-nft-netdev | kmod-nls-base | kmod-nls-cp437 | kmod-nls-iso8859-1 | kmod-nls-utf8 | kmod-ppp | kmod-pppoe | kmod-pppol2tp | kmod-pppox | kmod-pptp | kmod-scsi-core | kmod-slhc | kmod-spi-bitbang | kmod-spi-gpio | kmod-tun | kmod-udptunnel4 | kmod-udptunnel6 | kmod-usb-acm | kmod-usb-core | kmod-usb-ehci | kmod-usb-net | kmod-usb-net-cdc-ether | kmod-usb-net-cdc-ncm | kmod-usb-net-qmi-wwan | kmod-usb-net-rndis | kmod-usb-serial | kmod-usb-serial-ark3116 | kmod-usb-serial-belkin | kmod-usb-serial-ch341 | kmod-usb-serial-ch343 | kmod-usb-serial-cp210x | kmod-usb-serial-cypress-m8 | kmod-usb-serial-ftdi | kmod-usb-serial-option | kmod-usb-serial-pl2303 | kmod-usb-serial-wwan | kmod-usb-storage | kmod-usb-wdm | kmod-usb2 | kmod-wireguard | kmod-xfrm-interface`
  - Role / identity: `KERNEL_OR_KMOD` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=kernel; kernel paths=0; listed paths=2. Description: Kernel support for USB name/source alignment=False; source packages=134; executables=0; libraries=0; sibling roles={'KERNEL_OR_KMOD': 134}; kernel/module scope.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.

### F_vendor_multi_package

- Source / Package: `package/teltonika/data_sender` / `data-sender 1.15-1`
  - Description: Data sender daemon by Teltonika
  - Installed paths: `/usr/sbin/datasender | /lib/troubleshoot/data_sender.sh | /etc/init.d/data_sender | /etc/config/data_sender | /usr/share/acl.d/data_sender.json | /lib/data_sender/libdata_sender.sh`
  - Siblings: `data-sender | data-sender-mod-base | data-sender-mod-format-custom | data-sender-mod-gsm | data-sender-mod-http | data-sender-mod-lua-in | data-sender-mod-lua_format | data-sender-mod-mdcollect | data-sender-mod-mnfinfo | data-sender-mod-modbus | data-sender-mod-modbus-alarm | data-sender-mod-mqtt-in | data-sender-mod-mqtt-out | data-sender-mod-opcua | data-sender-mod-ubus`
  - Role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `(none)`
  - Evidence: Package name aligns with control Source basename; it has 6 listed paths and 14 siblings. Description: Data sender daemon by Teltonika name/source alignment=True; source packages=15; executables=2; libraries=0; sibling roles={'PLUGIN_OR_MODULE': 14, 'PRODUCT_OR_MAIN_PACKAGE': 1}; main-like runtime evidence exists but source/vendor identity needs independent confirmation.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/gps` / `gpsd 2025-04-29-2`
  - Description: Deamon providing gps related functionality.
  - Installed paths: `/usr/sbin/gpsd | /etc/config/gps | /etc/uci-defaults/7.10/01_gps_add_nmea_rules`
  - Siblings: `avl | gpsctl | gpsd | libgps | ntp_gps`
  - Role / identity: `SPLIT_RUNTIME_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Non-aligned executable/runtime package with 4 siblings; no utility or module signature. Description: Deamon providing gps related functionality. name/source alignment=False; source packages=5; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 3, 'UTILITY_OR_CLI_PACKAGE': 1}; sibling main candidates=(none). The package exposes only a structural subset of its Source.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/gsm` / `gsmctl f61d039a`
  - Description: Simple executable application to execute and read GSM modem AT commands. Created by Teltonika
  - Installed paths: `/usr/sbin/gsmctl`
  - Siblings: `gsmctl | gsmd | libgsm1.0 | liburc`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=net; executables=1; control description identifies utility/tool behavior. Description: Simple executable application to execute and read GSM modem AT commands. Created by Teltonika name/source alignment=False; source packages=4; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 2, 'SPLIT_RUNTIME_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; utility split with sibling main candidates=(none).
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/esim-lpac` / `esim-lpac 1.3.11`
  - Description: eSIM Lpac manager
  - Installed paths: `/sbin/lpac | /sbin/esim_delete_profiles | /etc/lpac_config.json`
  - Siblings: `esim-lpac | liblpac | lua_lpac | rpc_esim`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=utils; executables=2; control description identifies utility/tool behavior. Description: eSIM Lpac manager name/source alignment=True; source packages=4; executables=2; libraries=0; sibling roles={'LIBRARY_PACKAGE': 2, 'PLUGIN_OR_MODULE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; the installed CLI aligns with Source name, but CLI scope versus the complete upstream product remains unresolved.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/mctl` / `mctl 4.10`
  - Description: Simple executable application for modem restart. Created by Teltonika
  - Installed paths: `/sbin/mctl`
  - Siblings: `libmctl | mctl | modem_trackd`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=utils; executables=1; control description identifies utility/tool behavior. Description: Simple executable application for modem restart. Created by Teltonika name/source alignment=True; source packages=3; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 2}; the installed CLI aligns with Source name, but CLI scope versus the complete upstream product remains unresolved.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.

### G_propagated_cpe_id

- Source / Package: `package/network/services/strongswan` / `strongswan 5.9.14-24`
  - Description: StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This package contains shared libraries and scripts.
  - Installed paths: `/usr/lib/ipsec/libstrongswan.so.0 | /usr/lib/ipsec/libstrongswan.so.0.0.0 | /etc/strongswan.conf | /etc/config/ipsec | /lib/upgrade/keep.d/strongswan`
  - Siblings: `strongswan | strongswan-charon | strongswan-minimal | strongswan-mod-connmark | strongswan-mod-constraints | strongswan-mod-des | strongswan-mod-eap-identity | strongswan-mod-eap-mschapv2 | strongswan-mod-kernel-netlink | strongswan-mod-md4 | strongswan-mod-mgf1 | strongswan-mod-nonce | strongswan-mod-openssl | strongswan-mod-pem | strongswan-mod-pgp | strongswan-mod-pkcs1 | strongswan-mod-pkcs8 | strongswan-mod-pubkey | strongswan-mod-random | strongswan-mod-revocation | strongswan-mod-sha1 | strongswan-mod-socket-default | strongswan-mod-updown | strongswan-mod-vici | strongswan-mod-x509 | strongswan-mod-xauth-generic | strongswan-mod-xcbc | strongswan-swanctl`
  - Role / identity: `PRODUCT_OR_MAIN_PACKAGE` / `DIRECT_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `cpe:/a:strongswan:strongswan`
  - Evidence: Package name aligns with control Source basename; it has 5 listed paths and 27 siblings. Description: StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This package contains shared libraries and scripts. name/source alignment=True; source packages=28; executables=0; libraries=2; sibling roles={'META_OR_HELPER_PACKAGE': 1, 'PLUGIN_OR_MODULE': 24, 'PRODUCT_OR_MAIN_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; control Source name and installed core payload align. This is a product candidate, not a CPE decision.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/network/utils/iptables` / `iptables 1.8.7-3`
  - Description: IP firewall administration tool. Matches: - icmp - tcp - udp - comment - conntrack - limit - mac - mark - multiport - set - state - time Targets: - ACCEPT - CT - DNAT - DROP - R...
  - Installed paths: `/usr/sbin/iptables-save | /usr/sbin/xtables-legacy-multi`
  - Siblings: `ip6tables | iptables | iptables-mod-conntrack-extra | iptables-mod-ipopt | iptables-mod-ipsec | libip4tc2 | libip6tc2 | libxtables12`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `cpe:/a:netfilter:iptables`
  - Evidence: Section=net; executables=4; control description identifies utility/tool behavior. Description: IP firewall administration tool. Matches: - icmp - tcp - udp - comment - conntrack - limit - mac - mark - multiport - set - state - time Targets: - ACCEPT - CT - DNAT - DROP - R... name/source alignment=True; source packages=8; executables=4; libraries=0; sibling roles={'LIBRARY_PACKAGE': 3, 'PLUGIN_OR_MODULE': 3, 'UTILITY_OR_CLI_PACKAGE': 2}; the installed CLI aligns with Source name, but CLI scope versus the complete upstream product remains unresolved.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/libs/openssl` / `openssl-util 3.0.14-3`
  - Description: The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer Security (TLS) proto...
  - Installed paths: `/usr/bin/openssl`
  - Siblings: `libopenssl-conf | libopenssl-legacy | libopenssl3 | openssl-util`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `PARTIAL_OR_SPLIT_COMPONENT`
  - CPE-ID (reference only): `cpe:/a:openssl:openssl`
  - Evidence: Section=utils; executables=1; control description identifies utility/tool behavior. Description: The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer Security (TLS) proto... name/source alignment=False; source packages=4; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'META_OR_HELPER_PACKAGE': 1, 'PLUGIN_OR_MODULE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; utility split with sibling main candidates=(none).
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/network/utils/curl` / `curl 8.11.0-23.2`
  - Description: A client-side URL transfer utility
  - Installed paths: `/usr/bin/curl`
  - Siblings: `curl | libcurl4`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `cpe:/a:haxx:libcurl`
  - Evidence: Section=net; executables=1; control description identifies utility/tool behavior. Description: A client-side URL transfer utility name/source alignment=True; source packages=2; executables=1; libraries=0; sibling roles={'LIBRARY_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; the installed CLI aligns with Source name, but CLI scope versus the complete upstream product remains unresolved.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/utils/e2fsprogs` / `e2fsprogs 1.47.0-2`
  - Description: This package contains essential ext2 filesystem utilities which consists of e2fsck, mke2fs and most of the other core ext2 filesystem utilities.
  - Installed paths: `/usr/sbin/mkfs.ext2 | /usr/sbin/mkfs.ext3 | /usr/lib/libe2p.so.2 | /usr/lib/libe2p.so.2.3`
  - Siblings: `e2fsprogs | libcomerr0 | libext2fs2 | libss2`
  - Role / identity: `UTILITY_OR_CLI_PACKAGE` / `POSSIBLE_PRODUCT_CANDIDATE`
  - CPE-ID (reference only): `cpe:/a:e2fsprogs_project:e2fsprogs`
  - Evidence: Section=utils; executables=4; control description identifies utility/tool behavior. Description: This package contains essential ext2 filesystem utilities which consists of e2fsck, mke2fs and most of the other core ext2 filesystem utilities. name/source alignment=True; source packages=4; executables=4; libraries=2; sibling roles={'LIBRARY_PACKAGE': 3, 'UTILITY_OR_CLI_PACKAGE': 1}; the installed CLI aligns with Source name, but CLI scope versus the complete upstream product remains unresolved.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.

### H_identity_ambiguous

- Source / Package: `package/network/services/strongswan` / `strongswan-minimal 5.9.14-24`
  - Description: StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This meta-package contains only dependencies for a minimal IKEv2 setup.
  - Installed paths: `(empty .list)`
  - Siblings: `strongswan | strongswan-charon | strongswan-minimal | strongswan-mod-connmark | strongswan-mod-constraints | strongswan-mod-des | strongswan-mod-eap-identity | strongswan-mod-eap-mschapv2 | strongswan-mod-kernel-netlink | strongswan-mod-md4 | strongswan-mod-mgf1 | strongswan-mod-nonce | strongswan-mod-openssl | strongswan-mod-pem | strongswan-mod-pgp | strongswan-mod-pkcs1 | strongswan-mod-pkcs8 | strongswan-mod-pubkey | strongswan-mod-random | strongswan-mod-revocation | strongswan-mod-sha1 | strongswan-mod-socket-default | strongswan-mod-updown | strongswan-mod-vici | strongswan-mod-x509 | strongswan-mod-xauth-generic | strongswan-mod-xcbc | strongswan-swanctl`
  - Role / identity: `META_OR_HELPER_PACKAGE` / `NON_PRODUCT_ARTIFACT`
  - CPE-ID (reference only): `cpe:/a:strongswan:strongswan`
  - Evidence: The exact .list is empty; role relies on control metadata and sibling structure. Description: StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This meta-package contains only dependencies for a minimal IKEv2 setup. name/source alignment=False; source packages=28; executables=0; libraries=0; sibling roles={'META_OR_HELPER_PACKAGE': 1, 'PLUGIN_OR_MODULE': 24, 'PRODUCT_OR_MAIN_PACKAGE': 1, 'SPLIT_RUNTIME_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 1}; empty/development/helper payload does not itself show a complete runtime product.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/libs/toolchain` / `libpthread 1.2.4-3`
  - Description: POSIX thread library
  - Installed paths: `(empty .list)`
  - Siblings: `libatomic1 | libc | libgcc1 | libpthread | librt | libstdcpp6`
  - Role / identity: `META_OR_HELPER_PACKAGE` / `NON_PRODUCT_ARTIFACT`
  - CPE-ID (reference only): `(none)`
  - Evidence: The exact .list is empty; role relies on control metadata and sibling structure. Description: POSIX thread library name/source alignment=False; source packages=6; executables=0; libraries=0; sibling roles={'LIBRARY_PACKAGE': 3, 'META_OR_HELPER_PACKAGE': 2, 'SPLIT_RUNTIME_PACKAGE': 1}; empty/development/helper payload does not itself show a complete runtime product.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/reboot_utils` / `reboot_utils 2025-03-05-1`
  - Description: Reboot utilities
  - Installed paths: `(empty .list)`
  - Siblings: `reboot_utils | reboot_utils-periodic | reboot_utils-ping`
  - Role / identity: `META_OR_HELPER_PACKAGE` / `NON_PRODUCT_ARTIFACT`
  - CPE-ID (reference only): `(none)`
  - Evidence: The exact .list is empty; role relies on control metadata and sibling structure. Description: Reboot utilities name/source alignment=True; source packages=3; executables=0; libraries=0; sibling roles={'META_OR_HELPER_PACKAGE': 1, 'UTILITY_OR_CLI_PACKAGE': 2}; empty/development/helper payload does not itself show a complete runtime product.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `package/teltonika/macchina-sdk` / `macchina_sdk 0.0.1a`
  - Description: Macchina.io gateway SDK
  - Installed paths: `(empty .list)`
  - Siblings: `macchina_sdk`
  - Role / identity: `META_OR_HELPER_PACKAGE` / `NON_PRODUCT_ARTIFACT`
  - CPE-ID (reference only): `(none)`
  - Evidence: The exact .list is empty; role relies on control metadata and sibling structure. Description: Macchina.io gateway SDK name/source alignment=True; source packages=1; executables=0; libraries=0; sibling roles={'META_OR_HELPER_PACKAGE': 1}; empty/development/helper payload does not itself show a complete runtime product.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.
- Source / Package: `feeds/vuci/api-core` / `api-core 1`
  - Description: Provides core API functionality
  - Installed paths: `/sbin/event_server | /sbin/tls_generate_lua | /usr/lib/lua/vuci/usb.lua | /usr/lib/lua/api/post_logic.lua | /etc/init.d/event_server | /etc/config/vuci`
  - Siblings: `api-core`
  - Role / identity: `PLUGIN_OR_MODULE` / `AMBIGUOUS`
  - CPE-ID (reference only): `(none)`
  - Evidence: Section=webui; plugin/module paths=66; module-style name=False; listed paths=77. Description: Provides core API functionality name/source alignment=True; source packages=1; executables=9; libraries=0; sibling roles={'PLUGIN_OR_MODULE': 1}; single-package library/plugin scope may or may not represent an independent upstream product.
  - GT-rule relevance: Source sharing and propagated CPE-ID are relationship metadata; binary product scope still requires a human rule.

## Answers to the requested questions

1. `42` of `303` Sources are multi-package and contain `314` packages.
2. The exhaustive role distribution is above and in `packages.csv`.
3. Among 42 multi Sources, main+split appears in `9`; library, utility, and plugin/module splits appear in `25`, `24`, and `15` Sources respectively.
4. `33` multi Sources have no observed main/product-like package. In addition, all partial/ambiguous/unresolved rows require more than Source equality.
5. Description exists for all 575 controls. `.list` supplies content evidence for `455` packages; `120` empty lists require control/sibling evidence only.
6. Yes. `197` single-package Sources are classified as non-product, partial, ambiguous, or unresolved rather than product candidates.
7. CPE-ID propagation occurs in `12` multi Sources; the largest is StrongSwan with `28` packages.
8. OpenSSL has library/config/CLI splits and no main-role package; iptables has an aligned CLI candidate plus libraries/modules; StrongSwan has an aligned main candidate plus runtime/CLI/plugins; kernel/linux contains a virtual kernel package and kmod splits.
9. `21` aligned, payload-bearing main packages have the strongest current candidate evidence, without constituting CPE assignments.
10. Library-only, CLI-only, plugins/modules, kmods, firmware/meta/helper, vendor-only, and empty-list packages need separate human policy decisions.
11. The explicit ambiguous/unresolved set contains `184` packages; `packages.csv` records each package and why additional source/upstream evidence is needed.

## All 42 multi-package Sources

Each subsection is generated from exact control/list evidence. Descriptions 
and paths are shortened here; their complete values are in `packages.csv` and 
`multi_package_sources.csv`.

### `feeds/vuci/applications/vuci-app-data-sender/vuci-app-data-sender-api`

- Packages: `13`
- Main candidate(s): `(none)`
- Structure: 13 installed packages; plugin/module=13
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| data-sender-api-mod-format-custom | 1 | Vuci Data Sender API Format Custom module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_formats/ds_format_custom.lua |
| data-sender-api-mod-gsm | 1 | Vuci Data Sender API GSM module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_inputs/ds_input_gsm.lua |
| data-sender-api-mod-http | 1 | Vuci Data Sender API HTTP module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_outputs/ds_output_http.lua |
| data-sender-api-mod-lua-in | 1 | Vuci Data Sender API Lua module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_inputs/ds_input_lua.lua |
| data-sender-api-mod-lua_format | 1 | Vuci Data Sender API Lua Format module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_formats/ds_format_lua.lua |
| data-sender-api-mod-mdcollect | 1 | Vuci Data Sender API Mobile Usage module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_inputs/ds_input_mdcollect.lua |
| data-sender-api-mod-modbus | 1 | Vuci Data Sender API Modbus module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_inputs/ds_input_modbus.lua |
| data-sender-api-mod-modbus-alarm | 1 | Vuci Data Sender API Modbus Alarm module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_inputs/ds_input_modbus_alarm.lua |
| data-sender-api-mod-mqtt-in | 1 | Vuci Data Sender API MQTT Input module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_inputs/ds_input_mqtt.lua |
| data-sender-api-mod-mqtt-out | 1 | Vuci Data Sender API MQTT Output module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_outputs/ds_output_mqtt.lua |
| data-sender-api-mod-opcua | 1 | Vuci Data Sender API OPCUA module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_inputs/ds_input_opcua.lua |
| data-sender-api-mod-ubus | 1 | Vuci Data Sender API UBUS module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/api/services/ds_outputs/ds_output_ubus.lua |
| vuci-app-data-sender-api | 1 | VuCI API Support for Data Sender | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 6 | 0 | 0 | /usr/lib/lua/api/services/data_sender_format.lua \| /usr/lib/lua/api/services/data_sender_collections.lua \| /usr/share/rpcd/acl.d/datasender.json |

### `package/kernel/linux`

- Packages: `134`
- Main candidate(s): `(none)`
- Structure: 134 installed packages; kernel/kmod=134
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| kernel | 5.15.176-1-c87d2a600c553d5338b2de4b88b39f15 | Virtual kernel package | KERNEL_OR_KMOD | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-asn1-decoder | 5.15.176-1 | Simple ASN1 decoder | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-acompress | 5.15.176-1 | Asynchronous Compression operations | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-acompress |
| kmod-crypto-aead | 5.15.176-1 | CryptoAPI AEAD support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/09-crypto-aead \| /etc/modules.d/09-crypto-aead |
| kmod-crypto-arc4 | 5.15.176-1 | ARC4 cipher CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-authenc | 5.15.176-1 | Combined mode wrapper for IPsec | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-authenc |
| kmod-crypto-cbc | 5.15.176-1 | Cipher Block Chaining CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-cbc |
| kmod-crypto-ccm | 5.15.176-1 | Support for Counter with CBC MAC (CCM) | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-ccm |
| kmod-crypto-cmac | 5.15.176-1 | Support for Cipher-based Message Authentication Code (CMAC) | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-cmac |
| kmod-crypto-crc32c | 5.15.176-1 | CRC32c CRC module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/04-crypto-crc32c \| /etc/modules-boot.d/04-crypto-crc32c |
| kmod-crypto-ctr | 5.15.176-1 | Counter Mode CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-ctr |
| kmod-crypto-deflate | 5.15.176-1 | Deflate compression CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-deflate |
| kmod-crypto-des | 5.15.176-1 | DES/3DES cipher CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-des |
| kmod-crypto-ecb | 5.15.176-1 | Electronic CodeBook CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-ecb |
| kmod-crypto-echainiv | 5.15.176-1 | Encrypted Chain IV Generator | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-echainiv |
| kmod-crypto-gcm | 5.15.176-1 | GCM/GMAC CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-gcm |
| kmod-crypto-gf128 | 5.15.176-1 | GF(2^128) multiplication functions CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-gf128 |
| kmod-crypto-ghash | 5.15.176-1 | GHASH digest CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-ghash |
| kmod-crypto-hash | 5.15.176-1 | CryptoAPI hash support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/02-crypto-hash \| /etc/modules-boot.d/02-crypto-hash |
| kmod-crypto-hmac | 5.15.176-1 | HMAC digest CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-hmac |
| kmod-crypto-kpp | 5.15.176-1 | Key-agreement Protocol Primitives | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-lib-blake2s | 5.15.176-1 | BLAKE2s hash function library | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-lib-chacha20 | 5.15.176-1 | ChaCha library interface | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-lib-chacha20poly1305 | 5.15.176-1 | ChaCha20-Poly1305 AEAD support (8-byte nonce library version) | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-lib-curve25519 | 5.15.176-1 | Curve25519 scalar multiplication library | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-lib-poly1305 | 5.15.176-1 | Poly1305 library interface | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-manager | 5.15.176-1 | CryptoAPI algorithm manager | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-manager \| /etc/modules-boot.d/09-crypto-manager |
| kmod-crypto-md5 | 5.15.176-1 | MD5 digest CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-md5 |
| kmod-crypto-null | 5.15.176-1 | Null CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-null |
| kmod-crypto-pcompress | 5.15.176-1 | CryptoAPI Partial (de)compression operations | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-crypto-rng | 5.15.176-1 | CryptoAPI random number generation | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-rng |
| kmod-crypto-seqiv | 5.15.176-1 | CryptoAPI Sequence Number IV Generator | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-seqiv |
| kmod-crypto-sha1 | 5.15.176-1 | SHA1 digest CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-sha1 |
| kmod-crypto-sha256 | 5.15.176-1 | SHA224 SHA256 digest CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-sha256 |
| kmod-crypto-sha512 | 5.15.176-1 | SHA512 digest CryptoAPI module | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/09-crypto-sha512 |
| kmod-fs-autofs4 | 5.15.176-1 | Kernel module for AutoFS4 support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/30-fs-autofs4 |
| kmod-fs-ext4 | 5.15.176-1 | Kernel module for EXT4 filesystem support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/30-fs-ext4 \| /etc/modules.d/30-fs-ext4 |
| kmod-fs-msdos | 5.15.176-1 | Kernel module for MSDOS filesystem support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/40-fs-msdos |
| kmod-fs-ntfs | 5.15.176-1 | Kernel module for NTFS filesystem support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/30-fs-ntfs |
| kmod-fs-vfat | 5.15.176-1 | Kernel module for VFAT filesystem support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/30-fs-vfat |
| kmod-gpio-nxp-74hc164 | 5.15.176-1 | Kernel module for NXP 74HC164 GPIO expander | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/gpio-nxp-74hc164 \| /etc/modules-boot.d/gpio-nxp-74hc164 |
| kmod-gre | 5.15.176-1 | Generic Routing Encapsulation support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/39-gre |
| kmod-gre6 | 5.15.176-1 | Generic Routing Encapsulation support over IPv6 | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/39-gre6 |
| kmod-hwmon-core | 5.15.176-1 | Kernel modules for hardware monitoring | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-hwmon-mcp3021 | 5.15.176-1 | Kernel module for Linear Technology MCP3021/3221 current and voltage monitor chip | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/hwmon-mcp3021 |
| kmod-hwmon-tla2021 | 5.15.176-1 | Kernel module for Linear Technology TLA2021/2024 current and voltage monitor chip | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/hwmon-tla2021 |
| kmod-i2c-core | 5.15.176-1 | Kernel modules for I2C support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/51-i2c-core |
| kmod-i2c-mt7628 | 5.15.176-1 | Kernel modules for enable mt7621 i2c controller. | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/59-i2c-mt7628 |
| kmod-ip6-tunnel | 5.15.176-1 | Kernel modules for IPv6-in-IPv6 and IPv4-in-IPv6 tunnelling | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/32-ip6-tunnel |
| kmod-ip6tables | 5.15.176-1 | Netfilter IPv6 firewalling support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-ipsec | 5.15.176-1 | Kernel modules for IPsec support in both IPv4 and IPv6. Includes: - af_key - xfrm_algo - xfrm_ipcomp - xfrm_user | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/30-ipsec |
| kmod-ipsec4 | 5.15.176-1 | Kernel modules for IPsec support in IPv4. Includes: - ah4 - esp4 - ipcomp4 - xfrm4_mode_beet - xfrm4_mode_transport - xfrm4_mode_tunnel - xfrm4_tunnel | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/32-ipsec4 |
| kmod-ipsec6 | 5.15.176-1 | Kernel modules for IPsec support in IPv6. Includes: - ah6 - esp6 - ipcomp6 - xfrm6_mode_beet - xfrm6_mode_transport - xfrm6_mode_tunnel - xfrm6_tunnel | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/32-ipsec6 |
| kmod-ipt-conntrack | 5.15.176-1 | Netfilter (IPv4) kernel modules for connection tracking Includes: - conntrack - defrag - iptables_raw - NOTRACK - state | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-ipt-conntrack-extra | 5.15.176-1 | Netfilter (IPv4) extra kernel modules for connection tracking Includes: - connbytes - connmark/CONNMARK - conntrack - helper - recent | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-ipt-core | 5.15.176-1 | Netfilter core kernel modules Includes: - comment - limit - LOG - mac - multiport - REJECT - TCPMSS | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-ipt-ipopt | 5.15.176-1 | Netfilter (IPv4) modules for matching/changing IP packet options Includes: - CLASSIFY - dscp/DSCP - ecn/ECN - hl/HL - length - mark/MARK - statistic - tcpmss... | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-ipt-ipsec | 5.15.176-1 | Netfilter (IPv4) modules for matching IPSec packets Includes: - ah - esp - policy | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-ipt-ipset | 5.15.176-1 | IPset netfilter modules | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/49-ipt-ipset |
| kmod-ipt-nat | 5.15.176-1 | Netfilter (IPv4) kernel modules for basic NAT targets Includes: - MASQUERADE | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-ipt-offload | 5.15.176-1 | Netfilter routing/NAT offload support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-ipt-raw | 5.15.176-1 | Netfilter IPv4 raw table support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/ipt-raw |
| kmod-ipt-raw6 | 5.15.176-1 | Netfilter IPv6 raw table support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/ipt-raw6 |
| kmod-iptunnel | 5.15.176-1 | Kernel module for generic IP tunnel support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/31-iptunnel |
| kmod-iptunnel4 | 5.15.176-1 | Kernel modules for IPv4 tunneling | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/31-iptunnel4 |
| kmod-iptunnel6 | 5.15.176-1 | Kernel modules for IPv6 tunneling | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/31-iptunnel6 |
| kmod-l2tp | 5.15.176-1 | Kernel modules for L2TP V3 Support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/32-l2tp |
| kmod-l2tp-eth | 5.15.176-1 | Kernel modules for L2TP ethernet pseudowire support for L2TPv3 | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/33-l2tp-eth |
| kmod-l2tp-ip | 5.15.176-1 | Kernel modules for L2TP IP encapsulation for L2TPv3 | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/33-l2tp-ip |
| kmod-leds-gpio | 5.15.176-1 | Kernel module for LEDs on GPIO lines | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/60-leds-gpio \| /etc/modules.d/60-leds-gpio |
| kmod-lib-crc-ccitt | 5.15.176-1 | Kernel module for CRC-CCITT support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/lib-crc-ccitt |
| kmod-lib-crc16 | 5.15.176-1 | Kernel module for CRC16 support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/20-lib-crc16 \| /etc/modules.d/20-lib-crc16 |
| kmod-lib-crc32c | 5.15.176-1 | Kernel module for CRC32 support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/lib-crc32c |
| kmod-lib-textsearch | 5.15.176-1 | Textsearch support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/lib-textsearch |
| kmod-lib-zlib-deflate | 5.15.176-1 | Zlib support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/lib-zlib-deflate |
| kmod-lib-zlib-inflate | 5.15.176-1 | Zlib support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/lib-zlib-inflate |
| kmod-mii | 5.15.176-1 | MII library | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/15-mii \| /etc/modules.d/15-mii |
| kmod-mppe | 5.15.176-1 | Kernel modules for Microsoft PPP compression/encryption | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/mppe |
| kmod-nf-conntrack | 5.15.176-1 | Netfilter connection tracking | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/sysctl.d/11-nf-conntrack.conf |
| kmod-nf-conntrack-netlink | 5.15.176-1 | Kernel modules support for a netlink-based connection tracking userspace interface | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/nf-conntrack-netlink |
| kmod-nf-conntrack6 | 5.15.176-1 | Netfilter IPv6 connection tracking | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-flow | 5.15.176-1 | Netfilter flowtable support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/nf-flow |
| kmod-nf-ipt | 5.15.176-1 | Iptables core | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-ipt6 | 5.15.176-1 | Ip6tables core | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-log | 5.15.176-1 | Netfilter Logging | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-log6 | 5.15.176-1 | Netfilter IPV6 Logging | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-nat | 5.15.176-1 | Netfilter NAT | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-nathelper | 5.15.176-1 | Default Netfilter (IPv4) Conntrack and NAT helpers Includes: - ftp | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-nathelper-extra | 5.15.176-1 | Extra Netfilter (IPv4) Conntrack and NAT helpers Includes: - amanda - h323 - irc - mms - pptp - proto_gre - sip - snmp_basic - tftp - broadcast | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-reject | 5.15.176-1 | Netfilter IPv4 reject support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nf-reject6 | 5.15.176-1 | Netfilter IPv6 reject support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nfnetlink | 5.15.176-1 | Kernel modules support for a netlink-based userspace interface | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nft-core | 5.15.176-1 | Kernel module support for nftables | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nft-netdev | 5.15.176-1 | Netfilter nf_tables netdev support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/nft-netdev |
| kmod-nls-base | 5.15.176-1 | Kernel module for NLS (Native Language Support) | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-nls-cp437 | 5.15.176-1 | Kernel module for NLS Codepage 437 (United States, Canada) | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/25-nls-cp437 |
| kmod-nls-iso8859-1 | 5.15.176-1 | Kernel module for NLS ISO 8859-1 (Latin 1) | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/25-nls-iso8859-1 |
| kmod-nls-utf8 | 5.15.176-1 | Kernel module for NLS UTF-8 | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/25-nls-utf8 |
| kmod-ppp | 5.15.176-1 | Kernel modules for PPP support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/ppp |
| kmod-pppoe | 5.15.176-1 | Kernel module for PPPoE (PPP over Ethernet) support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/pppoe |
| kmod-pppol2tp | 5.15.176-1 | Kernel modules for PPPoL2TP (PPP over L2TP) support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/pppol2tp |
| kmod-pppox | 5.15.176-1 | Kernel helper module for PPPoE and PPTP support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-pptp | 5.15.176-1 | PPtP support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/pptp |
| kmod-scsi-core | 5.15.176-1 | SCSI device support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/40-scsi-core \| /etc/modules.d/40-scsi-core |
| kmod-slhc | 5.15.176-1 | Serial Line Header Compression | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-spi-bitbang | 5.15.176-1 | This package contains the SPI bitbanging library | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| kmod-spi-gpio | 5.15.176-1 | This package contains the GPIO-based bitbanging SPI Master | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/spi-gpio \| /etc/modules.d/spi-gpio |
| kmod-tun | 5.15.176-1 | Kernel support for the TUN/TAP tunneling device | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/30-tun |
| kmod-udptunnel4 | 5.15.176-1 | IPv4 UDP tunneling support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/32-udptunnel4 |
| kmod-udptunnel6 | 5.15.176-1 | IPv6 UDP tunneling support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/32-udptunnel6 |
| kmod-usb-acm | 5.15.176-1 | Kernel support for USB ACM devices (modems/isdn controllers) | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-acm |
| kmod-usb-core | 5.15.176-1 | Kernel support for USB | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/20-usb-core \| /etc/modules-boot.d/20-usb-core |
| kmod-usb-ehci | 5.15.176-1 | EHCI controller support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/35-usb-ehci \| /etc/modules.d/35-usb-ehci |
| kmod-usb-net | 5.15.176-1 | Kernel modules for USB-to-Ethernet convertors | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-net |
| kmod-usb-net-cdc-ether | 5.15.176-1 | Kernel support for USB CDC Ethernet devices | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-net-cdc-ether |
| kmod-usb-net-cdc-ncm | 5.15.176-1 | Kernel support for CDC NCM connections | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-net-cdc-ncm |
| kmod-usb-net-qmi-wwan | 5.15.176-1 | QMI WWAN driver for Qualcomm MSM based 3G and LTE modems | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-net-qmi-wwan |
| kmod-usb-net-rndis | 5.15.176-1 | Kernel support for RNDIS connections | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-net-rndis |
| kmod-usb-serial | 5.15.176-1 | Kernel support for USB-to-Serial converters | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial |
| kmod-usb-serial-ark3116 | 5.15.176-1 | Kernel support for ArkMicroChips ARK3116 USB-to-Serial converters | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-ark3116 |
| kmod-usb-serial-belkin | 5.15.176-1 | Kernel support for Belkin USB-to-Serial converters | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-belkin |
| kmod-usb-serial-ch341 | 5.15.176-1 | Kernel support for Winchiphead CH341 USB-to-Serial converters | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-ch341 |
| kmod-usb-serial-ch343 | 5.15.176-1 | Kernel support for Winchiphead CH343 USB-to-Serial converters | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-ch343 |
| kmod-usb-serial-cp210x | 5.15.176-1 | Kernel support for Silicon Labs cp210x USB-to-Serial converters | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-cp210x |
| kmod-usb-serial-cypress-m8 | 5.15.176-1 | Kernel support for devices with Cypress M8 USB to Serial chip (for example, the Delorme Earthmate LT-20 GPS) Supported microcontrollers in the CY4601 family ... | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-cypress-m8 |
| kmod-usb-serial-ftdi | 5.15.176-1 | Kernel support for FTDI USB-to-Serial converters | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-ftdi |
| kmod-usb-serial-option | 5.15.176-1 | Kernel support for Option HSDPA modems | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-option |
| kmod-usb-serial-pl2303 | 5.15.176-1 | Kernel support for Prolific PL2303 USB-to-Serial converters | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-pl2303 |
| kmod-usb-serial-wwan | 5.15.176-1 | Kernel support for USB GSM and CDMA modems | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-serial-wwan |
| kmod-usb-storage | 5.15.176-1 | Kernel support for USB Mass Storage devices | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/usb-storage \| /etc/modules.d/usb-storage |
| kmod-usb-wdm | 5.15.176-1 | USB Wireless Device Management support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/usb-wdm |
| kmod-usb2 | 5.15.176-1 | Kernel support for USB2 (EHCI) controllers | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules-boot.d/40-usb2 \| /etc/modules.d/40-usb2 |
| kmod-wireguard | 5.15.176-1 | WireGuard is a novel VPN that runs inside the Linux Kernel and utilizes state-of-the-art cryptography. It aims to be faster, simpler, leaner, and more useful... | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/wireguard |
| kmod-xfrm-interface | 5.15.176-1 | Kernel module for XFRM interface support | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/modules.d/xfrm-interface |

### `package/kernel/mac80211_515`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; kernel/kmod=2
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| kmod-cfg80211_515 | 5.15.176+6.5-1 | cfg80211 is the Linux wireless LAN (802.11) configuration API. | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 2 | 0 | /lib/modules/5.15.176/compat.ko \| /lib/modules/5.15.176/cfg80211.ko |
| kmod-mac80211_515 | 5.15.176+6.5-1 | Generic IEEE 802.11 Networking Stack (mac80211) | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 1 | 0 | /lib/modules/5.15.176/mac80211.ko |

### `package/kernel/mt76_515`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; kernel/kmod=2
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| kmod-mt76-core_515 | 5.15.176+2023-09-18-2afc7285-2 | MediaTek MT76xx wireless driver | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 1 | 0 | /lib/modules/5.15.176/mt76.ko |
| kmod-mt7603_515 | 5.15.176+2023-09-18-2afc7285-2 | MediaTek MT7603 wireless driver | KERNEL_OR_KMOD | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 1 | 1 | /lib/modules/5.15.176/mt7603e.ko \| /lib/firmware/mt7628_e2.bin \| /etc/modules.d/mt7603_515 |

### `package/libs/libcap`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1; utility=1
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:libcap_project:libcap`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libcap | 2.69-1 | Linux capabilities library library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 3 | 0 | 0 | 0 | /usr/lib/libcap.so.2.69 \| /usr/lib/libcap.so |
| libcap-bin | 2.69-1 | Linux capabilities . This package contains the libcap utilities. | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 4 | 0 | 0 | 0 | 0 | /usr/sbin/setcap \| /usr/sbin/getcap |

### `package/libs/libgpiod`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1; utility=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| gpiod-tools | 1.6.3-1 | Tools for interacting with the linux GPIO character device (gpiod stands for GPIO device), minimal required version. | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 3 | 0 | 0 | 0 | 0 | /usr/bin/gpiofind \| /usr/bin/gpioset |
| libgpiod | 1.6.3-1 | C library for interacting with the linux GPIO character device (gpiod stands for GPIO device). | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libgpiod.so.2.2.2 \| /usr/lib/libgpiod.so.2 |

### `package/libs/libnl`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=2
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:libnl_project:libnl`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libnl-core200 | 3.9.0-1 | Common code for all netlink libraries | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libnl-3.so.200 \| /usr/lib/libnl-3.so.200.26.0 |
| libnl-genl200 | 3.9.0-1 | Generic Netlink Library Functions | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libnl-genl-3.so.200 \| /usr/lib/libnl-genl-3.so.200.26.0 |

### `package/libs/libubox`

- Packages: `5`
- Main candidate(s): `(none)`
- Structure: 5 installed packages; library=3; utility=1; plugin/module=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| jshn | 2024-03-29-eb9bcb64-2 | Library for parsing and generating JSON from shell scripts | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/bin/jshn \| /usr/share/libubox/jshn.sh |
| libblobmsg-json20240329 | 2024-03-29-eb9bcb64-2 | blobmsg <-> json conversion library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /lib/libblobmsg_json.so.20240329 |
| libjson-script20240329 | 2024-03-29-eb9bcb64-2 | Minimalistic JSON based scripting engine | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /lib/libjson_script.so.20240329 |
| libubox-lua | 2024-03-29-eb9bcb64-2 | Lua binding for the OpenWrt Basic utility library | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/uloop.so |
| libubox20240329 | 2024-03-29-eb9bcb64-2 | Basic utility library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /lib/libubox.so.20240329 |

### `package/libs/openssl`

- Packages: `4`
- Main candidate(s): `(none)`
- Structure: 4 installed packages; library=1; utility=1; plugin/module=1; meta/helper=1
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:openssl:openssl`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libopenssl-conf | 3.0.14-3 | The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer ... | META_OR_HELPER_PACKAGE | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 | /etc/config/openssl \| /etc/ssl/openssl.cnf |
| libopenssl-legacy | 3.0.14-3 | The OpenSSL legacy provider supplies OpenSSL implementations of algorithms that have been deemed legacy. Such algorithms have commonly fallen out of use, hav... | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ossl-modules/legacy.so \| /etc/ssl/modules.cnf.d/legacy.cnf |
| libopenssl3 | 3.0.14-3 | The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer ... | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libssl.so.3 \| /usr/lib/libcrypto.so.3 |
| openssl-util | 3.0.14-3 | The OpenSSL Project is a collaborative effort to develop a robust, commercial-grade, full-featured, and Open Source toolkit implementing the Transport Layer ... | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/bin/openssl |

### `package/libs/toolchain`

- Packages: `6`
- Main candidate(s): `(none)`
- Structure: 6 installed packages; library=3; meta/helper=2
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libatomic1 | 8.4.0-3 | Atomic support library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /lib/libatomic.so.1 \| /lib/libatomic.so.1.2.0 |
| libc | 1.2.4-3 | C library | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 2 | 0 | 0 | 0 | /usr/bin/ldd \| /lib/ld-musl-mipsel-sf.so.1 \| /lib/libc.so |
| libgcc1 | 8.4.0-3 | GCC support library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /lib/libgcc_s.so.1 |
| libpthread | 1.2.4-3 | POSIX thread library | META_OR_HELPER_PACKAGE | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 |  |
| librt | 1.2.4-3 | POSIX.1b RealTime extension library | META_OR_HELPER_PACKAGE | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 |  |
| libstdcpp6 | 8.4.0-3 | GNU Standard C++ Library v3 | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 3 | 0 | 0 | 0 | /usr/lib/libstdc++.so.6 \| /usr/lib/libstdc++.so.6.0.25-gdb.py |

### `package/libs/uclient`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libuclient20201210 | 2021-05-14-6a6011df-1 | HTTP/1.1 client library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/libuclient.so |
| uclient-fetch | 2021-05-14-6a6011df-1 | Tiny wget replacement using libuclient | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /bin/uclient-fetch |

### `package/network/services/hostapd`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:w1.fi:hostapd`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| hostapd-common | 2023-09-08-e5ccbfc6-11 | hostapd/wpa_supplicant common support files | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /lib/netifd/dhcp-get-server.sh \| /etc/capabilities/wpad.json \| /etc/init.d/wpad \| /usr/share/acl.d/wpad_acl.json \| /usr/share/hostap/wdev.uc |
| wpad-openssl | 2023-09-08-e5ccbfc6-11 | This package contains a full featured IEEE 802.1x/WPA/EAP/RADIUS Authenticator and Supplicant | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 3 | 0 | 0 | 0 | 0 | /usr/sbin/wpad \| /usr/sbin/hostapd \| /usr/share/hostap/wpa_supplicant.uc \| /usr/share/hostap/hostapd.uc |

### `package/network/services/ppp`

- Packages: `4`
- Main candidate(s): `ppp`
- Structure: 4 installed packages; main/product-like=1; plugin/module=3
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:samba:ppp`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| ppp | 2.4.9.git-2021-01-04-4 | This package contains the PPP (Point-to-Point Protocol) daemon. | PRODUCT_OR_MAIN_PACKAGE | DIRECT_PRODUCT_CANDIDATE | 5 | 0 | 0 | 0 | 0 | /usr/sbin/pppd \| /lib/netifd/ppp-up \| /etc/ppp/options.sstp \| /etc/ppp/filter \| /lib/netifd/proto/pppoa.sh \| /lib/netifd/proto/pptp.sh \| /lib/upgrade/k... |
| ppp-mod-pppoe | 2.4.9.git-2021-01-04-4 | This package contains a PPPoE (PPP over Ethernet) plugin for ppp. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/pppd/2.4.9/pppoe.so |
| ppp-mod-pppol2tp | 2.4.9.git-2021-01-04-4 | This package contains a PPPoL2TP (PPP over L2TP) plugin for ppp. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/pppd/2.4.9/pppol2tp.so |
| ppp-mod-pptp | 2.4.9.git-2021-01-04-4 | This package contains a PPtP plugin for ppp. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/pppd/2.4.9/pptp.so \| /etc/ppp/options.pptp |

### `package/network/services/strongswan`

- Packages: `28`
- Main candidate(s): `strongswan`
- Structure: 28 installed packages; main/product-like=1; utility=1; plugin/module=24; meta/helper=1
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:strongswan:strongswan`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| strongswan | 5.9.14-24 | StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This package contains shared libraries and scripts. | PRODUCT_OR_MAIN_PACKAGE | DIRECT_PRODUCT_CANDIDATE | 0 | 2 | 0 | 0 | 0 | /usr/lib/ipsec/libstrongswan.so.0 \| /usr/lib/ipsec/libstrongswan.so.0.0.0 \| /etc/strongswan.conf \| /etc/config/ipsec \| /lib/upgrade/keep.d/strongswan |
| strongswan-charon | 5.9.14-24 | StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This package contains charon, an IKEv2 keying daemon. | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 2 | 0 | 0 | 0 | /usr/lib/ipsec/charon \| /usr/lib/ipsec/libcharon.so.0.0.0 \| /usr/lib/ipsec/libcharon.so.0 \| /etc/strongswan.d/charon.conf \| /etc/strongswan.d/charon-logg... |
| strongswan-minimal | 5.9.14-24 | StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This meta-package contains only dependencies for a minimal IKEv2 setup. | META_OR_HELPER_PACKAGE | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 |  |
| strongswan-mod-connmark | 5.9.14-24 | StrongSwan netfilter connection marking plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-connmark.so \| /etc/strongswan.d/charon/connmark.conf |
| strongswan-mod-constraints | 5.9.14-24 | StrongSwan advanced X509 constraint checking plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-constraints.so \| /etc/strongswan.d/charon/constraints.conf |
| strongswan-mod-des | 5.9.14-24 | StrongSwan DES crypto plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-des.so \| /etc/strongswan.d/charon/des.conf |
| strongswan-mod-eap-identity | 5.9.14-24 | StrongSwan EAP identity helper plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-eap-identity.so \| /etc/strongswan.d/charon/eap-identity.conf |
| strongswan-mod-eap-mschapv2 | 5.9.14-24 | StrongSwan EAP MS-CHAPv2 EAP auth plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-eap-mschapv2.so \| /etc/strongswan.d/charon/eap-mschapv2.conf |
| strongswan-mod-kernel-netlink | 5.9.14-24 | StrongSwan netlink kernel interface plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-kernel-netlink.so \| /etc/strongswan.d/charon/kernel-netlink.conf |
| strongswan-mod-md4 | 5.9.14-24 | StrongSwan MD4 crypto plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-md4.so \| /etc/strongswan.d/charon/md4.conf |
| strongswan-mod-mgf1 | 5.9.14-24 | StrongSwan MGF1 crypto plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-mgf1.so \| /etc/strongswan.d/charon/mgf1.conf |
| strongswan-mod-nonce | 5.9.14-24 | StrongSwan nonce genereation plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-nonce.so \| /etc/strongswan.d/charon/nonce.conf |
| strongswan-mod-openssl | 5.9.14-24 | StrongSwan OpenSSL crypto plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-openssl.so \| /etc/strongswan.d/charon/openssl.conf |
| strongswan-mod-pem | 5.9.14-24 | StrongSwan PEM decoding plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-pem.so \| /etc/strongswan.d/charon/pem.conf |
| strongswan-mod-pgp | 5.9.14-24 | StrongSwan PGP key decoding plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-pgp.so \| /etc/strongswan.d/charon/pgp.conf |
| strongswan-mod-pkcs1 | 5.9.14-24 | StrongSwan PKCS1 key decoding plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-pkcs1.so \| /etc/strongswan.d/charon/pkcs1.conf |
| strongswan-mod-pkcs8 | 5.9.14-24 | StrongSwan PKCS8 key decoding plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-pkcs8.so \| /etc/strongswan.d/charon/pkcs8.conf |
| strongswan-mod-pubkey | 5.9.14-24 | StrongSwan raw public key plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-pubkey.so \| /etc/strongswan.d/charon/pubkey.conf |
| strongswan-mod-random | 5.9.14-24 | StrongSwan RNG plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-random.so \| /etc/strongswan.d/charon/random.conf |
| strongswan-mod-revocation | 5.9.14-24 | StrongSwan X509 CRL/OCSP revocation plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-revocation.so \| /etc/strongswan.d/charon/revocation.conf |
| strongswan-mod-sha1 | 5.9.14-24 | StrongSwan SHA1 crypto plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-sha1.so \| /etc/strongswan.d/charon/sha1.conf |
| strongswan-mod-socket-default | 5.9.14-24 | StrongSwan default socket implementation for charon plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-socket-default.so \| /etc/strongswan.d/charon/socket-default.conf |
| strongswan-mod-updown | 5.9.14-24 | StrongSwan updown firewall plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 2 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/_updown \| /usr/lib/ipsec/_updown_no_fw \| /usr/lib/ipsec/plugins/libstrongswan-updown.so \| /etc/hotplug.d/ipsec/04-snat-for-default-route \|... |
| strongswan-mod-vici | 5.9.14-24 | StrongSwan Versatile IKE Configuration Interface plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 1 | 0 | 0 | /usr/lib/ipsec/libvici.so.0.0.0 \| /usr/lib/ipsec/libvici.so.0 \| /usr/lib/ipsec/plugins/libstrongswan-vici.so \| /etc/strongswan.d/charon/vici.conf |
| strongswan-mod-x509 | 5.9.14-24 | StrongSwan x509 certificate plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-x509.so \| /etc/strongswan.d/charon/x509.conf |
| strongswan-mod-xauth-generic | 5.9.14-24 | StrongSwan generic XAuth backend plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-xauth-generic.so \| /etc/strongswan.d/charon/xauth-generic.conf |
| strongswan-mod-xcbc | 5.9.14-24 | StrongSwan xcbc crypto plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ipsec/plugins/libstrongswan-xcbc.so \| /etc/strongswan.d/charon/xcbc.conf |
| strongswan-swanctl | 5.9.14-24 | StrongSwan is an OpenSource IPsec implementation for the Linux operating system. This package contains the swanctl utility. | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/swanctl \| /etc/swanctl/swanctl.conf \| /etc/init.d/swanctl \| /lib/upgrade/keep.d/strongswan-swanctl |

### `package/network/services/uhttpd`

- Packages: `3`
- Main candidate(s): `uhttpd`
- Structure: 3 installed packages; main/product-like=1; plugin/module=2
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| uhttpd | 2021-03-21-15346de8-9 | uHTTPd is a tiny single threaded HTTP server with TLS, CGI and Lua support. It is intended as a drop-in replacement for the Busybox HTTP daemon. | PRODUCT_OR_MAIN_PACKAGE | DIRECT_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /usr/sbin/uhttpd \| /etc/init.d/uhttpd \| /etc/config/uhttpd \| /lib/upgrade/keep.d/uhttpd |
| uhttpd-mod-lua | 2021-03-21-15346de8-9 | The Lua plugin adds a CGI-like Lua runtime interface to uHTTPd. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/uhttpd_lua.so |
| uhttpd-mod-ubus | 2021-03-21-15346de8-9 | The ubus plugin adds a HTTP/JSON RPC proxy for ubus and publishes the session.* namespace and procedures. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/uhttpd_ubus.so |

### `package/network/utils/curl`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1; utility=1
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:haxx:libcurl`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| curl | 8.11.0-23.2 | A client-side URL transfer utility | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /usr/bin/curl |
| libcurl4 | 8.11.0-23.2 | A client-side URL transfer library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libcurl.so.4 \| /usr/lib/libcurl.so.4.8.0 |

### `package/network/utils/ipset`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1; utility=1
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:netfilter:ipset`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| ipset | 7.6-1 | IPset administration utility | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /usr/sbin/ipset |
| libipset13 | 7.6-1 | IPset administration utility | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libipset.so.13 \| /usr/lib/libipset.so.13.1.0 |

### `package/network/utils/iptables`

- Packages: `8`
- Main candidate(s): `(none)`
- Structure: 8 installed packages; library=3; utility=2; plugin/module=3
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:netfilter:iptables`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| ip6tables | 1.8.7-3 | IPv6 firewall administration tool | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 3 | 0 | 0 | 0 | 0 | /usr/sbin/ip6tables-save \| /usr/sbin/ip6tables |
| iptables | 1.8.7-3 | IP firewall administration tool. Matches: - icmp - tcp - udp - comment - conntrack - limit - mac - mark - multiport - set - state - time Targets: - ACCEPT - ... | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 4 | 0 | 0 | 0 | 0 | /usr/sbin/iptables-save \| /usr/sbin/xtables-legacy-multi |
| iptables-mod-conntrack-extra | 1.8.7-3 | Extra iptables extensions for connection tracking. Matches: - connbytes - connlimit - connmark - recent - helper Targets: - CONNMARK | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| iptables-mod-ipopt | 1.8.7-3 | iptables extensions for matching/changing IP packet options. Matches: - dscp - ecn - length - statistic - tcpmss - unclean - hl Targets: - DSCP - CLASSIFY - ... | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| iptables-mod-ipsec | 1.8.7-3 | iptables extensions for matching ipsec traffic. Matches: - ah - esp - policy | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| libip4tc2 | 1.8.7-3 | IPv4 firewall - shared libiptc library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 3 | 0 | 0 | 0 | /usr/lib/libip4tc.so.2.0.0 \| /usr/lib/libip4tc.so.2 |
| libip6tc2 | 1.8.7-3 | IPv6 firewall - shared libiptc library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 3 | 0 | 0 | 0 | /usr/lib/libiptext6.so \| /usr/lib/libip6tc.so.2.0.0 |
| libxtables12 | 1.8.7-3 | IPv4/IPv6 firewall - shared xtables library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 3 | 0 | 0 | 0 | /usr/lib/libiptext.so \| /usr/lib/libxtables.so.12.4.0 |

### `package/network/utils/iwinfo`

- Packages: `4`
- Main candidate(s): `(none)`
- Structure: 4 installed packages; library=1; utility=1; plugin/module=1; meta/helper=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| iwinfo | 2023-05-17-c9f5c3f7-1 | Command line frontend for the wireless information library. | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /usr/bin/iwinfo |
| libiwinfo-data | 2023-05-17-c9f5c3f7-1 | libiwinfo Lua binding | META_OR_HELPER_PACKAGE | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 | /usr/share/libiwinfo/devices.txt |
| libiwinfo-lua | 2023-05-17-c9f5c3f7-1 | This is the Lua binding for the iwinfo library. It provides access to all enabled backends. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/iwinfo.so |
| libiwinfo20230121 | 2023-05-17-c9f5c3f7-1 | Wireless information library with simplified API for nl80211 and wext driver interfaces. | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/libiwinfo.so.20230121 |

### `package/system/fstools`

- Packages: `2`
- Main candidate(s): `fstools`
- Structure: 2 installed packages; main/product-like=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| block-mount | 2022-05-03-9e11b372-28 | Block device mounting and checking | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 3 | 1 | 0 | 0 | 0 | /usr/sbin/swapon \| /usr/sbin/swapoff \| /lib/libblkid-tiny.so \| /etc/hotplug.d/block/00-media-change \| /etc/uci-defaults/etc/10_fstab-fstools |
| fstools | 2022-05-03-9e11b372-28 | OpenWrt filesystem tools | PRODUCT_OR_MAIN_PACKAGE | DIRECT_PRODUCT_CANDIDATE | 3 | 1 | 0 | 0 | 0 | /sbin/mount_root \| /sbin/jffs2reset \| /lib/libfstools.so |

### `package/system/procd`

- Packages: `2`
- Main candidate(s): `procd`
- Structure: 2 installed packages; main/product-like=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| procd | 2021-02-23-37eed131-21 | OpenWrt system process manager | PRODUCT_OR_MAIN_PACKAGE | DIRECT_PRODUCT_CANDIDATE | 5 | 1 | 0 | 0 | 0 | /sbin/askfirst \| /sbin/procd \| /lib/libsetlbf.so \| /etc/hotplug.json \| /etc/hotplug-preinit.json \| /lib/functions/procd.sh |
| procd-init | 2021-02-23-37eed131-21 | OpenWrt system process manager init | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /sbin/init |

### `package/system/rpcd`

- Packages: `4`
- Main candidate(s): `(none)`
- Structure: 4 installed packages; utility=1; plugin/module=3
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| rpcd | 2021-03-11-ccb75178-8 | This package provides the UBUS RPC backend server to expose various functionality to frontend programs via JSON-RPC. | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 3 | 0 | 0 | 0 | 0 | /usr/libexec/rpcd/sys \| /usr/libexec/rpcd/lan_info \| /etc/uci-defaults/7.13/99_rpcd_increase_timeout \| /etc/uci-defaults/7.11/99_rpcd_sesitive_info_flag \... |
| rpcd-mod-file | 2021-03-11-ccb75178-8 | Provides ubus calls for file and directory operations. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/rpcd/file.so |
| rpcd-mod-iwinfo | 2021-03-11-ccb75178-8 | Provides ubus calls for accessing iwinfo data. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/rpcd/iwinfo.so |
| rpcd-mod-rpcsys | 2021-03-11-ccb75178-8 | Provides ubus calls for sysupgrade and password changing. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/rpcd/rpcsys.so |

### `package/system/ubox`

- Packages: `3`
- Main candidate(s): `ubox`
- Structure: 3 installed packages; main/product-like=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| getrandom | 2020-10-25-9ef88681-10 | OpenWrt getrandom system helper | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/bin/getrandom |
| logd | 2020-10-25-9ef88681-10 | OpenWrt system log implementation | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 2 | 0 | 0 | 0 | 0 | /sbin/logread \| /sbin/logd \| /etc/init.d/log |
| ubox | 2020-10-25-9ef88681-10 | OpenWrt system helper toolbox | PRODUCT_OR_MAIN_PACKAGE | DIRECT_PRODUCT_CANDIDATE | 2 | 1 | 0 | 0 | 0 | /sbin/validate_data \| /sbin/kmodloader \| /lib/libvalidate.so |

### `package/system/ubus`

- Packages: `4`
- Main candidate(s): `(none)`
- Structure: 4 installed packages; library=1; utility=1; plugin/module=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libubus-lua | 2021-06-30-4fc532c8-6 | Lua binding for the OpenWrt RPC client | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/ubus.so |
| libubus20210630 | 2021-06-30-4fc532c8-6 | OpenWrt RPC client library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /lib/libubus.so.20210630 |
| ubus | 2021-06-30-4fc532c8-6 | OpenWrt RPC client utility | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /bin/ubus |
| ubusd | 2021-06-30-4fc532c8-6 | OpenWrt RPC daemon | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /sbin/ubusd |

### `package/system/uci`

- Packages: `3`
- Main candidate(s): `(none)`
- Structure: 3 installed packages; library=1; utility=1; plugin/module=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libuci-lua | 2021-10-22-f84f49f0-12-12 | Lua plugin for UCI | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/lua/uci.so |
| libuci20130104 | 2021-10-22-f84f49f0-12-12 | C library for the Unified Configuration Interface (UCI) | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /lib/libuci.so |
| uci | 2021-10-22-f84f49f0-12-12 | Utility for the Unified Configuration Interface (UCI) | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /sbin/uci \| /lib/config/uci.sh |

### `package/teltonika/data_sender`

- Packages: `15`
- Main candidate(s): `data-sender`
- Structure: 15 installed packages; main/product-like=1; plugin/module=14
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| data-sender | 1.15-1 | Data sender daemon by Teltonika | PRODUCT_OR_MAIN_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 2 | 0 | 0 | 0 | 0 | /usr/sbin/datasender \| /lib/troubleshoot/data_sender.sh \| /etc/init.d/data_sender \| /etc/config/data_sender \| /usr/share/acl.d/data_sender.json \| /lib/d... |
| data-sender-mod-base | 1.15-1 | Base input plugin | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-format-custom | 1.15-1 | Format plugin for data concatenation | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-gsm | 1.15-1 | Input plugin for gsm information | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /usr/share/acl.d/ds_gsm.json |
| data-sender-mod-http | 1.15-1 | Output plugin for sending data over http | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-lua-in | 1.15-1 | Input plugin for custom scripts | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/data_sender/modules/input/lua/example_input_lua.lua |
| data-sender-mod-lua_format | 1.15-1 | Output plugin for custom formating | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /etc/data_sender/modules/format/lua/example_format_lua.lua |
| data-sender-mod-mdcollect | 1.15-1 | Input plugin for data usage information | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 | /usr/share/acl.d/ds_mdcollect.json |
| data-sender-mod-mnfinfo | 1.15-1 | Input plugin for manufacturer information | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-modbus | 1.15-1 | Input plugin for modbus data gathering | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-modbus-alarm | 1.15-1 | Input plugin for modbus alarm gathering | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-mqtt-in | 1.15-1 | Input plugin for subscribing MQTT data | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-mqtt-out | 1.15-1 | Output plugin for sending data over MQTT | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-opcua | 1.15-1 | Input plugin for OPC UA data gathering | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |
| data-sender-mod-ubus | 1.15-1 | Output plugin for sending data over UBUS | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 0 | 0 | 0 |  |

### `package/teltonika/ddns-scripts`

- Packages: `5`
- Main candidate(s): `ddns-scripts`
- Structure: 5 installed packages; main/product-like=1; meta/helper=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| ddns-scripts | 2025-02-06-1 | Dynamic DNS Client scripts (with IPv6 support) - Info: http://wiki.openwrt.org/doc/howto/ddns.client | PRODUCT_OR_MAIN_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 3 | 0 | 0 | 0 | 0 | /usr/lib/ddns/dynamic_dns_updater.sh \| /usr/lib/ddns/dynamic_dns_functions.sh \| /etc/uci-defaults/ddns.defaults \| /etc/ddns/services \| /usr/share/acl.d/d... |
| ddns-scripts_cloudflare.com-v4 | 2025-02-06-1 | Dynamic DNS Client scripts extension for CloudFlare.com API-v4 (require/install cURL) | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/lib/ddns/update_cloudflare_com_v4.sh |
| ddns-scripts_no-ip_com | 2025-02-06-1 | Dynamic DNS Client scripts extension for No-IP.com | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/lib/ddns/update_no-ip_com.sh |
| ddns-scripts_nsupdate | 2025-02-06-1 | Dynamic DNS Client scripts extension for direct updates using Bind nsupdate | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/lib/ddns/update_nsupdate.sh |
| tlt-ddns | 2025-02-06-1 | Dynamic DNS (DDNS or DynDNS) is a method of automatically updating a name server in the Domain Name System (DNS). This is most often utilized when the end us... | META_OR_HELPER_PACKAGE | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 |  |

### `package/teltonika/esim-lpac`

- Packages: `4`
- Main candidate(s): `(none)`
- Structure: 4 installed packages; library=2; utility=1; plugin/module=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| esim-lpac | 1.3.11 | eSIM Lpac manager | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 2 | 0 | 0 | 0 | 0 | /sbin/lpac \| /sbin/esim_delete_profiles \| /etc/lpac_config.json |
| liblpac | 1.3.11 | A library for eSIM Lpac manager | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/liblpac.so |
| lua_lpac | 1.3.11 | A lua library for eSIM Lpac manager | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 2 | 0 | 0 | /usr/lib/lua/lua_lpac.so \| /usr/lib/lua/lpac.lua |
| rpc_esim | 1.3.11 | RPC library for eSIM management | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/rpcd/rpc_esim.so |

### `package/teltonika/gps`

- Packages: `5`
- Main candidate(s): `(none)`
- Structure: 5 installed packages; library=1; utility=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| avl | 2025-04-29-2 | Daemon for sending data to AVL server. | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/avl \| /etc/config/avl \| /etc/init.d/avl |
| gpsctl | 2025-04-29-2 | Console line interface for gpsd daemon. | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/gpsctl |
| gpsd | 2025-04-29-2 | Deamon providing gps related functionality. | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/gpsd \| /etc/config/gps \| /etc/uci-defaults/7.10/01_gps_add_nmea_rules |
| libgps | 2025-04-29-2 | Library for communication with the gpsd daemon. | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/libgps.so |
| ntp_gps | 2025-04-29-2 | Daemon meant for syncing system time with GPS data. | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/ntp_gps \| /etc/init.d/ntp_gps |

### `package/teltonika/gsm`

- Packages: `4`
- Main candidate(s): `(none)`
- Structure: 4 installed packages; library=2; utility=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| gsmctl | f61d039a | Simple executable application to execute and read GSM modem AT commands. Created by Teltonika | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/gsmctl |
| gsmd | f61d039a | Simple server to route GSM modem AT commands. Created by Teltonika | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 3 | 0 | 0 | 0 | 0 | /usr/sbin/gsmd \| /bin/board_modem \| /etc/init.d/gsmd \| /etc/config/simcard \| /usr/share/iface/89-gsm-event \| /usr/share/gsm/4-notify-send-sms |
| libgsm1.0 | f61d039a | A simple lib with AT commands parser. Created by Teltonika | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libgsm.so \| /usr/lib/libgsm_utils.so |
| liburc | f61d039a | A library to handle URC | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/liburc.so |

### `package/teltonika/mctl`

- Packages: `3`
- Main candidate(s): `(none)`
- Structure: 3 installed packages; library=1; utility=2
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libmctl | 4.10 | A library for manage modem restart. Created by Teltonika | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/libmctl.so |
| mctl | 4.10 | Simple executable application for modem restart. Created by Teltonika | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /sbin/mctl |
| modem_trackd | 4.10 | Simple server to track modem state. Created by Teltonika | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/modem_trackd \| /etc/init.d/modem_trackd |

### `package/teltonika/mdcollect`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libmdcollect | 2024-12-02-2 | A library for mdcollectd | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/libmdcollect.so |
| mdcollectd | 2024-12-02-2 | mdcollectd | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/bin/mdcollectd \| /etc/init.d/mdcollectd \| /etc/config/mdcollectd |

### `package/teltonika/mnfinfo`

- Packages: `3`
- Main candidate(s): `(none)`
- Structure: 3 installed packages; library=1; utility=1; plugin/module=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libmnfinfo | 2.25.1 | Device mnf-info API library | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/libmnfinfo.so |
| mnfinfo | 2.25.1 | Device mnf-info command line interface | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /sbin/mnf_info |
| rpcd-mod-mnfinfo | 2.25.1 | mnfinfo rpcd module | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/rpcd/mnfinfo.so |

### `package/teltonika/mobutils`

- Packages: `3`
- Main candidate(s): `(none)`
- Structure: 3 installed packages; utility=2; meta/helper=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| mobutils | 3.14 | Mobile utilities | META_OR_HELPER_PACKAGE | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 | /etc/config/sms_gateway \| /usr/share/acl.d/mobutils.json |
| mobutils-call_utilities | 3.14 | Call utilities | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /sbin/call_utils \| /etc/config/call_utils \| /etc/init.d/call_utils |
| mobutils-sms_utilities | 3.14 | SMS utilities | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/sms_utils \| /etc/config/sms_utils \| /etc/uci-defaults/etc/99_sms_gateway |

### `package/teltonika/post_get`

- Packages: `3`
- Main candidate(s): `post-get`
- Structure: 3 installed packages; main/product-like=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| post-get | 1.5 | Call actions over HTTP POST/GET requests | PRODUCT_OR_MAIN_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /www/cgi-bin/post_get \| /etc/uci-defaults/etc/99_sms_post_get \| /etc/config/post_get |
| post-get-io | 1.5 | I/O handlers | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 4 | 0 | 0 | 0 | 0 | /www/cgi-bin/io_value \| /www/cgi-bin/io_invert |
| post-get-mobile | 1.5 | Mobile handlers | SPLIT_RUNTIME_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 7 | 0 | 0 | 0 | 0 | /www/cgi-bin/sms_list \| /www/cgi-bin/sms_total |

### `package/teltonika/reboot_utils`

- Packages: `3`
- Main candidate(s): `(none)`
- Structure: 3 installed packages; utility=2; meta/helper=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| reboot_utils | 2025-03-05-1 | Reboot utilities | META_OR_HELPER_PACKAGE | NON_PRODUCT_ARTIFACT | 0 | 0 | 0 | 0 | 0 |  |
| reboot_utils-periodic | 2025-03-05-1 | Periodic reboot by Teltonika | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/reboot_modem.sh \| /etc/config/periodic_reboot \| /etc/init.d/periodic_reboot |
| reboot_utils-ping | 2025-03-05-1 | ping_reboot | UTILITY_OR_CLI_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 1 | 0 | 0 | 0 | 0 | /usr/sbin/ping_reboot.sh \| /etc/reboot_utils/ping_reboot_init.sh \| /etc/config/ping_reboot |

### `package/teltonika/rut_fota`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1; utility=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| librut_fota | 2.16.1 | Library for handling rut_fota information | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/librut_fota.so \| /usr/lib/rpcd/fota.so |
| rut_fota | 2.16.1 | Firmware Over The Air Utility | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 1 | 0 | 0 | 0 | 0 | /sbin/rut_fota \| /etc/init.d/rut_fota \| /etc/config/rut_fota |

### `package/teltonika/uqmi`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1; utility=1
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libtlt_uqmi | 7.10-2 | A simple lib with wds commands. Created by Teltonika | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/libtlt_uqmi.so |
| uqmi | 7.10-2 | uqmi is a command line tool for controlling mobile broadband modems using the QMI-protocol. | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 8 | 0 | 0 | 0 | 0 | /lib/netifd/proto/qmux.sh \| /lib/netifd/dhcp_mobile.script |

### `package/utils/e2fsprogs`

- Packages: `4`
- Main candidate(s): `(none)`
- Structure: 4 installed packages; library=3; utility=1
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:e2fsprogs_project:e2fsprogs`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| e2fsprogs | 1.47.0-2 | This package contains essential ext2 filesystem utilities which consists of e2fsck, mke2fs and most of the other core ext2 filesystem utilities. | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 4 | 2 | 0 | 0 | 0 | /usr/sbin/mkfs.ext2 \| /usr/sbin/mkfs.ext3 \| /usr/lib/libe2p.so.2 \| /usr/lib/libe2p.so.2.3 |
| libcomerr0 | 1.47.0-2 | This package contains libcom_err, the common error description library bundled with e2fsprogs. | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libcom_err.so.0.0 \| /usr/lib/libcom_err.so.0 |
| libext2fs2 | 1.47.0-2 | libext2fs is a library which can access ext2, ext3 and ext4 filesystems. | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libext2fs.so.2.4 \| /usr/lib/libext2fs.so.2 |
| libss2 | 1.47.0-2 | This pacakge contains libss, a command-line interface parsing library bundled with e2fsprogs. | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libss.so.2 \| /usr/lib/libss.so.2.0 |

### `package/utils/lua`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=1; utility=1
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:lua:lua`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| liblua5.1.5 | 5.1.5-9 | Lua is a powerful light-weight programming language designed for extending applications. Lua is also frequently used as a general-purpose, stand-alone langua... | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/liblua.so.5.1.5 |
| lua | 5.1.5-9 | Lua is a powerful light-weight programming language designed for extending applications. Lua is also frequently used as a general-purpose, stand-alone langua... | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 2 | 0 | 0 | 0 | 0 | /usr/bin/lua \| /usr/bin/lua5.1 |

### `package/utils/ucode`

- Packages: `7`
- Main candidate(s): `(none)`
- Structure: 7 installed packages; library=1; utility=1; plugin/module=5
- CPE-ID consistency: `NO_CPE_ID`; values: `(none)`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libucode20220812 | 2023-06-06-c7d84aae-1 | The libucode package provides the shared runtime library for the ucode interpreter. | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 1 | 0 | 0 | 0 | /usr/lib/libucode.so.20220812 |
| ucode | 2023-06-06-c7d84aae-1 | ucode is a tiny script interpreter featuring an ECMAScript oriented script language and Jinja-inspired templating. | UTILITY_OR_CLI_PACKAGE | POSSIBLE_PRODUCT_CANDIDATE | 3 | 0 | 0 | 0 | 0 | /usr/bin/utpl \| /usr/bin/ucc |
| ucode-mod-fs | 2023-06-06-c7d84aae-1 | The filesystem plugin module allows interaction with the local file system. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ucode/fs.so |
| ucode-mod-nl80211 | 2023-06-06-c7d84aae-1 | The nl80211 plugin provides access to the Linux wireless 802.11 netlink API. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ucode/nl80211.so |
| ucode-mod-rtnl | 2023-06-06-c7d84aae-1 | The rtnl plugin provides access to the Linux routing netlink API. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ucode/rtnl.so |
| ucode-mod-ubus | 2023-06-06-c7d84aae-1 | The ubus module allows ucode template scripts to enumerate and invoke ubus procedures. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ucode/ubus.so |
| ucode-mod-uloop | 2023-06-06-c7d84aae-1 | The uloop module allows ucode scripts to interact with OpenWrt uloop event loop implementation. | PLUGIN_OR_MODULE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 0 | 1 | 0 | 0 | /usr/lib/ucode/uloop.so |

### `package/utils/util-linux`

- Packages: `2`
- Main candidate(s): `(none)`
- Structure: 2 installed packages; library=2
- CPE-ID consistency: `ALL_PACKAGES_SAME_CPE_ID`; values: `cpe:/a:kernel:util-linux`

| Package | Version | Description | Role | Identity | Exec | Lib | Plugin | Kmod | Firmware | Representative paths |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| libblkid1 | 2.36.1-2 | The libblkid library is used to identify block devices (disks) as to their content (e.g. filesystem type, partitions) as well as extracting additional inform... | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libblkid.so.1.1.0 \| /usr/lib/libblkid.so.1 |
| libuuid1 | 2.36.1-2 | The UUID library is used to generate unique identifiers for objects that may be accessible beyond the local system. This library generates UUIDs compatible w... | LIBRARY_PACKAGE | PARTIAL_OR_SPLIT_COMPONENT | 0 | 2 | 0 | 0 | 0 | /usr/lib/libuuid.so.1 \| /usr/lib/libuuid.so.1.3.0 |

## Human-review issues before Ground Truth rules

- Whether an aligned main runtime package and its Source have the same CPE 
  product scope.
- Whether library/CLI packages without a sibling main package represent an 
  independently identifiable product or only packaging structure.
- Whether empty-list meta/helper packages carry identity at all.
- How plugin/module and kernel/kmod packages relate to a parent product.
- How vendor-specific packages should be treated without exact source.
- Whether propagated control CPE-ID should apply at binary granularity; this 
  analysis observes propagation but does not accept or reject it.

## Validation and safety

- Sources: `303` == `303`
- Installed packages: `575` == `575`
- Single + multi packages: `575` == `575`
- Role partition: `575` == `575`
- Product identity partition: `575` == `575`
- Ground Truth records before/after: `0` / `0`
- CPE Dictionary queries: `0`; NVD Configuration/CVE queries: `0`; DB mutations: `0`.

## Stopping point

The analysis stops at empirical package role and product-scope evidence. No 
Ground Truth rule was generated or applied.

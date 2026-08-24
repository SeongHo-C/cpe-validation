# Unitronics wireguard-tools product-boundary audit

## Scope and decision

- Mode: **READ-ONLY**
- Component: `wireguard-tools` `1.0.20210223-4`
- CPE Dictionary snapshot: `20260819T035002Z`
- NVD CVE/Configuration snapshot: `20260820T110357Z`
- Product-boundary classification: **DIFFERENT_PRODUCT**
- Current-result audit status: **CHANGE_REQUIRED**

The fixed evidence identifies `wireguard-tools` as the separately released
userspace tooling project, not as the Windows client represented by the only
`wireguard:wireguard` CPE family entry. The current mapping should therefore not
be retained.

## Version verification

- Observed OpenWrt package version: `1.0.20210223-4`
- Verified upstream release: `1.0.20210223`
- Official tag: `v1.0.20210223`
- Official archive: `wireguard-tools-1.0.20210223.tar.xz`
- `-4`: OpenWrt package release/revision, not part of the upstream version

The date-shaped `20210223` portion is retained because it is part of the
official upstream release version.

## Official project boundaries

| Official project | Purpose | Canonical artifacts | Release scheme | Release/tag examples | Official repository |
|---|---|---|---|---|---|
| `wireguard-tools` | Cross-platform userspace tools that configure WireGuard implementations | wg(8), wg-quick(8) | 1.0.YYYYMMDD | 1.0.20210223, 1.0.20210315, 1.0.20210424, 1.0.20210914 | https://git.zx2c4.com/wireguard-tools/ |
| `wireguard-linux` | WireGuard implementation for the Linux kernel | Linux kernel WireGuard driver/module | Linux kernel branches/releases | devel, stable, backport branches | https://git.zx2c4.com/wireguard-linux/ |
| `wireguard-linux-compat` | Out-of-tree Linux kernel module backport | wireguard kernel module for Linux 3.10-5.5 | Kernel compatibility releases | separate compatibility repository | https://git.zx2c4.com/wireguard-linux-compat/ |
| `wireguard-windows` | Official WireGuard client application for Windows | wireguard.exe, manager service, UI | 0.x semantic client releases in the audited era | 0.5, 0.5.1, 0.5.2, 0.5.3 | https://git.zx2c4.com/wireguard-windows/refs/tags |
| `wireguard-go` | Cross-platform userspace WireGuard implementation | wireguard-go userspace tunnel implementation | Independent repository history | not the wireguard-tools release space | https://git.zx2c4.com/wireguard-go/ |
| `wireguard-android / wireguard-apple` | Official platform-specific Android and Apple clients | Android, macOS, and iOS applications | Platform-specific client releases | independent platform repositories | https://www.wireguard.com/repositories/ |

The official WireGuard repository catalog explicitly separates the Linux kernel
implementation, cross-platform configuration tools, Windows client, and other
platform implementations.

## Fixed CPE Dictionary family

- `vendor=wireguard` records: **1**
- Versions: `0.5.3`
- Direct `wireguard-tools` product/title matches: **0**

| CPE | Version | target_sw | Title | Status | Boundary signal |
|---|---|---|---|---|---|
| `cpe:2.3:a:wireguard:wireguard:0.5.3:*:*:*:*:*:*:*` | `0.5.3` | `*` | Wireguard Wireguard 0.5.3 | ACTIVE | WIREGUARD_WINDOWS_VERSION_REFERENCE |

Although `target_sw=*` and the title are generic, the entry's version reference
points to `WireGuard/wireguard-windows/tags`. Its `0.5.3` version also matches
the official Windows-client release space and not the tools release space.

## Fixed NVD Configuration evidence

- Distinct `wireguard:wireguard` criteria: **1**
- Occurrences: **2**
- Distinct CVEs: **2**
- Versions: `0.5.3`
- Version ranges: **none**
- Direct `wireguard-tools` expressions: **0**

| CVE | Vulnerable criteria | Configuration | Companion criteria | Platform signal |
|---|---|---|---|---|
| `CVE-2021-46873` | `cpe:2.3:a:wireguard:wireguard:0.5.3:*:*:*:*:*:*:*` | `AND` | `["cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"]` | WINDOWS_CLIENT_AND_CONFIGURATION |
| `CVE-2023-35838` | `cpe:2.3:a:wireguard:wireguard:0.5.3:*:*:*:*:*:*:*` | `AND` | `["cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"]` | WINDOWS_CLIENT_AND_CONFIGURATION |

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
| Actual product | `WireGuard` | `wireguard-tools` |
| Actual version | `1.0.20210223` | `1.0.20210223` |
| GT CPE | `cpe:2.3:a:wireguard:wireguard:1.0.20210223:*:*:*:*:*:*:*` | `null` |
| Validation Result | `VERSION_NOT_IN_DICTIONARY` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |

Recommendation:

```text
Ground Truth CPE = null
CPE Validation Result = DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
UI label = No Direct CPE Found
```

This report is advisory. It does not apply the recommendation to the candidate
artifact or database.

## Validation and provenance

- CPE canonical parse failures: **0**
- Ground Truth DB mutation: **0**
- Component mutation: **0**
- Candidate artifact mutation: **0**
- Migration: **0**
- Commit: **0**
- Component fingerprint unchanged: `6ce2bc5760b3d237d2d73a82ed01f24d5bd1a382e02c48f2f3d30cb4a4c68cdf`
- Ground Truth fingerprint unchanged: `767b6276ac7d40a9b1efb3611795f88df5d685f2bb882de6fc3c4cc8d6f1d80d`

Official upstream evidence:

- https://www.wireguard.com/repositories/
- https://git.zx2c4.com/wireguard-tools/tag/?h=v1.0.20210223
- https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-1.0.20210223.tar.xz
- https://git.zx2c4.com/wireguard-windows/refs/tags
- https://git.openwrt.org/e0f7f5bbce0d03e5192b5dad5a24fcb8566da97f
- https://github.com/openwrt/packages/blob/master/CONTRIBUTING.md

Fixed NVD descriptions, references, and full AND/OR Configuration structures
were read from the raw yearly feeds listed in `configuration_cases.csv`; counts
and positions were cross-checked against the imported fixed-snapshot schema.

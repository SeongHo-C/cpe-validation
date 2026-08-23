# PRODUCT_RUNTIME Rulebook v1 — representative dry-run

## Scope

This report applies `rulebook.md` to 32 representative exact-firmware
packages/components from Unitronics UCR-ST-B8 firmware `52.07.13.7`. It is not
the 582-component Ground Truth run.

No database row, SBOM component, CPE, Decision, discrepancy value, existing
analysis artifact, or migration was modified. No CPE Dictionary, NVD
Configuration, or CVE data was queried. Original SBOM CPE and control `CPE-ID`
were excluded from the decision inputs.

## Dataset and local evidence

- SBOM identifier prefix: `61602e128acb`
- SBOMDocument: `1364`
- SBOM components: `582`
- installed opkg packages: `575`
- directly observed non-opkg artifacts: `7`
- distinct exact control `Source` values: `303`
- multi-package Sources: `42`
- representative records in this dry-run: `32`
  - opkg packages: `31`
  - direct non-opkg artifact: `1` (`linux_kernel`)

The 31 opkg representatives all match `/usr/lib/opkg/status` on package,
version, and architecture. Their exact `.control`, `.list`, dependency, payload,
and sibling evidence comes from the existing second-pass analysis. The direct
Linux case uses the existing `BINARY_DIRECT` artifact traceability.

## Overall result

| Status | Count | Percent of 32 |
|---|---:|---:|
| `PRODUCT_RUNTIME` | 10 | 31.25% |
| `NON_PRODUCT_RUNTIME` | 19 | 59.38% |
| `REVIEW_REQUIRED` | 3 | 9.38% |
| Total | 32 | 100.00% |

| Source family | Cases | PRODUCT_RUNTIME | NON_PRODUCT_RUNTIME | REVIEW_REQUIRED |
|---|---:|---:|---:|---:|
| OpenSSL | 4 | 2 | 2 | 0 |
| curl | 2 | 2 | 0 | 0 |
| iptables | 8 | 2 | 6 | 0 |
| strongSwan | 8 | 2 | 4 | 2 |
| e2fsprogs | 4 | 1 | 2 | 1 |
| util-linux | 2 | 0 | 2 | 0 |
| Linux opkg splits | 3 | 0 | 3 | 0 |
| Linux direct artifact | 1 | 1 | 0 | 0 |

The totals are a property of the selected representative set and must not be
extrapolated to all 582 components.

## A. OpenSSL

| Package | Exact payload role | Existing role | Status | Strength |
|---|---|---|---|---|
| `libopenssl-conf` | configuration/init only | `META_OR_HELPER_PACKAGE` | `NON_PRODUCT_RUNTIME` | STRONG |
| `libopenssl-legacy` | dynamically loadable legacy provider | `PLUGIN_OR_MODULE` | `NON_PRODUCT_RUNTIME` | STRONG |
| `libopenssl3` | `libssl.so.3` and `libcrypto.so.3` | `LIBRARY_PACKAGE` | `PRODUCT_RUNTIME` | STRONG |
| `openssl-util` | `/usr/bin/openssl` | `UTILITY_OR_CLI_PACKAGE` | `PRODUCT_RUNTIME` | STRONG |

OpenSSL's versioned official manuals identify `ssl` as the TLS library,
`crypto` as the cryptographic library, and `openssl` as the command-line
program. Exact ownership aligns one-to-one with those roles. This makes
`libopenssl3` a reproducible positive even though its existing structural role
is `LIBRARY_PACKAGE`. The legacy provider remains an extension: it supplies a
selectable algorithm provider, not the principal libraries.

Result: packaging does not provide a Source-named main package, but two separate
binary packages still independently pass the positive runtime test.

## B. curl

| Package | Exact payload role | Existing role | Status | Strength |
|---|---|---|---|---|
| `curl` | canonical URL-transfer command | `UTILITY_OR_CLI_PACKAGE` | `PRODUCT_RUNTIME` | STRONG |
| `libcurl4` | principal URL-transfer library/API | `LIBRARY_PACKAGE` | `PRODUCT_RUNTIME` | STRONG |

The official curl project explicitly documents both the command-line tool and
libcurl. The CLI directly transfers URLs; it is not merely a configuration
frontend. libcurl is the project's public transfer library/API. Thus a single
Source legitimately yields two positives without inheritance between them.

## C. iptables

| Package group | Packages | Status | Reason |
|---|---|---|---|
| Canonical CLIs | `iptables`, `ip6tables` | `PRODUCT_RUNTIME` | Official project definition and exact commands agree |
| Extension splits | three `iptables-mod-*` cases | `NON_PRODUCT_RUNTIME` | Extra match/target packages; empty lists and explicit extension metadata |
| Supporting libraries | `libip4tc2`, `libip6tc2`, `libxtables12` | `NON_PRODUCT_RUNTIME` | Shared command/extension plumbing, not independently established principal product implementations |

The official netfilter project defines iptables as the userspace program and
explicitly includes ip6tables. Its documentation also describes shared-library
extensions that add tests or targets. The rule therefore includes both
functional CLIs while excluding the three extension packages.

The libraries are not excluded merely because they begin with `lib`. They are
excluded because the tested product boundary is the command-centric iptables
product and official evidence does not establish these internal split libraries
as principal product runtimes in their own right.

## D. strongSwan

| Package | Exact/upstream role | Existing role | Status | Strength |
|---|---|---|---|---|
| `strongswan` | owns core `libstrongswan` | `PRODUCT_OR_MAIN_PACKAGE` | `PRODUCT_RUNTIME` | STRONG |
| `strongswan-charon` | primary IKEv2 daemon and `libcharon` core | `SPLIT_RUNTIME_PACKAGE` | `PRODUCT_RUNTIME` | STRONG |
| `strongswan-minimal` | empty dependency-only profile | `META_OR_HELPER_PACKAGE` | `NON_PRODUCT_RUNTIME` | STRONG |
| `strongswan-mod-openssl` | selectable crypto backend | `PLUGIN_OR_MODULE` | `NON_PRODUCT_RUNTIME` | STRONG |
| `strongswan-mod-vici` | disableable control/configuration interface | `PLUGIN_OR_MODULE` | `NON_PRODUCT_RUNTIME` | STRONG |
| `strongswan-swanctl` | control/configuration/monitoring client for charon | `UTILITY_OR_CLI_PACKAGE` | `NON_PRODUCT_RUNTIME` | STRONG |
| `strongswan-mod-kernel-netlink` | Linux kernel-interface backend | `PLUGIN_OR_MODULE` | `REVIEW_REQUIRED` | MODERATE |
| `strongswan-mod-socket-default` | default IKE socket backend | `PLUGIN_OR_MODULE` | `REVIEW_REQUIRED` | MODERATE |

Version-matched official architecture identifies charon as the IKEv2 engine and
states that most daemon-core code resides in libcharon. Official component
documentation identifies libstrongswan as the base library used by daemons and
utilities. Those two exact packages are clear positives.

`swanctl` is an important and canonical official tool, but its documented
function is to configure, control, and monitor charon over VICI. It does not
implement IKEv2. Rulebook v1 therefore treats it differently from curl or
iptables, whose CLIs directly perform their products' defining operations.

The two review cases expose a real modular-architecture boundary. They are
packaged as plugins, yet official charon architecture includes socket and kernel
interfaces in the operational path, and the exact `strongswan-minimal` profile
depends on both. Available artifacts do not establish whether these particular
implementations are the exclusively selected runtime backends. A name-only
plugin exclusion would be too aggressive; automatic inclusion would also exceed
the evidence.

## E. e2fsprogs

| Package | Exact/upstream role | Existing role | Status | Strength |
|---|---|---|---|---|
| `e2fsprogs` | `mke2fs`, `mkfs.ext2/3/4` | `UTILITY_OR_CLI_PACKAGE` | `PRODUCT_RUNTIME` | STRONG |
| `libcomerr0` | bundled common-error library | `LIBRARY_PACKAGE` | `NON_PRODUCT_RUNTIME` | MODERATE |
| `libext2fs2` | filesystem-access library; exact main package depends on it | `LIBRARY_PACKAGE` | `REVIEW_REQUIRED` | MODERATE |
| `libss2` | bundled command parser | `LIBRARY_PACKAGE` | `NON_PRODUCT_RUNTIME` | MODERATE |

The exact e2fsprogs package owns the commands that the version-matched upstream
manual defines as creating ext2/ext3/ext4 filesystems, so the utility-suite rule
works without a GUI/daemon bias.

`libcom_err` and `libss` are described as bundled generic support libraries.
`libext2fs` is harder: the exact dynamically split e2fsprogs package depends on
it and it implements filesystem access, but upstream installation documentation
separates program installation from library/header installation. The v1 suite
boundary cannot select between “core dynamic implementation in this firmware”
and “partial library supplied by a program-oriented suite” without an explicit
product-boundary policy. It remains reviewable rather than being forced either
way.

## F. util-linux

| Package | Exact payload | Existing role | Status | Strength |
|---|---|---|---|---|
| `libblkid1` | `libblkid.so.1*` only | `LIBRARY_PACKAGE` | `NON_PRODUCT_RUNTIME` | MODERATE |
| `libuuid1` | `libuuid.so.1*` only | `LIBRARY_PACKAGE` | `NON_PRODUCT_RUNTIME` | MODERATE |

Only these two split libraries from the util-linux Source are installed; no
util-linux utility executable is an exact sibling. The official repository
describes util-linux as a collection of utilities and separately builds the two
libraries. Repository membership, Source equality, and shared release version
do not establish either library as the util-linux suite runtime.

These decisions are explicitly scoped to the `util-linux suite` boundary. They
do not decide whether `libblkid` or `libuuid` should later be investigated as an
independent product identity; doing so would be a separate upstream-boundary
step, not Source inheritance.

## G. Linux kernel versus package splits

| Component/package | Exact role | Status | Strength |
|---|---|---|---|
| direct `linux_kernel 5.15.176` artifact | firmware kernel binary with `BINARY_DIRECT` traceability | `PRODUCT_RUNTIME` | STRONG |
| opkg `kernel` | empty virtual package | `NON_PRODUCT_RUNTIME` | STRONG |
| `kmod-fs-ext4` | kernel-module/autoload split | `NON_PRODUCT_RUNTIME` | STRONG |
| `kmod-wireguard` | kernel-module/autoload split | `NON_PRODUCT_RUNTIME` | STRONG |

Official kernel build documentation distinguishes the resident kernel image
from modules. The directly observed kernel binary represents the runtime; the
empty virtual package does not. Neither selected `kmod-*` package inherits Linux
parent identity. The WireGuard result is deliberately limited to Linux parent
identity and does not decide an independent WireGuard boundary.

## Existing role versus PRODUCT_RUNTIME

The dry-run confirms that the existing role taxonomy and product runtime are
orthogonal axes:

| Existing structural role | New result examples |
|---|---|
| `UTILITY_OR_CLI_PACKAGE` → `PRODUCT_RUNTIME` | `openssl-util`, `curl`, `iptables`, `ip6tables`, `e2fsprogs` |
| `UTILITY_OR_CLI_PACKAGE` → `NON_PRODUCT_RUNTIME` | `strongswan-swanctl` |
| `LIBRARY_PACKAGE` → `PRODUCT_RUNTIME` | `libopenssl3`, `libcurl4` |
| `LIBRARY_PACKAGE` → `NON_PRODUCT_RUNTIME` | iptables support libraries, util-linux libraries, `libcomerr0`, `libss2` |
| `LIBRARY_PACKAGE` → `REVIEW_REQUIRED` | `libext2fs2` |
| `PLUGIN_OR_MODULE` → `NON_PRODUCT_RUNTIME` | OpenSSL legacy provider, iptables extensions, strongSwan OpenSSL/VICI plugins |
| `PLUGIN_OR_MODULE` → `REVIEW_REQUIRED` | strongSwan kernel-netlink and socket-default plugins |

No existing role was treated as a terminal answer.

## Evidence that was most decisive

1. Exact installed ownership was the strongest first gate: a real executable,
   daemon, or library could be tied to one binary package rather than its Source.
2. Official upstream role statements separated functional CLIs (`curl`,
   `iptables`, `mke2fs`, `openssl`) from a management CLI (`swanctl`).
3. Official library definitions made `libssl`/`libcrypto` and libcurl positive,
   while suite context kept generic/internal split libraries from being promoted.
4. Empty exact lists plus explicit descriptions conclusively identified virtual,
   meta, and several extension packages without inventing payload.
5. Sibling dependencies were decisive for detecting, but not resolving, the
   strongSwan mandatory-plugin boundary.

## Consistency checks

| Check | Result |
|---|---|
| Every selected record has exactly one terminal status | PASS (`32/32`) |
| Status partition sums to representative total | PASS (`10 + 19 + 3 = 32`) |
| All 31 opkg representatives match exact status version/architecture | PASS |
| All seven required Source families are represented | PASS |
| Same-Source status propagation used | PASS (`0` uses) |
| Original SBOM CPE used as evidence | PASS (`0` uses) |
| control `CPE-ID` used as evidence | PASS (`0` uses) |
| CPE/NVD/CVE lookup performed for a decision | PASS (`0` uses) |
| Existing role used as a terminal answer | PASS (`0` uses) |

### Cross-family rule tests

- CLI rule: consistent. A CLI is positive when it directly performs the
  defining operation; a control frontend alone is not.
- Library rule: consistent. Principal official runtime libraries are positive;
  partial/support libraries require independent product evidence.
- Plugin rule: consistent after adding the mandatory-runtime review gate.
  Optional providers/extensions are negative; potentially indispensable
  pluginized backends are not forced negative.
- Suite rule: consistent. Source/repository membership does not promote every
  split library.
- Kernel rule: consistent. Direct resident image, virtual package, and modules
  are separate decisions.

## REVIEW_REQUIRED cases

1. `strongswan-mod-kernel-netlink`: obtain exact plugin load configuration or
   binary/runtime evidence proving the selected Linux kernel-interface backend.
2. `strongswan-mod-socket-default`: obtain exact load configuration or daemon
   startup evidence proving this socket backend is indispensable and selected.
3. `libext2fs2`: set an explicit research boundary for independently exposed
   upstream libraries versus the e2fsprogs program suite, or obtain upstream
   documentation that unambiguously calls it a principal product runtime.

None of these cases requires a CPE lookup to resolve the runtime question.

## Contradictions and v1 refinements

No package received contradictory terminal statuses after the decision flow was
applied. Two apparent rule tensions were found and made explicit in v1:

1. **Plugin exclusion versus modular core architecture.** strongSwan pushes
   socket/kernel interfaces into plugins. A blanket plugin exclusion would
   conflict with the architecture. Q7 now routes incompletely proven mandatory
   backends to review.
2. **Core library versus suite-part library.** `libext2fs2` is required by the
   exact dynamic split but upstream program/library boundaries are mixed. Q3 and
   Q6 now require the tested upstream boundary to be stated and preserve review
   when evidence competes.

The different outcomes for `curl` and `swanctl` are not a contradiction: curl
performs the product's defining transfer operation, while swanctl controls the
separate charon implementation. Likewise, the different outcomes for
`libopenssl3` and `libuuid1` follow official product-boundary evidence, not their
shared `LIBRARY_PACKAGE` role.

## Answers before a 582-component run

1. **Can PRODUCT_RUNTIME be operationalized reproducibly?** Yes, provided exact
   ownership, a stated upstream product boundary, and official function evidence
   are mandatory, with review as a valid outcome.
2. **Is libopenssl3 consistently positive?** Yes; exact `libssl`/`libcrypto`
   ownership and official OpenSSL library definitions make it a strong positive.
3. **How are curl and libcurl classified?** Both are strong positives, each on
   its own official functional runtime evidence.
4. **How are iptables units separated?** `iptables`/`ip6tables` are positive;
   tested extension and support-library splits are negative.
5. **How are strongSwan units separated?** libstrongswan and charon/libcharon are
   positive; meta, selectable crypto/control plugins, and swanctl are negative;
   two core-looking platform plugins require review.
6. **Does the utility-suite rule work for e2fsprogs?** Yes for the installed
   filesystem-creation commands and generic helpers; libext2fs exposes the one
   unresolved suite/library boundary.
7. **Does util-linux avoid parent overmapping?** Yes; neither installed library
   inherits util-linux suite status.
8. **Can Linux and kmods be separated?** Yes; direct kernel binary is positive,
   while virtual and module packages are negative for Linux parent identity.
9. **What requires human review?** Potentially mandatory pluginized runtime
   backends and mixed suite/core-library boundaries.
10. **Must v1 change before the full run?** The two necessary refinements are
    already incorporated. Human approval should confirm the Q7 mandatory-plugin
    exception and the explicit product-boundary rule. The three review cases may
    remain reviewable; they should not be silently coerced for automation.

## Stop

The analysis stops at:

```text
exact firmware evidence
  -> Source/binary-package relationship
  -> official upstream product structure
  -> PRODUCT_RUNTIME / NON_PRODUCT_RUNTIME / REVIEW_REQUIRED
  -> STOP
```

Detailed machine-readable rows are in `representative_cases.csv`; evidence
source identifiers resolve through the registry in `rulebook.md`.

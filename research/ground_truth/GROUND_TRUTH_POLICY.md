# Ground Truth Policy

## 1. Purpose

This document defines the canonical policy used to construct and freeze the CPE
Ground Truth dataset for four industrial firmware SBOMs. The Ground Truth records
an independently verified software identity and version, determines whether a
direct CPE representation is justified, and preserves enough provenance for the
decision to be audited without treating the SBOM's original CPE as evidence.

The dataset is intended to support reproducible evaluation of SBOM CPE quality.
It is not a vulnerability-applicability decision and does not infer CVE impact.

## 2. Dataset

The frozen dataset contains 2,038 Components from four firmware images:

| Vendor | Firmware product | Version | SBOM document | Components |
|---|---|---:|---:|---:|
| Teltonika | RUT986 | `00.07.24.2` | 24 | 648 |
| ACKSYS | WaveOS PID40 family | `4.36.1.1` | 1362 | 361 |
| MDEX | MX560 | `12.01.07.151` | 1363 | 447 |
| Unitronics | UCR-ST-B8 | `52.07.13.7` | 1364 | 582 |

Every Component has exactly one frozen Ground Truth record.

## 3. Fixed External Snapshots

All CPE and NVD Configuration decisions are fixed to these external snapshots:

- CPE Dictionary: `20260819T035002Z`
- NVD Configuration: `20260820T110357Z`

Live services and later snapshots must not be used to silently refresh the frozen
dataset. A snapshot change requires a new named dataset and a full audit rerun.

## 4. Evidence Priority

Evidence is evaluated independently of the original SBOM CPE. Higher-priority
evidence constrains lower-priority evidence:

1. Exact firmware runtime evidence or exact source/SDK content belonging to the
   evaluated firmware.
2. Installed package metadata, file ownership, build recipes, source declarations,
   binary banners, embedded version strings, and deterministic build rules.
3. Immutable upstream source, tag, release, or official product documentation
   pinned to a hash, commit, or otherwise stable locator.
4. The fixed CPE Dictionary for CPE family and representation selection.
5. The fixed NVD Configuration snapshot, only after the Configuration-only gate.

Firmware-specific application of this order is as follows:

- **Teltonika RUT986:** exact GPL SDK and recipes, installed package metadata and
  runtime artifacts, pinned upstream source, then fixed CPE/NVD snapshots.
- **MDEX MX560:** exact GPL source/SDK, recipe and installed-package provenance,
  pinned upstream declarations, then fixed CPE/NVD snapshots.
- **ACKSYS WaveOS PID40:** exact firmware image and extracted root filesystem,
  package control/list ownership and runtime binaries, official vendor/upstream
  evidence, then fixed CPE/NVD snapshots.
- **Unitronics UCR-ST-B8:** exact firmware package/runtime observations, package
  metadata and directly observed runtime/source versions, pinned upstream evidence,
  then fixed CPE/NVD snapshots. Absence of a complete SDK is never filled by an
  assumption.

## 5. Original CPE Independence

The original SBOM CPE is excluded from determining actual product identity,
software version, product boundary, representative status, CPE family, and final
Ground Truth CPE. It is read only after the independent conclusion is complete,
for comparison and Validation Result assignment.

An original CPE may therefore be confirmed, corrected, or rejected, but it may not
bootstrap the evidence needed to justify itself.

## 6. Product Identity

Actual product identity is established from the highest-priority direct evidence.
A package name alone is not sufficient when it denotes a split library, wrapper,
plugin, helper, virtual package, vendor integration, or build artifact. Vendor and
upstream ownership are distinguished, and a source-package namespace is not
automatically treated as the runtime product name.

When the available evidence identifies only the observed package and cannot justify
an independently maintained software product, the package identity is preserved but
a direct official CPE is not asserted.

## 7. Product Boundary

The governing rule is:

> Same source does not imply same product, and same product does not imply the same
> CPE-bearing Component.

The audit distinguishes at least these boundaries:

- split libraries and ABI/runtime packages;
- plugins, modules, and optional providers;
- command-line helpers and support utilities;
- meta, virtual, and composite packages;
- vendor-internal services or integrations;
- duplicate runtime representations of one upstream product;
- firmware, board, kernel-module, and build artifacts;
- independent subproducts distributed from one source tree.

Parent or source-project CPEs are not inherited by a split or helper Component
unless direct evidence establishes that the Component is the product representative.

## 8. Representative Policy

For one independently verifiable upstream product/version within a firmware, exactly
one representative Component may carry the direct CPE. Split, duplicate, meta, or
derived Components remain CPE-null unless they independently constitute a different
product.

The representative is selected using direct package/runtime role and ownership
evidence, not by choosing whichever Component already has a CPE. Cross-firmware
reuse does not change the per-firmware representative decision.

## 9. Software Version Policy

The canonical version rule is `DIRECT_OR_DETERMINISTIC_VERSION_POLICY`.

Accepted **direct** methods include:

- `DIRECT_RUNTIME_VERSION`
- `DIRECT_SOURCE_DECLARATION`
- `DIRECT_PACKAGE_VERSION`
- `DIRECT_PACKAGE_TO_UPSTREAM_MAPPING`
- `DIRECT_OFFICIAL_TAG_MATCH`

Accepted **deterministic** methods include:

- `DETERMINISTIC_PACKAGE_NORMALIZATION`
- `DETERMINISTIC_SYNTAX_NORMALIZATION`

Deterministic normalization must be a reproducible syntactic or packaging transform;
it may not guess an upstream version. Package release suffixes may be separated when
the build metadata directly establishes the upstream/version boundary. Unsupported
inference is preserved as observed evidence but does not justify a direct versioned
CPE.

## 10. Source Snapshot Policy

`SOURCE_SNAPSHOT_POLICY` separates source provenance from software version:

```text
source date / commit / revision != software version
```

A date, commit, or revision is recorded as provenance unless direct source/build
semantics prove that it is part of the software's released version identifier.
Packaging dates and repository revisions are not promoted into CPE VERSION merely
because they appear in a package version string.

## 11. Qualifier Policy

`STRICT_DIRECT_QUALIFIER_POLICY` separates two questions:

1. What software version is verified by the evidence?
2. How does the fixed CPE ecosystem represent that version across VERSION and UPDATE?

VERSION/UPDATE qualifiers such as prerelease, patch date, or development markers are
included only when directly supported and consistently represented by the selected
CPE family. A verified qualifier must not be discarded merely to create a Dictionary
match, and an unverified qualifier must not be invented from a nearby CPE.

## 12. Rolling Version

An upstream rolling identifier is preserved when direct build semantics make it an
actual component of the software version. LuaJIT is the canonical example: the
upstream version generator deterministically incorporated the pinned source commit's
timestamp into `2.1.1705946796`. This is software-version evidence, not an arbitrary
source date.

## 13. CPE Family Selection

CPE representation is selected only after product identity, version, boundary, and
representative status are fixed. The lookup order is:

1. compatible Active Dictionary family and exact representation;
2. compatible Deprecated Dictionary entry and its replacement resolution;
3. version-not-registered expression in a verified Dictionary family;
4. NVD Configuration-only gate;
5. no direct official CPE.

Vendor/product spelling is selected from the independently compatible official
family. Similar names or source ancestry alone are insufficient.

## 14. Deprecated Resolution

A Deprecated CPE is never retained as final Ground Truth. Its `deprecatedBy` graph is
followed in the fixed Dictionary snapshot. Replacement is allowed only when there is
a unique, compatible, reachable Active endpoint that preserves the independently
verified product and version semantics.

Cycles, missing targets, ambiguous branches, incompatible endpoints, and dead ends do
not authorize automatic replacement. They require a focused audit or a CPE-null
decision.

## 15. NVD Configuration-only Gate

NVD Configuration is consulted for a direct expression only when both the Active and
Deprecated Dictionary contain no direct compatible family for the independently
verified product. A Configuration expression must directly name that product and
version; dependency, platform, parent-product, or transitive references do not pass
the gate.

Passing this gate supports `NVD_CONFIGURATION_ONLY`. It does not establish CVE
applicability and does not add the expression to the official CPE Dictionary.

## 16. Validation Results

Exactly six internal results are permitted:

- **`CPE_CONFIRMED`** — the original CPE agrees with the independently established
  canonical CPE representation.
- **`OFFICIAL_CPE_MAPPED`** — the original CPE is absent or incorrect, and a different
  compatible official Active CPE is independently established.
- **`VERSION_NOT_IN_DICTIONARY`** — a compatible official Dictionary family exists,
  but the verified version has no exact Active or Deprecated Dictionary entry; the
  Ground Truth preserves the verified family/version expression.
- **`NVD_CONFIGURATION_ONLY`** — no direct Active or Deprecated Dictionary family
  exists, and a direct expression passes the fixed NVD Configuration-only gate.
- **`DIRECT_OFFICIAL_CPE_NOT_CONFIRMED`** — the software/package observation is
  sufficiently characterized for the dataset, but no defensible direct official CPE
  can be assigned; Ground Truth CPE is null.
- **`UNRESOLVED`** — available evidence is insufficient to make the required product,
  version, boundary, representative, or CPE decision. Frozen final data contains no
  records in this state.

## 17. Known Special Cases

| Case | Observed identity/version | Verified version | Policy issue | Final GT behavior |
|---|---|---|---|---|
| pimd | `pimd`, package source around `2.99`/beta lineage | `3.0-beta1` | prerelease evidence versus Configuration base expression | `troglobit:pimd:3.0`; `NVD_CONFIGURATION_ONLY` |
| LuaJIT | `luajit2 2.1.2025.05.29-2` | `2.1.1705946796` | deterministic upstream rolling version | rolling identifier preserved; `VERSION_NOT_IN_DICTIONARY` |
| hostapd | `hostapd-hs20` snapshot package | `2.10-devel` | strict qualifier and representative selection | `w1.fi:hostapd:2.10`; mapped official family |
| wpa_supplicant | firmware-specific packages | `2.7-devel`, `2.10-devel`, `2.11-devel`, `2.12-devel` | direct runtime version versus CPE qualifier modeling | per-firmware `w1.fi:wpa_supplicant` expression |
| ncurses | `6.1.20180127` | `6.1.20180127` | composite VERSION/UPDATE fidelity | `invisible-island:ncurses:6.1:20180127` |
| conntrackd | dated package snapshot | `1.4.4` | runtime/package name versus upstream product | `netfilter:conntrack-tools:1.4.4` |
| coova-chilli | `1.3.0+20141128-4` | `1.3.0` | package normalization and official family spelling | `coovachilli_project:coovachilli:1.3.0` |
| Teltonika PPP | `2.4.9.git-2021-01-04-19` | `2.4.9` | direct source declaration and target platform | `samba:ppp:2.4.9`, `target_sw=linux` |
| MDEX PPP | `2.4.7-12` | `2.4.7` | independently selected alternative official family | `point-to-point_protocol_project:point-to-point_protocol:2.4.7` |
| libnl split packages | Teltonika/Unitronics `3.9.0-1` family | `3.9.0` | one core representative, split/meta non-inheritance | core Component carries `libnl_project:libnl:3.9.0` |
| Unitronics libmodbus | package `7.13` | `3.1.6` | package version differs from direct runtime version | `libmodbus:libmodbus:3.1.6` |
| Unitronics shellinabox | dated package release | `2.20` | direct runtime banner over package date | `shellinabox_project:shellinabox:2.20` |
| Teltonika libatomic1/libgcc1 | GCC runtime splits `8.4.0-3` | `8.4.0-3` package semantics | non-representative toolchain split; no parent inheritance | CPE null; `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |

## 18. Final Baseline

The frozen baseline is:

- Ground Truth records: **2,038**
- CPE-bearing records: **158**
- Ground Truth CPE null: **1,880**

| Validation Result | Count |
|---|---:|
| `CPE_CONFIRMED` | 10 |
| `OFFICIAL_CPE_MAPPED` | 101 |
| `VERSION_NOT_IN_DICTIONARY` | 45 |
| `NVD_CONFIGURATION_ONLY` | 2 |
| `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` | 1,880 |
| `UNRESOLVED` | 0 |

The 158 CPE-bearing records partition into 111 Active-exact mappings, 45
version-not-registered expressions, and 2 Configuration-only expressions.

## 19. Final Audit

The authoritative final audit result is:

- `2,038 / 2,038 CONSISTENT`
- evidence sufficient: 2,038
- evidence insufficient: 0
- review required: 0
- blocking issues: 0
- unresolved: 0
- deprecated final Ground Truth: 0
- within-firmware duplicate CPE groups: 0
- freeze recommendation: **`READY_TO_FREEZE`**

The portable export is a representation of this audited state, not a replacement for
the fact that the final audit was executed.

## 20. Change Control

After freeze, Ground Truth changes are permitted only when new blocking evidence is
identified. A change must follow this sequence:

1. focused, evidence-independent audit;
2. explicit correction with before/after and transaction safeguards;
3. full four-firmware final audit rerun;
4. new deterministic portable export and hashes;
5. review and freeze under a new dataset identity when the content changes.

Silent edits, live-snapshot refreshes, policy exceptions based on an original CPE,
and direct modification of the frozen export are prohibited.

# Unitronics Ground Truth CPE candidate build

## Scope

- SBOMDocument: `1364`
- Firmware: Unitronics UCR-ST-B8 `52.07.13.7`
- Components: 582 (`575 opkg + 7 non-opkg`; 303 distinct `Source` values)
- CPE Dictionary: `20260819T035002Z`
- NVD CVE/Configuration: `20260820T110357Z`

This is a first-pass candidate build, not final or persisted Ground Truth.
Original CPE and control `CPE-ID` were excluded from product/version/CPE
candidate selection and used only for the final Original-versus-GT comparison.

## Product adjudication

| Classification | Count | Percent |
|---|---:|---:|
| `PRODUCT_IDENTITY_CONFIRMED` | 175 | 30.07% |
| `DIRECT_SUBCOMPONENT_NO_PARENT_INHERITANCE` | 404 | 69.42% |
| `UNRESOLVED` | 3 | 0.52% |

The previous runtime status was not a hard gate. Exact control/list/status,
payload, sibling structure, prior rulebook evidence, and product-specific
official evidence were re-applied to every row. Clear kernel modules, VuCI
feature modules, plugins, helpers, and suite-only children were adjudicated as
direct subcomponents instead of being sent to a generic missing-registry queue.

## Decision distribution

| Decision | Count | Percent |
|---|---:|---:|
| `CPE_CONFIRMED` | 2 | 0.34% |
| `OFFICIAL_CPE_MAPPED` | 24 | 4.12% |
| `VERSION_NOT_IN_DICTIONARY` | 22 | 3.78% |
| `NVD_CONFIGURATION_ONLY` | 0 | 0.00% |
| `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` | 529 | 90.89% |
| `UNRESOLVED` | 5 | 0.86% |

Every component has one of the six existing internal Decisions.

## CPE resolution

| Resolution path | Count | Percent |
|---|---:|---:|
| `ACTIVE_EXACT` | 26 | 4.47% |
| `DEPRECATED_TO_ACTIVE` | 0 | 0.00% |
| `VERSION_NOT_IN_DICTIONARY` | 22 | 3.78% |
| `NVD_CONFIGURATION_ONLY` | 0 | 0.00% |
| `NO_DIRECT_CPE` | 529 | 90.89% |
| `UNRESOLVED` | 5 | 0.86% |

- Proposed GT CPE/expression: **48**
- Original equals GT: **2**
- Original differs from GT: **46**
- Deprecated final GT: **0**
- Configuration gate violations: **0**

## Human validation

- Total: **178**
- Strength: `{"MODERATE": 143, "STRONG": 27, "WEAK": 8}`
- CPE-mapped candidates: **48**
- Unresolved candidates: **5**
- Reasons: `{"CPE_PRODUCT_FAMILY_AMBIGUITY": 2, "OPAQUE_VENDOR_VERSION_IDENTIFIER": 5, "PRODUCT_BOUNDARY_OR_VERSION_UNRESOLVED": 3, "PRODUCT_WITHOUT_CONFIRMED_DIRECT_CPE": 125, "PROPOSED_GT_CPE_CONFIRMATION": 48, "UNRESOLVED": 5, "WEAK_EVIDENCE": 8}`

The list is focused on proposed CPEs, unresolved rows, weak evidence, CPE-family
ambiguity, and confirmed products for which no direct CPE was found. Clear
direct subcomponents are not automatically sent back for 582-row re-review.

## Newly observed ambiguity types

- `MULTI_PRODUCT_BINARY_BOUNDARY`: One package combines hostapd and wpa_supplicant roles; no single product CPE was selected. Examples: wpad-openssl.
- `UPSTREAM_VERSION_HIDDEN_BY_VENDOR_IDENTIFIER`: Exact installed Version does not reproducibly establish the public upstream release. Examples: libmodbus, shellinabox.
- `CPE_PRODUCT_FAMILY_AMBIGUITY`: canonical:ppp and samba:ppp remain semantically possible without using control/original CPE as truth. Examples: ppp, point-to-point_protocol.
- `OPAQUE_VENDOR_REVISION`: Short vendor hashes are preserved and require human provenance confirmation. Examples: gsmctl, gsmd, mobifd.

## Reproducibility limitations before Methods freeze

- The exact matching SDK/GPL Makefiles are unavailable, so non-representative package-release decompositions remain product-specific rather than globally inferred.
- Teltonika internal product names and complete installed Version strings are reproducible, but public release/tag semantics are often unavailable.
- A first-pass CPE family binding without a Dictionary hit remains a human-validation item; absence is not treated as proof of semantic correctness.
- This candidate set is not final Ground Truth and has not been persisted.

## Validation

- Component rows: 582 — PASS
- opkg + non-opkg: `575 + 7 = 582` — PASS
- Decision partition: 582 — PASS
- Every row has a Decision: True — PASS
- Every Decision uses the fixed six-code taxonomy: True — PASS
- Proposed GT canonical parse failures: 0 — PASS
- Deprecated final GT: 0 — PASS
- Configuration gate violations: 0 — PASS
- Ground Truth DB count: `0 -> 0` — PASS
- Existing local evidence hashes unchanged: True — PASS

No Ground Truth, Component, CPE/NVD snapshot, migration, production hook, CVE
applicability, or final RQ1 state was created or modified.

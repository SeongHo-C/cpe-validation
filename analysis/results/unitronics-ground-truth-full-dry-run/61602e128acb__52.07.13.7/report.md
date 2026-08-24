# Unitronics Ground Truth full READ-ONLY dry-run

## Scope

- SBOMDocument: `1364`
- Firmware: Unitronics UCR-ST-B8 `52.07.13.7`
- Components: 582 (`575 opkg + 7 non-opkg`)
- Distinct opkg `Source` values: 303
- CPE Dictionary: `20260819T035002Z`
- NVD CVE/Configuration: `20260820T110357Z`

This run generated proposed results only. It performed no Ground Truth,
Component, snapshot, migration, production-hook, live API, web, CVE
applicability, or RQ1-final-statistic operation.

## Automatic coverage

| Runtime status | Count | Percent |
|---|---:|---:|
| `NON_PRODUCT_RUNTIME` | 176 | 30.24% |
| `PRODUCT_RUNTIME` | 14 | 2.41% |
| `REVIEW_REQUIRED` | 392 | 67.35% |

`PRODUCT_RUNTIME` is intentionally evidence-closed: only cases already backed
by the fixed official evidence registry can be positive. Exact kmod, firmware,
meta/helper, and two BusyBox detector rows can be negative from reproducible
local accessory evidence. All other structural roles stop for review.

All 14 PRODUCT_RUNTIME rows have a fixed
normalized product version (100.00%).

Review-free terminal automation covers **189/582 (32.47%)**. A proposed
internal Decision is populated for **191/582 (32.82%)**; that broader figure
includes **2** explicit
`UNRESOLVED` rows that still require human review. The conservative terminal
coverage is therefore the review-free figure, not the broader populated-field
figure.

## Mapping paths

| Path | Count | Percent |
|---|---:|---:|
| `ACTIVE_EXACT` | 4 | 0.69% |
| `NO_DIRECT_CPE` | 3 | 0.52% |
| `REVIEW_STOP` | 393 | 67.53% |
| `SKIPPED_NON_PRODUCT_RUNTIME` | 176 | 30.24% |
| `VERSION_NOT_IN_DICTIONARY` | 6 | 1.03% |

## Proposed Decision distribution

| Decision / dry-run state | Count | Percent |
|---|---:|---:|
| `CPE_CONFIRMED` | 1 | 0.17% |
| `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` | 179 | 30.76% |
| `OFFICIAL_CPE_MAPPED` | 3 | 0.52% |
| `UNDECIDED_REVIEW` | 391 | 67.18% |
| `UNRESOLVED` | 2 | 0.34% |
| `VERSION_NOT_IN_DICTIONARY` | 6 | 1.03% |

`UNDECIDED_REVIEW` is not a database Decision. NON_PRODUCT_RUNTIME and
NO_DIRECT_CPE share `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED`, but retain different
`decision_reason` values in `components.csv`.

## Review Queue

- Total: **393**
- By stage: `{"CPE_PRODUCT_IDENTITY": 1, "PRODUCT_RUNTIME": 392}`
- By reproducible cause group: `{"CPE_PRODUCT_IDENTITY_AMBIGUITY": 1, "FIXED_RUNTIME_BOUNDARY_AMBIGUITY": 3, "NO_FIXED_OFFICIAL_RUNTIME_ROLE_EVIDENCE": 384, "VENDOR_RUNTIME_VERSION_AMBIGUITY": 5}`
- Human validation candidates with a CPE/expression: **10**

The main exception is not a parser or resolver failure. It is the absence of
fixed official upstream runtime-role evidence for packages not covered by the
existing evidence registry. Those rows are not promoted from names or package
roles. PPP additionally stops at CPE family identity because both
`canonical:ppp` and `samba:ppp` occur in the fixed Dictionary.

## Deprecated and Configuration-only

- Deprecated exact encounters: 0
- Deprecated family encounter rows: 1
- Deprecated-to-Active final mappings: 0
- Deprecated CPE used as final GT: 0
- Configuration gate/query components: 3
- Configuration-only products found: 0
- Gate violations: 0

## Representative regression

All 11 earlier representative cases remain identical in both Decision and
proposed GT CPE: **PASS**.

## Answers to the fifteen questions

1. PRODUCT_RUNTIME: **14**.
2. NON_PRODUCT_RUNTIME: **176**.
3. Runtime-stage review: **392**.
4. PRODUCT_RUNTIME normalized automatically: **14/14 (100.00%)**.
5. Active exact CPE: **4**.
6. Deprecated-to-Active: **0**.
7. VERSION_NOT_IN_DICTIONARY: **6**.
8. NVD_CONFIGURATION_ONLY: **0**.
9. Verified products with no direct representation: **3**.
10. UNRESOLVED: **2**.
11. Review Queue: **393**.
12. CPE-linked human validation candidates: **10**.
13. Representative contradiction: **none**.
14. Full reproducible terminal processing with the current evidence registry: **no**; only the reported non-review subset is terminally reproducible.
15. Methods freeze needs an expanded official runtime-role/product-boundary registry, vendor version evidence, and a fixed PPP CPE-family binding or explicit unresolved policy.

## Validation

- Component rows: 582 — PASS
- opkg + non-opkg: `575 + 7 = 582` — PASS
- Distinct opkg `Source` values: 303 — PASS
- Runtime partition: 582 — PASS
- Decision + undecided partition: 582 — PASS
- Proposed GT canonical parse failures: 0 — PASS
- Deprecated final GT: 0 — PASS
- Configuration gate violations: 0 — PASS
- Ground Truth count: `0 -> 0` — PASS
- Existing evidence artifact hashes unchanged: True — PASS

The run stops at proposed results, review queue, human-validation candidates,
and quantitative summary.

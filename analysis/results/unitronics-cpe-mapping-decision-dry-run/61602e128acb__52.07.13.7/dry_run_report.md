# CPE Mapping / Ground Truth Decision Rulebook v1 — first READ-ONLY dry-run

## Scope

This report maps previously verified upstream products and normalized product
versions for Unitronics UCR-ST-B8 firmware `52.07.13.7`. It does not create
Ground Truth records, persist discrepancy types, determine CVE applicability,
or process all 582 components.

Original SBOM CPE and firmware control `CPE-ID` were excluded from candidate
discovery. Original CPE was loaded only after a proposed GT CPE had been
independently selected or constructed.

## A. Fixed datasets

| Dataset | Snapshot | Status | Counts |
|---|---|---|---|
| CPE Dictionary | `20260819T035002Z` | `COMPLETE` | 1,811,261 total; 1,711,630 active; 99,631 deprecated |
| NVD CVE | `20260820T110357Z` | `COMPLETE` | 380,865 CVEs; 760,120 configurations; 3,170,148 cpeMatch rows |

All database queries ran against these identifiers in transactions explicitly
set to `READ ONLY`. No live API or current web Dictionary was used.

## B. Representative set

- Required core PRODUCT_RUNTIME cases: `10`
- Additional branch-coverage cases: `1`
- Total: `11`

The only addition was `netifd`. Version Normalization v1 had already classified
it as `PRODUCT_RUNTIME` with normalized snapshot version
`2024-01-04-c18cc79d`. It was selected minimally to test the no-direct-CPE
branch. PPP was not added: screening exposed multiple unrelated/packager CPE
families, and no extra branch required forcing a family choice.

## C. Decision distribution

| Proposed Decision | Count | Percent of 11 |
|---|---:|---:|
| `CPE_CONFIRMED` | 1 | 9.09% |
| `OFFICIAL_CPE_MAPPED` | 3 | 27.27% |
| `VERSION_NOT_IN_DICTIONARY` | 6 | 54.55% |
| `NVD_CONFIGURATION_ONLY` | 0 | 0.00% |
| `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` | 1 | 9.09% |
| `UNRESOLVED` | 0 | 0.00% |
| Total | 11 | 100.00% |

Mapping-path coverage differs from Decision counts because one Active exact
path can end in either `CPE_CONFIRMED` or `OFFICIAL_CPE_MAPPED`:

| Mapping branch | Cases |
|---|---:|
| `ACTIVE_EXACT` | 4 |
| `DEPRECATED_TO_ACTIVE` | 0 |
| `VERSION_NOT_IN_DICTIONARY` | 6 |
| `NVD_CONFIGURATION_ONLY` | 0 |
| `NO_DIRECT_CPE` | 1 |

## D. Active exact cases

| Component/package | Verified product/version | Unique Active CPE | Original comparison | Decision |
|---|---|---|---|---|
| `libopenssl3` | OpenSSL `3.0.14` | `cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*` | differs | `OFFICIAL_CPE_MAPPED` |
| `openssl-util` | OpenSSL `3.0.14` | same OpenSSL CPE | differs | `OFFICIAL_CPE_MAPPED` |
| `curl` | curl CLI `8.11.0` | `cpe:2.3:a:haxx:curl:8.11.0:*:*:*:*:*:*:*` | differs | `OFFICIAL_CPE_MAPPED` |
| `linux_kernel` | Linux kernel `5.15.176` | `cpe:2.3:o:linux:linux_kernel:5.15.176:*:*:*:*:*:*:*` | equal | `CPE_CONFIRMED` |

OpenSSL's two runtimes share one independently identified CPE product. curl CLI
and libcurl do not: the Dictionary has separate `haxx:curl` and `haxx:libcurl`
families.

## E. VERSION_NOT_IN_DICTIONARY cases

No exact Active or Deprecated entry existed for these verified versions, but a
compatible Active product family and unique stable-release template existed.

| Package(s) | Active family | Active entries | Proposed GT expression |
|---|---|---:|---|
| `libcurl4` | `(a,haxx,libcurl)` | 205 | `cpe:2.3:a:haxx:libcurl:8.11.0:*:*:*:*:*:*:*` |
| `iptables`, `ip6tables` | `(a,netfilter,iptables)` | 77 | `cpe:2.3:a:netfilter:iptables:1.8.7:*:*:*:*:*:*:*` |
| `strongswan`, `strongswan-charon` | `(a,strongswan,strongswan)` | 214 | `cpe:2.3:a:strongswan:strongswan:5.9.14:-:*:*:*:*:*:*` |
| `e2fsprogs` | `(a,e2fsprogs_project,e2fsprogs)` | 109 | `cpe:2.3:a:e2fsprogs_project:e2fsprogs:1.47.0:*:*:*:*:*:*:*` |

These are Ground Truth expressions, not official Active Dictionary entries.
The normalized product version was retained exactly.

Template selection was not “first row wins.” Stable generic entries for
libcurl 8.12.0, iptables 1.8.3, and e2fsprogs 1.46.5 use wildcard non-version
attributes. strongSwan stable 5.9.12 uses `update=-`, while its `dr`/`rc`
records are different upstream states. The proposed 5.9.14 expression therefore
preserves `update=-`.

## F. Deprecated resolution

Observed Deprecated mapping-path results:

| Check | Result |
|---|---:|
| Deprecated exact CPE | 0 |
| Deprecated product family in paths requiring resolution | 0 |
| `deprecatedBy` edges traversed | 0 |
| 1:1 replacement | 0 |
| multi-hop chain | 0 |
| multiple replacement | 0 |
| cycle | 0 |
| missing reference | 0 |
| resolved Active endpoint | 0 |
| vendor/product rename alias | 0 |

Four cases ended at unique Active exact entries before Deprecated traversal.
Their target families contain historical Deprecated records—15 for
`openssl:openssl` and 135 for `linux:linux_kernel`—but those records were not
mapping evidence and were not traversed. For the seven paths without Active
exact matches, no relevant Deprecated exact or family record existed.

Consequently `deprecated_resolution.csv` intentionally contains its schema and
zero data rows. The required cycle/missing/multiple logic is defined in
`rulebook.md`, but no selected case exercised it. Deprecated-to-Active behavior
therefore remains unvalidated rather than implicitly passing.

## G. Configuration-only

Only netifd passed the Configuration-only query gate:

```text
Dictionary product-wide netifd records: 0 Active + 0 Deprecated
NVD Configuration product-wide netifd occurrences: 0
```

It therefore did not become `NVD_CONFIGURATION_ONLY`. Its upstream identity
and normalized snapshot version remain verified, so the result is:

```text
DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
proposed_gt_cpe = null
```

No expression was forced from the Original CPE. `configuration_only_cases.csv`
contains zero data rows. Configuration-only definition violations are `0`.

## H. Original CPE discrepancies

The comparison used parsed 11-field tuples and ran only after proposed GT was
available.

| Field | Cases differing |
|---|---:|
| part | 0 |
| vendor | 8 |
| product | 5 |
| version | 9 |
| update | 2 |
| edition/language/sw_edition/target_sw/target_hw/other | 0 |

- Original equals proposed: `1` (`linux_kernel`)
- Original differs from proposed: `9`
- `N/A` because no proposed GT: `1` (`netifd`)

These values were not written as Discrepancy Type selections.

## I. Review-required and exceptions

No selected record has `review_required=true`. No Decision was forced.

The dry-run nevertheless found four rule-design issues requiring explicit
handling:

1. Active family presence does not imply a registered verified version.
2. Same Source/version does not merge curl CLI and libcurl CPE identities.
3. Stable family templates can distinguish `*` from `-`; strongSwan exposes the
   difference.
4. The existing structural parser is sufficient for these unescaped examples
   but does not provide complete CPE binding canonical equivalence.

## J. Are the six Decisions sufficient?

They express all 11 observed outcomes without a terminal contradiction:

- one original official CPE confirmed;
- three corrected to an Active official CPE;
- six verified versions absent from an Active family;
- one verified product/version with no direct CPE representation.

The taxonomy cannot yet be declared fully validated. No case exercised
Deprecated-to-Active resolution, Configuration-only, or `UNRESOLVED`. Those
branches must remain open for later representative evidence rather than being
synthetically populated.

## K. Required changes before a 582-component dry-run

1. implement complete CPE 2.3 binding canonicalization/unescaping;
2. formalize upstream-to-CPE family binding and product-wide alias scans;
3. formalize stable-template selection, including wildcard versus NA fields;
4. emit machine-checkable Deprecated path/branch/cycle/missing provenance;
5. enforce Active + Deprecated Dictionary absence before Configuration lookup;
6. route ambiguous families, templates, and replacement endpoints to
   `review_required` with no forced Decision.

## L. Validation

| Check | Result |
|---|---|
| Representative count | PASS (`11`) |
| Decision partition | PASS (`1 + 3 + 6 + 0 + 1 + 0 = 11`) |
| Mapping branch partition | PASS (`4 + 0 + 6 + 0 + 1 = 11`) |
| Fixed CPE snapshot only | PASS |
| Fixed NVD snapshot only | PASS |
| Live API calls | PASS (`0`) |
| Configuration-only gate violations | PASS (`0`) |
| Forced GT where unavailable | PASS (`0`) |
| Ground Truth record count | PASS (`0 -> 0`) |
| Database mutations | PASS (`0`) |
| Existing artifact modifications | PASS (`0`) |

Detailed case-level data is in `representative_cases.csv`. The two empty
provenance CSVs are intentional zero-observation results, not omitted analyses.

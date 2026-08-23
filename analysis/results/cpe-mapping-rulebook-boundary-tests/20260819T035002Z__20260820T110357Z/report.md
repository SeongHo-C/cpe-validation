# CPE Mapping Rulebook boundary tests

## Scope

This is a read-only boundary test. It does not create Ground Truth records,
run the 582 Unitronics components, evaluate CVE applicability, mutate either
snapshot, or hook these helpers into the production save path.

All database reads ran inside a PostgreSQL transaction set to `READ ONLY`.

## Fixed snapshots

| Dataset | Snapshot | Counts |
|---|---|---|
| CPE Dictionary | `20260819T035002Z` | 1,811,261 total; 1,711,630 Active; 99,631 Deprecated |
| NVD CVE | `20260820T110357Z` | 380,865 CVEs; 760,120 Configurations; 3,170,148 cpeMatch rows |

## Canonical parser

- Full Dictionary scan: 1,811,261 CPEs
- Status counts: `{"VALID": 1811261}`
- The parser distinguishes all 11 ordered attributes, ANY (`*`), NA (`-`),
  and an invalid empty attribute. Escape-aware parse/serialize and canonical
  comparison are covered by tests. URI percent encoding is not conflated with
  a CPE 2.3 formatted-string binding.
- Specification basis: [NIST IR 7695](https://csrc.nist.gov/pubs/ir/7695/final).

## Branch results

| Case | Branch | Observed in fixed snapshot | Actual | Review | Result |
|---|---|---:|---|---:|---|
| ACTIVE-EXACT-01 | ACTIVE_EXACT | true | ACTIVE_EXACT | false | PASS |
| VERSION-NOT-01 | VERSION_NOT_IN_DICTIONARY | true | VERSION_NOT_IN_DICTIONARY | false | PASS |
| DEP-1TO1-01 | DEPRECATED_TO_ACTIVE_1_TO_1 | true | RESOLVED_ACTIVE | false | PASS |
| DEP-MULTIHOP-01 | DEPRECATED_TO_ACTIVE_MULTI_HOP | true | RESOLVED_ACTIVE | false | PASS |
| DEP-MULTIPLE-01 | DEPRECATED_MULTIPLE_REPLACEMENTS | true | REVIEW_REQUIRED | true | PASS |
| CONFIG-ONLY-01 | CONFIGURATION_ONLY | true | NVD_CONFIGURATION_ONLY | false | PASS |
| NO-DIRECT-01 | NO_DIRECT_CPE | true | DIRECT_OFFICIAL_CPE_NOT_CONFIRMED | false | PASS |
| MULTIPLE-TEMPLATE-01 | MULTIPLE_STABLE_TEMPLATES | true | REVIEW_REQUIRED | true | PASS |

Actual deprecated cases are in `deprecated_cases.csv`; an unobserved branch is
reported as such and is covered only by a unit fixture, never by inserting
synthetic production data.

## Deprecated graph observations

- Deprecated sources: 99,631
- Direct replacement edges: 100,215
- Direct resolved sources: 94,486
- Multi-hop resolved sources: 4,888
- Sources with multiple direct replacements: 270
- Sources reaching multiple distinct Active endpoints without an evidence filter: 252
- Cycle-affected sources: 0
- Missing-reference-affected sources: 0
- Maximum observed depth: 4
- Declared target-name mismatches: 0

The resolver retains all branches, stops on cycle/missing/deprecated dead-end,
and returns an Active endpoint only when semantic filtering leaves one endpoint.

## Stable templates

- strongSwan final-release filter: `UNIQUE_STABLE_TEMPLATE`;
  selected template `["-", "*", "*", "*", "*", "*", "*"]`.
- Unfiltered actual gitlab family: `MULTIPLE_COMPATIBLE_TEMPLATES`
  across 39 templates; automatic generation blocked.

Compatibility filtering is caller-supplied evidence. The resolver never uses
the first CPE record as a template.

## Configuration-only gate

Actual family `a:microsoft:microsoft_365` has zero Active and zero Deprecated
Dictionary records, then yields 170
Configuration occurrences across 170 CVEs. The
gate status is `ALLOWED`. Range applicability was not evaluated.

## Unitronics 11-case regression

Regression result: **PASS**.
No case changed. Counts remain:

```json
{
  "CPE_CONFIRMED": 1,
  "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED": 1,
  "NVD_CONFIGURATION_ONLY": 0,
  "OFFICIAL_CPE_MAPPED": 3,
  "UNRESOLVED": 0,
  "VERSION_NOT_IN_DICTIONARY": 6
}
```

## Answers to the twelve exit questions

1. **Yes.** The canonical parser preserves the ordered 11 attributes and
   distinguishes STRING, ANY, NA, and invalid empty values.
2. **Yes.** Escaped colon, backslash, special characters, and redundant quoting
   round-trip canonically; tests compare parsed attributes, not raw strings.
3. **Yes, when compatibility evidence leaves one non-version template.** The
   strongSwan case reproducibly preserves `update=-`.
4. **Yes.** Multiple/no-template results have no generated CPE and require review.
5. **Yes.** The actual 1:1 branch result is recorded in the CSV.
6. **Yes; an actual multi-hop case was reproduced.**
7. **Yes.** Every branch is traversed; multiple compatible endpoints prohibit
   automatic selection.
8. **Yes.** Cycle and missing-reference checks run over the full Deprecated
   graph. Actual source counts are 0 and
   0; both paths also have unit fixtures.
9. **Yes.** Active blocks first, Deprecated blocks second, and only absence of
   both permits Configuration lookup.
10. **Yes.** The Microsoft 365 case is reproduced from the fixed NVD snapshot.
11. **Yes.** All 11 representative Decisions remain unchanged.
12. **No defect was found in these four boundary helpers.** The full dry-run
   orchestration must still supply independently verified product identity,
   normalized version, and an explicit compatibility predicate. Ambiguous or
   absent evidence remains an intentional review stop, not an automatic result.

# Unitronics Ground Truth Methodology & Reproducibility Final Audit

## Final verdict

**`READY_WITH_MINOR_FIXES`**

The core Ground Truth construction is conservative, internally consistent, and
computationally reproducible from the fixed local evidence and database
snapshots. A fresh read-only run reproduced all eight candidate-build artifacts
and all three independent-audit artifacts byte-for-byte. The 48 CPE-bearing
candidates remain independently accepted, and no final expression is
Deprecated.

One taxonomy/documentation issue must be resolved before database application:
the current narrow description of **Unable to Determine** covers insufficient
product or version evidence, but two rows (`libnl-core200` and
`libnl-genl200`) reached that result because more than one compatible CPE family
template remained after product and version had already been confirmed. The
conservative stop is methodologically correct; the result definition is not yet
wide enough to describe both observed causes.

## Ratings

| Area | Rating | Basis |
|---|---|---|
| Methodological Consistency | `PASS_WITH_LIMITATION` | Resolution order, circularity controls, conservative stops, and result partition are consistent. The Unable to Determine definition does not cover the two template-ambiguity rows. |
| Evidence Traceability | `PASS_WITH_LIMITATION` | All 48 CPE-bearing rows and all 529 No Direct CPE Found rows contain the required row-level reasoning and firmware provenance. Official upstream references are URL-only and are not content-hashed. |
| Computational Reproducibility | `PASS_WITH_LIMITATION` | Fresh fixed-snapshot runs matched 8/8 candidate and 3/3 audit artifacts byte-for-byte. Reproduction still requires the local PostgreSQL snapshots and precomputed evidence artifacts; the full HTML is not generated from scratch. |

## Fixed scope and inputs

| Item | Fixed value |
|---|---|
| Manufacturer / product | Unitronics UCR-ST-B8 |
| Firmware | `52.07.13.7` |
| Firmware SHA-256 | `6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c` |
| SBOMDocument | `1364` |
| Components | `582` |
| SBOM SHA-256 | `61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e` |
| CPE Dictionary snapshot | `20260819T035002Z` |
| NVD CVE/Configuration snapshot | `20260820T110357Z` |
| Audited source revision | `903505548cc4349d9213c70b404d4a7d9ed0c28d` |

Both management commands select these snapshot IDs explicitly, require COMPLETE
snapshots, and run database reads inside PostgreSQL transactions set to
`READ ONLY`. Neither command applies an implicit latest-snapshot rule.

## Result partition validation

| CPE Validation Result | Count |
|---|---:|
| CPE Confirmed | 2 |
| Correct CPE Found | 24 |
| Version Not Registered | 22 |
| NVD Configuration Only | 0 |
| No Direct CPE Found | 529 |
| Unable to Determine | 5 |
| **Total** | **582** |

The partition check `2 + 24 + 22 + 0 + 529 + 5 = 582` passes. Exactly 48
rows carry a Ground Truth CPE or Ground Truth CPE expression: 2 CPE Confirmed,
24 Correct CPE Found, and 22 Version Not Registered.

## Methodological consistency audit

### 1. Product and version precede CPE resolution

The candidate builder first produces an independent `ProductJudgment` from the
SBOM component and exact firmware/package evidence. The recorded evidence
includes package, Version, Source, SourceName, Description, payload/list/status,
sibling structure, and selected upstream references. CPE family resolution is
invoked only after this judgment exists.

Version processing is product-specific. Package release suffixes are removed
only under fixed product/upstream rules; there is no global rule that strips a
suffix merely because a hyphen is present.

### 2. Circular evidence is excluded

Original SBOM CPE and firmware control CPE-ID are not inputs to product,
version, family, or template selection. Original CPE enters only after an
independently produced expression exists, to assign the CPE Validation Result
and calculate canonical attribute discrepancies. The independent 48-row audit
records zero Original CPE, control CPE-ID, current GT CPE, and current result
inputs in Pass A. Circular evidence risk is 0.

### 3. Source and package boundaries are conservative

The implementation does not infer `same Source -> same product -> same CPE`.
Plugins, optional modules, helpers, configuration packages, kernel modules,
firmware/board-data artifacts, and other bounded subcomponents are stopped from
inheriting a parent CPE. Library, CLI, and split-package status are not terminal
rules by themselves; payload and upstream product boundaries are evaluated.

This distinction is visible inside No Direct CPE Found:

- 404 rows: `NON_DIRECT_SUBCOMPONENT`; deliberate non-inheritance.
- 123 rows: `NO_CPE_REPRESENTATION`; product/family evidence exists, but neither
  Dictionary nor gated Configuration evidence yields a direct representation.
- 2 rows: `CPE_PRODUCT_FAMILY_AMBIGUITY`; product identity exists, but a unique
  CPE family cannot be selected.

Thus the 529 rows must not be reported as one undifferentiated “no CPE” group.

### 4. Prerelease and development states are preserved

For `wpa_supplicant`, exact firmware evidence records `2.11-devel` as the
actual product version. The approved CPE expression uses `version=2.11` and
`update=devel`:

```text
cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*
```

The MOVE_TO_UPDATE branch requires a recognized release-state token and
supporting family practice. The fixed family contains comparable `update=preN`
rows. A generic hyphen or arbitrary suffix does not trigger the branch. Final
2.11 and development 2.11-devel therefore remain distinguishable.

### 5. CPE resolution order matches the stated method

The implemented order is:

```text
verified product/version
  -> compatible Active exact CPE
  -> exact Deprecated CPE and full deprecatedBy traversal
  -> compatible Active family template / Version Not Registered
  -> only if Active and Deprecated family counts are both zero:
       fixed NVD Configuration lookup
  -> NVD Configuration Only or No Direct CPE Found
```

Multiple compatible Active exact entries, non-unique Deprecated endpoints, and
multiple/no compatible stable templates stop as unresolved. The resolver never
selects the first database row or first replacement edge.

### 6. Deprecated CPE cannot become final Ground Truth

The full fixed-snapshot graph contains 99,631 Deprecated sources and 100,215
replacement edges. It records 94,486 direct Active resolutions, 4,888 multi-hop
Active resolutions, 270 sources with multiple direct replacements, 252 sources
reaching different Active endpoints, 5 dead ends, maximum depth 4, no cycles,
and no missing references.

All branches are retained. Cycle, missing-reference, dead-end, and multiple
compatible endpoint statuses require review. Candidate finalization occurs only
when one compatible Active endpoint remains. The Unitronics candidate and audit
artifacts both contain 0 final Deprecated Ground Truth expressions.

### 7. Version Not Registered is an expression, not an official entry

All 22 rows have an Active product family, no Active exact version entry, and at
least one supporting family-template observation. Twenty-one preserve the
verified product version directly in the CPE version attribute; `wpa_supplicant`
preserves the same information across version/update. Their update templates are
17 `*`, 4 `-`, and 1 `devel`.

These are Ground Truth CPE expressions, not claims that the expressions are
official Active Dictionary entries. They remain canonical structured inputs for
a later NVD Configuration range comparison, but this audit performs no CVE
applicability or range evaluation.

### 8. Configuration-only lookup is correctly gated

Configuration lookup is permitted only when both Active and Deprecated counts
for the complete `(part, vendor, product)` tuple are zero. Boundary tests
reproduce the allowed and blocked branches against the fixed snapshots. The
Unitronics build entered the gate for 123 components, recorded 0 gate
violations, and produced 0 NVD Configuration Only results. A zero result is
consistent with the policy.

### 9. Uncertainty handling is conservative but needs one definition fix

The five Unable to Determine rows are not forced into a CPE:

- `libmodbus`, `shellinabox`, and `wpad-openssl`: upstream product/version or
  product boundary is insufficiently established.
- `libnl-core200` and `libnl-genl200`: product `libnl` and version `3.9.0` are
  confirmed, but multiple compatible non-version CPE templates remain.

The two causes are reproducibly distinguished by `product_classification`,
`cpe_resolution_path`, and the stored result-reason provenance field. The
second cause is outside the current narrow Unable to Determine description. The
definition should cover inability to establish a unique Ground Truth CPE
expression as well as product/version uncertainty. No new mapping is needed.

## Canonicalization audit

The canonical parser successfully processed all 1,811,261 formatted-string CPE
2.3 names in the fixed Dictionary. It preserves the ordered 11 WFN attributes,
distinguishes ANY (`*`) and NA (`-`), handles escaped colon/backslash and quoted
special characters, performs canonical parse/serialize round trips, and returns
ordered attribute discrepancies.

Percent-encoded CPE URI binding is intentionally not decoded as a CPE 2.3
formatted-string binding. It is rejected at this boundary, preventing URI
encoding from being silently conflated with formatted-string escaping. A caller
that needs URI binding must perform an explicit binding conversion first.

## Independent validation audit

The two-pass audit scopes exactly the 48 CPE-bearing candidates. Pass A receives
exact firmware/SBOM/package/upstream evidence and an independent audit registry;
current GT and Original CPE values are introduced only after Pass B resolves the
CPE. Results are:

| Audit status | Count |
|---|---:|
| ACCEPTED | 48 |
| CORRECTION_REQUIRED | 0 |
| EVIDENCE_REVIEW_REQUIRED | 0 |

All 48 rows contain non-empty product evidence, version evidence, evidence
references, and resolution paths. Canonical parse failures, final Deprecated GT,
and circular evidence risks are all zero. This supports wording such as:

> CPE-bearing Ground Truth candidates were independently reviewed against the
> collected firmware, upstream, and fixed-snapshot evidence before finalization.

This must not be described as an inter-rater study or a blinded multi-reviewer
experiment; the evidence supports a separate two-pass audit, not those stronger
claims.

## Evidence traceability and live dependencies

The candidate rows provide product/version reasoning, exact firmware provenance,
family binding basis, resolution path, CPE Validation Result reason, and
canonical discrepancy fields. All 48 CPE-bearing rows have every audited
provenance field populated. The 529 No Direct CPE Found rows also have complete
reasoning, resolution-path, and exact-firmware fields. The five unresolved rows
retain the observed identifier and the reason it was not promoted.

The evidence manifest contains 11 local artifacts with SHA-256 hashes and 15
official upstream URLs with access dates. Candidate and audit execution does not
call live NVD, a current Dictionary endpoint, live web search, or any upstream
URL. It reads the fixed database snapshots and local evidence artifacts.

Remaining evidence limitations are:

1. Official upstream pages are mutable URL references with no captured content
   hash or archived copy.
2. Exact firmware paths point to an extraction environment outside the
   repository; the derived CSV evidence is hashed, but raw re-extraction needs
   the firmware/extraction inputs and tooling.
3. The complete HTML review document is a static artifact; only the approved
   `wpa_supplicant` card has a focused deterministic refresh command. The core
   CSV/JSON Ground Truth artifacts are reproducible, but the full HTML is not
   generated from scratch by the candidate command.
4. Reproduction requires the fixed PostgreSQL snapshot contents and the exact
   code/artifact revision. The existing candidate summaries do not embed a git
   commit or environment lock; this audit records the source revision.

## Direct computational reproduction

On 2026-08-24, the candidate builder and independent audit were rerun into a
temporary directory using the fixed snapshot IDs. Results:

- Candidate build: **8/8 files byte-identical** to the existing artifacts.
- Independent CPE audit: **3/3 files byte-identical** to the existing artifacts.
- Canonical/mapping/prerelease/candidate/audit regression tests: **52/52 PASS**.
- Django system check: PASS.
- Ground Truth database count: `0 -> 0`.

No live network dependency was exercised.

## Required minor fix before database application

**`METH-01 — Align the Unable to Determine definition with observed causes.`**

Before persisting the 582 results, the Methodology and UI/help description must
state that Unable to Determine also covers inability to derive a unique Ground
Truth CPE expression after product/version confirmation. Alternatively, a
separate result would be required. The existing internal result code can remain
unchanged, and the two libnl rows require no new CPE mapping.

This is a taxonomy/documentation alignment issue, not a correction to the five
conservative outcomes.

## Principles that must appear in the paper

1. Identify the actual software product and upstream version before CPE lookup.
2. Do not use Original CPE or firmware control CPE-ID as Ground Truth evidence;
   compare them only after independent Ground Truth construction.
3. Do not inherit a parent CPE solely from Source/package relationships; evaluate
   the installed product boundary and payload.
4. Remove package/build metadata only with product-specific evidence, and
   preserve prerelease/development state using family-supported CPE attributes.
5. Resolve Deprecated CPEs through the complete `deprecatedBy` graph and accept
   only one compatible Active endpoint; never select the first branch.
6. When an Active family exists but the exact verified version does not, preserve
   the version in a Ground Truth CPE expression and label it Version Not
   Registered.
7. Do not force a CPE when product/version, family, replacement endpoint, or CPE
   template evidence is non-unique or insufficient; retain the reason for the
   conservative result.

## Safety and final consistency

- Components: 582 — PASS
- CPE Validation Result partition: 582 — PASS
- CPE-bearing GT: 48 — PASS
- Independent audit accepted: 48 — PASS
- Final Deprecated GT: 0 — PASS
- Circular evidence risk: 0 — PASS
- Canonical parse failure: 0 — PASS
- Ground Truth DB: `0 -> 0` — PASS
- DB mutations: 0 — PASS
- Migrations: 0 — PASS
- Existing artifact modifications: 0 — PASS
- Commit performed by this audit: 0 — PASS

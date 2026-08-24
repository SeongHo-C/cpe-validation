# Unitronics Ground Truth Methodology Final Audit

## Final verdict

**`READY_FOR_FINALIZATION`**

The only blocking issue from the preceding Methodology & Reproducibility Audit,
`METH-01`, is resolved. The Unable to Determine help text now covers all four
required uncertainty dimensions without changing its internal code, label, or
any Ground Truth value:

> The product, version, product boundary, or a unique Ground Truth CPE could not
> be established with sufficient evidence.

The definition covers both observed cause classes:

- Product/version/product-boundary evidence is insufficient:
  `libmodbus`, `shellinabox`, and `wpad-openssl`.
- Product/version is confirmed but one unique Ground Truth CPE expression cannot
  be established: `libnl-core200` and `libnl-genl200`.

## Final ratings

| Area | Rating | Basis |
|---|---|---|
| Methodological Consistency | `PASS` | The result definition now matches every observed Unable to Determine cause. Resolution order, circularity controls, conservative stops, and all Ground Truth principles remain unchanged. |
| Evidence Traceability | `PASS_WITH_LIMITATION` | Row-level provenance and fixed local evidence remain complete. Official upstream evidence still uses mutable URL references without captured content hashes. |
| Computational Reproducibility | `PASS_WITH_LIMITATION` | Core candidate/audit artifacts remain byte-identical to the validated baseline. Long-term reproduction still requires the fixed database snapshots and evidence environment; full HTML generation remains partial. |

## Blocking issues

**Blocking issues: `NONE`**

The previous issue did not require a CPE remapping, result change, schema change,
or migration. It was resolved by aligning the centralized UI description and
its test expectation with the already recorded provenance.

## Scope and fixed inputs

| Item | Value |
|---|---|
| Manufacturer / product | Unitronics UCR-ST-B8 |
| Firmware | `52.07.13.7` |
| Firmware SHA-256 | `6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c` |
| SBOMDocument / components | `1364` / `582` |
| SBOM SHA-256 | `61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e` |
| CPE Dictionary snapshot | `20260819T035002Z` |
| NVD CVE/Configuration snapshot | `20260820T110357Z` |
| Base source revision | `903505548cc4349d9213c70b404d4a7d9ed0c28d` |

## CPE Validation Result invariance

| CPE Validation Result | Before | After |
|---|---:|---:|
| CPE Confirmed | 2 | 2 |
| Correct CPE Found | 24 | 24 |
| Version Not Registered | 22 | 22 |
| NVD Configuration Only | 0 | 0 |
| No Direct CPE Found | 529 | 529 |
| Unable to Determine | 5 | 5 |
| **Total** | **582** | **582** |

- CPE-bearing Ground Truth candidates: `48 -> 48`
- GT CPE changes: `0`
- CPE Validation Result changes: `0`
- Unable to Determine changes: `0`

The description-only change does not enter candidate construction, product or
version normalization, Dictionary resolution, Deprecated traversal, or the
Configuration-only gate. Candidate `components.csv` and `summary.json` SHA-256
values remain identical to the pre-change baseline.

## Independent CPE audit invariance

| Audit status | Before | After |
|---|---:|---:|
| ACCEPTED | 48 | 48 |
| CORRECTION_REQUIRED | 0 | 0 |
| EVIDENCE_REVIEW_REQUIRED | 0 | 0 |

- Circular evidence risk: 0
- Canonical parse failure: 0
- Final Deprecated GT: 0
- Product/version/GT/result/discrepancy corrections: 0

Independent audit `audit_results.csv` and `summary.json` hashes remain unchanged.

## Unable to Determine and No Direct CPE Found remain distinct

### Unable to Determine

The evidence is insufficient or non-unique for at least one required Ground
Truth dimension: product identity, product version, product boundary, or one
unique Ground Truth CPE expression. No CPE is forced.

### No Direct CPE Found

The software/product relationship is sufficiently established, but the
component either intentionally does not inherit a parent CPE or no direct
Dictionary/Configuration representation can be confirmed. Existing provenance
continues to distinguish:

- 404 deliberate bounded-subcomponent non-inheritance rows.
- 123 verified-product/no-representation rows.
- 2 verified-product/CPE-family-ambiguity rows.

The definition alignment therefore does not merge the two CPE Validation
Results.

## Final methodology flow

```text
SBOM Component
  -> Exact Firmware Evidence
  -> Actual Software Product / Version
  -> Product / Subcomponent Boundary
  -> Active Exact CPE
  -> Deprecated CPE -> one compatible Active replacement
  -> Active Family / Version Not Registered
  -> only when Dictionary family is absent: fixed NVD Configuration
  -> CPE Validation Result
  -> independent validation of CPE-bearing candidates
```

The seven established Ground Truth principles are unchanged:

1. Identify actual product and upstream version before CPE lookup.
2. Exclude Original CPE and firmware CPE-ID from Ground Truth evidence; compare
   only after independent construction.
3. Never inherit a parent CPE solely from a shared Source relationship.
4. Separate package/build metadata only with product-specific evidence and
   preserve prerelease state.
5. Traverse every Deprecated replacement branch and accept only one compatible
   Active endpoint.
6. Preserve a verified missing version in a Ground Truth CPE expression and use
   Version Not Registered.
7. Never force a CPE when product, version, boundary, family, endpoint, or
   template evidence is insufficient or non-unique.

## Non-blocking limitations

The following previously recorded limitations remain and do not block database
application:

1. Fifteen official upstream evidence references are URLs with access dates but
   no archived content hashes.
2. Full raw firmware re-extraction requires the external extraction environment
   and tooling; the derived local evidence artifacts are content-hashed.
3. Core CSV/JSON artifacts are reproducible, but the complete Human Validation
   HTML is not generated from scratch by the candidate command.
4. Long-term reproduction requires preservation of the fixed PostgreSQL
   snapshots and executable environment.

## Verification and safety

- Frontend Ground Truth tests: 10/10 PASS
- TypeScript/Vite production build: PASS
- Frontend lint: PASS
- Relevant backend methodology/canonical/mapping tests: 52/52 PASS
- Django system check: PASS
- Candidate and audit baseline hashes: unchanged
- Existing analysis artifacts: unchanged
- Ground Truth DB: `0 -> 0`
- DB mutations: 0
- Migrations: 0
- Commit performed: 0

## Database application readiness

**`READY`**


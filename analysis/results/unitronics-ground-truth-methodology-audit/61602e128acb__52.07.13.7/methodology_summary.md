# Ground Truth Methodology Structure

## 1. Ground Truth inputs

- Unitronics UCR-ST-B8 firmware `52.07.13.7`
- Firmware SHA-256
  `6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c`
- SBOMDocument `1364`, 582 components
- SBOM SHA-256
  `61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e`
- COMPLETE CPE Dictionary snapshot `20260819T035002Z`
- COMPLETE NVD CVE/Configuration snapshot `20260820T110357Z`
- Fixed local rulebooks, evidence CSVs, evidence manifest, and source revision

## 2. Evidence hierarchy

1. Exact firmware/SBOM evidence: package, Version, Source, SourceName,
   Description, Depends, control/list/status, installed paths, detected banners.
2. Same-Source sibling structure, used as context rather than automatic CPE
   inheritance.
3. Official upstream evidence when product boundary or upstream version semantics
   require corroboration.
4. Fixed CPE Dictionary and NVD snapshots for resolution after product/version
   identification.

Original SBOM CPE and firmware control CPE-ID are excluded from Ground Truth
construction. They are comparison inputs only after an independent GT expression
has been produced.

## 3. Software product/version identification

- Establish the installed software product boundary from payload, role, source,
  siblings, and upstream structure.
- Do not treat library, CLI, plugin, split package, or shared Source as an
  automatic positive or negative CPE rule.
- Separate package/build metadata only with product-specific evidence; do not
  apply a global suffix-stripping regex.
- Preserve prerelease states. Example: actual version `2.11-devel` is represented
  as CPE `version=2.11`, `update=devel` only because upstream semantics and family
  practice support MOVE_TO_UPDATE.

## 4. CPE resolution procedure

```text
SBOM Component
  -> exact firmware evidence
  -> actual software product and version
  -> product/subcomponent boundary
  -> compatible Active exact CPE
  -> exact Deprecated CPE and full deprecatedBy traversal
  -> compatible Active family template / Version Not Registered
  -> only when Active=0 and Deprecated=0 for the family:
       fixed NVD Configuration lookup
  -> CPE Validation Result
  -> independent validation of CPE-bearing candidates
```

- Deprecated resolution retains every branch and accepts only one compatible
  Active endpoint.
- Multiple exact entries, multiple endpoints, dead ends, cycles, missing
  references, and multiple/no stable templates stop automatic selection.
- Version Not Registered produces a canonical Ground Truth expression, not an
  official Dictionary-entry claim.

## 5. CPE Validation Result definitions

- **CPE Confirmed**: independently derived GT is canonically equal to Original.
- **Correct CPE Found**: an official Active CPE is independently resolved and is
  canonically different from Original.
- **Version Not Registered**: product/version is verified, an Active family
  exists, and the exact compatible version expression is absent; the verified
  version is preserved in the GT expression.
- **NVD Configuration Only**: the family is absent from Active and Deprecated
  Dictionary rows but has one compatible fixed-snapshot Configuration template.
- **No Direct CPE Found**: either a bounded subcomponent intentionally does not
  inherit a parent CPE, or a verified product lacks a unique direct CPE
  representation. Provenance distinguishes these causes.
- **Unable to Determine**: evidence cannot establish a required GT dimension,
  including product/version/boundary or a unique compatible CPE expression.

The last definition is the required clarification before DB application; two
libnl rows have confirmed product/version but ambiguous CPE templates.

## 6. Uncertainty handling

- Do not force a CPE from structural similarity, first-row selection, first
  replacement edge, or Dictionary absence alone.
- Preserve observed identifiers even when they cannot be promoted to an upstream
  product version.
- Record product classification, product/version reasoning, family basis,
  resolution path, result reason, evidence strength, and human-review reason.
- Treat product/version insufficiency and CPE-template ambiguity as distinct
  provenance causes even when both use Unable to Determine.

## 7. Independent validation procedure

- Scope exactly the 48 CPE-bearing candidates.
- Pass A independently confirms product/version from firmware, package, and
  upstream evidence without Original CPE, firmware CPE-ID, current GT, or current
  result inputs.
- Pass B independently resolves the CPE against the fixed Dictionary snapshot.
- Only then compare audited values with candidate values and calculate canonical
  discrepancies.
- Final evidence: 48 ACCEPTED, 0 corrections, 0 evidence reviews, 0 circular
  evidence risks, 0 Deprecated final GT, and 0 parse failures.

Describe this as an independent two-pass review. Do not claim blinded review,
multiple human raters, or inter-rater agreement.

## 8. Reproducibility controls

- Pin firmware/SBOM hashes, SBOMDocument ID, snapshot IDs and snapshot hashes.
- Run candidate/audit database access in PostgreSQL READ ONLY transactions.
- Hash every local evidence artifact and refuse to overwrite existing output
  directories.
- Record the exact code revision and run the canonical/mapping regression suite.
- Keep live NVD, current Dictionary, live web search, and CVE applicability out
  of candidate reproduction.
- Archive or content-hash mutable official upstream pages for stronger long-term
  traceability.
- Preserve raw firmware/extraction tooling if reproduction from firmware rather
  than from the hashed evidence CSVs is required.
- Treat the core CSV/JSON outputs as computational artifacts; the current full
  HTML review page is not generated from scratch by the candidate command.


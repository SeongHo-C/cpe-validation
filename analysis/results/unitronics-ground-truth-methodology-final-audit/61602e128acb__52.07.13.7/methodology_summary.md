# Final Ground Truth Methodology Structure

## 1. Ground Truth inputs

- Unitronics UCR-ST-B8 firmware `52.07.13.7`
- Firmware SHA-256
  `6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c`
- SBOMDocument `1364`, 582 components
- SBOM SHA-256
  `61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e`
- CPE Dictionary snapshot `20260819T035002Z`
- NVD CVE/Configuration snapshot `20260820T110357Z`
- Fixed local evidence artifacts, rulebooks, and source revision

## 2. Evidence hierarchy

1. Exact firmware and SBOM evidence: package, Version, Source, SourceName,
   Description, Depends, control/list/status, payload paths, and binary banners.
2. Same-Source sibling structure as context, never automatic parent-CPE
   inheritance.
3. Official upstream evidence for product boundary and version semantics.
4. Fixed Dictionary and NVD snapshots only after product/version identification.

Original CPE and firmware CPE-ID are excluded from Ground Truth construction and
used only for comparison after an independent expression exists.

## 3. Software product/version identification

- Determine the installed software boundary from payload, role, source,
  siblings, and upstream structure.
- Do not use library, CLI, plugin, split-package, or shared-Source status as an
  automatic terminal rule.
- Separate package/build metadata only with product-specific evidence.
- Preserve prerelease/development state; for example, actual `2.11-devel` is
  represented as CPE `version=2.11`, `update=devel` under the approved
  family-supported policy.

## 4. CPE resolution procedure

```text
SBOM Component
  -> Exact Firmware Evidence
  -> Actual Software Product / Version
  -> Product / Subcomponent Boundary
  -> Active Exact CPE
  -> Deprecated CPE and complete deprecatedBy traversal
  -> Active Family / Version Not Registered
  -> Dictionary family absent: fixed NVD Configuration
  -> CPE Validation Result
  -> CPE-bearing candidate independent validation
```

Multiple exact CPEs, replacement endpoints, or compatible templates block
automatic selection. Deprecated CPE itself cannot be final Ground Truth.

## 5. CPE Validation Result definitions

- **CPE Confirmed**: independently derived GT is canonically equal to Original.
- **Correct CPE Found**: one official Active CPE is independently resolved and
  differs canonically from Original.
- **Version Not Registered**: product/version and Active family are confirmed,
  but the exact compatible version entry is absent; preserve the verified
  version in the Ground Truth expression.
- **NVD Configuration Only**: the family is absent from both Active and
  Deprecated Dictionary rows but has one compatible fixed-snapshot
  Configuration template.
- **No Direct CPE Found**: the product relationship is sufficiently established,
  but the component intentionally does not inherit a parent CPE or has no
  confirmed direct Dictionary/Configuration representation.
- **Unable to Determine**: **the product, version, product boundary, or a unique
  Ground Truth CPE could not be established with sufficient evidence.**

The final definition includes product/version uncertainty and the case where
product/version is confirmed but the compatible Ground Truth CPE expression is
non-unique.

## 6. Uncertainty handling

- Never select the first family row or first Deprecated replacement branch.
- Preserve observed identifiers that cannot be promoted to an upstream version.
- Stop when product, version, boundary, family, endpoint, or template evidence
  is insufficient or non-unique.
- Record the uncertainty cause separately from the CPE Validation Result.
- Keep Unable to Determine distinct from No Direct CPE Found: the former is an
  evidence sufficiency/uniqueness result, while the latter is a product/CPE
  representation result.

## 7. Independent validation procedure

- Scope exactly the 48 CPE-bearing candidates.
- Pass A confirms product/version without Original CPE, firmware CPE-ID, current
  GT, or current result inputs.
- Pass B independently resolves the CPE against the fixed Dictionary snapshot.
- Compare candidate and audited values only after both passes.
- Final evidence: 48 ACCEPTED, 0 corrections, 0 circular risks, 0 Deprecated
  final GT, and 0 canonical parse failures.

Describe this as an independent two-pass review, not as a blinded or inter-rater
study.

## 8. Reproducibility controls

- Pin firmware/SBOM hashes, IDs, snapshots, snapshot hashes, and source revision.
- Use PostgreSQL READ ONLY transactions for candidate/audit database access.
- Hash local evidence artifacts and refuse to overwrite existing output paths.
- Exclude live NVD, current Dictionary, web search, and CVE applicability from
  Ground Truth reproduction.
- Preserve fixed PostgreSQL snapshots and the execution environment.
- Archive/content-hash mutable upstream pages for stronger long-term evidence
  verification.
- Preserve raw extraction inputs/tooling when reproduction from firmware rather
  than from derived hashed evidence is required.

## Final readiness

- Methodological Consistency: `PASS`
- Evidence Traceability: `PASS_WITH_LIMITATION`
- Computational Reproducibility: `PASS_WITH_LIMITATION`
- Blocking issues: `NONE`
- Verdict: `READY_FOR_FINALIZATION`
- Ground Truth DB application readiness: `READY`


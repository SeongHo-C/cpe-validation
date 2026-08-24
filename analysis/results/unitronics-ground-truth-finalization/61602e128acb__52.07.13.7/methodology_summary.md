# Final Ground Truth methodology

## Product-boundary rule

Do not approve a mapping from similar vendor/product labels or CPE-family existence alone. Verify the official upstream product boundary against CPE title/reference/version space and, when needed, fixed-snapshot NVD usage context.

## Reproducible flow

```text
  -> SBOM Component
  -> Exact Firmware Evidence
  -> Actual Software Product / Version
  -> Product / Subcomponent Boundary
  -> Official Upstream Product Boundary
  -> CPE Family Product Boundary Validation
  -> Active Exact CPE
  -> Deprecated -> Active
  -> Version Not Registered
  -> NVD Configuration Only
  -> CPE Validation Result
```

The approved `wireguard-tools` case is encoded as a narrow audited exclusion,
not as a generic semantic matching engine. Its upstream version remains
`1.0.20210223`; only the invalid `wireguard:wireguard` family binding is removed.

## Final audit

- Methodological Consistency: `PASS`
- Evidence Traceability: `PASS_WITH_LIMITATION`
- Computational Reproducibility: `PASS_WITH_LIMITATION`
- Blocking issues: `0`
- Verdict: `READY_FOR_FINALIZATION`

## Non-blocking limitations

- Fifteen official upstream URL references do not have archived content hashes.
- Full raw firmware re-extraction requires the external extraction environment and tooling.
- The core CSV/JSON artifacts reproduce, but complete Human Validation HTML generation from scratch remains partial.
- Long-term reproduction requires preservation of the fixed PostgreSQL snapshots and executable environment.

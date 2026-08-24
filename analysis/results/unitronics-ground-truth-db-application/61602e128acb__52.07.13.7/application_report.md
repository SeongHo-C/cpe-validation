# Unitronics Ground Truth DB Application Report

## Application identity

- Applied at: `2026-08-24T15:43:07.700065+00:00`
- SBOMDocument: `1364`
- Manufacturer/Product/Firmware: `Unitronics / UCR-ST-B8 / 52.07.13.7`
- Firmware SHA-256: `6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c`
- SBOM SHA-256: `61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e`
- CPE Dictionary snapshot: `20260819T035002Z`
- NVD snapshot: `20260820T110357Z`

## Verified source artifacts

- `analysis/results/unitronics-ground-truth-candidate-build/61602e128acb__52.07.13.7/components.csv`: `bf83592d1fd92c2f972a4f178f8ca01fd33cf0944d044e24aeda8b8b438c8ac9`
- `analysis/results/unitronics-ground-truth-candidate-build/61602e128acb__52.07.13.7/summary.json`: `c20ddefa98afe53b423cc1c5846ce8e2471bd3f1f41c3021ff1bee2792275a0a`
- `analysis/results/unitronics-ground-truth-candidate-build/61602e128acb__52.07.13.7/evidence_manifest.csv`: `b94441d0625386e050ca0843bbe016c915cce492cc67da3ec5e9ed64fbb51903`
- `analysis/results/unitronics-ground-truth-cpe-audit/61602e128acb__52.07.13.7/audit_results.csv`: `cc75c750042489183f25c67bea379dbf3556c14c296ce91142d1c9e5d5960593`
- `analysis/results/unitronics-ground-truth-cpe-audit/61602e128acb__52.07.13.7/summary.json`: `50d5f37c63d545f97355bd7436106174e5386fccdd76c7a2889a86b8711d68f1`
- `analysis/results/unitronics-ground-truth-methodology-final-audit/61602e128acb__52.07.13.7/summary.json`: `cee4b1962343685fd3d782e0f052a4525b5edd6a1ccd50cf793129ff6ee3a840`

## Preflight

- Components: `582`
- Target Ground Truth records before apply: `0`
- Global Ground Truth records before apply: `0`
- Original Component fingerprint: `9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e`
- Candidate rows and unique Component IDs: `582 / 582`
- Independent CPE audit: `48 ACCEPTED / 0 CORRECTION_REQUIRED / 0 EVIDENCE_REVIEW_REQUIRED`
- Methodology verdict/readiness/blockers: `READY_FOR_FINALIZATION / READY / 0`

## Applied CPE Validation Results

| Internal code | DB count |
|---|---:|
| `CPE_CONFIRMED` | 2 |
| `OFFICIAL_CPE_MAPPED` | 24 |
| `VERSION_NOT_IN_DICTIONARY` | 22 |
| `NVD_CONFIGURATION_ONLY` | 0 |
| `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` | 529 |
| `UNRESOLVED` | 5 |

## Post-write verification

- Ground Truth records: `582`
- GT CPE present/null: `48 / 534`
- Candidate-to-DB CPE mismatch: `0`
- Candidate-to-DB result mismatch: `0`
- Canonical parse failures: `0`
- Deprecated final GT CPEs: `0`
- Discrepancy Type assignments: `0`
- Correction Type assignments: `0`
- Post-write Component fingerprint: `9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e`
- Original Component mutation: `0`

## wpa_supplicant

- Actual candidate version: `2.11-devel`
- Ground Truth CPE: `cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*`
- CPE Validation Result: `VERSION_NOT_IN_DICTIONARY`

## Safety and final status

- Application used `transaction.atomic()` and an SBOM row lock.
- Any in-transaction validation failure rolls back all Ground Truth inserts.
- Existing Ground Truth records are never overwritten, updated, or deleted.
- Incorrect CPE Fields and Correction Types were intentionally left empty.
- Original Components and fixed snapshot data were not modified.
- Final status: `SUCCESS`

# Unitronics Ground Truth finalization

## Result

**SUCCESS**

- Applied at: `2026-08-24T23:24:49.125986+00:00`
- Transaction: `transaction.atomic()`
- Ground Truth rows changed: `1`
- Component mutations: `0`
- Migration: `0`

## wireguard-tools

| Field | Before | After |
|---|---|---|
| GT CPE | `cpe:2.3:a:wireguard:wireguard:1.0.20210223:*:*:*:*:*:*:*` | `null` |
| Decision | `VERSION_NOT_IN_DICTIONARY` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| Resolution outcome | `MANUAL_FROM_OFFICIAL_FAMILY` | `DIRECT_OFFICIAL_NOT_CONFIRMED` |

Actual product/version: `wireguard-tools 1.0.20210223`.

## Final topology

- Ground Truth records: **582**
- CPE-bearing / null: **39 / 543**
- Distinct canonical CPE / duplicate groups: **39 / 0**
- Deprecated final GT / parse failures: **0 / 0**
- Decisions: `{"CPE_CONFIRMED": 2, "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED": 538, "NVD_CONFIGURATION_ONLY": 0, "OFFICIAL_CPE_MAPPED": 21, "UNRESOLVED": 5, "VERSION_NOT_IN_DICTIONARY": 16}`
- Candidate CPE/Decision mismatches: **0 / 0**

## Final audits

- Product boundary: `{"CHANGE_CPE": 0, "KEEP": 39, "REMOVE_CPE": 0, "REVIEW_REQUIRED": 0}`
- Independent CPE: `{"ACCEPTED": 39, "CORRECTION_REQUIRED": 0, "EVIDENCE_REVIEW_REQUIRED": 0}`
- Version Not Registered satisfying all invariants: **16 / 16**
- Circular evidence risks: **0**
- Methodology verdict / blockers: **READY_FOR_FINALIZATION / 0**

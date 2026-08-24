# Unitronics Ground Truth CPE independent audit

## Scope and independence boundary

- Firmware: Unitronics UCR-ST-B8 `52.07.13.7`
- SBOMDocument: `1364`
- Audited rows: **48 CPE-bearing candidates only**
- CPE Dictionary: `20260819T035002Z`
- NVD snapshot identity check: `20260820T110357Z`
- Unable to Determine rows audited: **0**
- No Direct CPE rows audited: **0**

Pass A received only exact SBOM/firmware package, description, payload, Source,
sibling, detector, and official-evidence references. Original CPE, firmware
control CPE-ID, current GT CPE, and current validation result were introduced
only after Pass B completed.

## Final audit status

| Status | Count |
|---|---:|
| `ACCEPTED` | 48 |
| `CORRECTION_REQUIRED` | 0 |
| `EVIDENCE_REVIEW_REQUIRED` | 0 |

**All 48 candidates are accepted unchanged and can be finalized as-is.**

### By current CPE Validation Result

| Current result | Accepted | Correction required | Evidence review required |
|---|---:|---:|---:|
| CPE Confirmed | 2 | 0 | 0 |
| Correct CPE Found | 24 | 0 | 0 |
| Version Not Registered | 22 | 0 | 0 |

## Pass A — independent product/version audit

| Pass A status | Count |
|---|---:|
| `PRODUCT_VERSION_CONFIRMED` | 48 |
| `PRODUCT_CORRECTION_REQUIRED` | 0 |
| `VERSION_CORRECTION_REQUIRED` | 0 |
| `EVIDENCE_INSUFFICIENT` | 0 |

- Product corrections: **0**
- Version corrections: **0**
- Circular evidence risks: **0**

## Pass B — independent CPE audit

| Resolution | Count |
|---|---:|
| `ACTIVE_EXACT` | 26 |
| `DEPRECATED_TO_ACTIVE` | 0 |
| `VERSION_NOT_IN_DICTIONARY` | 22 |

- GT CPE corrections: **0**
- CPE Validation Result corrections: **0**
- Discrepancy-field corrections: **0**
- Final Deprecated GT: **0**

The two current **CPE Confirmed** rows (Linux kernel and SQLite) are independently
verified: exact-firmware product/version evidence exists, each Original CPE is
Active in the fixed Dictionary, and each is canonically equal to the independently
derived GT CPE.

All **22** current **Version Not Registered** rows satisfy the required
conditions unchanged. In particular, `wpa_supplicant` preserves the exact firmware
product version `2.11-devel`, while its approved CPE expression represents the
release state as `version=2.11`, `update=devel`. The fixed family has comparable
Active prerelease rows with explicit `update=preN` values.

## Correction required

| Component | Current version | Audited version | Current GT CPE | Audited GT CPE | Reason |
|---|---|---|---|---|---|
| None | — | — | — | — | — |

The approved `wpa_supplicant` expression is **Version Not Registered**: the fixed
Dictionary contains the `a:w1.fi:wpa_supplicant` Active family, has no exact
`version=2.11`, `update=devel` entry, and supports release-state modeling in the
`update` attribute.

## Required representative checks

- **OpenSSL** — ACCEPTED: libopenssl3 and openssl-util independently resolve to Active exact OpenSSL 3.0.14.
- **curl / libcurl** — ACCEPTED: curl resolves Active exact 8.11.0; libcurl 8.11.0 is preserved as Version Not Registered in the distinct haxx:libcurl family.
- **iptables / ip6tables** — ACCEPTED: both payloads belong to iptables 1.8.7; the Active family exists, exact version is absent, and the generic '*' template is supported.
- **strongSwan** — ACCEPTED: strongswan, charon, and swanctl independently identify 5.9.14; exact Active is absent and 5.9.x final-release history supports update='-'.
- **e2fsprogs** — ACCEPTED: exact utilities and official 1.47.0 release evidence agree; family exists and exact Active version is absent.
- **Linux kernel** — ACCEPTED: exact Linux 5.15.176 banner and module tree independently support the Active exact CPE and canonical equality with Original.
- **Lua** — ACCEPTED: library and interpreter identify final patch release 5.1.5; family patch-release history supports update='*'.
- **musl** — ACCEPTED: exact musl loader/libc payload and version 1.2.4 agree; generic '*' template is applicable to the MIPS firmware rather than x86-specific entries.
- **wpa_supplicant** — ACCEPTED: exact firmware preserves 2.11-devel; the approved CPE expression uses version=2.11 and update=devel, supported by prerelease-update rows in the fixed family.

## Evidence sufficiency

| Strength | Count |
|---|---:|
| `STRONG` | 27 |
| `MODERATE` | 21 |
| `WEAK` | 0 |

No audited row is classified `EVIDENCE_REVIEW_REQUIRED`. Moderate rows have
sufficient exact package/source/payload evidence for acceptance but less direct
component-specific upstream documentation than Strong rows.

## Validation and safety

- Audit rows: `48` — PASS
- Unique Component IDs: `48` — PASS
- Current distribution: `2 + 24 + 22 = 48` — PASS
- Audited GT canonical parse failures: `0` — PASS
- Final Deprecated GT: `0` — PASS
- Candidate source artifacts unchanged: `True` — PASS
- Ground Truth DB: `0 -> 0` — PASS
- DB mutation, migration, Configuration lookup, CVE applicability: `0` — PASS
- Unable to Determine artifact reads/audits: `0` — PASS

This audit does not persist a Ground Truth record.

# Unitronics representative Ground Truth application

## Applied scope

- Applied at: `2026-08-24T21:22:12.777785+00:00`
- Candidate: `analysis/results/unitronics-ground-truth-candidate-build/61602e128acb__52.07.13.7/components.csv`
- Candidate SHA-256: `dbc3f7b149fcc0830b223529985e2326786064f92382d013d4dcd13bd0d6ee9b`
- Approved records updated: **8**
- Transaction: `transaction.atomic()`
- Record deletion/recreation: **0**

Updated Components: `ip6tables, libcap-bin, libipset13, liblua5.1.5, libsqlite3-0, openssl-util, strongswan-charon, strongswan-swanctl`

## Before and after

- Ground Truth records: `582 -> 582`
- CPE present: `48 -> 40`
- CPE null: `534 -> 542`
- Component fingerprint: `9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e -> 9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e`
- Ground Truth fingerprint: `cd40eeba9c88161d521c22d0fb6a16114dedec658efac57e82ddfa34409c9ef1 -> 9157dec9eaaa26f963d87a501a4d44c015e6adfef31f6d2c825b4187a35478cd`

## Final Decision distribution

| Internal code | Count |
|---|---:|
| `CPE_CONFIRMED` | 2 |
| `OFFICIAL_CPE_MAPPED` | 21 |
| `VERSION_NOT_IN_DICTIONARY` | 17 |
| `NVD_CONFIGURATION_ONLY` | 0 |
| `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` | 537 |
| `UNRESOLVED` | 5 |

No reason/taxonomy field was added. Each target's dictionary FK and manual CPE
expression were cleared, and its Decision was set to
`DIRECT_OFFICIAL_CPE_NOT_CONFIRMED`. Existing notes and M2M values were not used
to store a new policy code.

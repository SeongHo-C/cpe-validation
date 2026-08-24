# Unitronics representative Ground Truth final audit

## Final dataset

- Ground Truth records: **582**
- CPE-bearing Components: **40**
- GT CPE null: **542**
- Distinct canonical GT CPE: **40**
- Duplicate canonical GT CPE groups: **0**
- Components in duplicate groups: **0**
- Canonical parse failures: **0**
- Deprecated final GT: **0**

## Removed derived splits

| Component | GT CPE | Decision |
|---|---|---|
| `ip6tables` | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| `libcap-bin` | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| `libipset13` | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| `liblua5.1.5` | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| `libsqlite3-0` | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| `openssl-util` | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| `strongswan-charon` | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| `strongswan-swanctl` | `null` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |

## Retained representatives

| Component | GT CPE | Decision |
|---|---|---|
| `ipset` | `cpe:2.3:a:netfilter:ipset:7.6:*:*:*:*:*:*:*` | `VERSION_NOT_IN_DICTIONARY` |
| `iptables` | `cpe:2.3:a:netfilter:iptables:1.8.7:*:*:*:*:*:*:*` | `VERSION_NOT_IN_DICTIONARY` |
| `libcap` | `cpe:2.3:a:libcap_project:libcap:2.69:*:*:*:*:*:*:*` | `OFFICIAL_CPE_MAPPED` |
| `libopenssl3` | `cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*` | `OFFICIAL_CPE_MAPPED` |
| `lua` | `cpe:2.3:a:lua:lua:5.1.5:*:*:*:*:*:*:*` | `VERSION_NOT_IN_DICTIONARY` |
| `sqlite` | `cpe:2.3:a:sqlite:sqlite:3.41.2:*:*:*:*:*:*:*` | `CPE_CONFIRMED` |
| `strongswan` | `cpe:2.3:a:strongswan:strongswan:5.9.14:-:*:*:*:*:*:*` | `VERSION_NOT_IN_DICTIONARY` |

## Independent-product regression

| Component | GT CPE | Decision |
|---|---|---|
| `curl` | `cpe:2.3:a:haxx:curl:8.11.0:*:*:*:*:*:*:*` | `OFFICIAL_CPE_MAPPED` |
| `libcurl4` | `cpe:2.3:a:haxx:libcurl:8.11.0:*:*:*:*:*:*:*` | `VERSION_NOT_IN_DICTIONARY` |

## Independent CPE audit

- `ACCEPTED`: **40**
- `CORRECTION_REQUIRED`: **0**
- `EVIDENCE_REVIEW_REQUIRED`: **0**
- Final Deprecated GT: **0**

## Integrity

- Candidate-to-DB CPE mismatch: **0**
- Candidate-to-DB Decision mismatch: **0**
- Component mutation: **0**
- Non-target Ground Truth mutation: **0**
- Discrepancy Type assignments: **0**
- Correction Type assignments: **0**

## Regression validation

- `sboms` tests: **270 passed**
- Django system check: **PASS**
- Migration dry-run check: **No changes detected**

The test suite was run with `CPE_DICTIONARY_SNAPSHOT_ID` unset so each isolated
test database selected the sole complete snapshot created by its fixture.

The final topology audit is a rerun over the 40 current CPE-bearing records; it
does not alter the historical duplicate audit or OpenSSL representative audit.
The approved methodology is: one representative Component per upstream
product/version for distribution-specific splits, without parent-CPE inheritance
to derived splits; independently identifiable CPE products remain separate.

**Unitronics representative Ground Truth finalization: SUCCESS**

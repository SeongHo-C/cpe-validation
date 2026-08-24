# Unitronics Ground Truth Duplicate CPE Audit

## Audit scope and result

This is a read-only cross-component audit of the 48 CPE-bearing Ground Truth
records for SBOMDocument `1364`. Original SBOM CPE and firmware control CPE-ID
were excluded from product-boundary reasoning. Existing candidate/audit results
were used for identity and provenance, but their prior `ACCEPTED` status was not
treated as an answer to cross-component duplication.

| Metric | Count |
|---|---:|
| CPE-bearing Ground Truth Components | 48 |
| Distinct canonical GT CPEs | 40 |
| Unique GT CPE groups | 33 |
| Duplicated GT CPE groups | 7 |
| Components in duplicate groups | 15 |
| Semantic near-duplicate groups | 0 |

Duplicate group status:

- `KEEP_SINGLE_REPRESENTATIVE`: 6
- `KEEP_MULTIPLE`: 0
- `REPRESENTATIVE_AMBIGUOUS`: 1
- `DATA_INCONSISTENCY`: 0

Component recommendations across all 48 records:

- `KEEP_GT_CPE`: 39
- `REMOVE_DUPLICATED_GT_CPE`: 7
- `REVIEW_REQUIRED`: 2

## Duplicate group evidence and recommendations

### DUP-01 — `cpe:2.3:a:libcap_project:libcap:2.69:*:*:*:*:*:*:*`

- Status: `KEEP_SINGLE_REPRESENTATIVE`
- Q1 — Same Source/upstream: YES: both packages are version 2.69-1 from package/libs/libcap and identify upstream libcap 2.69.
- Q2 — Product boundary: libcap owns the core libcap shared library; libcap-bin is an explicit utility split containing setcap/getcap/getpcaps/capsh.
- Q3 — Representative: libcap aligns with the upstream product name and provides libcap.so.2.69; libcap-bin depends on libcap.
- Q4 — Derived packages: libcap-bin: utility/CLI split
- Q5 — Independent CPE product: NO: no evidence identifies libcap-bin as a separate CPE product.
- Evidence: Exact control/list evidence gives libcap three library paths and libcap-bin four utility executables; Source and normalized version are identical.

| ID | Component | Package role | Current result | Recommendation | Recommended result |
|---:|---|---|---|---|---|
| 199846 | `libcap-bin` | `UTILITY_OR_CLI_PACKAGE` | `OFFICIAL_CPE_MAPPED` | `REMOVE_DUPLICATED_GT_CPE` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| 199848 | `libcap` | `LIBRARY_PACKAGE` | `OFFICIAL_CPE_MAPPED` | `KEEP_GT_CPE` | `OFFICIAL_CPE_MAPPED` |
### DUP-02 — `cpe:2.3:a:lua:lua:5.1.5:*:*:*:*:*:*:*`

- Status: `KEEP_SINGLE_REPRESENTATIVE`
- Q1 — Same Source/upstream: YES: both packages are version 5.1.5-9 from package/utils/lua and identify upstream Lua 5.1.5.
- Q2 — Product boundary: lua is the upstream-name-aligned language interpreter package; liblua5.1.5 is the shared-library split used by other programs.
- Q3 — Representative: lua owns /usr/bin/lua and /usr/bin/lua5.1, is name-aligned, and depends on liblua5.1.5.
- Q4 — Derived packages: liblua5.1.5: library split
- Q5 — Independent CPE product: NO: the fixed Dictionary evidence identifies Lua, not a separate liblua5.1.5 CPE product.
- Evidence: Exact control/list evidence distinguishes the interpreter package from its one-file shared-library dependency.

| ID | Component | Package role | Current result | Recommendation | Recommended result |
|---:|---|---|---|---|---|
| 199870 | `liblua5.1.5` | `LIBRARY_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `REMOVE_DUPLICATED_GT_CPE` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| 199920 | `lua` | `UTILITY_OR_CLI_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `KEEP_GT_CPE` | `VERSION_NOT_IN_DICTIONARY` |
### DUP-03 — `cpe:2.3:a:netfilter:ipset:7.6:*:*:*:*:*:*:*`

- Status: `KEEP_SINGLE_REPRESENTATIVE`
- Q1 — Same Source/upstream: YES: both packages are version 7.6-1 from package/network/utils/ipset and identify upstream ipset 7.6.
- Q2 — Product boundary: ipset is the name-aligned administration utility; libipset13 is the shared-library split.
- Q3 — Representative: ipset owns /usr/sbin/ipset and depends on libipset13; its name and payload directly represent the CPE product.
- Q4 — Derived packages: libipset13: library split
- Q5 — Independent CPE product: NO: no separate libipset13 CPE product was established.
- Evidence: The package pair consists of one canonical executable and two libipset.so paths from the same Source/version.

| ID | Component | Package role | Current result | Recommendation | Recommended result |
|---:|---|---|---|---|---|
| 199686 | `ipset` | `UTILITY_OR_CLI_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `KEEP_GT_CPE` | `VERSION_NOT_IN_DICTIONARY` |
| 199862 | `libipset13` | `LIBRARY_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `REMOVE_DUPLICATED_GT_CPE` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
### DUP-04 — `cpe:2.3:a:netfilter:iptables:1.8.7:*:*:*:*:*:*:*`

- Status: `KEEP_SINGLE_REPRESENTATIVE`
- Q1 — Same Source/upstream: YES: both packages are version 1.8.7-3 from package/network/utils/iptables and identify upstream iptables 1.8.7.
- Q2 — Product boundary: iptables is the name-aligned primary firewall administration package; ip6tables is the IPv6 utility split and depends on iptables.
- Q3 — Representative: iptables owns the canonical iptables/xtables executables and is the Source-name-aligned package.
- Q4 — Derived packages: ip6tables: IPv6 utility/CLI split
- Q5 — Independent CPE product: NO: the exact CPE product is iptables and no independent ip6tables CPE product was established.
- Evidence: Exact lists separate iptables executables from ip6tables executables; dependency and naming identify the latter as a split.

| ID | Component | Package role | Current result | Recommendation | Recommended result |
|---:|---|---|---|---|---|
| 199684 | `ip6tables` | `UTILITY_OR_CLI_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `REMOVE_DUPLICATED_GT_CPE` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| 199690 | `iptables` | `UTILITY_OR_CLI_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `KEEP_GT_CPE` | `VERSION_NOT_IN_DICTIONARY` |
### DUP-05 — `cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*`

- Status: `REPRESENTATIVE_AMBIGUOUS`
- Q1 — Same Source/upstream: YES: both packages are version 3.0.14-3 from package/libs/openssl and identify upstream OpenSSL 3.0.14.
- Q2 — Product boundary: libopenssl3 contains the core libssl/libcrypto runtime while openssl-util contains the canonical /usr/bin/openssl CLI; no installed package named openssl represents both halves.
- Q3 — Representative: AMBIGUOUS: the core shared libraries and canonical executable are both central upstream product payloads, and neither package alone represents the complete toolkit.
- Q4 — Derived packages: libopenssl3: core library split; openssl-util: canonical CLI split
- Q5 — Independent CPE product: NO separate CPE products were established, but evidence is insufficient to choose one representative component.
- Evidence: Exact lists show libssl.so.3/libcrypto.so.3 versus /usr/bin/openssl. openssl-util depends on libopenssl3; both are classified as partial splits and there is no main package.

| ID | Component | Package role | Current result | Recommendation | Recommended result |
|---:|---|---|---|---|---|
| 199888 | `libopenssl3` | `LIBRARY_PACKAGE` | `OFFICIAL_CPE_MAPPED` | `REVIEW_REQUIRED` | `OFFICIAL_CPE_MAPPED` |
| 199958 | `openssl-util` | `UTILITY_OR_CLI_PACKAGE` | `OFFICIAL_CPE_MAPPED` | `REVIEW_REQUIRED` | `OFFICIAL_CPE_MAPPED` |
### DUP-06 — `cpe:2.3:a:sqlite:sqlite:3.41.2:*:*:*:*:*:*:*`

- Status: `KEEP_SINGLE_REPRESENTATIVE`
- Q1 — Same Source/upstream: PARTIAL: both identify SQLite 3.41.2, but sqlite is a direct non-opkg artifact while libsqlite3-0 is the owning opkg package.
- Q2 — Product boundary: Both components point to the same physical core payload, /usr/lib/libsqlite3.so.0.8.6; libsqlite3-0 is the distribution library package and sqlite is the upstream-product-aligned direct artifact.
- Q3 — Representative: sqlite directly names the upstream product and was independently identified from the exact shared-library artifact; retaining both would double count the same file/product instance.
- Q4 — Derived packages: libsqlite3-0: distribution library package
- Q5 — Independent CPE product: NO: both mappings resolve to the exact sqlite:sqlite CPE and the same installed library file.
- Evidence: The libsqlite3-0 .list owns libsqlite3.so.0.8.6, which is the exact source_path used by the non-opkg sqlite detector component.

| ID | Component | Package role | Current result | Recommendation | Recommended result |
|---:|---|---|---|---|---|
| 199896 | `libsqlite3-0` | `LIBRARY_PACKAGE` | `OFFICIAL_CPE_MAPPED` | `REMOVE_DUPLICATED_GT_CPE` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| 200196 | `sqlite` | `LIBRARY_PACKAGE` | `CPE_CONFIRMED` | `KEEP_GT_CPE` | `CPE_CONFIRMED` |
### DUP-07 — `cpe:2.3:a:strongswan:strongswan:5.9.14:-:*:*:*:*:*:*`

- Status: `KEEP_SINGLE_REPRESENTATIVE`
- Q1 — Same Source/upstream: YES: all three packages are version 5.9.14-24 from package/network/services/strongswan and identify strongSwan 5.9.14.
- Q2 — Product boundary: strongswan is the Source-name-aligned main package with core libstrongswan libraries/configuration; strongswan-charon is a split daemon runtime and strongswan-swanctl is a CLI split.
- Q3 — Representative: strongswan is explicitly classified PRODUCT_OR_MAIN_PACKAGE and DIRECT_PRODUCT_CANDIDATE; both duplicate siblings depend on it.
- Q4 — Derived packages: strongswan-charon: split runtime/daemon; strongswan-swanctl: utility/CLI split
- Q5 — Independent CPE product: NO: neither charon nor swanctl was established as a separate CPE product in the fixed evidence.
- Evidence: The 28-package Source has one main package, one split runtime, one CLI split, and plugin modules; exact dependencies point back to strongswan.

| ID | Component | Package role | Current result | Recommendation | Recommended result |
|---:|---|---|---|---|---|
| 199996 | `strongswan-charon` | `SPLIT_RUNTIME_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `REMOVE_DUPLICATED_GT_CPE` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| 200022 | `strongswan-swanctl` | `UTILITY_OR_CLI_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `REMOVE_DUPLICATED_GT_CPE` | `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` |
| 200023 | `strongswan` | `PRODUCT_OR_MAIN_PACKAGE` | `VERSION_NOT_IN_DICTIONARY` | `KEEP_GT_CPE` | `VERSION_NOT_IN_DICTIONARY` |

## Required comparison cases

### libcap / libcap-bin

Keep the GT CPE on `libcap`; recommend removing it from `libcap-bin`. The latter
is an explicit utilities split, depends on `libcap`, and has no independently
identified CPE product. The proposed post-change result for `libcap-bin` is
`DIRECT_OFFICIAL_CPE_NOT_CONFIRMED` with no GT CPE.

### OpenSSL

`libopenssl3` and `openssl-util` are an exact duplicate group, but no single
installed package represents both the core libraries and canonical CLI. Both
remain `REVIEW_REQUIRED`; this audit does not recommend a DB change for either.

### strongSwan

Keep `strongswan`, the Source-name-aligned main package. Recommend removing the
duplicate mapping from `strongswan-charon` (split daemon runtime) and
`strongswan-swanctl` (CLI split), both of which depend on the main package.

### curl / libcurl and e2fsprogs

`curl` and `libcurl4` are not duplicate or semantic near-duplicate groups: they
map to independently named CPE products `curl` and `libcurl`. `e2fsprogs` is the
only CPE-bearing member of its Source family; `libext2fs2` did not inherit its
parent CPE. No duplicate recommendation is created for these cases.

## Projected effect (recommendation only)

- Current CPE-bearing Components: 48
- Projected CPE-bearing Components: 41
- Projected distinct canonical GT CPEs: 40
- Projected removed duplicate mappings: 7
- Projected remaining duplicate groups: 1 (OpenSSL, pending review)
- Clear representative Components: `libcap` (DUP-01), `lua` (DUP-02), `ipset` (DUP-03), `iptables` (DUP-04), `sqlite` (DUP-06), `strongswan` (DUP-07)

## Methodology conclusion

The evidence supports adding the once-per-upstream-product/version rule to the
Ground Truth methodology, with an explicit evidence gate. Exact duplicate CPEs
must not be removed mechanically: the audit must first establish package/product
boundaries, preserve independently identifiable CPE products, and use
`REVIEW_REQUIRED` when no unique representative exists.

Recommended rule:

> A Ground Truth CPE is assigned once per upstream product/version within a
> firmware SBOM. When the same upstream product is represented by multiple
> distribution-specific split packages, the CPE is retained only on the
> component that most directly represents the upstream product. Derived split
> packages do not inherit the same CPE unless they correspond to an independently
> identifiable CPE product.

## Read-only validation

- Canonical parse failures: `0`
- Candidate-to-DB CPE/result mismatches: `0 / 0`
- Component fingerprint before/after: `9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e` / `9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e`
- Ground Truth fingerprint before/after: `cd40eeba9c88161d521c22d0fb6a16114dedec658efac57e82ddfa34409c9ef1` / `cd40eeba9c88161d521c22d0fb6a16114dedec658efac57e82ddfa34409c9ef1`
- Original Component mutations: `0`
- Ground Truth DB mutations: `0`
- Candidate/audit artifact modifications: `0 / 0`
- Migration: `0`

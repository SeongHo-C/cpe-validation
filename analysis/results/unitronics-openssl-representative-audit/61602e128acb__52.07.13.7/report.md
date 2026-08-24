# OpenSSL Representative Component Audit

## Conclusion

**Final choice: A — `libopenssl3` is the representative Component for OpenSSL 3.0.14.**

`libopenssl3` contains the exact firmware's OpenSSL core runtime implementation (`libcrypto.so.3` and `libssl.so.3`). `openssl-util` contains only the canonical `/usr/bin/openssl` command-line application and has a declared dependency on `libopenssl3` (as well as the configuration and legacy-provider splits). This makes the library package the non-arbitrary representative under the prescribed priority: core implementation, official architecture, payload, dependency, executable, then naming.

This is a read-only recommendation. No Ground Truth, database row, candidate artifact, prior duplicate-audit artifact, migration, or source SBOM field was changed.

## 1. Exact firmware package structure

Dataset: Unitronics UCR-ST-B8 firmware `52.07.13.7`, SBOM document `1364` (`61602e128acb`), CPE Dictionary snapshot `20260819T035002Z`.

The extraction path recorded by the prior evidence (`/logs/firmware/binwalk_extracted/firmware.extracted/260000/squashfs-root`) is not mounted in this session, so the raw `.control`, `.list`, and `status` files could not be reopened. The audit therefore revalidated the immutable exact-firmware-derived package table before use:

- Artifact: `analysis/results/unitronics-source-package-analysis/61602e128acb__52.07.13.7/packages.csv`
- SHA-256: `30e016f31ea84dc0189af4f43b30996c692a7af44e53efc8e83ca3c3a812c050`
- It records each package's parsed `.control`, full `.list` payload, and version/architecture agreement with `status`.

This access limitation affects re-opening the raw files, not the identity or contents of the hash-verified derived evidence. No firmware re-extraction was performed.

| Field | `libopenssl3` | `openssl-util` |
|---|---|---|
| Component ID | `199888` | `199958` |
| Package | `libopenssl3` | `openssl-util` |
| Version | `3.0.14-3` | `3.0.14-3` |
| Source | `package/libs/openssl` | `package/libs/openssl` |
| SourceName | `libopenssl` | `openssl-util` |
| Section | `libs` | `utils` |
| Description boundary | OpenSSL shared libraries needed by other programs | OpenSSL command-line utility |
| Depends | `libc, libatomic1` | `libc, libopenssl3, libopenssl-conf, libopenssl-legacy` |
| Control | `/usr/lib/opkg/info/libopenssl3.control` | `/usr/lib/opkg/info/openssl-util.control` |
| List | `/usr/lib/opkg/info/libopenssl3.list` | `/usr/lib/opkg/info/openssl-util.list` |
| Status check | version and architecture match | version and architecture match |

The source is split into four installed packages:

| Package | Exact payload | Role |
|---|---|---|
| `libopenssl3` | `/usr/lib/libcrypto.so.3`; `/usr/lib/libssl.so.3` | Core shared libraries |
| `libopenssl-conf` | `/etc/config/openssl`; `/etc/ssl/openssl.cnf`; `/etc/init.d/openssl` | Configuration/helper split; depends on `libopenssl3` |
| `libopenssl-legacy` | `/usr/lib/ossl-modules/legacy.so`; `/etc/ssl/modules.cnf.d/legacy.cnf` | Legacy provider module; depends on `libopenssl3` and `libopenssl-conf` |
| `openssl-util` | `/usr/bin/openssl` | Command-line utility; depends on all three splits above |

All listed paths were recorded as existing regular files, with zero missing listed paths.

## 2. `libopenssl3` payload and dependency role

The complete package payload is:

```text
/usr/lib/libssl.so.3
/usr/lib/libcrypto.so.3
```

There are two library files and no executable. The package description explicitly says these shared libraries are needed by other programs, and the exact installed-package metadata confirms this role:

- 20 installed packages directly declare `libopenssl3` in `Depends`.
- 17 of those are outside the four-package OpenSSL split.
- Examples include `libcurl4`, `openvpn-openssl`, `strongswan-mod-openssl`, `wpad-openssl`, `libustream-openssl20201210`, and `open62541`.

Thus the firmware can use OpenSSL cryptographic/TLS runtime functionality through these libraries without invoking the CLI. Removing `libopenssl3` would leave those declared dependencies—and `openssl-util` itself—unsatisfied. This is a package-dependency observation; no unrecorded ELF linkage is asserted.

## 3. `openssl-util` payload and dependency role

The complete package payload is:

```text
/usr/bin/openssl
```

There is one executable and no library, provider, or configuration file. The package is the canonical user-facing OpenSSL CLI, but its own declared dependency is:

```text
openssl-util
  -> libopenssl3
  -> libopenssl-conf
  -> libopenssl-legacy
```

Only one installed package (`lua_crypto`) directly declares `openssl-util`; that package also directly declares `libopenssl3`. The exact payload contains no independent cryptographic implementation. Combined with the official architecture below, the evidence identifies `openssl-util` as a client/utility over the core libraries, not as the implementation foundation.

## 4. Official OpenSSL architecture evidence

Only official OpenSSL documentation and the official OpenSSL repository were used:

- [`crypto(7)` for OpenSSL 3.0](https://docs.openssl.org/3.0/man7/crypto/) defines `libcrypto` as the library implementing a wide range of cryptographic algorithms. It says OpenSSL TLS/CMS and third-party products use its services. It also places the built-in default and base providers in `libcrypto`.
- [`ssl(7)` for OpenSSL 3.0](https://docs.openssl.org/3.0/man7/ssl/) defines the OpenSSL SSL library as the implementation of SSL, TLS, and DTLS protocols and exposes its runtime API.
- [`openssl(1)` for OpenSSL 3.0](https://docs.openssl.org/3.0/man1/openssl/) defines `openssl` as the command-line program for using OpenSSL crypto-library functions from the shell. It is canonical, but it is a consumer-facing application rather than the library implementation itself.
- [`provider(7)` for OpenSSL 3.0](https://docs.openssl.org/3.0/man7/provider/) defines a provider as code supplying algorithm-operation implementations to the OpenSSL libraries; providers may be built in or dynamically loaded.
- [`config(5)` for OpenSSL 3.0](https://docs.openssl.org/3.0/man5/config/) shows that configuration can load/activate providers and set SSL/TLS configuration, supporting the distinct configuration/provider package roles seen in the firmware.
- [OpenSSL 3.0.14 `INSTALL.md`](https://github.com/openssl/openssl/blob/openssl-3.0.14/INSTALL.md) states that a build produces the OpenSSL libraries (`libcrypto`, `libssl`) and the OpenSSL binary (`openssl`), and installs the binary under `bin` and libraries under `lib`.
- The exact [OpenSSL 3.0.14 `apps/build.info`](https://github.com/openssl/openssl/blob/openssl-3.0.14/apps/build.info) declares the `openssl` program's build dependency on `libssl`; the exact [top-level `build.info`](https://github.com/openssl/openssl/blob/openssl-3.0.14/build.info) declares `libssl`'s dependency on `libcrypto`. This official build chain independently agrees with the firmware package direction.

The official product distribution therefore includes libraries, the CLI, providers, and configuration. The firmware SBOM/package granularity is finer than the upstream `openssl:openssl` CPE product granularity.

## 5. Product-boundary comparison

| Criterion | `libopenssl3` | `openssl-util` |
|---|---|---|
| Direct relation to upstream product | Same source/version; library split | Same source/version; utility split |
| Core runtime implementation | **Yes:** `libcrypto.so.3`, `libssl.so.3` | **No:** no library/provider payload |
| Canonical executable | No | **Yes:** `/usr/bin/openssl` |
| Dependency target | **20** installed packages; 17 outside OpenSSL siblings | 1 installed package; it also depends on `libopenssl3` |
| Pairwise dependency | Does not depend on `openssl-util` | **Depends on `libopenssl3`** |
| Independent use in firmware | Libraries are directly consumed by other packages without the CLI | Declared package dependencies require the libraries/config/provider |
| Foundation for product functions | **Yes:** crypto and TLS implementations | Uses/exposes those functions at the command line |
| Utility/client character | No | **Yes** |
| Representative suitability under the stated priority | **Selected** | Not selected |

Neither split alone is the entire upstream OpenSSL distribution. Nevertheless, choosing `libopenssl3` is not arbitrary: it owns both officially defined implementation libraries, is the dependency foundation for the CLI and many other installed packages, and remains useful without the CLI. The CLI's canonical name is real evidence, but executable presence and naming rank below core implementation and dependency in the required policy.

Original SBOM CPE and firmware `CPE-ID` values were explicitly excluded from this representative decision.

## 6. Final recommendation

```text
Choice: A — libopenssl3 representative

libopenssl3
  keep: cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*
  keep validation result: OFFICIAL_CPE_MAPPED

openssl-util
  recommend removing duplicated GT CPE
  recommend validation result: DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
  UI meaning: No Direct CPE Found
```

The recommendation does not deny that `/usr/bin/openssl` is an authentic OpenSSL artifact. It says that a distribution-specific utility split should not receive a second copy of the same upstream product/version CPE when the selected research representation is one CPE-bearing Component per upstream product/version.

## 7. Recommendation reason

`libopenssl3` most directly implements the identity represented by `cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*` under the audit's fixed ordering:

1. It contains the core cryptographic and TLS implementation libraries.
2. Official OpenSSL architecture defines those libraries as implementations, while defining `openssl` as a command-line program using library functions.
3. Exact firmware payload and dependency metadata match that architecture.
4. `openssl-util` depends on `libopenssl3`; the reverse is not true.
5. The CLI's canonical executable and closer package naming do not override the stronger evidence.

This resolves the previous `REPRESENTATIVE_AMBIGUOUS` finding for duplicate group `DUP-05` without changing the prior audit artifact.

## 8. Expected Ground Truth effect if separately applied

No change was applied in this audit. If the recommendation is later applied:

- OpenSSL CPE-bearing Components: 2 -> 1.
- Whole-dataset CPE-bearing Components: 48 -> 47 when applying only this OpenSSL recommendation.
- When combined with the seven removal recommendations already present in the prior duplicate audit: 48 -> 40 CPE-bearing Components, 40 distinct canonical GT CPEs, and 0 remaining duplicate groups.
- Ground Truth record count remains 582; `openssl-util` remains a reviewed Ground Truth record, but without a direct GT CPE.

This is consistent with the proposed “one representative CPE per upstream product/version” rule and its RQ1/RQ2 purpose of avoiding repeated counting of one upstream product caused solely by distribution split-package granularity. It does not establish a general automatic deletion rule: independent CPE products and cases without an objectively preferred representative still require separate evidence.

## Read-only validation

- Database before/after component count: `582` / `582`
- Database before/after Ground Truth count: `582` / `582`
- Database before/after CPE-bearing count: `48` / `48`
- Component fingerprint before/after: `9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e` / `9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e`
- Ground Truth fingerprint before/after: `cd40eeba9c88161d521c22d0fb6a16114dedec658efac57e82ddfa34409c9ef1` / `cd40eeba9c88161d521c22d0fb6a16114dedec658efac57e82ddfa34409c9ef1`
- Prior duplicate-audit `summary.json` SHA-256 before/after: `5282a67b777ca8050a304e3447d881195895111f967cc97bf639022bab08bc6f` / `5282a67b777ca8050a304e3447d881195895111f967cc97bf639022bab08bc6f`
- Candidate `components.csv` SHA-256 before/after: `bf83592d1fd92c2f972a4f178f8ca01fd33cf0944d044e24aeda8b8b438c8ac9` / `bf83592d1fd92c2f972a4f178f8ca01fd33cf0944d044e24aeda8b8b438c8ac9`
- Migration count: `0`
- Commit count: `0`

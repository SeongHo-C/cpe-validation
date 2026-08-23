# Version Normalization Rulebook v1 — representative dry-run

## Scope

This report applies `rulebook.md` to 21 representatives from Unitronics
UCR-ST-B8 firmware `52.07.13.7`. It does not normalize all 582 components and
does not query or write CPE, NVD Configuration, CVE, Ground Truth CPE, Ground
Truth Decision, Component, or database data.

Existing artifacts were used read-only. Original SBOM CPE and installed control
`CPE-ID` were not used. Version outcomes were established before and without a
CPE Dictionary.

## Dataset and evidence boundary

- SBOMDocument: `1364`
- SBOM SHA-256 prefix: `61602e128acb`
- SBOM components: `582`
- installed opkg packages: `575`
- direct non-opkg artifacts: `7`
- representative cases: `21`
  - conventional release/runtime cases: `10`
  - date/git snapshot cases: `5`
  - vendor-specific cases: `5`
  - composite non-product control: `1`
- exact opkg representatives: `20`; all match SBOM/control/status version and
  status architecture
- direct artifact representatives: `1` (`linux_kernel`)

The exact SDK/GPL and package Makefiles for this firmware remain unavailable.
Official OpenWrt packaging policy is used to interpret package-version layers,
but no current or other-vendor Makefile is treated as exact firmware evidence.

## Overall normalization result

| Normalization status | Count | Percent of 21 |
|---|---:|---:|
| `EXACT_PRODUCT_VERSION` | 1 | 4.76% |
| `PACKAGE_RELEASE_REMOVED` | 9 | 42.86% |
| `SOURCE_VERSION_DERIVED` | 0 | 0.00% |
| `DATE_OR_GIT_VERSION` | 5 | 23.81% |
| `VENDOR_SPECIFIC_VERSION` | 5 | 23.81% |
| `NO_PRODUCT_VERSION` | 1 | 4.76% |
| `REVIEW_REQUIRED` | 0 | 0.00% |
| Total | 21 | 100.00% |

- Non-null `normalized_product_version`: `14`
- Null normalized value, observed candidate preserved: `7`
- Conventional release cases with package release removed: `9`
- Date/git cases with only a separately proven package revision removed: `4`
- Total records where a package revision was removed: `13`
- Evidence strength: `15 STRONG`, `6 MODERATE`, `0 WEAK`

The status counts describe this selected set only and must not be extrapolated to
the full dataset.

## PRODUCT_RUNTIME relationship

| Runtime status | Count | Version handling |
|---|---:|---|
| `PRODUCT_RUNTIME` | 14 | active normalization |
| `NON_PRODUCT_RUNTIME` | 2 | one syntax-only snapshot control; one no-product kmod control |
| `REVIEW_REQUIRED` | 5 | vendor form classified provisionally; normalized value remains null |

Ten runtime decisions were carried forward unchanged from PRODUCT_RUNTIME v1.
The remaining eleven cases are a deliberately limited application of that
rulebook for required date/git/vendor/edge coverage, not a 582-component runtime
classification.

## A. OpenSSL

| Package | Observed | Official upstream | Status | Normalized |
|---|---|---|---|---|
| `libopenssl3` | `3.0.14-3` | `3.0.14` | `PACKAGE_RELEASE_REMOVED` | `3.0.14` |
| `openssl-util` | `3.0.14-3` | `3.0.14` | `PACKAGE_RELEASE_REMOVED` | `3.0.14` |

The exact four-package Source shares `3.0.14-3`, while official OpenSSL 3.0
release notes identify `3.0.14`. Official OpenWrt policy distinguishes upstream
version from package release. Both runtime packages therefore share product
version `3.0.14`, but only after independent PRODUCT_RUNTIME decisions.

## B. curl and libcurl

| Package identity | Observed | Official upstream | Status | Normalized |
|---|---|---|---|---|
| curl CLI | `8.11.0-23.2` | `8.11.0` | `PACKAGE_RELEASE_REMOVED` | `8.11.0` |
| libcurl | `8.11.0-23.2` | `8.11.0` | `PACKAGE_RELEASE_REMOVED` | `8.11.0` |

Official curl history explicitly states that curl and libcurl are released in
sync with the same version. The dotted `23.2` suffix is not removed by pattern;
it is removed because official release `8.11.0`, exact sibling alignment, Source
provenance, and official package-release semantics all agree. The identities
remain distinct despite sharing the normalized version.

## C. iptables

| Package | Observed | Official upstream | Status | Normalized |
|---|---|---|---|---|
| `iptables` | `1.8.7-3` | `1.8.7` | `PACKAGE_RELEASE_REMOVED` | `1.8.7` |
| `ip6tables` | `1.8.7-3` | `1.8.7` | `PACKAGE_RELEASE_REMOVED` | `1.8.7` |

The official netfilter archive publishes iptables 1.8.7. All eight exact Source
siblings share `1.8.7-3`; sibling equality is corroboration, while the official
release and package policy establish the actual boundary.

## D. strongSwan

| Package | Observed | Official upstream | Status | Normalized |
|---|---|---|---|---|
| `strongswan` | `5.9.14-24` | `5.9.14` | `PACKAGE_RELEASE_REMOVED` | `5.9.14` |
| `strongswan-charon` | `5.9.14-24` | `5.9.14` | `PACKAGE_RELEASE_REMOVED` | `5.9.14` |

The official project announced strongSwan 5.9.14, and all 28 exact Source
siblings share `5.9.14-24`. The main library package and charon runtime share the
product release without extending that conclusion to plugins or the meta package.

## E. e2fsprogs

| Package | Observed | Official upstream | Status | Normalized |
|---|---|---|---|---|
| `e2fsprogs` | `1.47.0-2` | `1.47.0` | `PACKAGE_RELEASE_REMOVED` | `1.47.0` |

The official release notes identify e2fsprogs 1.47.0. All four exact Source
siblings use `1.47.0-2`; the runtime utility package receives normalized version
`1.47.0`, without normalizing the unresolved/non-runtime split libraries here.

## F. direct Linux kernel

| Component | Observed | Official upstream | Status | Normalized |
|---|---|---|---|---|
| direct `linux_kernel` | `5.15.176` | `5.15.176` | `EXACT_PRODUCT_VERSION` | `5.15.176` |

The direct artifact's `BINARY_DIRECT` traceability and kernel.org archive agree.
No package revision is present. The opkg virtual kernel version and kmod versions
are not substituted for the direct product version.

## G. date/git snapshots

| Package | Observed | Preserved upstream/source identity | Release removed? | Normalized value |
|---|---|---|---:|---|
| `netifd` | `2024-01-04-c18cc79d-16` | `2024-01-04-c18cc79d` | yes | `2024-01-04-c18cc79d` |
| `procd` | `2021-02-23-37eed131-21` | `2021-02-23-37eed131` | yes | `2021-02-23-37eed131` |
| `opkg` | `2021-06-13-1bf042dd-2` | `2021-06-13-1bf042dd` | yes | `2021-06-13-1bf042dd` |
| `ppp` | `2.4.9.git-2021-01-04-4` | `2.4.9.git-2021-01-04` | yes | `2.4.9.git-2021-01-04` |
| `luci-lib-ip` | `git-20.250.76529-62505bd` | whole identifier | no | null; structure-only candidate preserved |

Official OpenWrt policy defines source-control package versions using source date
plus revision and defines `PKG_RELEASE` separately. These values remain snapshot
identifiers. In particular, the PPP value is not collapsed to `2.4.9`, because
its `.git-2021-01-04` portion identifies code beyond/the snapshot around that
release. The legacy LuCI generated identifier is preserved whole; its final hash
is not interpreted as a package release.

## H. vendor-specific versions

| Package | Observed | Exact vendor evidence | Status | Normalized |
|---|---|---|---|---|
| `data-sender` | `1.15-1` | Teltonika Source; 15 siblings share value | `VENDOR_SPECIFIC_VERSION` | null |
| `gpsd` | `2025-04-29-2` | Teltonika GPS Source; 5 siblings share value | `VENDOR_SPECIFIC_VERSION` | null |
| `gsmctl` | `f61d039a` | Teltonika GSM Source; 4 siblings share hash | `VENDOR_SPECIFIC_VERSION` | null |
| `mobifd` | `ab396378` | single Teltonika Source and exact daemon | `VENDOR_SPECIFIC_VERSION` | null |
| `modbus_client` | `2025-02-20` | single Teltonika Source and exact executable | `VENDOR_SPECIFIC_VERSION` | null |

Official Teltonika documentation confirms several functions, including gsmctl
and Data to Server, but does not define these internal package-version mappings.
The exact UCR-ST-B8 SDK/Makefiles are unavailable. Consequently:

- `1.15-1` is not reduced to `1.15`;
- date-looking values are not asserted as release dates;
- short hashes are not expanded or translated;
- the public `gpsd` name is not used to inherit an unrelated public product
  version.

All observed values remain available as preserved candidates.

## Composite and format edge checks

`kmod-mt76-core_515` was selected with observed value:

```text
5.15.176+2023-09-18-2afc7285-2
```

The value appears to contain kernel ABI, source date/hash, and package-revision
layers. Because the component is a kmod excluded from Linux parent identity, it
receives `NO_PRODUCT_VERSION`; no delimiter is rewritten.

A read-only format scan over the 575 exact opkg versions found:

| Form | Exact package count |
|---|---:|
| `alpha` / `beta` / `rc` / `pre` token | 0 |
| epoch prefix | 0 |
| trailing `-rN` | 0 |
| trailing `_N` | 0 |
| `+` composite | 7 |

This was only a format inventory. No bulk normalization was performed. Rulebook
v1 nevertheless protects pre-release tokens and requires explicit epoch and
multi-delimiter handling before transformation.

## Package-release removal consistency

The same proof test was applied to all conventional release runtimes:

| Upstream family | Observed suffix | Official release exists | Exact sibling agreement | Package-policy support | Result |
|---|---|---:|---:|---:|---|
| OpenSSL | `-3` | yes | yes | yes | remove |
| curl/libcurl | `-23.2` | yes | yes | yes | remove |
| iptables/ip6tables | `-3` | yes | yes | yes | remove |
| strongSwan | `-24` | yes | yes | yes | remove |
| e2fsprogs | `-2` | yes | yes | yes | remove |

No suffix was removed based on its last token alone. The same gate also allowed
four OpenWrt snapshot package revisions to be removed while preserving the
date/git source identity.

## Rulebook consistency answers

1. **Is release removal consistent across the required projects?** Yes. All
   conventional cases passed the same six-part proof test.
2. **Can pre-release and package release be distinguished?** Yes by official
   upstream semantics, not regex. No actual selected/exact version contains a
   pre-release token.
3. **Are date/git snapshots handled safely?** Yes. Validated source identifiers
   are retained; none is converted to a nearby semantic release.
4. **Are vendor versions protected?** Yes. Five vendor forms remain null and
   losslessly preserved.
5. **Are sibling versions useful?** Yes as corroboration, never as sufficient
   proof. All conventional required Sources were sibling-consistent.
6. **Can one Source have multiple runtimes/identities?** Yes. curl/libcurl share
   8.11.0 but retain distinct product identities; OpenSSL libraries/CLI likewise
   remain separate runtime records.
7. **Is the result reproducible?** Yes for the 14 non-null cases because every
   transformation records exact equality, official version evidence, packaging
   semantics, and the removed layer.

## REVIEW_REQUIRED

No selected version-normalization record ended in normalization status
`REVIEW_REQUIRED`. This does not mean all 582 versions are resolvable:

- five vendor cases have runtime `REVIEW_REQUIRED` and intentionally use the
  more informative version status `VENDOR_SPECIFIC_VERSION` with null normalized
  values;
- any future weak suffix inference, SBOM/control mismatch, unknown epoch, or
  ambiguous pre-release boundary must terminate as normalization
  `REVIEW_REQUIRED`;
- the full dataset has not been normalized.

## Contradictions and refinements

No terminal-status contradiction was found. Three apparent tensions were
resolved explicitly in v1:

1. **Same `-N` shape, different meaning.** A release suffix, date component,
   pre-release token, or vendor build can share delimiters. The proof test, not
   shape, determines removal.
2. **Same Source version, distinct identities.** curl and libcurl demonstrate
   that version sharing does not merge product identity.
3. **Official feature evidence versus package-version evidence.** Teltonika
   feature documentation confirms functionality but not internal package version
   semantics, so vendor values stay null.

## Before a 582-component dry-run

Rulebook v1 does not require a definition rewrite, but full automation should
not start until reviewers approve these controls:

1. accept the six-part package-release proof test, including dotted releases;
2. accept date/hash snapshots as valid product-version candidates without
   semantic conversion;
3. keep non-product syntax samples out of later mapping inputs;
4. resolve PRODUCT_RUNTIME `REVIEW_REQUIRED` separately from version form;
5. require cached/recorded official evidence identifiers so results remain
   reproducible if upstream pages change;
6. route any `WEAK` transformation to null `REVIEW_REQUIRED`.

## Validation

| Check | Result |
|---|---|
| Every representative has exactly one normalization status | PASS (`21/21`) |
| Status partition | PASS (`1 + 9 + 0 + 5 + 5 + 1 + 0 = 21`) |
| Exact opkg SBOM/control/status versions agree | PASS (`20/20`) |
| Required core families present | PASS |
| Date/git representatives | PASS (`5`) |
| Vendor-specific representatives | PASS (`5`) |
| Non-null values backed by STRONG/MODERATE evidence | PASS (`14/14`) |
| WEAK automatic normalization | PASS (`0`) |
| CPE/NVD/CVE evidence use | PASS (`0`) |
| Existing artifact or database writes | PASS (`0`) |

Detailed rows are in `representative_cases.csv`; evidence identifiers resolve
through the registry in `rulebook.md`.

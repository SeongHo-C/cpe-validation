# Version Normalization Rulebook v1

## Scope and stop condition

This rulebook determines a product-version candidate from an exact observed
SBOM/opkg version. It applies to a binary package or directly observed SBOM
component and stops before any CPE, NVD Configuration, CVE, Ground Truth CPE,
or Ground Truth Decision operation.

The normal path is:

```text
PRODUCT_RUNTIME status
  -> exact observed versions
  -> source/package provenance
  -> official upstream version evidence
  -> normalized product version or explicit null
  -> STOP
```

It is not a string cleanup rule. In particular, a final `-<number>` is never
removed solely because it looks like a package release.

## Units and fields

The decision unit is the binary package/SBOM component. Source siblings are
supporting evidence and do not merge distinct product identities.

- `observed_sbom_version`: version recorded on the SBOM component.
- `observed_firmware_version`: exact installed control/status version, or a
  directly traced artifact version for a non-opkg component.
- `source_snapshot_version`: an upstream source date/revision identifier when
  the upstream packages directly from a source-control snapshot.
- `package_release`: distribution/vendor packaging revision, distinct from the
  upstream product/source version.
- `normalized_product_version`: version identifying the upstream product or
  source snapshot. It remains null when the boundary is not proven.
- `preserved_version_candidate`: lossless value retained for later review even
  when no normalized product version is asserted.

`normalized_product_version` is not a CPE expression and must not be chosen to
match a Dictionary entry.

## Evidence hierarchy

### E1 — exact firmware

Compare:

- SBOM component name/version;
- `/usr/lib/opkg/info/<package>.control`;
- `/usr/lib/opkg/status`;
- `Package`, `Version`, `Source`, `SourceName`, and `SourceDateEpoch`;
- direct artifact traceability for a non-opkg component.

If SBOM and exact installed versions disagree, return `REVIEW_REQUIRED`. Do not
select one silently.

### E2 — exact Source siblings

Record every distinct version among packages from the same exact `Source`.
Identical sibling versions support a source-version plus package-release
interpretation, but never prove it alone. Different product identities may
legitimately share one source version, as curl and libcurl do.

### E3 — official upstream evidence

Prefer official release notes/pages, release archives, repository tags or
commits, project documentation, and official packaging policy. This evidence
must establish either:

- the released product version;
- the exact source snapshot/date/revision; or
- the distribution package-release semantics.

Search snippets, CPE records, and unofficial package databases are not decision
evidence.

### E4 — related packaging/source metadata

Use this only as corroboration. Another firmware, another vendor SDK, or a
current upstream Makefile is not exact-firmware evidence. The exact SDK/GPL and
Makefiles remain unavailable for this firmware.

## Normalization statuses

### `EXACT_PRODUCT_VERSION`

The exact observed value is directly confirmed as the upstream product version.
No characters are removed or rewritten.

### `PACKAGE_RELEASE_REMOVED`

An observed suffix is removed only after the package-release proof test below
passes. The remaining value is an official upstream product release.

### `SOURCE_VERSION_DERIVED`

Official source evidence establishes a product/source version not directly
expressed as a removable prefix of the observed package version. The derivation
must be recorded, not guessed.

### `DATE_OR_GIT_VERSION`

The upstream is a dated/revision snapshot rather than a conventional release.
Preserve the validated source identifier; never convert it to an arbitrary
semantic release. A separately proven package release may be removed, while the
date/revision portion remains intact.

### `VENDOR_SPECIFIC_VERSION`

The version belongs to a vendor package/build and no reproducible official
upstream product-version mapping is available. Preserve the observed value and
leave `normalized_product_version` null.

### `NO_PRODUCT_VERSION`

No product version is needed for the tested boundary, normally because the
component is a meta/virtual/module/accessory package and is only present as a
format-control case.

### `REVIEW_REQUIRED`

The observed/upstream relationship cannot be reproduced, exact versions
conflict, a suffix boundary remains ambiguous, or only weak evidence supports a
transformation. Preserve the observed value and leave the normalized value null.

## Runtime applicability

Version normalization is active by default only for `PRODUCT_RUNTIME`.

- `PRODUCT_RUNTIME`: `ACTIVE` normalization.
- runtime `REVIEW_REQUIRED`: the version form may be classified, but any
  normalized value remains `PROVISIONAL` unless the version evidence itself is
  independent and strong.
- `NON_PRODUCT_RUNTIME`: normally `NO_PRODUCT_VERSION`. A deliberately selected
  syntax-control case may be assigned a structural status such as
  `DATE_OR_GIT_VERSION`, but must use `STRUCTURE_ONLY` applicability and must not
  feed later product mapping.

## Package-release proof test

`PACKAGE_RELEASE_REMOVED` requires all of the following:

1. SBOM and exact firmware versions match.
2. Official upstream evidence directly confirms the remaining prefix as a
   product release.
3. Official packaging policy or exact build metadata defines the suffix as a
   package revision.
4. Exact Source siblings use a compatible version structure.
5. Removing the suffix does not remove an upstream pre-release, patch level,
   build metadata, ABI identifier, date, or revision.
6. The boundary is independent of CPE/Dictionary contents.

If any required condition fails, do not remove the suffix. Select the applicable
date/git/vendor status or `REVIEW_REQUIRED`.

Decimal package revisions such as `23.2` are allowed only when conditions 1–6
prove the entire suffix to be packaging metadata. The syntax itself is never the
proof.

## Date/revision snapshot proof test

For a value resembling `YYYY-MM-DD-<hash>-<release>`:

1. Verify that official project/package policy uses date plus source revision.
2. Confirm the exact date/revision in an official repository, official package
   page/archive, or versioned project metadata.
3. Remove only a separately proven package release.
4. Preserve `YYYY-MM-DD-<hash>` as the normalized snapshot version.
5. Set status `DATE_OR_GIT_VERSION`; do not map the snapshot to the nearest
   semantic release.

For legacy generated versions such as `git-20.250.76529-62505bd`, preserve the
whole official identifier unless its subfields have an explicitly documented
separation. Do not treat the final hash as a package release.

## Vendor-specific proof test

A package is `VENDOR_SPECIFIC_VERSION` when exact metadata establishes vendor
origin and public vendor material does not establish the package's own upstream
release/version relationship.

- A semantic-looking value such as `1.15-1` does not authorize `1.15`.
- A date such as `2025-02-20` is not automatically a release date.
- A short hash such as `f61d039a` is preserved but not expanded or mapped.
- Firmware/RutOS documentation proving that a feature exists does not prove the
  internal package's version semantics.

Set `normalized_product_version` to null and retain the observed value in
`preserved_version_candidate`.

## Edge-case rules

### Pre-release identifiers

`rc`, `alpha`, `beta`, `pre`, and similar identifiers belong to upstream when
official upstream evidence says so. Examples:

```text
1.2.3-rc1    -> keep rc1
1.2.3-beta2  -> keep beta2
```

Only a package revision outside the validated pre-release token may be removed.
No selected exact package contains an `alpha`/`beta`/`rc`/`pre` token, but the
full installed-version format scan explicitly checked for them.

### Date-only values

A date is not changed. It becomes a normalized source version only when official
evidence identifies the date as the source snapshot. Otherwise use vendor or
review status.

### Git hashes and revisions

Never translate a commit/hash to a semantic version. A short hash remains short;
do not fabricate the full revision. A source date can accompany it only when
official metadata supports the pair.

### Multiple delimiters and `+`

Values such as `kernel+module-source-release` may combine kernel ABI,
out-of-tree source version, and package release. Parse them only with build
metadata. A kernel module excluded from Linux parent identity normally receives
`NO_PRODUCT_VERSION`, with the composite observed value preserved.

### Epochs

When an epoch is observed, store it separately from product version and verify
its packaging semantics. Do not pass the epoch into normalized product version
unless official upstream itself uses it. No epoch-form version was observed in
the exact 575-package format scan.

### `_release`, `-rN`, and `+vendorN`

These delimiters are never normalized by regex alone. Require official/exact
packaging evidence for the specific package. The exact scan found no trailing
`-rN` or `_N` form; seven `+` composite versions were present and one kmod was
selected as a structure-only control.

## Decision flow

```text
1. Load prior PRODUCT_RUNTIME status.
   |
   +-- NON_PRODUCT_RUNTIME?
   |     +-- ordinary case -> NO_PRODUCT_VERSION
   |     +-- selected syntax control -> STRUCTURE_ONLY; never mapping input
   |
   +-- PRODUCT_RUNTIME or REVIEW_REQUIRED -> continue

2. SBOM version == exact firmware version?
   |
   +-- no/missing conflict -> REVIEW_REQUIRED, normalized=null
   +-- yes -> continue

3. Can official upstream identity/version be reproduced?
   |
   +-- no, exact vendor package -> VENDOR_SPECIFIC_VERSION, normalized=null
   +-- no otherwise -> REVIEW_REQUIRED, normalized=null
   +-- yes -> continue

4. Observed value exactly equals official product release?
   |
   +-- yes -> EXACT_PRODUCT_VERSION
   +-- no -> continue

5. Is it an official date/revision snapshot form?
   |
   +-- yes:
   |     +-- package revision separately proven -> remove only that revision
   |     +-- not proven -> preserve whole value
   |     -> DATE_OR_GIT_VERSION
   +-- no -> continue

6. Does the package-release proof test pass?
   |
   +-- yes -> PACKAGE_RELEASE_REMOVED
   +-- no -> continue

7. Can official source evidence derive a different exact version?
   |
   +-- yes -> SOURCE_VERSION_DERIVED, record derivation
   +-- no -> REVIEW_REQUIRED, normalized=null
```

## Required automation record

Every record must include at least:

```text
component/package
source
product_runtime_status
observed_sbom_version
observed_firmware_version
sibling_versions
upstream_product
official_upstream_version
normalization_status
normalized_product_version
normalization_reason
evidence
evidence_strength
```

This dry-run also records applicability, status origin, preserved candidate,
whether a package release was removed, SourceName, and SourceDateEpoch.

## Evidence strength

- `STRONG`: exact SBOM/control/status agreement and direct official
  release/snapshot or package-policy evidence.
- `MODERATE`: exact metadata is strong, but official package-specific version
  evidence is incomplete; no transformation beyond a protected vendor/null
  outcome is permitted.
- `WEAK`: relies on string form, naming, or indirect material. Any transformed
  value with weak evidence must become `REVIEW_REQUIRED` and null.

## Official evidence registry

- `UP-OPENWRT-POLICY`: official policy separates `PKG_VERSION` or
  `PKG_SOURCE_DATE`+`PKG_SOURCE_VERSION` from `PKG_RELEASE` and describes the
  generated date/hash identifier:
  <https://openwrt.org/docs/guide-developer/package-policies>
- `UP-OPENWRT-PACKAGES`: official package-creation documentation defines
  upstream `PKG_VERSION`, repository revision/date fields, and package release:
  <https://openwrt.org/docs/guide-developer/packages>
- `UP-OPENSSL-3.0.14`: official OpenSSL 3.0 release notes list 3.0.14:
  <https://openssl-library.org/news/openssl-3.0-notes/>
- `UP-CURL-8.11.0`: official curl release record identifies 8.11.0:
  <https://curl.se/ch/8.11.0.html>
- `UP-CURL-VERSIONS`: official version history states that curl and libcurl are
  released in sync with the same version:
  <https://curl.se/docs/versions.html>
- `UP-IPTABLES-1.8.7`: official netfilter downloads list iptables 1.8.7:
  <https://www.netfilter.org/projects/iptables/downloads.html>
- `UP-STRONGSWAN-5.9.14`: official announcement identifies strongSwan 5.9.14:
  <https://strongswan.org/blog/2024/03/19/strongswan-5.9.14-released.html>
- `UP-E2FSPROGS-1.47.0`: official repository release notes identify e2fsprogs
  1.47.0:
  <https://github.com/tytso/e2fsprogs/blob/master/doc/RelNotes/v1.47.0.txt>
- `UP-LINUX-5.15.176`: kernel.org's official archive publishes Linux 5.15.176
  and its changelog:
  <https://cdn.kernel.org/pub/linux/kernel/v5.x/>
- `UP-NETIFD`: the official OpenWrt repository identifies netifd and the
  official archive publishes the `2024-01-04-c18cc79d` version:
  <https://github.com/openwrt/netifd>
- `UP-NETIFD-PACKAGE`: official OpenWrt archive entry for the selected snapshot:
  <https://archive.openwrt.org/releases/23.05.3/packages/mipsel_24kc/base/>
- `UP-PROCD`: the official OpenWrt repository identifies procd as its service /
  process manager: <https://github.com/openwrt/procd>
- `UP-OPKG-SNAPSHOT`: official OpenWrt package metadata identifies
  `2021-06-13-1bf042dd-2`:
  <https://openwrt.org/packages/pkgdata_owrt21_2/opkg>
- `UP-OPKG-REPO`: official OpenWrt opkg repository log includes the 2021-06-13
  revision line: <https://git.openwrt.org/project/opkg-lede/>
- `UP-PPP-SNAPSHOT`: official OpenWrt package metadata identifies the
  `2.4.9.git-2021-01-04` snapshot plus package release:
  <https://openwrt.org/packages/pkgdata/ppp>
- `UP-PPP-2.4.9`: the official PPP repository NEWS records the 2.4.9 release and
  subsequent unreleased changes: <https://github.com/ppp-project/ppp/blob/master/NEWS>
- `UP-LUCI-LIB-IP`: official OpenWrt package metadata preserves
  `git-20.250.76529-62505bd` as the package version:
  <https://openwrt.org/packages/pkgdata_owrt21_2/luci-lib-ip>
- `UP-TELTONIKA-GSMCTL`: official Teltonika documentation confirms the gsmctl
  feature/command but does not publish the internal package version mapping:
  <https://wiki.teltonika-networks.com/view/RUTX_gsmctl_Commands>
- `UP-TELTONIKA-DATA-SENDER`: official Teltonika documentation confirms the
  Data to Server feature but not the internal package version mapping:
  <https://wiki.teltonika-networks.com/view/RUTX08_Data_to_Server>
- `UP-TELTONIKA-SDK`: official SDK/GPL index shows firmware-family SDK releases;
  it does not provide the exact UCR-ST-B8 package Makefiles used here:
  <https://wiki.teltonika-networks.com/view/Software_Development_Kit>

## Versioning note

This is Rulebook `v1`, validated against 21 representatives only. Any change to
suffix proof, snapshot preservation, runtime applicability, or vendor handling
requires a new rulebook version before a 582-component dry-run.

# CPE prerelease version policy: wpa_supplicant 2.11-devel

## Decision

**Candidate B is recommended.**

```text
version = 2.11
update = devel
recommended_gt_cpe = cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*
recommended_validation_result = VERSION_NOT_IN_DICTIONARY
```

The observed upstream product version remains `2.11-devel`; only its CPE WFN
representation is decomposed into base release `2.11` plus development-state
update `devel`.

## NIST CPE 2.3 basis

Primary source: [NISTIR 7695, CPE Naming Specification 2.3](https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7695.pdf).

- Section 5.3.3.4 defines `version` as the vendor-specific release version and
  says discoverable version information should be copied directly without
  truncation or modification.
- Section 5.3.3.5 defines `update` as the vendor-specific update, service pack,
  or point release.
- The specification's Internet Explorer Beta example uses
  `version=8.0.6001, update=beta`.
- NIST does not define a universal regex that sends every suffix to `update`.
  Upstream semantics and same-family practice are therefore required.

## Fixed Dictionary family census

- Snapshot: `20260819T035002Z`
- Family: `a:w1.fi:wpa_supplicant`
- Rows: **77**
- Active: **77**
- Deprecated: **0**
- Explicit prerelease tokens in `update`: **2**
- Target prerelease tokens in `version`: **0**

| Prerelease CPE | Version | Update | Status | Same-version generic entry |
|---|---|---|---|---|
| `cpe:2.3:a:w1.fi:wpa_supplicant:0.2.3:pre1:*:*:*:*:*:*` | `0.2.3` | `pre1` | ACTIVE | `cpe:2.3:a:w1.fi:wpa_supplicant:0.2.3:*:*:*:*:*:*:*` |
| `cpe:2.3:a:w1.fi:wpa_supplicant:0.3.0:pre4:*:*:*:*:*:*` | `0.3.0` | `pre4` | ACTIVE | `cpe:2.3:a:w1.fi:wpa_supplicant:0.3.0:*:*:*:*:*:*:*` |

The complete 77-row export is in `family_cases.csv`. The token-kind counts are
`pre=2`, `rc=0`, `beta=0`, `alpha=0`, `devel=0`, and `snapshot=0`. Exact
searched-token counts are `pre=0`, `pre1=1`, `pre2=0`, `rc=0`, `rc1=0`,
`beta=0`, `alpha=0`, `devel=0`, and `snapshot=0`; the additional discovered
token is `pre4=1`.
Both observed family prereleases split the upstream `-preN` suffix into the
`update` attribute; none of the searched prerelease tokens appears in `version`.

## Upstream meaning

- The official pre-final source identifies
  [`VERSION_STR "2.11-devel"`](https://git.w1.fi/cgit/hostap/plain/src/common/version.h?h=hostap_2_11%5E).
- The official `hostap_2_11` source identifies
  [`VERSION_STR "2.11"`](https://git.w1.fi/cgit/hostap/plain/src/common/version.h?h=hostap_2_11).
- The [official release archive](https://w1.fi/releases/) publishes a distinct
  `wpa_supplicant-2.11.tar.gz` final release and historical
  `0.2.3-pre1`/`0.3.0-pre4` archives.

Therefore `devel` is an upstream development state, not an OpenWrt package
release, and it must not be removed or conflated with final `2.11`.

## Candidate comparison

| Candidate | Version / update | NIST compatibility | Family consistency | Preserves observation | Distinguishes final | Decision | Reason |
|---|---|---|---|---|---|---|---|
| A | `2.11` / `*` | SYNTACTICALLY_VALID_BUT_IMPRECISE | GENERIC_UPDATE_PATTERN_BUT_DEVEL_NOT_EXPLICIT | No | No | REJECTED | The explicit devel state is lost. In a WFN, update='*' is ANY, not an exact assertion of the observed development state. |
| B | `2.11` / `devel` | COMPATIBLE_AND_SEMANTICALLY_ALIGNED | CONSISTENT_WITH_EXPLICIT_PRE_UPDATE_ROWS | Yes | Yes | RECOMMENDED | It preserves the upstream base release and explicit development state across the version/update attributes, matching the family's pre1 and pre4 modeling. |
| C | `2.11-devel` / `*` | SYNTACTICALLY_VALID_BUT_NOT_PREFERRED | INCONSISTENT_WITH_EXPLICIT_PRE_UPDATE_ROWS | Yes | Yes | REJECTED | It is lossless and syntactically valid, but treats a release-state suffix as an atomic version despite this family's split modeling. |

Candidate A is also semantically broad because `update=*` means ANY update,
not an explicit final or development state. Candidate C is a legal formatted
string, but it does not follow the only two prerelease precedents in this family.

## General normalization rule

| Outcome | Apply when | Constraint/example |
|---|---|---|
| `MOVE_TO_UPDATE` | The upstream suffix is a separable release-state/update token and the same CPE family consistently models comparable tokens in update. | 1.2.3-pre1 -> version=1.2.3, update=pre1; 1.2.3-rc1 -> version=1.2.3, update=rc1; wpa_supplicant 2.11-devel -> version=2.11, update=devel |
| `KEEP_IN_VERSION` | The complete string is the upstream canonical version, the suffix is not a separately modeled release state, or family evidence consistently keeps the token in version. | Do not split solely because a version contains '-' or letters. |
| `PACKAGE_RELEASE_REMOVE` | Authoritative package metadata proves the suffix is a distribution package/build revision outside the upstream product version. | Remove only the proven package revision, never pre/rc/beta/devel. |
| `REVIEW_REQUIRED` | Upstream semantics are ambiguous, family practice is absent or mixed, or splitting would discard or invent version information. | Escalate instead of applying a global suffix regex. |

The rule is evidence-driven: do not implement a global suffix regex.

## Existing audit impact (not applied)

| State | Actual product version | GT CPE | Discrepancy fields | Result |
|---|---|---|---|---|
| Current candidate | `2.11` | `cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*` | `[]` | `VERSION_NOT_IN_DICTIONARY` |
| First audit | `2.11-devel` | `cpe:2.3:a:w1.fi:wpa_supplicant:2.11-devel:*:*:*:*:*:*:*` | `["VERSION"]` | `VERSION_NOT_IN_DICTIONARY` |
| New recommendation | `2.11-devel` | `cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*` | `["UPDATE"]` | `VERSION_NOT_IN_DICTIONARY` |

No existing candidate or audit artifact is changed in this task. A future approved
change would separate human product version `2.11-devel` from CPE attributes
`version=2.11, update=devel`, update the wpa-specific audit expectation/tests,
and regenerate the affected audit recommendation.

## Validation and guardrails

- Fixed snapshot only: `True`
- Family rows exported: `77`
- Family database count: `77`
- Family canonical parse failures: `0`
- Candidate A/B/C canonical parse failures: `0`
- Recommended CPE absent with Active family present: `True`
- Protected candidate/audit artifacts unchanged: `True`
- Ground Truth DB: `0 -> 0`
- Migration, NVD Configuration query, CVE applicability, DB mutation: `0`

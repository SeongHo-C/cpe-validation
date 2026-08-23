# CPE Mapping / Ground Truth Decision Rulebook v1 — first dry-run

## Scope and status

This rulebook connects an independently verified `PRODUCT_RUNTIME`, upstream
product identity, and normalized product version to fixed CPE Dictionary and
NVD CVE snapshots. It stops before persistence and before CVE applicability.

The rulebook is a first dry-run version, not a frozen production rule. It was
tested on 11 representatives: the 10 required core runtimes plus one previously
validated netifd runtime selected solely to exercise the no-direct-CPE branch.

No original SBOM CPE or firmware control `CPE-ID` may influence product
identity, normalized version, CPE family discovery, or candidate selection.
They are loaded only after a proposed Ground Truth CPE has been independently
determined.

## Fixed datasets

Only these database snapshots are permitted:

| Dataset | Snapshot | Status | Counts |
|---|---|---|---|
| CPE Dictionary | `20260819T035002Z` | `COMPLETE` | 1,811,261 total; 1,711,630 active; 99,631 deprecated |
| NVD CVE | `20260820T110357Z` | `COMPLETE` | 380,865 CVEs; 760,120 configurations; 3,170,148 cpeMatch rows |

Snapshot fingerprints:

- CPE manifest SHA-256:
  `d0353e020f67a19070ebf297615cba0a91b636f3f89bd580f73fd786719fddce`
- CPE content SHA-256:
  `9035416631831f5f50d3c723d813370532e7ceee0c5a93c8473897d5a97bfd7a`
- NVD manifest SHA-256:
  `80b6107f5225923794d725b252527f575ad2b0c800765fc5ce6d0b07c18d94eb`
- NVD content SHA-256:
  `a8a1b6ca66a0383272a3ca035559229b1fc59535f029828b984a3998234c6eab`

Database work must execute in a transaction set to `READ ONLY`. Live NVD APIs
and current web Dictionary searches are outside the evidence boundary.

## Input contract

Every mapping input must already contain:

```text
component_id
PRODUCT_RUNTIME
upstream_product
normalized_product_version
version-normalization evidence
```

If product identity or normalized version is missing or not sufficiently
supported, stop with `UNRESOLVED`. Dictionary absence is never a reason for
`UNRESOLVED`.

The three axes are independent:

```text
Source relationship != product identity != CPE identity
```

One Source may produce separate CPE products, as curl and libcurl demonstrate.
Conversely, several binary packages may implement one CPE product, as the two
OpenSSL and two strongSwan representatives demonstrate.

## Search identity binding

The search tuple is constructed from prior upstream evidence and the fixed
Dictionary's product titles/family records, never from Original CPE fields.
The binding must record `part`, `vendor`, and `product` explicitly.

| Verified upstream boundary | Search tuple |
|---|---|
| OpenSSL library or CLI | `(a, openssl, openssl)` |
| curl command-line tool | `(a, haxx, curl)` |
| libcurl runtime library | `(a, haxx, libcurl)` |
| iptables/ip6tables suite runtime | `(a, netfilter, iptables)` |
| strongSwan/charon runtime | `(a, strongswan, strongswan)` |
| e2fsprogs suite | `(a, e2fsprogs_project, e2fsprogs)` |
| Linux kernel | `(o, linux, linux_kernel)` |
| OpenWrt netifd search-only tuple | `(a, openwrt, netifd)` |

The netifd tuple is a search binding, not a claimed official CPE identity. The
analysis additionally scans the entire Dictionary and Configuration data for
the product value `netifd`, regardless of vendor, before declaring no direct
representation.

## CPE parsing and comparison

Parse both Original and proposed strings into these 11 CPE 2.3 fields:

```text
part, vendor, product, version, update, edition, language,
sw_edition, target_sw, target_hw, other
```

For this dry-run, all compared values are structurally valid and contain no
escaped bound-value equivalence that changes comparison. Equality is therefore
the equality of the parsed 11-field tuples, not raw-string equality.

Before a full 582-case run, the project parser must be upgraded or wrapped with
a complete binding-aware canonicalizer. The current parser intentionally
preserves escapes and does not prove that differently escaped but equivalent
CPE strings are canonical equals.

## Decision flow

```text
0. PRODUCT_RUNTIME and verified normalized version present?
   no  -> UNRESOLVED
   yes -> continue

1. Unique compatible Active exact CPE exists?
   yes -> proposed GT = that Active CPE
          compare parsed Original only now
          equal     -> CPE_CONFIRMED
          different -> OFFICIAL_CPE_MAPPED
   no  -> continue

2. Search Deprecated exact CPEs, then Deprecated product-family aliases.
   unique compatible Active endpoint -> proposed GT = Active endpoint;
                                        compare Original as in step 1
   ambiguous/multiple/cycle/missing   -> review_required; do not decide
   no resolution                      -> continue

3. Compatible Active product family exists, but normalized version does not?
   yes -> derive a unique compatible non-version WFN template
          proposed GT expression keeps the verified normalized version
          Decision = VERSION_NOT_IN_DICTIONARY
   no  -> continue

4. Entire Active + Deprecated Dictionary has no matching product tuple?
   no  -> do not query Configuration-only; return to review of identity/alias
   yes -> query only NVD snapshot 20260820T110357Z

5. Unique compatible Configuration product identity exists?
   yes -> proposed GT expression uses verified normalized version, not the
          criteria wildcard/range version
          Decision = NVD_CONFIGURATION_ONLY
   ambiguous -> review_required; do not decide
   no -> DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
```

`review_required` is an audit flag, not a seventh Decision.

## Active exact rule

An Active exact candidate must uniquely match:

- independently bound `(part, vendor, product)`;
- verified normalized product version; and
- software-compatible non-version WFN attributes.

A product/version-only hit is insufficient when multiple `update`, edition,
platform, or hardware variants remain compatible. A unique Active exact entry
ends Dictionary traversal; historical deprecated family members may be counted
for context but are not used to replace an already valid Active exact result.

## Deprecated resolution rule

Deprecated records are historical aliases, never proposed Ground Truth CPEs.
For every evaluated Deprecated record preserve:

```text
deprecated CPE and UUID
direct deprecatedBy list
ordered replacement path(s)
depth
cycle and missing-reference flags
all terminal Active endpoints
semantic compatibility result
```

Resolution performs depth-first traversal over `deprecated_by[].cpeName`, with
a path-local visited set. It must:

1. reject cycles;
2. retain every branch rather than selecting the first edge;
3. reject a missing endpoint or an endpoint outside the fixed snapshot;
4. require every proposed endpoint to be Active;
5. compare all 11 WFN attributes and the verified product/version identity;
6. accept only one compatible Active endpoint.

For a Deprecated family alias, resolve all family endpoints to product tuples.
Only one semantically supported Active family permits a second exact-version
search. If the Active family exists but the verified version does not, use
`VERSION_NOT_IN_DICTIONARY`; ambiguity sets `review_required=true`.

## VERSION_NOT_IN_DICTIONARY expression rule

The expression is a research Ground Truth expression, not an official Active
Dictionary entry. It preserves normalized product version and uses a unique,
compatible family template.

This dry-run found the following reproducible templates:

| Product | Active template evidence | Constructed version template |
|---|---|---|
| libcurl | `cpe:2.3:a:haxx:libcurl:8.12.0:*:*:*:*:*:*:*` | all non-version attributes `*` |
| iptables | `cpe:2.3:a:netfilter:iptables:1.8.3:*:*:*:*:*:*:*` | all non-version attributes `*` |
| strongSwan | `cpe:2.3:a:strongswan:strongswan:5.9.12:-:*:*:*:*:*:*` | `update=-`; remaining fields `*` |
| e2fsprogs | `cpe:2.3:a:e2fsprogs_project:e2fsprogs:1.46.5:*:*:*:*:*:*:*` | all non-version attributes `*` |

Pre-release variants and incompatible architecture-only variants are not
templates for a verified final generic release. The strongSwan case proves that
blindly filling all trailing fields with `*` is not always faithful to the
family's stable-release convention.

If compatible stable entries still expose more than one non-version template,
do not select the first record. Set `review_required=true` and leave proposed GT
empty.

## Configuration-only rule

Configuration is queried only after confirming zero Active and zero Deprecated
Dictionary records for the product tuple. Product-name-wide alias scans must
also be recorded where the canonical vendor token is not independently fixed.

For every matching criteria record preserve:

```text
criteria and parsed 11 fields
versionStartIncluding / versionStartExcluding
versionEndIncluding / versionEndExcluding
matchCriteriaId
vulnerable flag
representative CVE
occurrence and distinct-CVE counts
```

Configuration proves a candidate product identity, not installed-version
applicability. A wildcard or ranged criteria never replaces the independently
verified normalized version in the proposed GT expression. CVE applicability
is explicitly deferred.

## No-direct and unresolved separation

- `DIRECT_OFFICIAL_CPE_NOT_CONFIRMED`: product/runtime identity and normalized
  version are verified, but neither Dictionary nor Configuration provides a
  direct product representation.
- `UNRESOLVED`: the upstream product identity or product version itself is not
  sufficiently verified before CPE search.

Neither absence nor a search spelling mismatch may silently become
`UNRESOLVED`.

## Original comparison and discrepancies

Original CPE is loaded only after proposed GT exists. Compare the parsed 11
fields in fixed order and record every unequal attribute. If no proposed GT is
available, discrepancy is `N/A`.

The comparison is an analysis column only. It does not create or modify
Discrepancy Type records.

## First-dry-run findings and required refinements

The six Decision codes represented every decided case in this selected set,
with no overlapping terminal Decision. They are not yet proven sufficient for
the full dataset because no representative reached Deprecated-to-Active,
Configuration-only, or `UNRESOLVED`.

Before a 582-component dry-run:

1. add complete CPE 2.3 binding canonicalization/unescaping;
2. formalize upstream-to-CPE family binding and product-wide alias discovery;
3. encode stable-release template selection, including `*` versus `-`;
4. make Deprecated traversal and ambiguity output machine-checkable;
5. require Dictionary absence before any Configuration-only query;
6. preserve snapshot fingerprints and query-gate outcomes per record;
7. route every ambiguous family/template/replacement to `review_required`
   without forcing one of the six Decisions.

## Stop condition

This dry-run ends at a proposed CPE expression and proposed Decision. It does
not create Ground Truth records, persist discrepancy fields, calculate CVE
applicability, or process the remaining components.

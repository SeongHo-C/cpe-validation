# CPE UPDATE-Field Supporting Analysis

## Purpose

This package preserves the minimum evidence used to separate two Ground Truth
questions:

1. What software version and qualifier were verified by direct or deterministic
   evidence?
2. How does the selected CPE family directly represent that information across
   CPE 2.3 `VERSION` and `UPDATE`?

The full analysis engine, management command, test, and generated history are not
part of the frozen Ground Truth. The CPE Dictionary itself is not copied here.

## Snapshot

- CPE Dictionary snapshot: `20260819T035002Z`
- Total CPE names: 1,811,261
- Active / Deprecated: 1,711,630 / 99,631

## Overall UPDATE Statistics

| UPDATE state | Count | Share |
|---|---:|---:|
| ANY (`*`) | 1,553,793 | 85.785152% |
| NA (`-`) | 48,381 | 2.671122% |
| Concrete | 209,087 | 11.543726% |

- Distinct concrete UPDATE values: 25,545
- Families containing a concrete UPDATE: 7,626

## Main Finding

The fixed Dictionary does not provide one universal rule for placing a version
qualifier in `VERSION` or `UPDATE`. Representation must be justified with direct,
same-family evidence. Global suffix splitting or normalization is not supported.

## Policy

The final policy is `STRICT_DIRECT_QUALIFIER_POLICY`. It is applied only after
`DIRECT_OR_DETERMINISTIC_VERSION_POLICY` establishes the actual software version.
A verified qualifier remains version evidence, but it is placed into a CPE
attribute only when the selected family directly and consistently supports that
representation. This package records final policy consequences, not every
intermediate recommendation made during the exploratory audit.

## Ground Truth Examples

### wpa_supplicant development qualifier

The active `w1.fi:wpa_supplicant` family has 77 entries: 75 use `UPDATE=*` and
two use concrete UPDATE values `pre1` and `pre4`. No entry places `devel` in
either `VERSION` or `UPDATE`. Therefore verified versions such as `2.12-devel`
and `2.11-devel` retain `devel` in version provenance, while the final CPE-level
representations use base `VERSION=2.12` or `2.11` and `UPDATE=*`; `devel` is not
invented as a Dictionary qualifier.

### hostapd development qualifier

The active `w1.fi:hostapd` family has 52 entries, all with `UPDATE=*`, and no
`devel` precedent in either `VERSION` or `UPDATE`. Direct evidence verifies
`2.10-devel`, while the final CPE representation is
`cpe:2.3:a:w1.fi:hostapd:2.10:*:*:*:*:*:*:*`.

### ncurses date UPDATE

The active `invisible-island:ncurses` family has 321 entries: 302 concrete
UPDATE values are date-like, 13 use `*`, and six use `-`. This direct same-family
convention supports verified version `6.1.20180127` as CPE `VERSION=6.1` and
`UPDATE=20180127`:
`cpe:2.3:a:invisible-island:ncurses:6.1:20180127:*:*:*:*:*:*`.

### pimd beta1

Direct source evidence verifies `pimd` version `3.0-beta1`, but the fixed CPE
Dictionary has no applicable direct family precedent for placing `beta1` in a
CPE qualifier. The fixed NVD Configuration represents the product at base
`VERSION=3.0`, so the final `NVD_CONFIGURATION_ONLY` expression is
`cpe:2.3:a:troglobit:pimd:3.0:*:*:*:*:*:*:*`; `beta1` remains verified version
provenance.

## Preserved Evidence

`family_evidence.csv` contains the three Dictionary-family evidence rows used
above.

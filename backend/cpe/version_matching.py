"""Version constraint matching for the fixed RQ3 research contract.

No version normalization, inference, or fallback ordering is performed.
No-range constraints use CPE logical equality/pattern semantics. Range
ordering is supported only when the component version and every endpoint are
strict dotted-numeric strings. Other ordering forms remain explicitly
unsupported rather than becoming false matches.
"""

from __future__ import annotations

import re
from enum import Enum

from cpe.cpe23_canonical import CPE23Attribute, CPE23ValueKind
from cpe.matching import AttributeRelation, compare_cpe_attribute_values


STRICT_DOTTED_NUMERIC_PATTERN = r"^[0-9]+(?:\.[0-9]+)*$"
_STRICT_DOTTED_NUMERIC = re.compile(STRICT_DOTTED_NUMERIC_PATTERN)


class VersionMatchResult(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    INVALID_NVD_RANGE = "INVALID_NVD_RANGE"
    UNSUPPORTED_VERSION_COMPARISON = "UNSUPPORTED_VERSION_COMPARISON"


class DottedNumericComparison(str, Enum):
    LESS = "LESS"
    EQUAL = "EQUAL"
    GREATER = "GREATER"
    UNSUPPORTED = "UNSUPPORTED"


def is_strict_dotted_numeric(value: str) -> bool:
    return _STRICT_DOTTED_NUMERIC.fullmatch(value) is not None


def compare_strict_dotted_numeric(
    left: str,
    right: str,
) -> DottedNumericComparison:
    """Compare dotted integers without defining prefix-equivalence.

    Leading zeroes affect only the temporary integer tuples. Raw strings are
    not changed. If unequal tuple lengths share their complete shorter prefix
    (for example ``1.2`` and ``1.2.0``), ordering is unsupported.
    """

    if not (
        is_strict_dotted_numeric(left)
        and is_strict_dotted_numeric(right)
    ):
        return DottedNumericComparison.UNSUPPORTED

    left_parts = tuple(int(part) for part in left.split("."))
    right_parts = tuple(int(part) for part in right.split("."))
    for left_part, right_part in zip(left_parts, right_parts):
        if left_part < right_part:
            return DottedNumericComparison.LESS
        if left_part > right_part:
            return DottedNumericComparison.GREATER
    if len(left_parts) != len(right_parts):
        return DottedNumericComparison.UNSUPPORTED
    return DottedNumericComparison.EQUAL


def _invalid_range(
    version_start_including: str | None,
    version_start_excluding: str | None,
    version_end_including: str | None,
    version_end_excluding: str | None,
) -> bool:
    endpoints = (
        version_start_including,
        version_start_excluding,
        version_end_including,
        version_end_excluding,
    )
    if any(
        endpoint is not None
        and (not isinstance(endpoint, str) or endpoint == "")
        for endpoint in endpoints
    ):
        return True
    return (
        version_start_including is not None
        and version_start_excluding is not None
    ) or (
        version_end_including is not None
        and version_end_excluding is not None
    )


def _satisfies_boundary(
    comparison: DottedNumericComparison,
    *,
    is_start: bool,
    inclusive: bool,
) -> bool:
    if is_start:
        return comparison is DottedNumericComparison.GREATER or (
            inclusive and comparison is DottedNumericComparison.EQUAL
        )
    return comparison is DottedNumericComparison.LESS or (
        inclusive and comparison is DottedNumericComparison.EQUAL
    )


def match_version_constraint(
    criteria_version: CPE23Attribute,
    component_version: CPE23Attribute,
    *,
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
) -> VersionMatchResult:
    """Evaluate one NVD version constraint against one component version."""

    endpoints = (
        version_start_including,
        version_start_excluding,
        version_end_including,
        version_end_excluding,
    )
    if _invalid_range(*endpoints):
        return VersionMatchResult.INVALID_NVD_RANGE

    present = tuple(endpoint for endpoint in endpoints if endpoint is not None)
    if not present:
        relation = compare_cpe_attribute_values(
            criteria_version,
            component_version,
            case_sensitive=True,
        )
        return (
            VersionMatchResult.MATCH
            if relation in {AttributeRelation.EQUAL, AttributeRelation.SUPERSET}
            else VersionMatchResult.NO_MATCH
        )

    # The fixed-snapshot precondition found only criteria VERSION=ANY with a
    # range. Concrete/NA plus range has no approved semantics.
    if criteria_version.kind is not CPE23ValueKind.ANY:
        return VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON
    if component_version.kind is not CPE23ValueKind.STRING:
        return VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON

    component_raw = component_version.canonical
    if not is_strict_dotted_numeric(component_raw) or any(
        not is_strict_dotted_numeric(endpoint) for endpoint in present
    ):
        return VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON

    boundaries = (
        (version_start_including, True, True),
        (version_start_excluding, True, False),
        (version_end_including, False, True),
        (version_end_excluding, False, False),
    )
    comparisons: list[tuple[DottedNumericComparison, bool, bool]] = []
    for endpoint, is_start, inclusive in boundaries:
        if endpoint is None:
            continue
        comparison = compare_strict_dotted_numeric(
            component_raw,
            endpoint,
        )
        if comparison is DottedNumericComparison.UNSUPPORTED:
            return VersionMatchResult.UNSUPPORTED_VERSION_COMPARISON
        comparisons.append((comparison, is_start, inclusive))

    return (
        VersionMatchResult.MATCH
        if all(
            _satisfies_boundary(
                comparison,
                is_start=is_start,
                inclusive=inclusive,
            )
            for comparison, is_start, inclusive in comparisons
        )
        else VersionMatchResult.NO_MATCH
    )

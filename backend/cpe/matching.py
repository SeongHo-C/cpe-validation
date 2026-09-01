"""Directional CPE 2.3 logical attribute matching.

The NVD criteria CPE is the source pattern and the component CPE is the
target. Parsing and formatted-string decoding are delegated to the project
canonical parser; this module never splits a CPE string itself.

The relation model follows NISTIR 7696 name matching: a source name matches a
target when every included source attribute is EQUAL to or a SUPERSET of the
target attribute. Target-side unquoted wildcards are UNDEFINED, and WFN string
comparison is case-insensitive for every attribute. The separate RQ3 version
range comparator remains outside this module's NIST WFN matching scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from cpe.cpe23 import CPE23_ATTRIBUTE_NAMES
from cpe.cpe23_canonical import (
    CPE23Attribute,
    CPE23Name,
    CPE23ValueKind,
    parse_cpe23,
)


class AttributeRelation(str, Enum):
    EQUAL = "EQUAL"
    SUPERSET = "SUPERSET"
    SUBSET = "SUBSET"
    DISJOINT = "DISJOINT"
    UNDEFINED = "UNDEFINED"


class CPEAttributeMatchStatus(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    INVALID_CRITERIA_CPE = "INVALID_CRITERIA_CPE"
    INVALID_COMPONENT_CPE = "INVALID_COMPONENT_CPE"


@dataclass(frozen=True)
class AttributeComparison:
    attribute: str
    relation: AttributeRelation


@dataclass(frozen=True)
class CPEAttributeMatchResult:
    status: CPEAttributeMatchStatus
    comparisons: tuple[AttributeComparison, ...]
    ignored_attributes: tuple[str, ...]
    error_message: str = ""

    @property
    def matched(self) -> bool:
        return self.status is CPEAttributeMatchStatus.MATCH


@dataclass(frozen=True)
class _LogicalToken:
    value: str
    wildcard: bool


def _logical_tokens(value: str) -> tuple[_LogicalToken, ...]:
    """Decode WFN quoting while retaining wildcard/literal identity."""

    tokens: list[_LogicalToken] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character == "\\":
            index += 1
            if index >= len(value):
                raise ValueError("Canonical CPE attribute has an incomplete escape")
            tokens.append(_LogicalToken(value[index], False))
        else:
            tokens.append(
                _LogicalToken(
                    character,
                    character in {"*", "?"},
                )
            )
        index += 1
    return tuple(tokens)


def _contains_wildcard(tokens: tuple[_LogicalToken, ...]) -> bool:
    return any(token.wildcard for token in tokens)


def _literal_value(
    tokens: tuple[_LogicalToken, ...],
    *,
    case_sensitive: bool,
) -> str:
    value = "".join(token.value for token in tokens)
    return value if case_sensitive else value.lower()


def _source_pattern_matches(
    source_tokens: tuple[_LogicalToken, ...],
    target_tokens: tuple[_LogicalToken, ...],
    *,
    case_sensitive: bool,
) -> bool:
    pattern_parts: list[str] = []
    for token in source_tokens:
        if token.wildcard and token.value == "*":
            pattern_parts.append(".*")
        elif token.wildcard and token.value == "?":
            # NISTIR 7696 section 6.3: zero or one target characters.
            pattern_parts.append(".?")
        else:
            pattern_parts.append(re.escape(token.value))
    target = _literal_value(
        target_tokens,
        case_sensitive=case_sensitive,
    )
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.fullmatch("".join(pattern_parts), target, flags=flags) is not None


def compare_cpe_attribute_values(
    source: CPE23Attribute,
    target: CPE23Attribute,
    *,
    case_sensitive: bool = False,
) -> AttributeRelation:
    """Return the directional WFN relation from source to target."""

    source_tokens = (
        _logical_tokens(source.canonical)
        if source.kind is CPE23ValueKind.STRING
        else ()
    )
    target_tokens = (
        _logical_tokens(target.canonical)
        if target.kind is CPE23ValueKind.STRING
        else ()
    )

    # Per CPE Name Matching, target-side unquoted wildcards are undefined.
    if target_tokens and _contains_wildcard(target_tokens):
        return AttributeRelation.UNDEFINED

    if source.kind is target.kind:
        if source.kind in {CPE23ValueKind.ANY, CPE23ValueKind.NA}:
            return AttributeRelation.EQUAL
        if not _contains_wildcard(source_tokens):
            source_value = _literal_value(
                source_tokens,
                case_sensitive=case_sensitive,
            )
            target_value = _literal_value(
                target_tokens,
                case_sensitive=case_sensitive,
            )
            return (
                AttributeRelation.EQUAL
                if source_value == target_value
                else AttributeRelation.DISJOINT
            )

    if source.kind is CPE23ValueKind.ANY:
        return AttributeRelation.SUPERSET
    if target.kind is CPE23ValueKind.ANY:
        return AttributeRelation.SUBSET
    if (
        source.kind is CPE23ValueKind.NA
        or target.kind is CPE23ValueKind.NA
    ):
        return AttributeRelation.DISJOINT

    if _contains_wildcard(source_tokens):
        return (
            AttributeRelation.SUPERSET
            if _source_pattern_matches(
                source_tokens,
                target_tokens,
                case_sensitive=case_sensitive,
            )
            else AttributeRelation.DISJOINT
        )
    return AttributeRelation.DISJOINT


def _parse_name(
    value: str | CPE23Name,
) -> tuple[CPE23Name | None, str]:
    if isinstance(value, CPE23Name):
        return value, ""
    parsed = parse_cpe23(value)
    if parsed.is_valid and parsed.name is not None:
        return parsed.name, ""
    return None, parsed.error_message or parsed.status.value


def match_cpe_attributes(
    criteria_cpe: str | CPE23Name,
    component_cpe: str | CPE23Name,
    *,
    ignore_version: bool = False,
) -> CPEAttributeMatchResult:
    """Match an NVD criteria source against a component target.

    All 11 CPE attributes are evaluated by default. For an NVD leaf carrying
    a version range, callers must set ``ignore_version=True`` and route the
    version through ``match_version_constraint`` separately.
    """

    criteria, error = _parse_name(criteria_cpe)
    ignored = ("version",) if ignore_version else ()
    if criteria is None:
        return CPEAttributeMatchResult(
            CPEAttributeMatchStatus.INVALID_CRITERIA_CPE,
            (),
            ignored,
            error,
        )

    component, error = _parse_name(component_cpe)
    if component is None:
        return CPEAttributeMatchResult(
            CPEAttributeMatchStatus.INVALID_COMPONENT_CPE,
            (),
            ignored,
            error,
        )

    comparisons = tuple(
        AttributeComparison(
            attribute,
            compare_cpe_attribute_values(
                criteria.attribute(attribute),
                component.attribute(attribute),
            ),
        )
        for attribute in CPE23_ATTRIBUTE_NAMES
        if not (ignore_version and attribute == "version")
    )
    matched = all(
        comparison.relation
        in {AttributeRelation.EQUAL, AttributeRelation.SUPERSET}
        for comparison in comparisons
    )
    return CPEAttributeMatchResult(
        (
            CPEAttributeMatchStatus.MATCH
            if matched
            else CPEAttributeMatchStatus.NO_MATCH
        ),
        comparisons,
        ignored,
    )

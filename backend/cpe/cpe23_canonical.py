from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from cpe.cpe23 import (
    CPE23_ATTRIBUTE_NAMES,
    parse_cpe23_formatted_string,
)


class CPE23ValueKind(str, Enum):
    ANY = "ANY"
    NA = "NA"
    STRING = "STRING"


class CPE23CanonicalStatus(str, Enum):
    VALID = "VALID"
    INVALID_STRUCTURE = "INVALID_STRUCTURE"
    INVALID_EMPTY_ATTRIBUTE = "INVALID_EMPTY_ATTRIBUTE"
    INVALID_ATTRIBUTE = "INVALID_ATTRIBUTE"


class CPE23CanonicalizationError(ValueError):
    pass


@dataclass(frozen=True)
class CPE23Attribute:
    name: str
    raw: str
    canonical: str
    kind: CPE23ValueKind


@dataclass(frozen=True)
class CPE23Name:
    attributes: tuple[CPE23Attribute, ...]

    def attribute(self, name: str) -> CPE23Attribute:
        try:
            index = CPE23_ATTRIBUTE_NAMES.index(name)
        except ValueError as error:
            raise KeyError(name) from error
        return self.attributes[index]

    @property
    def fields(self) -> dict[str, str]:
        return {
            attribute.name: attribute.canonical
            for attribute in self.attributes
        }

    @property
    def family(self) -> tuple[str, str, str]:
        fields = self.fields
        return fields["part"], fields["vendor"], fields["product"]


@dataclass(frozen=True)
class CPE23CanonicalParseResult:
    raw_cpe: Any
    status: CPE23CanonicalStatus
    name: CPE23Name | None = None
    error_message: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status is CPE23CanonicalStatus.VALID


_UNQUOTED = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-._"
)
_QUOTABLE = frozenset(
    "\\?!\"#$%&'()+,/:;<=>@[]^`{|}~-._*"
)


def _canonicalize_attribute(
    name: str,
    raw: str,
) -> CPE23Attribute:
    if raw == "":
        raise CPE23CanonicalizationError(
            f"{name} is empty; empty, ANY ('*'), and NA ('-') differ"
        )
    if raw == "*":
        return CPE23Attribute(name, raw, "*", CPE23ValueKind.ANY)
    if raw == "-":
        return CPE23Attribute(name, raw, "-", CPE23ValueKind.NA)

    canonical: list[str] = []
    wildcard_positions: list[tuple[int, str]] = []
    logical_position = 0
    index = 0
    while index < len(raw):
        character = raw[index]
        if character == "\\":
            index += 1
            if index >= len(raw):
                raise CPE23CanonicalizationError(
                    f"{name} ends with an incomplete escape"
                )
            quoted = raw[index]
            if quoted not in _QUOTABLE:
                raise CPE23CanonicalizationError(
                    f"{name} contains an invalid quoted character "
                    f"{quoted!r}"
                )
            if quoted in ".-_":
                canonical.append(quoted)
            else:
                canonical.extend(("\\", quoted))
            logical_position += 1
        elif character in _UNQUOTED:
            canonical.append(character)
            logical_position += 1
        elif character in "*?":
            canonical.append(character)
            wildcard_positions.append((logical_position, character))
            logical_position += 1
        else:
            raise CPE23CanonicalizationError(
                f"{name} contains unquoted special character "
                f"{character!r}"
            )
        index += 1

    if wildcard_positions:
        positions = [position for position, _ in wildcard_positions]
        first_non_wildcard = 0
        while (
            first_non_wildcard < logical_position
            and first_non_wildcard in positions
        ):
            first_non_wildcard += 1
        last_non_wildcard = logical_position - 1
        while last_non_wildcard >= 0 and last_non_wildcard in positions:
            last_non_wildcard -= 1
        if any(
            first_non_wildcard <= position <= last_non_wildcard
            for position in positions
        ):
            raise CPE23CanonicalizationError(
                f"{name} contains an embedded unquoted wildcard"
            )
        asterisks = [
            position
            for position, character in wildcard_positions
            if character == "*"
        ]
        if any(
            position not in {0, logical_position - 1}
            for position in asterisks
        ):
            raise CPE23CanonicalizationError(
                f"{name} contains an unquoted '*' away from an endpoint"
            )

    return CPE23Attribute(
        name=name,
        raw=raw,
        canonical="".join(canonical),
        kind=CPE23ValueKind.STRING,
    )


def parse_cpe23(raw_cpe: Any) -> CPE23CanonicalParseResult:
    """Parse and canonicalize a CPE 2.3 formatted-string binding.

    The existing project parser performs the escape-aware 11-field split.
    This wrapper adds formatted-string value validation, explicit ANY/NA
    kinds, and removal of unnecessary quoting for '.', '-', and '_'.
    Percent-encoded URI bindings remain distinct and are rejected here.
    """

    structural = parse_cpe23_formatted_string(raw_cpe)
    if not structural.is_structurally_valid:
        return CPE23CanonicalParseResult(
            raw_cpe=raw_cpe,
            status=CPE23CanonicalStatus.INVALID_STRUCTURE,
            error_message=(
                f"{structural.status.value}: {structural.error_message}"
            ),
        )

    attributes: list[CPE23Attribute] = []
    try:
        for name in CPE23_ATTRIBUTE_NAMES:
            attributes.append(
                _canonicalize_attribute(name, structural.fields[name])
            )
    except CPE23CanonicalizationError as error:
        status = (
            CPE23CanonicalStatus.INVALID_EMPTY_ATTRIBUTE
            if " is empty;" in str(error)
            else CPE23CanonicalStatus.INVALID_ATTRIBUTE
        )
        return CPE23CanonicalParseResult(
            raw_cpe=raw_cpe,
            status=status,
            error_message=str(error),
        )

    return CPE23CanonicalParseResult(
        raw_cpe=raw_cpe,
        status=CPE23CanonicalStatus.VALID,
        name=CPE23Name(tuple(attributes)),
    )


def _require_name(value: str | CPE23Name) -> CPE23Name:
    if isinstance(value, CPE23Name):
        return value
    result = parse_cpe23(value)
    if not result.is_valid or result.name is None:
        raise CPE23CanonicalizationError(
            result.error_message or "Invalid CPE 2.3 formatted string"
        )
    return result.name


def serialize_cpe23(value: str | CPE23Name) -> str:
    name = _require_name(value)
    return "cpe:2.3:" + ":".join(
        attribute.canonical for attribute in name.attributes
    )


def canonicalize_cpe23(raw_cpe: str) -> str:
    return serialize_cpe23(raw_cpe)


def compare_cpe23(left: str | CPE23Name, right: str | CPE23Name) -> bool:
    left_name = _require_name(left)
    right_name = _require_name(right)
    return tuple(
        attribute.canonical for attribute in left_name.attributes
    ) == tuple(
        attribute.canonical for attribute in right_name.attributes
    )


def compare_cpe23_attributes(
    left: str | CPE23Name,
    right: str | CPE23Name,
) -> tuple[str, ...]:
    """Return the ordered names of canonically unequal attributes."""

    left_name = _require_name(left)
    right_name = _require_name(right)
    return tuple(
        attribute_name
        for attribute_name, left_attribute, right_attribute in zip(
            CPE23_ATTRIBUTE_NAMES,
            left_name.attributes,
            right_name.attributes,
            strict=True,
        )
        if left_attribute.canonical != right_attribute.canonical
    )

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


CPE23_PREFIX = "cpe:2.3:"
CPE23_ATTRIBUTE_NAMES = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


class CPE23StructuralStatus(str, Enum):
    STRUCTURALLY_VALID = "STRUCTURALLY_VALID"
    INVALID_PREFIX = "INVALID_PREFIX"
    INVALID_FIELD_COUNT = "INVALID_FIELD_COUNT"
    INVALID_ESCAPE = "INVALID_ESCAPE"
    INVALID_PART = "INVALID_PART"


@dataclass(frozen=True)
class CPE23ParseResult:
    raw_cpe: Any
    status: CPE23StructuralStatus
    error_message: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def is_structurally_valid(self) -> bool:
        return (
            self.status
            is CPE23StructuralStatus.STRUCTURALLY_VALID
        )

    def raw_field(self, attribute_name: str) -> str:
        return self.fields.get(attribute_name, "")

    @property
    def part_raw(self) -> str:
        return self.raw_field("part")

    @property
    def vendor_raw(self) -> str:
        return self.raw_field("vendor")

    @property
    def product_raw(self) -> str:
        return self.raw_field("product")

    @property
    def version_raw(self) -> str:
        return self.raw_field("version")

    @property
    def update_raw(self) -> str:
        return self.raw_field("update")

    @property
    def edition_raw(self) -> str:
        return self.raw_field("edition")

    @property
    def language_raw(self) -> str:
        return self.raw_field("language")

    @property
    def sw_edition_raw(self) -> str:
        return self.raw_field("sw_edition")

    @property
    def target_sw_raw(self) -> str:
        return self.raw_field("target_sw")

    @property
    def target_hw_raw(self) -> str:
        return self.raw_field("target_hw")

    @property
    def other_raw(self) -> str:
        return self.raw_field("other")


def parse_cpe23_formatted_string(raw_cpe: Any) -> CPE23ParseResult:
    """Perform limited structural validation of a CPE 2.3 string.

    This parser preserves bound values exactly as written. It does not
    unescape values and does not claim complete NIST CPE grammar validation.
    """

    if not isinstance(raw_cpe, str) or not raw_cpe.startswith(
        CPE23_PREFIX
    ):
        return CPE23ParseResult(
            raw_cpe=raw_cpe,
            status=CPE23StructuralStatus.INVALID_PREFIX,
            error_message=(
                "CPE must be a string beginning with 'cpe:2.3:'"
            ),
        )

    values: list[str] = []
    current: list[str] = []
    escaped = False
    for character in raw_cpe[len(CPE23_PREFIX) :]:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            current.append(character)
            escaped = True
            continue
        if character == ":":
            values.append("".join(current))
            current = []
            continue
        current.append(character)

    if escaped:
        return CPE23ParseResult(
            raw_cpe=raw_cpe,
            status=CPE23StructuralStatus.INVALID_ESCAPE,
            error_message=(
                "CPE ends with an incomplete escape sequence"
            ),
        )

    values.append("".join(current))
    if len(values) != len(CPE23_ATTRIBUTE_NAMES):
        return CPE23ParseResult(
            raw_cpe=raw_cpe,
            status=CPE23StructuralStatus.INVALID_FIELD_COUNT,
            error_message=(
                "CPE 2.3 formatted string must contain exactly "
                f"{len(CPE23_ATTRIBUTE_NAMES)} attribute fields; "
                f"found {len(values)}"
            ),
        )

    if values[0] not in {"a", "o", "h"}:
        return CPE23ParseResult(
            raw_cpe=raw_cpe,
            status=CPE23StructuralStatus.INVALID_PART,
            error_message=(
                "CPE part must be one of 'a', 'o', or 'h'; "
                f"found {values[0]!r}"
            ),
        )

    return CPE23ParseResult(
        raw_cpe=raw_cpe,
        status=CPE23StructuralStatus.STRUCTURALLY_VALID,
        fields=dict(zip(CPE23_ATTRIBUTE_NAMES, values, strict=True)),
    )

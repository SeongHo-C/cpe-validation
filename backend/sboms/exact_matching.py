from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from cpe_dictionary.snapshot_selection import (
    CpeDictionarySnapshotAmbiguousError,
    CpeDictionarySnapshotSelectionError,
    CpeDictionarySnapshotUnavailableError,
    select_cpe_dictionary_snapshot,
)


class CPEExactMatchStatus(str, Enum):
    OFFICIAL_ACTIVE = "OFFICIAL_ACTIVE"
    OFFICIAL_DEPRECATED = "OFFICIAL_DEPRECATED"
    NOT_IN_DICTIONARY = "NOT_IN_DICTIONARY"
    NOT_PRESENT = "NOT_PRESENT"


class CPEExactMatchIntegrityError(Exception):
    pass


@dataclass(frozen=True)
class CPEExactMatchResult:
    status: CPEExactMatchStatus
    input_cpe: str | None
    snapshot_id: str
    matched_cpe_name_id: str | None
    matched_cpe_name: str | None
    deprecated: bool | None


def _not_present_result(
    raw_cpe: str | None,
    snapshot: CpeDictionarySnapshot,
) -> CPEExactMatchResult:
    return CPEExactMatchResult(
        status=CPEExactMatchStatus.NOT_PRESENT,
        input_cpe=raw_cpe,
        snapshot_id=snapshot.snapshot_id,
        matched_cpe_name_id=None,
        matched_cpe_name=None,
        deprecated=None,
    )


def _not_in_dictionary_result(
    raw_cpe: str,
    snapshot: CpeDictionarySnapshot,
) -> CPEExactMatchResult:
    return CPEExactMatchResult(
        status=CPEExactMatchStatus.NOT_IN_DICTIONARY,
        input_cpe=raw_cpe,
        snapshot_id=snapshot.snapshot_id,
        matched_cpe_name_id=None,
        matched_cpe_name=None,
        deprecated=None,
    )


def _matched_result(
    raw_cpe: str,
    snapshot: CpeDictionarySnapshot,
    cpe_name: CpeName,
) -> CPEExactMatchResult:
    status = (
        CPEExactMatchStatus.OFFICIAL_DEPRECATED
        if cpe_name.deprecated
        else CPEExactMatchStatus.OFFICIAL_ACTIVE
    )
    return CPEExactMatchResult(
        status=status,
        input_cpe=raw_cpe,
        snapshot_id=snapshot.snapshot_id,
        matched_cpe_name_id=str(cpe_name.cpe_name_id),
        matched_cpe_name=cpe_name.cpe_name,
        deprecated=cpe_name.deprecated,
    )


def match_cpes(
    raw_cpes: Iterable[str | None],
    snapshot: CpeDictionarySnapshot,
) -> dict[str | None, CPEExactMatchResult]:
    """Match unique input strings with one exact Dictionary query."""

    unique_inputs = list(dict.fromkeys(raw_cpes))
    lookup_values = [
        raw_cpe
        for raw_cpe in unique_inputs
        if raw_cpe is not None and raw_cpe != ""
    ]
    matched_by_raw_cpe: dict[str, CpeName] = {}
    if lookup_values:
        matched_records = CpeName.objects.filter(
            snapshot=snapshot,
            cpe_name__in=lookup_values,
        ).only(
            "cpe_name_id",
            "cpe_name",
            "deprecated",
        )
        for matched_record in matched_records:
            if matched_record.cpe_name in matched_by_raw_cpe:
                raise CPEExactMatchIntegrityError(
                    "Duplicate CPE Dictionary records returned for "
                    f"snapshot {snapshot.snapshot_id}: "
                    f"{matched_record.cpe_name}"
                )
            matched_by_raw_cpe[
                matched_record.cpe_name
            ] = matched_record

    results: dict[str | None, CPEExactMatchResult] = {}
    for raw_cpe in unique_inputs:
        if raw_cpe is None or raw_cpe == "":
            results[raw_cpe] = _not_present_result(
                raw_cpe,
                snapshot,
            )
            continue
        matched_record = matched_by_raw_cpe.get(raw_cpe)
        if matched_record is None:
            results[raw_cpe] = _not_in_dictionary_result(
                raw_cpe,
                snapshot,
            )
        else:
            results[raw_cpe] = _matched_result(
                raw_cpe,
                snapshot,
                matched_record,
            )
    return results


def match_cpe(
    raw_cpe: str | None,
    snapshot: CpeDictionarySnapshot,
) -> CPEExactMatchResult:
    return match_cpes([raw_cpe], snapshot)[raw_cpe]

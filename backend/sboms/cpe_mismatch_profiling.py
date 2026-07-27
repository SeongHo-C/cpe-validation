from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable

from django.db.models import Count, Q

from cpe.cpe23 import (
    CPE23StructuralStatus,
    parse_cpe23_formatted_string,
)
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from sboms.exact_matching import (
    CPEExactMatchStatus,
    match_cpes,
)
from sboms.models import Component


SCHEMA_VERSION = 1
SUMMARY_FILENAME = "summary.json"
UNIQUE_CPE_MISMATCH_PROFILES_FILENAME = (
    "unique_cpe_mismatch_profiles.csv"
)
FIELD_VALUE_COUNTS_FILENAME = "field_value_counts.json"
OUTPUT_FILENAMES = (
    SUMMARY_FILENAME,
    UNIQUE_CPE_MISMATCH_PROFILES_FILENAME,
    FIELD_VALUE_COUNTS_FILENAME,
)
ANALYSIS_SCOPE = (
    "Exact structured-field presence counts only; not candidate "
    "ranking, semantic correctness, or Ground Truth."
)

PROFILE_FIELDS = (
    "primary_cpe",
    "component_count",
    "structural_status",
    "structural_error_message",
    "part",
    "vendor",
    "product",
    "version",
    "same_part_vendor_product_version_count",
    "same_part_vendor_product_version_active_count",
    "same_part_vendor_product_version_deprecated_count",
    "same_part_vendor_product_count",
    "same_part_vendor_product_active_count",
    "same_part_vendor_product_deprecated_count",
    "same_part_product_count",
    "same_part_product_active_count",
    "same_part_product_deprecated_count",
    "profile_status",
    "snapshot_id",
)

UNPARSABLE_PART_KEY = "<unparsable>"


class CPEMismatchProfileStatus(str, Enum):
    SAME_PART_VENDOR_PRODUCT_VERSION = (
        "SAME_PART_VENDOR_PRODUCT_VERSION"
    )
    SAME_PART_VENDOR_PRODUCT = "SAME_PART_VENDOR_PRODUCT"
    SAME_PART_PRODUCT = "SAME_PART_PRODUCT"
    NO_STRUCTURED_MATCH = "NO_STRUCTURED_MATCH"
    UNPARSABLE = "UNPARSABLE"


class CPEMismatchProfilingError(Exception):
    pass


@dataclass(frozen=True)
class StructuredMatchCounts:
    total: int = 0
    active: int = 0
    deprecated: int = 0

    def add(
        self,
        *,
        total: int,
        active: int,
        deprecated: int,
    ) -> StructuredMatchCounts:
        return StructuredMatchCounts(
            total=self.total + total,
            active=self.active + active,
            deprecated=self.deprecated + deprecated,
        )


@dataclass(frozen=True)
class CPEMismatchProfileAnalysis:
    summary: dict[str, Any]
    unique_cpe_mismatch_profiles: tuple[dict[str, Any], ...]
    field_value_counts: dict[str, Any]


def _profile_status_counter() -> Counter[str]:
    return Counter(
        {
            status.value: 0
            for status in CPEMismatchProfileStatus
        }
    )


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _sorted_counts(counter: Counter[str]) -> dict[str, int]:
    return {
        value: counter[value]
        for value in sorted(counter)
    }


def _classify_profile(
    four_field_counts: StructuredMatchCounts,
    three_field_counts: StructuredMatchCounts,
    two_field_counts: StructuredMatchCounts,
) -> CPEMismatchProfileStatus:
    if four_field_counts.total > 0:
        return (
            CPEMismatchProfileStatus
            .SAME_PART_VENDOR_PRODUCT_VERSION
        )
    if three_field_counts.total > 0:
        return CPEMismatchProfileStatus.SAME_PART_VENDOR_PRODUCT
    if two_field_counts.total > 0:
        return CPEMismatchProfileStatus.SAME_PART_PRODUCT
    return CPEMismatchProfileStatus.NO_STRUCTURED_MATCH


def _aggregate_dictionary_counts(
    snapshot: CpeDictionarySnapshot,
    *,
    raw_mismatch_cpes: set[str],
    four_field_keys: set[tuple[str, str, str, str]],
    three_field_keys: set[tuple[str, str, str]],
    two_field_keys: set[tuple[str, str]],
) -> tuple[
    dict[tuple[str, str, str, str], StructuredMatchCounts],
    dict[tuple[str, str, str], StructuredMatchCounts],
    dict[tuple[str, str], StructuredMatchCounts],
    int,
]:
    """Aggregate all three match levels with one grouped query."""

    if not two_field_keys:
        return {}, {}, {}, 0

    products_by_part: defaultdict[str, set[str]] = defaultdict(set)
    for part, product in two_field_keys:
        products_by_part[part].add(product)

    part_product_filter: Q | None = None
    for part in sorted(products_by_part):
        clause = Q(
            part=part,
            product__in=sorted(products_by_part[part]),
        )
        part_product_filter = (
            clause
            if part_product_filter is None
            else part_product_filter | clause
        )
    if part_product_filter is None:
        raise CPEMismatchProfilingError(
            "Structured Dictionary filter unexpectedly has no keys"
        )

    grouped_rows = (
        CpeName.objects.filter(
            snapshot=snapshot,
        )
        .filter(part_product_filter)
        .values(
            "part",
            "vendor",
            "product",
            "version",
        )
        .annotate(
            total_count=Count("id"),
            active_count=Count(
                "id",
                filter=Q(deprecated=False),
            ),
            deprecated_count=Count(
                "id",
                filter=Q(deprecated=True),
            ),
            raw_exact_count=Count(
                "id",
                filter=Q(cpe_name__in=raw_mismatch_cpes),
            ),
        )
        .order_by()
    )

    four_field_counts: dict[
        tuple[str, str, str, str],
        StructuredMatchCounts,
    ] = {}
    three_field_counts: dict[
        tuple[str, str, str],
        StructuredMatchCounts,
    ] = {}
    two_field_counts: dict[
        tuple[str, str],
        StructuredMatchCounts,
    ] = {}

    for row in grouped_rows:
        if row["raw_exact_count"]:
            raise CPEMismatchProfilingError(
                "A raw exact match was found inside the mismatch "
                "profile population"
            )
        two_field_key = (row["part"], row["product"])
        if two_field_key not in two_field_keys:
            continue
        three_field_key = (
            row["part"],
            row["vendor"],
            row["product"],
        )
        four_field_key = (
            row["part"],
            row["vendor"],
            row["product"],
            row["version"],
        )
        values = {
            "total": row["total_count"],
            "active": row["active_count"],
            "deprecated": row["deprecated_count"],
        }
        two_field_counts[two_field_key] = two_field_counts.get(
            two_field_key,
            StructuredMatchCounts(),
        ).add(**values)
        if three_field_key in three_field_keys:
            three_field_counts[
                three_field_key
            ] = three_field_counts.get(
                three_field_key,
                StructuredMatchCounts(),
            ).add(**values)
        if four_field_key in four_field_keys:
            four_field_counts[
                four_field_key
            ] = four_field_counts.get(
                four_field_key,
                StructuredMatchCounts(),
            ).add(**values)

    return (
        four_field_counts,
        three_field_counts,
        two_field_counts,
        1,
    )


def build_cpe_mismatch_profile_analysis(
    snapshot: CpeDictionarySnapshot,
) -> CPEMismatchProfileAnalysis:
    """Measure field presence without semantic judgment or DB writes."""

    started_at = perf_counter()
    totals = Component.objects.aggregate(
        total_components=Count("id"),
    )
    component_count_rows = (
        Component.objects.exclude(cpe="")
        .exclude(cpe__isnull=True)
        .values("cpe")
        .annotate(component_count=Count("id"))
        .order_by("cpe")
    )
    component_counts = {
        row["cpe"]: row["component_count"]
        for row in component_count_rows
    }

    matches = match_cpes(component_counts, snapshot)
    dictionary_query_count = 1 if component_counts else 0
    unique_exact_status_counts = Counter(
        {
            CPEExactMatchStatus.OFFICIAL_ACTIVE.value: 0,
            CPEExactMatchStatus.OFFICIAL_DEPRECATED.value: 0,
            CPEExactMatchStatus.NOT_IN_DICTIONARY.value: 0,
        }
    )
    mismatch_component_counts: dict[str, int] = {}
    for raw_cpe in sorted(component_counts):
        result = matches[raw_cpe]
        if result.snapshot_id != snapshot.snapshot_id:
            raise CPEMismatchProfilingError(
                "Exact-match snapshot provenance does not match "
                f"{snapshot.snapshot_id}: {result.snapshot_id}"
            )
        if result.status is CPEExactMatchStatus.NOT_PRESENT:
            raise CPEMismatchProfilingError(
                "A non-empty Primary CPE was classified NOT_PRESENT: "
                f"{raw_cpe}"
            )
        unique_exact_status_counts[result.status.value] += 1
        if result.status is CPEExactMatchStatus.NOT_IN_DICTIONARY:
            mismatch_component_counts[raw_cpe] = (
                component_counts[raw_cpe]
            )

    parse_results = {
        raw_cpe: parse_cpe23_formatted_string(raw_cpe)
        for raw_cpe in mismatch_component_counts
    }
    four_field_keys: set[tuple[str, str, str, str]] = set()
    three_field_keys: set[tuple[str, str, str]] = set()
    two_field_keys: set[tuple[str, str]] = set()
    for parse_result in parse_results.values():
        if not parse_result.is_structurally_valid:
            continue
        four_field_keys.add(
            (
                parse_result.part_raw,
                parse_result.vendor_raw,
                parse_result.product_raw,
                parse_result.version_raw,
            )
        )
        three_field_keys.add(
            (
                parse_result.part_raw,
                parse_result.vendor_raw,
                parse_result.product_raw,
            )
        )
        two_field_keys.add(
            (
                parse_result.part_raw,
                parse_result.product_raw,
            )
        )

    (
        four_field_counts,
        three_field_counts,
        two_field_counts,
        structured_query_count,
    ) = _aggregate_dictionary_counts(
        snapshot,
        raw_mismatch_cpes=set(mismatch_component_counts),
        four_field_keys=four_field_keys,
        three_field_keys=three_field_keys,
        two_field_keys=two_field_keys,
    )
    dictionary_query_count += structured_query_count

    profile_status_counts = _profile_status_counter()
    component_weighted_profile_status_counts = (
        _profile_status_counter()
    )
    unique_field_counts = {
        field: Counter()
        for field in ("part", "vendor", "product", "version")
    }
    weighted_field_counts = {
        field: Counter()
        for field in ("part", "vendor", "product", "version")
    }
    profile_status_by_part: defaultdict[
        str,
        Counter[str],
    ] = defaultdict(_profile_status_counter)
    rows: list[dict[str, Any]] = []

    for raw_cpe in sorted(mismatch_component_counts):
        component_count = mismatch_component_counts[raw_cpe]
        parse_result = parse_results[raw_cpe]
        if not parse_result.is_structurally_valid:
            profile_status = CPEMismatchProfileStatus.UNPARSABLE
            part = vendor = product = version = ""
            four_counts = three_counts = two_counts = (
                StructuredMatchCounts()
            )
            part_bucket = UNPARSABLE_PART_KEY
        else:
            part = parse_result.part_raw
            vendor = parse_result.vendor_raw
            product = parse_result.product_raw
            version = parse_result.version_raw
            four_counts = four_field_counts.get(
                (part, vendor, product, version),
                StructuredMatchCounts(),
            )
            three_counts = three_field_counts.get(
                (part, vendor, product),
                StructuredMatchCounts(),
            )
            two_counts = two_field_counts.get(
                (part, product),
                StructuredMatchCounts(),
            )
            profile_status = _classify_profile(
                four_counts,
                three_counts,
                two_counts,
            )
            part_bucket = part
            for field, value in (
                ("part", part),
                ("vendor", vendor),
                ("product", product),
                ("version", version),
            ):
                unique_field_counts[field][value] += 1
                weighted_field_counts[field][value] += component_count

        profile_status_counts[profile_status.value] += 1
        component_weighted_profile_status_counts[
            profile_status.value
        ] += component_count
        profile_status_by_part[part_bucket][
            profile_status.value
        ] += 1
        rows.append(
            {
                "primary_cpe": raw_cpe,
                "component_count": component_count,
                "structural_status": parse_result.status.value,
                "structural_error_message": (
                    parse_result.error_message
                ),
                "part": part,
                "vendor": vendor,
                "product": product,
                "version": version,
                "same_part_vendor_product_version_count": (
                    four_counts.total
                ),
                "same_part_vendor_product_version_active_count": (
                    four_counts.active
                ),
                "same_part_vendor_product_version_deprecated_count": (
                    four_counts.deprecated
                ),
                "same_part_vendor_product_count": (
                    three_counts.total
                ),
                "same_part_vendor_product_active_count": (
                    three_counts.active
                ),
                "same_part_vendor_product_deprecated_count": (
                    three_counts.deprecated
                ),
                "same_part_product_count": two_counts.total,
                "same_part_product_active_count": two_counts.active,
                "same_part_product_deprecated_count": (
                    two_counts.deprecated
                ),
                "profile_status": profile_status.value,
                "snapshot_id": snapshot.snapshot_id,
            }
        )

    rows.sort(
        key=lambda row: (
            row["profile_status"],
            -row["component_count"],
            row["primary_cpe"],
        )
    )
    total_components = totals["total_components"]
    components_with_primary_cpe = sum(component_counts.values())
    unique_primary_cpes = len(component_counts)
    unique_not_in_dictionary = unique_exact_status_counts[
        CPEExactMatchStatus.NOT_IN_DICTIONARY.value
    ]
    component_weighted_not_in_dictionary = sum(
        mismatch_component_counts.values()
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "analysis_scope": ANALYSIS_SCOPE,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_manifest_sha256": snapshot.manifest_sha256,
        "generated_at": _utc_timestamp(),
        "analysis_duration_seconds": round(
            perf_counter() - started_at,
            6,
        ),
        "total_components": total_components,
        "components_with_primary_cpe": components_with_primary_cpe,
        "components_without_primary_cpe": (
            total_components - components_with_primary_cpe
        ),
        "unique_primary_cpes": unique_primary_cpes,
        "unique_official_active": unique_exact_status_counts[
            CPEExactMatchStatus.OFFICIAL_ACTIVE.value
        ],
        "unique_official_deprecated": unique_exact_status_counts[
            CPEExactMatchStatus.OFFICIAL_DEPRECATED.value
        ],
        "unique_not_in_dictionary": unique_not_in_dictionary,
        "profiled_unique_cpes": len(rows),
        "unparsable_unique_cpes": profile_status_counts[
            CPEMismatchProfileStatus.UNPARSABLE.value
        ],
        "component_weighted_not_in_dictionary": (
            component_weighted_not_in_dictionary
        ),
        "profile_status_counts": dict(profile_status_counts),
        "component_weighted_profile_status_counts": dict(
            component_weighted_profile_status_counts
        ),
        "dictionary_record_count": snapshot.record_count,
        "dictionary_active_count": snapshot.active_count,
        "dictionary_deprecated_count": snapshot.deprecated_count,
        "unique_part_vendor_product_version_keys": len(
            four_field_keys
        ),
        "unique_part_vendor_product_keys": len(
            three_field_keys
        ),
        "unique_part_product_keys": len(two_field_keys),
        "dictionary_query_count": dictionary_query_count,
        "field_value_counts_truncated": False,
    }
    field_value_counts = {
        "schema_version": SCHEMA_VERSION,
        "analysis_scope": ANALYSIS_SCOPE,
        "snapshot_id": snapshot.snapshot_id,
        "field_value_counts_truncated": False,
        "unique_cpe_counts": {
            field: _sorted_counts(counter)
            for field, counter in unique_field_counts.items()
        },
        "component_weighted_counts": {
            field: _sorted_counts(counter)
            for field, counter in weighted_field_counts.items()
        },
        "profile_status_by_part": {
            part: dict(profile_status_by_part[part])
            for part in sorted(profile_status_by_part)
        },
    }
    analysis = CPEMismatchProfileAnalysis(
        summary=summary,
        unique_cpe_mismatch_profiles=tuple(rows),
        field_value_counts=field_value_counts,
    )
    validate_cpe_mismatch_profile_analysis(analysis)
    return analysis


def validate_cpe_mismatch_profile_analysis(
    analysis: CPEMismatchProfileAnalysis,
) -> None:
    summary = analysis.summary
    rows = analysis.unique_cpe_mismatch_profiles
    failures: list[str] = []
    if (
        summary["unique_official_active"]
        + summary["unique_official_deprecated"]
        + summary["unique_not_in_dictionary"]
        != summary["unique_primary_cpes"]
    ):
        failures.append(
            "unique exact-match status counts != unique_primary_cpes"
        )
    if (
        sum(summary["profile_status_counts"].values())
        != summary["unique_not_in_dictionary"]
    ):
        failures.append(
            "sum(profile_status_counts) != unique_not_in_dictionary"
        )
    if (
        sum(
            summary[
                "component_weighted_profile_status_counts"
            ].values()
        )
        != summary["component_weighted_not_in_dictionary"]
    ):
        failures.append(
            "sum(component_weighted_profile_status_counts) != "
            "component_weighted_not_in_dictionary"
        )
    if len(rows) != summary["profiled_unique_cpes"]:
        failures.append("profile row count != profiled_unique_cpes")
    if len(rows) != summary["unique_not_in_dictionary"]:
        failures.append(
            "profile row count != unique_not_in_dictionary"
        )
    if (
        summary["components_with_primary_cpe"]
        + summary["components_without_primary_cpe"]
        != summary["total_components"]
    ):
        failures.append(
            "Primary CPE component counts != total_components"
        )
    if len({row["primary_cpe"] for row in rows}) != len(rows):
        failures.append("duplicate Primary CPE profile rows")
    expected_order = sorted(
        rows,
        key=lambda row: (
            row["profile_status"],
            -row["component_count"],
            row["primary_cpe"],
        ),
    )
    if list(rows) != expected_order:
        failures.append("profile rows are not deterministically sorted")

    for row in rows:
        if row["snapshot_id"] != summary["snapshot_id"]:
            failures.append(
                "profile row snapshot provenance mismatch: "
                f"{row['primary_cpe']}"
            )
        four_counts = StructuredMatchCounts(
            total=row[
                "same_part_vendor_product_version_count"
            ],
            active=row[
                "same_part_vendor_product_version_active_count"
            ],
            deprecated=row[
                "same_part_vendor_product_version_deprecated_count"
            ],
        )
        three_counts = StructuredMatchCounts(
            total=row["same_part_vendor_product_count"],
            active=row["same_part_vendor_product_active_count"],
            deprecated=row[
                "same_part_vendor_product_deprecated_count"
            ],
        )
        two_counts = StructuredMatchCounts(
            total=row["same_part_product_count"],
            active=row["same_part_product_active_count"],
            deprecated=row[
                "same_part_product_deprecated_count"
            ],
        )
        for label, counts in (
            ("four-field", four_counts),
            ("three-field", three_counts),
            ("two-field", two_counts),
        ):
            if counts.total != counts.active + counts.deprecated:
                failures.append(
                    f"{label} total != active + deprecated: "
                    f"{row['primary_cpe']}"
                )
        if not (
            four_counts.total
            <= three_counts.total
            <= two_counts.total
        ):
            failures.append(
                "structured count hierarchy violated: "
                f"{row['primary_cpe']}"
            )
        if (
            row["structural_status"]
            == CPE23StructuralStatus.STRUCTURALLY_VALID.value
        ):
            expected_status = _classify_profile(
                four_counts,
                three_counts,
                two_counts,
            ).value
        else:
            expected_status = (
                CPEMismatchProfileStatus.UNPARSABLE.value
            )
        if row["profile_status"] != expected_status:
            failures.append(
                "profile status does not match structured counts: "
                f"{row['primary_cpe']}"
            )

    if (
        analysis.field_value_counts["snapshot_id"]
        != summary["snapshot_id"]
    ):
        failures.append(
            "field-value snapshot provenance mismatch"
        )
    if failures:
        raise CPEMismatchProfilingError("; ".join(failures))


def _render_csv(
    fieldnames: tuple[str, ...],
    rows: Iterable[dict[str, Any]],
) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=fieldnames,
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def render_cpe_mismatch_profile_analysis(
    analysis: CPEMismatchProfileAnalysis,
) -> dict[str, str]:
    validate_cpe_mismatch_profile_analysis(analysis)
    return {
        SUMMARY_FILENAME: (
            json.dumps(
                analysis.summary,
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ),
        UNIQUE_CPE_MISMATCH_PROFILES_FILENAME: _render_csv(
            PROFILE_FIELDS,
            analysis.unique_cpe_mismatch_profiles,
        ),
        FIELD_VALUE_COUNTS_FILENAME: (
            json.dumps(
                analysis.field_value_counts,
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ),
    }


def write_cpe_mismatch_profile_analysis(
    analysis: CPEMismatchProfileAnalysis,
    output_directory: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, ...]:
    """Atomically write known outputs, refusing replacement by default."""

    output_paths = tuple(
        output_directory / filename
        for filename in OUTPUT_FILENAMES
    )
    existing_paths = [
        path for path in output_paths if path.exists()
    ]
    if existing_paths and not overwrite:
        raise CPEMismatchProfilingError(
            "Refusing to overwrite existing mismatch profile "
            "output(s): "
            + ", ".join(str(path) for path in existing_paths)
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    rendered = render_cpe_mismatch_profile_analysis(analysis)
    temporary_paths: dict[str, Path] = {}
    try:
        for filename in OUTPUT_FILENAMES:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{filename}.",
                suffix=".tmp",
                dir=output_directory,
            )
            temporary_path = Path(temporary_name)
            temporary_paths[filename] = temporary_path
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="",
            ) as stream:
                stream.write(rendered[filename])
                stream.flush()
                os.fsync(stream.fileno())

        for filename, output_path in zip(
            OUTPUT_FILENAMES,
            output_paths,
            strict=True,
        ):
            os.replace(temporary_paths[filename], output_path)
        return output_paths
    finally:
        for temporary_path in temporary_paths.values():
            temporary_path.unlink(missing_ok=True)

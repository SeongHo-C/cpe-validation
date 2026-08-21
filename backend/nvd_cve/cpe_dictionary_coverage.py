from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from django.db import connection, transaction

from cpe.cpe23 import CPE23StructuralStatus, parse_cpe23_formatted_string
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from cpe_dictionary.snapshot_selection import select_cpe_dictionary_snapshot
from nvd_cve.cpe_match_analysis import _collect_database_state
from nvd_cve.models import NvdCpeMatch, NvdCveRecord, NvdCveSnapshot
from nvd_cve.snapshot_selection import select_nvd_cve_snapshot


ANALYSIS_SCOPE = (
    "Read-only raw-string exact and raw part/vendor/product tuple coverage "
    "analysis between active COMPLETE NVD CVE and CPE Dictionary snapshots. "
    "A distinct criteria string is called a distinct Configuration "
    "criteria expression, not a unique CPE. No normalization, deprecated "
    "replacement traversal, range evaluation, or applicability matching "
    "is performed."
)
SUMMARY_FILENAME = "summary.json"
REPORT_FILENAME = "report.md"
CRITERIA_COVERAGE_FILENAME = "criteria_coverage.csv.gz"
OUTPUT_FILENAMES = (
    SUMMARY_FILENAME,
    REPORT_FILENAME,
    CRITERIA_COVERAGE_FILENAME,
)
STREAM_CHUNK_SIZE = 2_000
TOP_TUPLE_LIMIT = 30

EXACT_PRESENT = "EXACT_PRESENT"
EXACT_ABSENT_TUPLE_PRESENT = (
    "EXACT_ABSENT_SAME_PRODUCT_TUPLE_PRESENT"
)
EXACT_ABSENT_TUPLE_ABSENT = (
    "EXACT_ABSENT_SAME_PRODUCT_TUPLE_ABSENT"
)
COVERAGE_CLASSES = (
    EXACT_PRESENT,
    EXACT_ABSENT_TUPLE_PRESENT,
    EXACT_ABSENT_TUPLE_ABSENT,
)
RANGE_USAGE_PATTERNS = (
    "NO_RANGE_ONLY",
    "RANGE_ONLY",
    "BOTH_RANGE_AND_NO_RANGE",
)
VULNERABLE_USAGE_GROUPS = (
    "TRUE_ONLY",
    "FALSE_ONLY",
    "BOTH_TRUE_AND_FALSE",
)
CRITERIA_FORMS = (
    "CONCRETE",
    "WILDCARD_NO_RANGE",
    "WILDCARD_RANGE",
    "WILDCARD_BOTH",
    "HYPHEN",
    "OTHER",
)
PART_GROUPS = ("a", "o", "h", "other")
ROLLUP_KEYS = (
    "EXACT_PRESENT",
    "EXACT_ABSENT",
    "SAME_PRODUCT_TUPLE_PRESENT",
    "SAME_PRODUCT_TUPLE_ABSENT",
)
REPRESENTATIVE_LIMITS = {
    EXACT_PRESENT: 10,
    EXACT_ABSENT_TUPLE_PRESENT: 20,
    EXACT_ABSENT_TUPLE_ABSENT: 30,
}
CSV_FIELDS = (
    "criteria",
    "criteria_structural_status",
    "part",
    "vendor",
    "product",
    "version",
    "version_category",
    "occurrence_count",
    "distinct_cve_count",
    "vulnerable_true_count",
    "vulnerable_false_count",
    "vulnerable_usage_group",
    "range_usage_pattern",
    "exact_present",
    "exact_dictionary_status",
    "same_product_tuple_present",
    "tuple_dictionary_count",
    "tuple_active_count",
    "tuple_deprecated_count",
    "tuple_status_composition",
    "final_coverage_class",
    "nvd_snapshot_id",
    "cpe_dictionary_snapshot_id",
)


class NvdCpeDictionaryCoverageError(Exception):
    """The read-only coverage analysis could not be completed safely."""


@dataclass(frozen=True, slots=True)
class DictionaryTupleStats:
    dictionary_count: int
    active_count: int
    deprecated_count: int

    @property
    def status_composition(self) -> str:
        if self.active_count and self.deprecated_count:
            return "MIXED_ACTIVE_AND_DEPRECATED"
        if self.active_count:
            return "ACTIVE_ONLY"
        if self.deprecated_count:
            return "DEPRECATED_ONLY"
        return "EMPTY_OR_UNEXPECTED"


@dataclass(frozen=True, slots=True)
class CriteriaAggregate:
    criteria: str
    occurrence_count: int
    distinct_cve_count: int
    vulnerable_true_count: int
    vulnerable_false_count: int
    has_range: bool
    has_no_range: bool


@dataclass(frozen=True, slots=True)
class ClassificationKey:
    coverage_class: str
    criteria_form: str
    version_category: str
    range_usage_pattern: str
    vulnerable_usage_group: str
    part_group: str
    product_tuple: tuple[str, str, str] | None


@dataclass(slots=True)
class MutableMetric:
    distinct_criteria_expression_count: int = 0
    occurrence_count: int = 0
    distinct_cve_count: int = 0

    def add_expression(self, occurrence_count: int) -> None:
        self.distinct_criteria_expression_count += 1
        self.occurrence_count += occurrence_count

    def as_dict(self) -> dict[str, int]:
        return {
            "distinct_criteria_expression_count": (
                self.distinct_criteria_expression_count
            ),
            "occurrence_count": self.occurrence_count,
            "distinct_cve_count": self.distinct_cve_count,
        }


@dataclass(slots=True)
class MutableTupleUsage:
    part: str
    vendor: str
    product: str
    distinct_criteria_expression_count: int = 0
    occurrence_count: int = 0
    distinct_cve_count: int = 0
    vulnerable_true_count: int = 0
    vulnerable_false_count: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "part": self.part,
            "vendor": self.vendor,
            "product": self.product,
            "distinct_criteria_expression_count": (
                self.distinct_criteria_expression_count
            ),
            "occurrence_count": self.occurrence_count,
            "distinct_cve_count": self.distinct_cve_count,
            "vulnerable_true_count": self.vulnerable_true_count,
            "vulnerable_false_count": self.vulnerable_false_count,
        }


@dataclass(frozen=True)
class NvdCpeDictionaryCoverageAnalysis:
    summary: dict[str, Any]
    staged_criteria_coverage_path: Path


class _TopRows:
    def __init__(self, limit: int, key: Any) -> None:
        self.limit = limit
        self.key = key
        self.rows: list[dict[str, Any]] = []

    def add(self, row: dict[str, Any]) -> None:
        self.rows.append(row)
        self.rows.sort(key=self.key)
        del self.rows[self.limit :]


class _RepresentativeCollector:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.by_occurrence = _TopRows(
            limit,
            lambda row: (
                -row["occurrence_count"],
                -row["distinct_cve_count"],
                row["criteria"],
            ),
        )
        self.by_cve = _TopRows(
            limit,
            lambda row: (
                -row["distinct_cve_count"],
                -row["occurrence_count"],
                row["criteria"],
            ),
        )
        self.by_true = _TopRows(
            3,
            lambda row: (
                -row["vulnerable_true_count"],
                -row["occurrence_count"],
                row["criteria"],
            ),
        )
        self.by_false = _TopRows(
            3,
            lambda row: (
                -row["vulnerable_false_count"],
                -row["occurrence_count"],
                row["criteria"],
            ),
        )
        self.by_form = {
            form: _TopRows(
                1,
                lambda row: (
                    -row["occurrence_count"],
                    -row["distinct_cve_count"],
                    row["criteria"],
                ),
            )
            for form in CRITERIA_FORMS
        }
        self.by_part = {
            part: _TopRows(
                1,
                lambda row: (
                    -row["occurrence_count"],
                    -row["distinct_cve_count"],
                    row["criteria"],
                ),
            )
            for part in PART_GROUPS
        }
        self.by_exact_status = {
            status: _TopRows(
                1,
                lambda row: (
                    -row["occurrence_count"],
                    -row["distinct_cve_count"],
                    row["criteria"],
                ),
            )
            for status in ("ACTIVE", "DEPRECATED")
        }
        self.by_tuple_composition = {
            composition: _TopRows(
                1,
                lambda row: (
                    -row["occurrence_count"],
                    -row["distinct_cve_count"],
                    row["criteria"],
                ),
            )
            for composition in (
                "ACTIVE_ONLY",
                "DEPRECATED_ONLY",
                "MIXED_ACTIVE_AND_DEPRECATED",
                "ABSENT",
            )
        }

    def add(self, row: dict[str, Any]) -> None:
        copied = row.copy()
        self.by_occurrence.add(copied)
        self.by_cve.add(copied)
        self.by_true.add(copied)
        self.by_false.add(copied)
        self.by_form[row["criteria_form"]].add(copied)
        self.by_part[row["part_group"]].add(copied)
        exact_status = row["exact_dictionary_status"]
        if exact_status:
            self.by_exact_status[exact_status].add(copied)
        self.by_tuple_composition[
            row["tuple_status_composition"]
        ].add(copied)

    def selected(self) -> list[dict[str, Any]]:
        candidates = [
            *self.by_occurrence.rows[:5],
            *self.by_cve.rows[:3],
            *self.by_true.rows[:2],
            *self.by_false.rows[:2],
            *(
                collector.rows[0]
                for form in CRITERIA_FORMS
                if (collector := self.by_form[form]).rows
            ),
            *(
                collector.rows[0]
                for part in PART_GROUPS
                if (collector := self.by_part[part]).rows
            ),
            *(
                collector.rows[0]
                for status in ("ACTIVE", "DEPRECATED")
                if (collector := self.by_exact_status[status]).rows
            ),
            *(
                collector.rows[0]
                for composition in (
                    "ACTIVE_ONLY",
                    "DEPRECATED_ONLY",
                    "MIXED_ACTIVE_AND_DEPRECATED",
                    "ABSENT",
                )
                if (
                    collector := self.by_tuple_composition[composition]
                ).rows
            ),
            *self.by_occurrence.rows,
            *self.by_cve.rows,
        ]
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in candidates:
            if row["criteria"] in seen:
                continue
            selected.append(row)
            seen.add(row["criteria"])
            if len(selected) == self.limit:
                break
        return selected


class _Metrics:
    def __init__(self) -> None:
        self.cells: defaultdict[
            tuple[str, str, str], MutableMetric
        ] = defaultdict(MutableMetric)
        self.rollups: defaultdict[
            tuple[str, str, str], MutableMetric
        ] = defaultdict(MutableMetric)
        self.group_cve_counts: Counter[tuple[str, str]] = Counter()

    @staticmethod
    def dimensions(key: ClassificationKey) -> tuple[tuple[str, str], ...]:
        return (
            ("overall", "ALL"),
            ("criteria_form", key.criteria_form),
            ("vulnerable_usage", key.vulnerable_usage_group),
            ("part", key.part_group),
        )

    @staticmethod
    def rollup_keys(coverage_class: str) -> tuple[str, ...]:
        if coverage_class == EXACT_PRESENT:
            return ("EXACT_PRESENT",)
        if coverage_class == EXACT_ABSENT_TUPLE_PRESENT:
            return ("EXACT_ABSENT", "SAME_PRODUCT_TUPLE_PRESENT")
        return ("EXACT_ABSENT", "SAME_PRODUCT_TUPLE_ABSENT")

    def add_expression(
        self,
        key: ClassificationKey,
        occurrence_count: int,
    ) -> None:
        for dimension, group in self.dimensions(key):
            self.cells[
                (dimension, group, key.coverage_class)
            ].add_expression(occurrence_count)
            for rollup in self.rollup_keys(key.coverage_class):
                self.rollups[
                    (dimension, group, rollup)
                ].add_expression(occurrence_count)

    def add_cve(
        self,
        cell_keys: set[tuple[str, str, str]],
        group_keys: set[tuple[str, str]],
        rollup_keys: set[tuple[str, str, str]],
    ) -> None:
        for key in cell_keys:
            self.cells[key].distinct_cve_count += 1
        for key in group_keys:
            self.group_cve_counts[key] += 1
        for key in rollup_keys:
            self.rollups[key].distinct_cve_count += 1


_stream_number = 0


def _quoted_table(model: type[Any]) -> str:
    return connection.ops.quote_name(model._meta.db_table)


def _stream_query(
    sql: str,
    params: Sequence[Any],
) -> Iterator[tuple[Any, ...]]:
    global _stream_number

    raw_connection = connection.connection
    if raw_connection is None:
        raise NvdCpeDictionaryCoverageError(
            "Database connection is unavailable."
        )
    _stream_number += 1
    with raw_connection.cursor(
        name=f"nvd_cpe_dictionary_coverage_{_stream_number}"
    ) as cursor:
        cursor.itersize = STREAM_CHUNK_SIZE
        cursor.execute(sql, params)
        while rows := cursor.fetchmany(STREAM_CHUNK_SIZE):
            yield from rows


def _rate(count: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(count * 100.0 / total, 8)


def _range_usage_pattern(
    has_range: bool,
    has_no_range: bool,
) -> str:
    if has_range and has_no_range:
        return "BOTH_RANGE_AND_NO_RANGE"
    if has_range:
        return "RANGE_ONLY"
    if has_no_range:
        return "NO_RANGE_ONLY"
    raise NvdCpeDictionaryCoverageError(
        "A criteria expression has neither range nor no-range usage."
    )


def _vulnerable_usage_group(true_count: int, false_count: int) -> str:
    if true_count and false_count:
        return "BOTH_TRUE_AND_FALSE"
    if true_count:
        return "TRUE_ONLY"
    if false_count:
        return "FALSE_ONLY"
    raise NvdCpeDictionaryCoverageError(
        "A criteria expression has no vulnerable usage."
    )


def _version_category(version: str | None) -> str:
    if version == "*":
        return "STAR"
    if version == "-":
        return "HYPHEN"
    if version not in {None, ""}:
        return "CONCRETE"
    return "OTHER"


def _criteria_form(version_category: str, range_pattern: str) -> str:
    if version_category == "CONCRETE":
        return "CONCRETE"
    if version_category == "HYPHEN":
        return "HYPHEN"
    if version_category == "STAR":
        return {
            "NO_RANGE_ONLY": "WILDCARD_NO_RANGE",
            "RANGE_ONLY": "WILDCARD_RANGE",
            "BOTH_RANGE_AND_NO_RANGE": "WILDCARD_BOTH",
        }[range_pattern]
    return "OTHER"


def classify_criteria_expression(
    aggregate: CriteriaAggregate,
    *,
    exact_deprecated: bool | None,
    dictionary_tuples: dict[
        tuple[str, str, str], DictionaryTupleStats
    ],
) -> tuple[dict[str, Any], ClassificationKey]:
    parsed = parse_cpe23_formatted_string(aggregate.criteria)
    if parsed.is_structurally_valid:
        part = parsed.part_raw
        vendor = parsed.vendor_raw
        product = parsed.product_raw
        version = parsed.version_raw
        product_tuple: tuple[str, str, str] | None = (
            part,
            vendor,
            product,
        )
        tuple_stats = dictionary_tuples.get(product_tuple)
    else:
        part = ""
        vendor = ""
        product = ""
        version = ""
        product_tuple = None
        tuple_stats = None

    exact_present = exact_deprecated is not None
    if exact_present and tuple_stats is None:
        raise NvdCpeDictionaryCoverageError(
            "An exact Dictionary CPE lacks its parsed product tuple."
        )
    if exact_present:
        coverage_class = EXACT_PRESENT
        exact_status = "DEPRECATED" if exact_deprecated else "ACTIVE"
    elif tuple_stats is not None:
        coverage_class = EXACT_ABSENT_TUPLE_PRESENT
        exact_status = ""
    else:
        coverage_class = EXACT_ABSENT_TUPLE_ABSENT
        exact_status = ""

    range_pattern = _range_usage_pattern(
        aggregate.has_range,
        aggregate.has_no_range,
    )
    vulnerable_group = _vulnerable_usage_group(
        aggregate.vulnerable_true_count,
        aggregate.vulnerable_false_count,
    )
    version_category = _version_category(version)
    criteria_form = _criteria_form(version_category, range_pattern)
    part_group = part if part in {"a", "o", "h"} else "other"
    row = {
        "criteria": aggregate.criteria,
        "criteria_structural_status": parsed.status.value,
        "part": part,
        "vendor": vendor,
        "product": product,
        "version": version,
        "version_category": version_category,
        "criteria_form": criteria_form,
        "part_group": part_group,
        "occurrence_count": aggregate.occurrence_count,
        "distinct_cve_count": aggregate.distinct_cve_count,
        "vulnerable_true_count": aggregate.vulnerable_true_count,
        "vulnerable_false_count": aggregate.vulnerable_false_count,
        "vulnerable_usage_group": vulnerable_group,
        "range_usage_pattern": range_pattern,
        "exact_present": exact_present,
        "exact_dictionary_status": exact_status,
        "same_product_tuple_present": tuple_stats is not None,
        "tuple_dictionary_count": (
            tuple_stats.dictionary_count if tuple_stats else 0
        ),
        "tuple_active_count": tuple_stats.active_count if tuple_stats else 0,
        "tuple_deprecated_count": (
            tuple_stats.deprecated_count if tuple_stats else 0
        ),
        "tuple_status_composition": (
            tuple_stats.status_composition if tuple_stats else "ABSENT"
        ),
        "final_coverage_class": coverage_class,
    }
    key = ClassificationKey(
        coverage_class=coverage_class,
        criteria_form=criteria_form,
        version_category=version_category,
        range_usage_pattern=range_pattern,
        vulnerable_usage_group=vulnerable_group,
        part_group=part_group,
        product_tuple=product_tuple,
    )
    return row, key


def _load_dictionary_tuples(
    snapshot: CpeDictionarySnapshot,
) -> tuple[
    dict[tuple[str, str, str], DictionaryTupleStats],
    dict[str, int],
]:
    table = _quoted_table(CpeName)
    sql = f"""
        SELECT
            part,
            vendor,
            product,
            COUNT(*) AS dictionary_count,
            COUNT(*) FILTER (WHERE deprecated IS FALSE) AS active_count,
            COUNT(*) FILTER (WHERE deprecated IS TRUE) AS deprecated_count
        FROM {table}
        WHERE snapshot_id = %s
        GROUP BY part, vendor, product
        ORDER BY part, vendor, product
    """
    tuples: dict[tuple[str, str, str], DictionaryTupleStats] = {}
    totals = {
        "dictionary_count": 0,
        "active_count": 0,
        "deprecated_count": 0,
    }
    for part, vendor, product, count, active, deprecated in _stream_query(
        sql, [snapshot.pk]
    ):
        stats = DictionaryTupleStats(
            dictionary_count=count,
            active_count=active,
            deprecated_count=deprecated,
        )
        if active + deprecated != count:
            raise NvdCpeDictionaryCoverageError(
                "Dictionary tuple active/deprecated counts do not sum."
            )
        tuples[(part, vendor, product)] = stats
        totals["dictionary_count"] += count
        totals["active_count"] += active
        totals["deprecated_count"] += deprecated

    expected = {
        "dictionary_count": snapshot.record_count,
        "active_count": snapshot.active_count,
        "deprecated_count": snapshot.deprecated_count,
    }
    if totals != expected:
        raise NvdCpeDictionaryCoverageError(
            "Dictionary tuple aggregates do not match snapshot metadata."
        )
    return tuples, totals


def _criteria_query(
    nvd_snapshot: NvdCveSnapshot,
    cpe_snapshot: CpeDictionarySnapshot,
) -> Iterator[tuple[Any, ...]]:
    match_table = _quoted_table(NvdCpeMatch)
    record_table = _quoted_table(NvdCveRecord)
    dictionary_table = _quoted_table(CpeName)
    has_range = """
        m.version_start_including IS NOT NULL
        OR m.version_start_excluding IS NOT NULL
        OR m.version_end_including IS NOT NULL
        OR m.version_end_excluding IS NOT NULL
    """
    sql = f"""
        WITH criteria_stats AS MATERIALIZED (
            SELECT
                m.criteria,
                COUNT(*) AS occurrence_count,
                COUNT(DISTINCT m.cve_record_id) AS distinct_cve_count,
                COUNT(*) FILTER (
                    WHERE m.vulnerable IS TRUE
                ) AS vulnerable_true_count,
                COUNT(*) FILTER (
                    WHERE m.vulnerable IS FALSE
                ) AS vulnerable_false_count,
                BOOL_OR({has_range}) AS has_range,
                BOOL_OR(NOT ({has_range})) AS has_no_range
            FROM {match_table} m
            JOIN {record_table} r ON r.id = m.cve_record_id
            WHERE r.snapshot_id = %s
            GROUP BY m.criteria
        )
        SELECT
            stats.criteria,
            stats.occurrence_count,
            stats.distinct_cve_count,
            stats.vulnerable_true_count,
            stats.vulnerable_false_count,
            stats.has_range,
            stats.has_no_range,
            dictionary.id IS NOT NULL AS exact_present,
            dictionary.deprecated AS exact_deprecated
        FROM criteria_stats stats
        LEFT JOIN {dictionary_table} dictionary
          ON dictionary.snapshot_id = %s
         AND dictionary.cpe_name = stats.criteria
        ORDER BY stats.criteria
    """
    return _stream_query(sql, [nvd_snapshot.pk, cpe_snapshot.pk])


def _csv_row(
    row: dict[str, Any],
    *,
    nvd_snapshot_id: str,
    cpe_snapshot_id: str,
) -> dict[str, Any]:
    result = {field: row.get(field, "") for field in CSV_FIELDS}
    result["exact_present"] = str(row["exact_present"]).lower()
    result["same_product_tuple_present"] = str(
        row["same_product_tuple_present"]
    ).lower()
    result["nvd_snapshot_id"] = nvd_snapshot_id
    result["cpe_dictionary_snapshot_id"] = cpe_snapshot_id
    return result


def _create_staged_gzip(staging_directory: Path) -> tuple[int, Path]:
    staging_directory.mkdir(parents=True, exist_ok=True)
    return tempfile.mkstemp(
        dir=staging_directory,
        prefix=".criteria_coverage.",
        suffix=".csv.gz",
    )


def _write_criteria_coverage(
    nvd_snapshot: NvdCveSnapshot,
    cpe_snapshot: CpeDictionarySnapshot,
    dictionary_tuples: dict[
        tuple[str, str, str], DictionaryTupleStats
    ],
    staged_path: Path,
) -> dict[str, Any]:
    metrics = _Metrics()
    lookup: dict[str, ClassificationKey] = {}
    representatives = {
        coverage: _RepresentativeCollector(REPRESENTATIVE_LIMITS[coverage])
        for coverage in COVERAGE_CLASSES
    }
    configuration_only_tuples: dict[
        tuple[str, str, str], MutableTupleUsage
    ] = {}
    exact_status_counts: defaultdict[str, MutableMetric] = defaultdict(
        MutableMetric
    )
    tuple_composition_counts: defaultdict[str, MutableMetric] = defaultdict(
        MutableMetric
    )
    structural_expression_counts: Counter[str] = Counter()
    structural_occurrence_counts: Counter[str] = Counter()
    version_range_exceptions = {
        "CONCRETE_WITH_RANGE": MutableMetric(),
        "HYPHEN_WITH_RANGE": MutableMetric(),
    }
    version_range_exception_samples = {
        "CONCRETE_WITH_RANGE": _TopRows(
            20,
            lambda row: (-row["occurrence_count"], row["criteria"]),
        ),
        "HYPHEN_WITH_RANGE": _TopRows(
            20,
            lambda row: (-row["occurrence_count"], row["criteria"]),
        ),
    }
    row_count = 0

    with staged_path.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_output,
            mtime=0,
        ) as compressed:
            with io.TextIOWrapper(
                compressed,
                encoding="utf-8",
                newline="",
            ) as text_output:
                writer = csv.DictWriter(
                    text_output,
                    fieldnames=CSV_FIELDS,
                    lineterminator="\n",
                )
                writer.writeheader()
                for values in _criteria_query(nvd_snapshot, cpe_snapshot):
                    (
                        criteria,
                        occurrence_count,
                        distinct_cve_count,
                        true_count,
                        false_count,
                        has_range,
                        has_no_range,
                        exact_present,
                        exact_deprecated,
                    ) = values
                    if bool(exact_present) != (exact_deprecated is not None):
                        raise NvdCpeDictionaryCoverageError(
                            "Exact Dictionary join status is inconsistent."
                        )
                    aggregate = CriteriaAggregate(
                        criteria=criteria,
                        occurrence_count=occurrence_count,
                        distinct_cve_count=distinct_cve_count,
                        vulnerable_true_count=true_count,
                        vulnerable_false_count=false_count,
                        has_range=has_range,
                        has_no_range=has_no_range,
                    )
                    row, key = classify_criteria_expression(
                        aggregate,
                        exact_deprecated=exact_deprecated,
                        dictionary_tuples=dictionary_tuples,
                    )
                    writer.writerow(
                        _csv_row(
                            row,
                            nvd_snapshot_id=nvd_snapshot.snapshot_id,
                            cpe_snapshot_id=cpe_snapshot.snapshot_id,
                        )
                    )
                    if criteria in lookup:
                        raise NvdCpeDictionaryCoverageError(
                            "Duplicate criteria expression aggregate."
                        )
                    lookup[criteria] = key
                    metrics.add_expression(key, occurrence_count)
                    representatives[key.coverage_class].add(row)
                    structural_status = row["criteria_structural_status"]
                    structural_expression_counts[structural_status] += 1
                    structural_occurrence_counts[
                        structural_status
                    ] += occurrence_count

                    if row["exact_dictionary_status"]:
                        exact_status_counts[
                            row["exact_dictionary_status"]
                        ].add_expression(occurrence_count)
                    tuple_composition_counts[
                        row["tuple_status_composition"]
                    ].add_expression(occurrence_count)

                    if (
                        key.coverage_class
                        == EXACT_ABSENT_TUPLE_ABSENT
                        and key.product_tuple is not None
                    ):
                        tuple_usage = configuration_only_tuples.get(
                            key.product_tuple
                        )
                        if tuple_usage is None:
                            tuple_usage = MutableTupleUsage(
                                part=key.product_tuple[0],
                                vendor=key.product_tuple[1],
                                product=key.product_tuple[2],
                            )
                            configuration_only_tuples[
                                key.product_tuple
                            ] = tuple_usage
                        tuple_usage.distinct_criteria_expression_count += 1
                        tuple_usage.occurrence_count += occurrence_count
                        tuple_usage.vulnerable_true_count += true_count
                        tuple_usage.vulnerable_false_count += false_count

                    if (
                        row["version_category"] in {"CONCRETE", "HYPHEN"}
                        and row["range_usage_pattern"]
                        != "NO_RANGE_ONLY"
                    ):
                        exception_key = (
                            f"{row['version_category']}_WITH_RANGE"
                        )
                        version_range_exceptions[
                            exception_key
                        ].add_expression(occurrence_count)
                        version_range_exception_samples[exception_key].add(
                            row.copy()
                        )
                    row_count += 1

    return {
        "metrics": metrics,
        "lookup": lookup,
        "representatives": representatives,
        "configuration_only_tuples": configuration_only_tuples,
        "exact_status_counts": exact_status_counts,
        "tuple_composition_counts": tuple_composition_counts,
        "structural_expression_counts": structural_expression_counts,
        "structural_occurrence_counts": structural_occurrence_counts,
        "version_range_exceptions": version_range_exceptions,
        "version_range_exception_samples": (
            version_range_exception_samples
        ),
        "row_count": row_count,
    }


def _count_distinct_cves(
    nvd_snapshot: NvdCveSnapshot,
    *,
    lookup: dict[str, ClassificationKey],
    metrics: _Metrics,
    configuration_only_tuples: dict[
        tuple[str, str, str], MutableTupleUsage
    ],
) -> dict[str, Any]:
    match_table = _quoted_table(NvdCpeMatch)
    record_table = _quoted_table(NvdCveRecord)
    sql = f"""
        SELECT m.cve_record_id, m.criteria
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
        ORDER BY m.cve_record_id
    """
    current_cve_id: int | None = None
    cell_keys: set[tuple[str, str, str]] = set()
    group_keys: set[tuple[str, str]] = set()
    rollup_keys: set[tuple[str, str, str]] = set()
    tuple_keys: set[tuple[str, str, str]] = set()
    range_exception_keys: set[str] = set()
    range_exception_cve_counts: Counter[str] = Counter()
    occurrence_count = 0
    cves_with_matches = 0

    def flush() -> None:
        nonlocal cves_with_matches
        if current_cve_id is None:
            return
        metrics.add_cve(cell_keys, group_keys, rollup_keys)
        for product_tuple in tuple_keys:
            configuration_only_tuples[
                product_tuple
            ].distinct_cve_count += 1
        for exception_key in range_exception_keys:
            range_exception_cve_counts[exception_key] += 1
        cves_with_matches += 1

    for cve_record_id, criteria in _stream_query(sql, [nvd_snapshot.pk]):
        if current_cve_id is not None and cve_record_id != current_cve_id:
            flush()
            cell_keys.clear()
            group_keys.clear()
            rollup_keys.clear()
            tuple_keys.clear()
            range_exception_keys.clear()
        current_cve_id = cve_record_id
        try:
            key = lookup[criteria]
        except KeyError as error:
            raise NvdCpeDictionaryCoverageError(
                "Occurrence criteria is missing from classification lookup."
            ) from error
        for dimension, group in metrics.dimensions(key):
            cell_keys.add((dimension, group, key.coverage_class))
            group_keys.add((dimension, group))
            for rollup in metrics.rollup_keys(key.coverage_class):
                rollup_keys.add((dimension, group, rollup))
        if (
            key.coverage_class == EXACT_ABSENT_TUPLE_ABSENT
            and key.product_tuple is not None
        ):
            tuple_keys.add(key.product_tuple)
        if (
            key.version_category in {"CONCRETE", "HYPHEN"}
            and key.range_usage_pattern != "NO_RANGE_ONLY"
        ):
            range_exception_keys.add(
                f"{key.version_category}_WITH_RANGE"
            )
        occurrence_count += 1
    flush()
    return {
        "occurrence_count": occurrence_count,
        "cves_with_cpe_matches": cves_with_matches,
        "range_exception_distinct_cve_counts": dict(
            range_exception_cve_counts
        ),
    }


def _finalize_dimensions(metrics: _Metrics) -> dict[str, Any]:
    orders = {
        "overall": ("ALL",),
        "criteria_form": CRITERIA_FORMS,
        "vulnerable_usage": VULNERABLE_USAGE_GROUPS,
        "part": PART_GROUPS,
    }
    result: dict[str, Any] = {}
    for dimension, groups in orders.items():
        dimension_result: dict[str, Any] = {}
        for group in groups:
            cells = {
                coverage: metrics.cells[
                    (dimension, group, coverage)
                ].as_dict()
                for coverage in COVERAGE_CLASSES
            }
            total_expression = sum(
                row["distinct_criteria_expression_count"]
                for row in cells.values()
            )
            total_occurrence = sum(
                row["occurrence_count"] for row in cells.values()
            )
            total = {
                "distinct_criteria_expression_count": total_expression,
                "occurrence_count": total_occurrence,
                "distinct_cve_count": metrics.group_cve_counts[
                    (dimension, group)
                ],
            }
            for row in cells.values():
                row["expression_percent_within_group"] = _rate(
                    row["distinct_criteria_expression_count"],
                    total_expression,
                )
                row["occurrence_percent_within_group"] = _rate(
                    row["occurrence_count"], total_occurrence
                )
            rollups = {
                key: metrics.rollups[(dimension, group, key)].as_dict()
                for key in ROLLUP_KEYS
            }
            exact_absent_expression = rollups["EXACT_ABSENT"][
                "distinct_criteria_expression_count"
            ]
            exact_absent_occurrence = rollups["EXACT_ABSENT"][
                "occurrence_count"
            ]
            rollups["SAME_PRODUCT_TUPLE_PRESENT"][
                "expression_percent_of_exact_absent"
            ] = _rate(
                rollups["SAME_PRODUCT_TUPLE_PRESENT"][
                    "distinct_criteria_expression_count"
                ],
                exact_absent_expression,
            )
            rollups["SAME_PRODUCT_TUPLE_PRESENT"][
                "occurrence_percent_of_exact_absent"
            ] = _rate(
                rollups["SAME_PRODUCT_TUPLE_PRESENT"][
                    "occurrence_count"
                ],
                exact_absent_occurrence,
            )
            rollups["SAME_PRODUCT_TUPLE_ABSENT"][
                "expression_percent_of_exact_absent"
            ] = _rate(
                rollups["SAME_PRODUCT_TUPLE_ABSENT"][
                    "distinct_criteria_expression_count"
                ],
                exact_absent_expression,
            )
            rollups["SAME_PRODUCT_TUPLE_ABSENT"][
                "occurrence_percent_of_exact_absent"
            ] = _rate(
                rollups["SAME_PRODUCT_TUPLE_ABSENT"][
                    "occurrence_count"
                ],
                exact_absent_occurrence,
            )
            dimension_result[group] = {
                "total": total,
                "coverage_classes": cells,
                "coverage_rollups": rollups,
            }
        result[dimension] = dimension_result
    return result


def _top_configuration_only_tuples(
    tuples: dict[tuple[str, str, str], MutableTupleUsage],
) -> dict[str, Any]:
    by_occurrence = _TopRows(
        TOP_TUPLE_LIMIT,
        lambda row: (
            -row["occurrence_count"],
            -row["distinct_cve_count"],
            row["part"],
            row["vendor"],
            row["product"],
        ),
    )
    by_cve = _TopRows(
        TOP_TUPLE_LIMIT,
        lambda row: (
            -row["distinct_cve_count"],
            -row["occurrence_count"],
            row["part"],
            row["vendor"],
            row["product"],
        ),
    )
    part_counts: Counter[str] = Counter()
    vendors: set[str] = set()
    products: set[str] = set()
    expression_count = 0
    occurrence_count = 0
    for usage in tuples.values():
        row = usage.as_dict()
        by_occurrence.add(row)
        by_cve.add(row.copy())
        part_counts[
            usage.part if usage.part in {"a", "o", "h"} else "other"
        ] += 1
        vendors.add(usage.vendor)
        products.add(usage.product)
        expression_count += usage.distinct_criteria_expression_count
        occurrence_count += usage.occurrence_count
    return {
        "distinct_product_tuple_count": len(tuples),
        "part_distribution": {
            part: part_counts[part] for part in PART_GROUPS
        },
        "distinct_vendor_value_count": len(vendors),
        "distinct_product_value_count": len(products),
        "criteria_expressions_with_parseable_tuple": expression_count,
        "occurrences_with_parseable_tuple": occurrence_count,
        "top_by_occurrence": by_occurrence.rows,
        "top_by_distinct_cve": by_cve.rows,
    }


def _simple_metric_rows(
    metrics: dict[str, MutableMetric],
    ordered_keys: Sequence[str],
) -> list[dict[str, Any]]:
    return [
        {
            "value": key,
            "distinct_criteria_expression_count": metrics[
                key
            ].distinct_criteria_expression_count,
            "occurrence_count": metrics[key].occurrence_count,
        }
        for key in ordered_keys
    ]


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _build_summary(
    *,
    nvd_snapshot: NvdCveSnapshot,
    cpe_snapshot: CpeDictionarySnapshot,
    dictionary_tuples: dict[
        tuple[str, str, str], DictionaryTupleStats
    ],
    criteria_result: dict[str, Any],
    cve_result: dict[str, int],
    staged_path: Path,
) -> dict[str, Any]:
    dimensions = _finalize_dimensions(criteria_result["metrics"])
    overall = dimensions["overall"]["ALL"]
    configuration_only = _top_configuration_only_tuples(
        criteria_result["configuration_only_tuples"]
    )
    c_class = overall["coverage_classes"][
        EXACT_ABSENT_TUPLE_ABSENT
    ]
    configuration_only["unparseable_criteria_expression_count"] = (
        c_class["distinct_criteria_expression_count"]
        - configuration_only["criteria_expressions_with_parseable_tuple"]
    )
    configuration_only["unparseable_occurrence_count"] = (
        c_class["occurrence_count"]
        - configuration_only["occurrences_with_parseable_tuple"]
    )

    exact_status = _simple_metric_rows(
        criteria_result["exact_status_counts"],
        ("ACTIVE", "DEPRECATED"),
    )
    tuple_compositions = _simple_metric_rows(
        criteria_result["tuple_composition_counts"],
        (
            "ACTIVE_ONLY",
            "DEPRECATED_ONLY",
            "MIXED_ACTIVE_AND_DEPRECATED",
            "ABSENT",
        ),
    )
    structural_rows = [
        {
            "status": status.value,
            "distinct_criteria_expression_count": criteria_result[
                "structural_expression_counts"
            ][status.value],
            "occurrence_count": criteria_result[
                "structural_occurrence_counts"
            ][status.value],
        }
        for status in CPE23StructuralStatus
    ]
    range_exceptions = []
    for key in ("CONCRETE_WITH_RANGE", "HYPHEN_WITH_RANGE"):
        exception_metric = criteria_result["version_range_exceptions"][key]
        range_exceptions.append(
            {
                "type": key,
                "distinct_criteria_expression_count": (
                    exception_metric.distinct_criteria_expression_count
                ),
                "occurrence_count": exception_metric.occurrence_count,
                "distinct_cve_count": cve_result[
                    "range_exception_distinct_cve_counts"
                ].get(key, 0),
                "representative_cases": criteria_result[
                    "version_range_exception_samples"
                ][key].rows,
            }
        )

    return {
        "analysis_scope": ANALYSIS_SCOPE,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "nvd_snapshot_id": nvd_snapshot.snapshot_id,
            "nvd_snapshot_status": nvd_snapshot.status,
            "nvd_manifest_sha256": nvd_snapshot.manifest_sha256,
            "nvd_content_sha256": nvd_snapshot.content_sha256,
            "cve_count": nvd_snapshot.record_count,
            "cves_with_cpe_matches": cve_result["cves_with_cpe_matches"],
            "cpe_match_occurrence_count": nvd_snapshot.cpe_match_count,
            "distinct_configuration_criteria_expression_count": (
                criteria_result["row_count"]
            ),
            "cpe_dictionary_snapshot_id": cpe_snapshot.snapshot_id,
            "cpe_dictionary_snapshot_status": cpe_snapshot.status,
            "cpe_dictionary_manifest_sha256": cpe_snapshot.manifest_sha256,
            "cpe_dictionary_content_sha256": cpe_snapshot.content_sha256,
            "cpe_dictionary_name_count": cpe_snapshot.record_count,
            "cpe_dictionary_active_count": cpe_snapshot.active_count,
            "cpe_dictionary_deprecated_count": (
                cpe_snapshot.deprecated_count
            ),
            "cpe_dictionary_product_tuple_count": len(dictionary_tuples),
        },
        "comparison_definitions": {
            "expression_unit": "DISTINCT NvdCpeMatch.criteria",
            "expression_term": (
                "distinct Configuration criteria expression"
            ),
            "exact": (
                "case-sensitive raw criteria == CpeName.cpe_name"
            ),
            "product_tuple": (
                "case-sensitive raw parsed (part, vendor, product)"
            ),
            "range_identity": (
                "not compared; only NO_RANGE_ONLY, RANGE_ONLY, and "
                "BOTH_RANGE_AND_NO_RANGE usage are retained"
            ),
        },
        "overall_coverage": overall,
        "coverage_by_criteria_form": dimensions["criteria_form"],
        "coverage_by_vulnerable_usage": dimensions[
            "vulnerable_usage"
        ],
        "coverage_by_part": dimensions["part"],
        "exact_dictionary_status": exact_status,
        "tuple_status_composition": tuple_compositions,
        "criteria_structural_status": structural_rows,
        "version_range_exceptional_forms": range_exceptions,
        "configuration_only_product_tuples": configuration_only,
        "representative_cases": {
            coverage: criteria_result["representatives"][
                coverage
            ].selected()
            for coverage in COVERAGE_CLASSES
        },
        "criteria_coverage_artifact": {
            "filename": CRITERIA_COVERAGE_FILENAME,
            "row_count": criteria_result["row_count"],
            "columns": list(CSV_FIELDS),
            "compression": "gzip (mtime=0)",
            "sha256": _file_sha256(staged_path),
            "compressed_size_bytes": staged_path.stat().st_size,
        },
    }


def _validate_summary(summary: dict[str, Any]) -> None:
    dataset = summary["dataset"]
    overall = summary["overall_coverage"]
    total = overall["total"]
    coverage = overall["coverage_classes"]
    rollups = overall["coverage_rollups"]
    total_expressions = dataset[
        "distinct_configuration_criteria_expression_count"
    ]
    total_occurrences = dataset["cpe_match_occurrence_count"]
    failures: list[str] = []

    if total["distinct_criteria_expression_count"] != total_expressions:
        failures.append("overall expression total mismatch")
    if total["occurrence_count"] != total_occurrences:
        failures.append("overall occurrence total mismatch")
    if (
        sum(
            row["distinct_criteria_expression_count"]
            for row in coverage.values()
        )
        != total_expressions
    ):
        failures.append("A + B + C expression total mismatch")
    if sum(row["occurrence_count"] for row in coverage.values()) != (
        total_occurrences
    ):
        failures.append("A + B + C occurrence total mismatch")
    if (
        rollups["EXACT_PRESENT"]["distinct_criteria_expression_count"]
        + rollups["EXACT_ABSENT"][
            "distinct_criteria_expression_count"
        ]
        != total_expressions
    ):
        failures.append("exact present + absent expression mismatch")
    if (
        rollups["SAME_PRODUCT_TUPLE_PRESENT"][
            "distinct_criteria_expression_count"
        ]
        + rollups["SAME_PRODUCT_TUPLE_ABSENT"][
            "distinct_criteria_expression_count"
        ]
        != rollups["EXACT_ABSENT"][
            "distinct_criteria_expression_count"
        ]
    ):
        failures.append("exact absent tuple coverage expression mismatch")

    dimension_expectations = (
        ("coverage_by_criteria_form", CRITERIA_FORMS),
        ("coverage_by_vulnerable_usage", VULNERABLE_USAGE_GROUPS),
        ("coverage_by_part", PART_GROUPS),
    )
    for dimension_name, expected_groups in dimension_expectations:
        dimension = summary[dimension_name]
        if tuple(dimension) != tuple(expected_groups):
            failures.append(f"{dimension_name} group ordering mismatch")
        if sum(
            group["total"]["distinct_criteria_expression_count"]
            for group in dimension.values()
        ) != total_expressions:
            failures.append(f"{dimension_name} expression total mismatch")
        if sum(
            group["total"]["occurrence_count"]
            for group in dimension.values()
        ) != total_occurrences:
            failures.append(f"{dimension_name} occurrence total mismatch")
        for group_name, group in dimension.items():
            if sum(
                row["distinct_criteria_expression_count"]
                for row in group["coverage_classes"].values()
            ) != group["total"]["distinct_criteria_expression_count"]:
                failures.append(
                    f"{dimension_name}.{group_name} coverage mismatch"
                )

    artifact = summary["criteria_coverage_artifact"]
    if artifact["row_count"] != total_expressions:
        failures.append("criteria CSV row count mismatch")
    structural = summary["criteria_structural_status"]
    if sum(
        row["distinct_criteria_expression_count"] for row in structural
    ) != total_expressions:
        failures.append("structural status expression total mismatch")
    if sum(row["occurrence_count"] for row in structural) != total_occurrences:
        failures.append("structural status occurrence total mismatch")

    exact_status = summary["exact_dictionary_status"]
    if sum(
        row["distinct_criteria_expression_count"] for row in exact_status
    ) != coverage[EXACT_PRESENT]["distinct_criteria_expression_count"]:
        failures.append("exact active/deprecated expression mismatch")
    if sum(row["occurrence_count"] for row in exact_status) != coverage[
        EXACT_PRESENT
    ]["occurrence_count"]:
        failures.append("exact active/deprecated occurrence mismatch")

    tuple_composition = summary["tuple_status_composition"]
    if sum(
        row["distinct_criteria_expression_count"]
        for row in tuple_composition
    ) != total_expressions:
        failures.append("tuple composition expression total mismatch")
    if sum(row["occurrence_count"] for row in tuple_composition) != (
        total_occurrences
    ):
        failures.append("tuple composition occurrence total mismatch")

    config_only = summary["configuration_only_product_tuples"]
    if (
        config_only["criteria_expressions_with_parseable_tuple"]
        + config_only["unparseable_criteria_expression_count"]
        != coverage[EXACT_ABSENT_TUPLE_ABSENT][
            "distinct_criteria_expression_count"
        ]
    ):
        failures.append("configuration-only tuple expression mismatch")
    if (
        config_only["occurrences_with_parseable_tuple"]
        + config_only["unparseable_occurrence_count"]
        != coverage[EXACT_ABSENT_TUPLE_ABSENT]["occurrence_count"]
    ):
        failures.append("configuration-only tuple occurrence mismatch")

    if failures:
        raise NvdCpeDictionaryCoverageError(
            "Coverage invariant validation failed: " + "; ".join(failures)
        )


def analyze_nvd_cpe_dictionary_coverage(
    *,
    configured_nvd_snapshot_id: str | None,
    configured_cpe_snapshot_id: str | None,
    staging_directory: Path,
) -> NvdCpeDictionaryCoverageAnalysis:
    before = _collect_database_state()
    descriptor, staged_name = _create_staged_gzip(staging_directory)
    os.close(descriptor)
    staged_path = Path(staged_name)
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION READ ONLY")
                cursor.execute("SHOW transaction_read_only")
                if cursor.fetchone()[0] != "on":
                    raise NvdCpeDictionaryCoverageError(
                        "PostgreSQL did not enter a read-only transaction."
                    )
            nvd_snapshot = select_nvd_cve_snapshot(
                configured_nvd_snapshot_id
            )
            cpe_snapshot = select_cpe_dictionary_snapshot(
                configured_cpe_snapshot_id
            )
            dictionary_tuples, _ = _load_dictionary_tuples(cpe_snapshot)
            criteria_result = _write_criteria_coverage(
                nvd_snapshot,
                cpe_snapshot,
                dictionary_tuples,
                staged_path,
            )
            cve_result = _count_distinct_cves(
                nvd_snapshot,
                lookup=criteria_result["lookup"],
                metrics=criteria_result["metrics"],
                configuration_only_tuples=criteria_result[
                    "configuration_only_tuples"
                ],
            )
            if cve_result["occurrence_count"] != (
                nvd_snapshot.cpe_match_count
            ):
                raise NvdCpeDictionaryCoverageError(
                    "Distinct-CVE pass occurrence count mismatch."
                )
            summary = _build_summary(
                nvd_snapshot=nvd_snapshot,
                cpe_snapshot=cpe_snapshot,
                dictionary_tuples=dictionary_tuples,
                criteria_result=criteria_result,
                cve_result=cve_result,
                staged_path=staged_path,
            )
            _validate_summary(summary)

        after = _collect_database_state()
        state_unchanged = (
            before["table_counts"] == after["table_counts"]
            and before["nvd_snapshot_metadata"]
            == after["nvd_snapshot_metadata"]
            and before["cpe_dictionary_snapshot_metadata"]
            == after["cpe_dictionary_snapshot_metadata"]
        )
        summary["validation"] = {
            "coverage_invariants_passed": True,
            "database_state_unchanged": state_unchanged,
        }
        summary["safety"] = {
            "postgresql_read_only_transactions": (
                before["transaction_read_only"]
                and after["transaction_read_only"]
            ),
            "database_writes": 0,
            "database_state_unchanged": state_unchanged,
            "before": before,
            "after": after,
            "prohibited_operations_performed": [],
        }
        if not state_unchanged:
            raise NvdCpeDictionaryCoverageError(
                "Database state changed while coverage analysis ran."
            )
        _validate_summary(summary)
        return NvdCpeDictionaryCoverageAnalysis(
            summary=summary,
            staged_criteria_coverage_path=staged_path,
        )
    except BaseException:
        try:
            staged_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _number(value: int) -> str:
    return f"{value:,}"


def _markdown(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _coverage_table(group: dict[str, Any]) -> list[str]:
    labels = {
        EXACT_PRESENT: "Exact present",
        EXACT_ABSENT_TUPLE_PRESENT: (
            "Exact absent + same product tuple"
        ),
        EXACT_ABSENT_TUPLE_ABSENT: (
            "Configuration-only product tuple"
        ),
    }
    lines = [
        "| Coverage class | Distinct criteria | % | Occurrences | % | Distinct CVEs |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for coverage_class in COVERAGE_CLASSES:
        row = group["coverage_classes"][coverage_class]
        lines.append(
            "| {label} | {expressions} | {expression_percent:.8f} | "
            "{occurrences} | {occurrence_percent:.8f} | {cves} |".format(
                label=labels[coverage_class],
                expressions=_number(
                    row["distinct_criteria_expression_count"]
                ),
                expression_percent=row[
                    "expression_percent_within_group"
                ],
                occurrences=_number(row["occurrence_count"]),
                occurrence_percent=row[
                    "occurrence_percent_within_group"
                ],
                cves=_number(row["distinct_cve_count"]),
            )
        )
    return lines


def _dimension_table(dimension: dict[str, Any]) -> list[str]:
    lines = [
        "| Group | Criteria | Occurrences | CVEs | Exact criteria/occ. | Same tuple criteria/occ. | Configuration-only criteria/occ. |",
        "| --- | ---: | ---: | ---: | --- | --- | --- |",
    ]
    for group_name, group in dimension.items():
        coverage = group["coverage_classes"]

        def coverage_cell(coverage_class: str) -> str:
            row = coverage[coverage_class]
            return (
                f"{_number(row['distinct_criteria_expression_count'])} "
                f"({row['expression_percent_within_group']:.4f}%) / "
                f"{_number(row['occurrence_count'])} "
                f"({row['occurrence_percent_within_group']:.4f}%)"
            )

        lines.append(
            "| {group} | {expressions} | {occurrences} | {cves} | "
            "{exact} | {tuple_present} | {tuple_absent} |".format(
                group=_markdown(group_name),
                expressions=_number(
                    group["total"][
                        "distinct_criteria_expression_count"
                    ]
                ),
                occurrences=_number(group["total"]["occurrence_count"]),
                cves=_number(group["total"]["distinct_cve_count"]),
                exact=coverage_cell(EXACT_PRESENT),
                tuple_present=coverage_cell(
                    EXACT_ABSENT_TUPLE_PRESENT
                ),
                tuple_absent=coverage_cell(
                    EXACT_ABSENT_TUPLE_ABSENT
                ),
            )
        )
    return lines


def _tuple_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| part | vendor | product | criteria | occurrences | CVEs | vuln=true | vuln=false |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            "| {part} | {vendor} | {product} | {criteria} | "
            "{occurrences} | {cves} | {true_count} | {false_count} |".format(
                part=_markdown(row["part"]),
                vendor=_markdown(row["vendor"]),
                product=_markdown(row["product"]),
                criteria=_number(
                    row["distinct_criteria_expression_count"]
                ),
                occurrences=_number(row["occurrence_count"]),
                cves=_number(row["distinct_cve_count"]),
                true_count=_number(row["vulnerable_true_count"]),
                false_count=_number(row["vulnerable_false_count"]),
            )
        )
    return lines


def _representative_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| criteria | part/vendor/product/version | range | vulnerable | occurrences | CVEs | exact | tuple A/D |",
        "| --- | --- | --- | --- | ---: | ---: | --- | ---: |",
    ]
    for row in rows:
        identity = "/".join(
            _markdown(row[field])
            for field in ("part", "vendor", "product", "version")
        )
        lines.append(
            "| {criteria} | {identity} | {range_pattern} | {vulnerable} | "
            "{occurrences} | {cves} | {exact} | {active}/{deprecated} |".format(
                criteria=_markdown(row["criteria"]),
                identity=identity,
                range_pattern=row["range_usage_pattern"],
                vulnerable=row["vulnerable_usage_group"],
                occurrences=_number(row["occurrence_count"]),
                cves=_number(row["distinct_cve_count"]),
                exact=(
                    row["exact_dictionary_status"]
                    if row["exact_present"]
                    else "ABSENT"
                ),
                active=_number(row["tuple_active_count"]),
                deprecated=_number(row["tuple_deprecated_count"]),
            )
        )
    return lines


def render_report(summary: dict[str, Any]) -> str:
    dataset = summary["dataset"]
    overall = summary["overall_coverage"]
    rollups = overall["coverage_rollups"]
    configuration_only = summary["configuration_only_product_tuples"]
    artifact = summary["criteria_coverage_artifact"]
    exact = overall["coverage_classes"][EXACT_PRESENT]
    tuple_absent = overall["coverage_classes"][
        EXACT_ABSENT_TUPLE_ABSENT
    ]
    exact_absent = rollups["EXACT_ABSENT"]
    lines = [
        "# NVD Configuration Criteria × CPE Dictionary Coverage",
        "",
        f"생성 시각(UTC): `{summary['generated_at_utc']}`",
        "",
        "> 이 보고서의 단위는 distinct Configuration criteria expression이다. "
        "이를 unique CPE로 해석하지 않으며, raw exact string과 raw "
        "part/vendor/product tuple coverage만 관측한다.",
        "",
        "## A. Dataset",
        "",
        f"- NVD Snapshot: `{dataset['nvd_snapshot_id']}` (`{dataset['nvd_snapshot_status']}`)",
        f"- CPE Dictionary Snapshot: `{dataset['cpe_dictionary_snapshot_id']}` "
        f"(`{dataset['cpe_dictionary_snapshot_status']}`)",
        f"- CVE records: {_number(dataset['cve_count'])}",
        f"- CVEs with cpeMatch: {_number(dataset['cves_with_cpe_matches'])}",
        f"- CPE Match occurrences: {_number(dataset['cpe_match_occurrence_count'])}",
        f"- Distinct Configuration criteria expressions: "
        f"{_number(dataset['distinct_configuration_criteria_expression_count'])}",
        f"- Dictionary CPE Names: {_number(dataset['cpe_dictionary_name_count'])}",
        f"- Dictionary product tuples: "
        f"{_number(dataset['cpe_dictionary_product_tuple_count'])}",
        "",
        "## B. Overall Coverage",
        "",
        *_coverage_table(overall),
        "",
        f"Exact-absent expression {_number(exact_absent['distinct_criteria_expression_count'])}개 중 "
        f"동일 product tuple이 존재하는 비율은 "
        f"{rollups['SAME_PRODUCT_TUPLE_PRESENT']['expression_percent_of_exact_absent']:.8f}%다. "
        "Distinct-CVE 열은 class 간 중복될 수 있으므로 합산하지 않는다.",
        "",
        "## C. Criteria Form × Coverage",
        "",
        *_dimension_table(summary["coverage_by_criteria_form"]),
        "",
        "각 form의 class별 occurrence, distinct-CVE, exact-absent rollup 및 "
        "비율은 `summary.json`에 수록했다.",
        "",
        "### Concrete/Hyphen + range 예외 확인",
        "",
    ]
    for exception in summary["version_range_exceptional_forms"]:
        lines.append(
            f"- {exception['type']}: "
            f"{_number(exception['distinct_criteria_expression_count'])} expressions, "
            f"{_number(exception['occurrence_count'])} occurrences"
        )
    lines.extend(
        [
            "",
            "## D. Vulnerable Usage × Coverage",
            "",
            *_dimension_table(summary["coverage_by_vulnerable_usage"]),
            "",
            "`vulnerable`은 criteria identity가 아닌 usage stratification으로 "
            "처리했으며 false occurrence도 제외하지 않았다.",
            "",
            "## E. Part × Coverage",
            "",
            *_dimension_table(summary["coverage_by_part"]),
            "",
            "## F. Configuration-only Product Tuples",
            "",
            f"- Distinct product tuples: "
            f"{_number(configuration_only['distinct_product_tuple_count'])}",
            f"- Distinct vendor values: "
            f"{_number(configuration_only['distinct_vendor_value_count'])}",
            f"- Distinct product values: "
            f"{_number(configuration_only['distinct_product_value_count'])}",
            f"- Part distribution: `{json.dumps(configuration_only['part_distribution'], sort_keys=True)}`",
            f"- Unparseable criteria expressions in this class: "
            f"{_number(configuration_only['unparseable_criteria_expression_count'])}",
            "",
            "### Occurrence 기준 상위 30개",
            "",
            *_tuple_table(configuration_only["top_by_occurrence"]),
            "",
            "### Distinct CVE 기준 상위 30개",
            "",
            *_tuple_table(configuration_only["top_by_distinct_cve"]),
            "",
            "`Configuration-only product tuple`은 invalid CPE 또는 Dictionary "
            "omission을 뜻하지 않는다.",
            "",
            "## G. Representative Cases",
            "",
        ]
    )
    labels = {
        EXACT_PRESENT: "EXACT_PRESENT (최대 10)",
        EXACT_ABSENT_TUPLE_PRESENT: (
            "EXACT_ABSENT + SAME_PRODUCT_TUPLE_PRESENT (최대 20)"
        ),
        EXACT_ABSENT_TUPLE_ABSENT: (
            "EXACT_ABSENT + SAME_PRODUCT_TUPLE_ABSENT (최대 30)"
        ),
    }
    for coverage_class in COVERAGE_CLASSES:
        lines.extend(
            [
                f"### {labels[coverage_class]}",
                "",
                *_representative_table(
                    summary["representative_cases"][coverage_class]
                ),
                "",
            ]
        )
    lines.extend(
        [
            "## H. Interpretation",
            "",
            f"1. Dictionary exact CPE로 존재하는 비율은 expression 기준 "
            f"{exact['expression_percent_within_group']:.8f}%, occurrence 기준 "
            f"{exact['occurrence_percent_within_group']:.8f}%다.",
            f"2. Exact-absent 중 동일 product tuple이 존재하는 비율은 expression 기준 "
            f"{rollups['SAME_PRODUCT_TUPLE_PRESENT']['expression_percent_of_exact_absent']:.8f}%, "
            f"occurrence 기준 {rollups['SAME_PRODUCT_TUPLE_PRESENT']['occurrence_percent_of_exact_absent']:.8f}%다.",
            f"3. Product tuple도 Dictionary에 없는 표현은 "
            f"{_number(tuple_absent['distinct_criteria_expression_count'])}개 "
            f"({tuple_absent['expression_percent_within_group']:.8f}%), "
            f"{_number(tuple_absent['occurrence_count'])} occurrences "
            f"({tuple_absent['occurrence_percent_within_group']:.8f}%)다.",
            "4. Concrete/wildcard/range, vulnerable usage, part별 차이는 위 표와 "
            "`summary.json`의 class별 expression/usage/CVE 지표로 분리했다.",
            "5. Dictionary만으로 향후 후보 공간을 제한하기 전에는 "
            "Configuration-only tuple의 source/provenance, escaped-field grammar, "
            "deprecated replacement, 그리고 range-to-version 관계를 별도 단계에서 "
            "검증해야 한다. 이번 분석에서는 어느 것도 평가하지 않았다.",
            "",
            "## Artifacts",
            "",
            f"- `{SUMMARY_FILENAME}`: 전체 집계와 대표 사례",
            f"- `{CRITERIA_COVERAGE_FILENAME}`: "
            f"{_number(artifact['row_count'])} expression rows, "
            f"SHA-256 `{artifact['sha256']}`",
            "",
            "## Safety",
            "",
            f"- PostgreSQL READ ONLY transactions: "
            f"`{str(summary['safety']['postgresql_read_only_transactions']).lower()}`",
            f"- DB writes: `{summary['safety']['database_writes']}`",
            f"- 작업 전후 전체 table counts와 NVD/CPE snapshot metadata 동일: "
            f"`{str(summary['safety']['database_state_unchanged']).lower()}`",
            f"- Coverage invariants passed: "
            f"`{str(summary['validation']['coverage_invariants_passed']).lower()}`",
            "- Models/migrations/API/UI/matching logic 변경: 없음",
            "",
        ]
    )
    return "\n".join(lines)


def _write_text_atomically(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_coverage_analysis(
    analysis: NvdCpeDictionaryCoverageAnalysis,
    output_directory: Path,
) -> dict[str, Path]:
    _validate_summary(analysis.summary)
    output_directory.mkdir(parents=True, exist_ok=True)
    summary_path = output_directory / SUMMARY_FILENAME
    report_path = output_directory / REPORT_FILENAME
    criteria_path = output_directory / CRITERIA_COVERAGE_FILENAME
    _write_text_atomically(
        summary_path,
        json.dumps(
            analysis.summary,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
    )
    _write_text_atomically(report_path, render_report(analysis.summary))
    os.replace(analysis.staged_criteria_coverage_path, criteria_path)
    return {
        SUMMARY_FILENAME: summary_path,
        REPORT_FILENAME: report_path,
        CRITERIA_COVERAGE_FILENAME: criteria_path,
    }

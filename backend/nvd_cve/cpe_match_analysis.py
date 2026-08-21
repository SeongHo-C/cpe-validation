from __future__ import annotations

import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from django.db import connection, transaction

from cpe.cpe23 import (
    CPE23_ATTRIBUTE_NAMES,
    CPE23StructuralStatus,
    parse_cpe23_formatted_string,
)
from nvd_cve.models import NvdCpeMatch, NvdCveRecord, NvdCveSnapshot
from nvd_cve.snapshot_selection import select_nvd_cve_snapshot


ANALYSIS_SCOPE = (
    "Read-only profiling of NVD CVE Configuration cpeMatch usage. "
    "Raw criteria strings are not treated as unique CPE identities, and "
    "no CPE Dictionary comparison or CPE matching semantics are applied."
)
RANGE_FIELDS = (
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
)
VERSION_CATEGORIES = ("star", "concrete", "hyphen", "other")
OUTPUT_FILENAMES = ("summary.json", "report.md")
NULL_VALUE = "<NULL>"
STREAM_CHUNK_SIZE = 2_000
EXAMPLE_LIMIT = 20
EXCEPTION_EXAMPLE_LIMIT = 30
EXAMPLES_PER_EXCEPTION_CATEGORY = 5
PARSER_ATTENTION_CATEGORIES = (
    "structural_invalid",
    "empty_vendor",
    "empty_product",
    "empty_version",
    "contains_escape_sequence",
    "embedded_unescaped_wildcard",
)


class NvdCpeMatchAnalysisError(Exception):
    """A read-only NVD CPE Match analysis could not be completed."""


@dataclass(frozen=True)
class NvdCpeMatchAnalysis:
    summary: dict[str, Any]


class _TopRows:
    def __init__(self, limit: int, key: Any) -> None:
        self.limit = limit
        self.key = key
        self.rows: list[dict[str, Any]] = []

    def add(self, row: dict[str, Any]) -> None:
        self.rows.append(row)
        self.rows.sort(key=self.key)
        del self.rows[self.limit :]


def _quoted_table(model: type[Any]) -> str:
    return connection.ops.quote_name(model._meta.db_table)


def _scope_sql() -> tuple[str, str]:
    match_table = _quoted_table(NvdCpeMatch)
    record_table = _quoted_table(NvdCveRecord)
    return match_table, record_table


def _fetch_one(sql: str, params: Sequence[Any]) -> tuple[Any, ...]:
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()
    if row is None:
        raise NvdCpeMatchAnalysisError("An aggregate query returned no row.")
    return row


def _fetch_all(
    sql: str,
    params: Sequence[Any],
) -> list[tuple[Any, ...]]:
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return list(cursor.fetchall())


_stream_number = 0


def _stream_query(
    sql: str,
    params: Sequence[Any],
) -> Iterator[tuple[Any, ...]]:
    global _stream_number

    raw_connection = connection.connection
    if raw_connection is None:
        raise NvdCpeMatchAnalysisError("Database connection is unavailable.")
    _stream_number += 1
    cursor_name = f"nvd_cpe_profile_{_stream_number}"
    with raw_connection.cursor(name=cursor_name) as cursor:
        cursor.itersize = STREAM_CHUNK_SIZE
        cursor.execute(sql, params)
        while True:
            rows = cursor.fetchmany(STREAM_CHUNK_SIZE)
            if not rows:
                break
            yield from rows


def _counter_rows(
    counter: Counter[Any],
    *,
    key_name: str,
    count_name: str,
) -> list[dict[str, Any]]:
    return [
        {key_name: key, count_name: counter[key]}
        for key in sorted(counter, key=lambda value: (str(type(value)), value))
    ]


def _version_category(version: str | None) -> str:
    if version == "*":
        return "star"
    if version == "-":
        return "hyphen"
    if version not in {None, ""}:
        return "concrete"
    return "other"


def _field_token_category(value: str) -> str:
    if value == "*":
        return "star"
    if value == "-":
        return "hyphen"
    if value == "":
        return "empty"
    return "concrete"


def _contains_unescaped_wildcard(value: str) -> bool:
    escaped = False
    for character in value:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character in {"*", "?"}:
            return True
    return False


def _parse_profile(criteria: str) -> tuple[Any, str, str, list[str]]:
    parsed = parse_cpe23_formatted_string(criteria)
    flags: list[str] = []
    if not parsed.is_structurally_valid:
        flags.append("structural_invalid")
        return parsed, "other_or_malformed", "other", flags

    part = parsed.part_raw
    version_category = _version_category(parsed.version_raw)
    if parsed.vendor_raw == "":
        flags.append("empty_vendor")
    if parsed.product_raw == "":
        flags.append("empty_product")
    if parsed.version_raw == "":
        flags.append("empty_version")
    if any("\\" in value for value in parsed.fields.values()):
        flags.append("contains_escape_sequence")
    if any(
        value != "*" and _contains_unescaped_wildcard(value)
        for value in parsed.fields.values()
    ):
        flags.append("embedded_unescaped_wildcard")
    return parsed, part, version_category, flags


def _rate(count: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(count * 100.0 / total, 8)


def _storage_structure() -> dict[str, Any]:
    field_names = (
        "criteria",
        "vulnerable",
        "configuration_operator",
        "configuration_negate",
        "node_operator",
        "node_negate",
        *RANGE_FIELDS,
        "match_criteria_id",
        "cve_record",
    )
    fields: dict[str, Any] = {}
    for name in field_names:
        field = NvdCpeMatch._meta.get_field(name)
        fields[name] = {
            "django_type": field.get_internal_type(),
            "nullable": field.null,
            "database_column": field.column,
        }
    return {
        "model": "nvd_cve.models.NvdCpeMatch",
        "table": NvdCpeMatch._meta.db_table,
        "fields": fields,
        "position_identity": [
            "cve_record",
            "configuration_index",
            "node_index",
            "match_index",
        ],
        "cve_relation": {
            "model": "nvd_cve.models.NvdCveRecord",
            "foreign_key": "cve_record",
            "snapshot_path": "cve_record.snapshot",
            "on_delete": "CASCADE",
        },
        "importer_behavior": {
            "criteria": "required non-empty string; preserved verbatim",
            "vulnerable": "required JSON boolean; stored non-null",
            "match_criteria_id": "required valid UUID; stored as UUIDField",
            "range_fields": (
                "missing key becomes NULL; present value must be a string "
                "and is preserved verbatim, including an empty string"
            ),
            "operators_and_negate": (
                "optional configuration/node values copied onto each "
                "flattened cpeMatch occurrence"
            ),
            "configurations": (
                "original configuration array retained in "
                "NvdCveRecord.configurations JSONField"
            ),
        },
        "cpe_parser": {
            "function": "cpe.cpe23.parse_cpe23_formatted_string",
            "field_count": len(CPE23_ATTRIBUTE_NAMES),
            "attributes": list(CPE23_ATTRIBUTE_NAMES),
            "semantics": (
                "limited structural validation only; bound values remain "
                "escaped/raw and are not semantically matched"
            ),
        },
    }


def _basic_cardinality(snapshot_pk: int) -> dict[str, Any]:
    match_table, record_table = _scope_sql()
    row = _fetch_one(
        f"""
        SELECT
            COUNT(*),
            COUNT(*) FILTER (WHERE m.vulnerable IS TRUE),
            COUNT(*) FILTER (WHERE m.vulnerable IS FALSE),
            COUNT(*) FILTER (WHERE m.vulnerable IS NULL),
            COUNT(DISTINCT m.criteria),
            COUNT(DISTINCT m.match_criteria_id),
            COUNT(*) FILTER (
                WHERE m.version_start_including IS NULL
                  AND m.version_start_excluding IS NULL
                  AND m.version_end_including IS NULL
                  AND m.version_end_excluding IS NULL
            ),
            COUNT(*) FILTER (
                WHERE m.version_start_including IS NOT NULL
                   OR m.version_start_excluding IS NOT NULL
                   OR m.version_end_including IS NOT NULL
                   OR m.version_end_excluding IS NOT NULL
            )
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
        """,
        [snapshot_pk],
    )
    return {
        "total_occurrences": row[0],
        "vulnerable_true_occurrences": row[1],
        "vulnerable_false_occurrences": row[2],
        "vulnerable_null_occurrences": row[3],
        "distinct_criteria_strings": row[4],
        "distinct_match_criteria_ids": row[5],
        "range_absent_occurrences": row[6],
        "range_present_occurrences": row[7],
    }


def _criteria_profiles(
    snapshot_pk: int,
    basic: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    match_table, record_table = _scope_sql()
    criteria_occurrences: Counter[int] = Counter()
    criteria_id_variants: Counter[int] = Counter()
    range_variants: Counter[int] = Counter()
    part_occurrences: Counter[str] = Counter()
    part_distinct: Counter[str] = Counter()
    version_occurrences: Counter[str] = Counter()
    version_distinct: Counter[str] = Counter()
    structural_occurrences: Counter[str] = Counter()
    structural_distinct: Counter[str] = Counter()
    flag_occurrences: Counter[str] = Counter()
    flag_distinct: Counter[str] = Counter()
    field_profiles: dict[str, dict[str, Counter[str]]] = {
        field: {"occurrence": Counter(), "distinct": Counter()}
        for field in CPE23_ATTRIBUTE_NAMES
    }
    top_occurrences = _TopRows(
        EXAMPLE_LIMIT,
        lambda item: (-item["occurrence_count"], item["criteria"]),
    )
    top_ranges = _TopRows(
        EXAMPLE_LIMIT,
        lambda item: (
            -item["distinct_range_tuple_count"],
            -item["occurrence_count"],
            item["criteria"],
        ),
    )
    top_both = _TopRows(
        EXAMPLE_LIMIT,
        lambda item: (-item["occurrence_count"], item["criteria"]),
    )
    top_multi_ids = _TopRows(
        EXAMPLE_LIMIT,
        lambda item: (
            -item["distinct_match_criteria_id_count"],
            -item["occurrence_count"],
            item["criteria"],
        ),
    )
    exceptional_examples_by_category: defaultdict[
        str, list[dict[str, Any]]
    ] = defaultdict(list)
    vulnerable_python_groups = {
        "true_only": {"distinct_criteria_strings": 0, "occurrences": 0},
        "false_only": {"distinct_criteria_strings": 0, "occurrences": 0},
        "both": {"distinct_criteria_strings": 0, "occurrences": 0},
        "null_or_unexpected": {
            "distinct_criteria_strings": 0,
            "occurrences": 0,
        },
    }

    sql = f"""
        SELECT
            m.criteria,
            COUNT(*) AS occurrence_count,
            COUNT(DISTINCT m.cve_record_id) AS distinct_cve_count,
            COUNT(DISTINCT m.match_criteria_id) AS match_id_count,
            COUNT(DISTINCT jsonb_build_array(
                m.version_start_including,
                m.version_start_excluding,
                m.version_end_including,
                m.version_end_excluding
            )) AS range_variant_count,
            COUNT(*) FILTER (WHERE m.vulnerable IS TRUE) AS true_count,
            COUNT(*) FILTER (WHERE m.vulnerable IS FALSE) AS false_count,
            COUNT(*) FILTER (WHERE m.vulnerable IS NULL) AS null_count
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
        GROUP BY m.criteria
        ORDER BY m.criteria
    """
    for row in _stream_query(sql, [snapshot_pk]):
        (
            criteria,
            occurrence_count,
            distinct_cve_count,
            match_id_count,
            range_variant_count,
            true_count,
            false_count,
            null_count,
        ) = row
        criteria_occurrences[occurrence_count] += 1
        criteria_id_variants[match_id_count] += 1
        range_variants[range_variant_count] += 1
        parsed, part, version_category, flags = _parse_profile(criteria)
        part_occurrences[part] += occurrence_count
        part_distinct[part] += 1
        version_occurrences[version_category] += occurrence_count
        version_distinct[version_category] += 1
        structural_status = parsed.status.value
        structural_occurrences[structural_status] += occurrence_count
        structural_distinct[structural_status] += 1
        for flag in flags:
            flag_occurrences[flag] += occurrence_count
            flag_distinct[flag] += 1
        if parsed.is_structurally_valid:
            for field, value in parsed.fields.items():
                token_category = _field_token_category(value)
                field_profiles[field]["occurrence"][token_category] += (
                    occurrence_count
                )
                field_profiles[field]["distinct"][token_category] += 1

        common_row = {
            "criteria": criteria,
            "occurrence_count": occurrence_count,
            "distinct_cve_count": distinct_cve_count,
            "distinct_match_criteria_id_count": match_id_count,
            "distinct_range_tuple_count": range_variant_count,
        }
        top_occurrences.add(common_row.copy())
        top_ranges.add(common_row.copy())
        if match_id_count > 1:
            top_multi_ids.add(common_row.copy())
        if true_count and false_count:
            group = "both"
            top_both.add(
                {
                    **common_row,
                    "vulnerable_true_occurrences": true_count,
                    "vulnerable_false_occurrences": false_count,
                }
            )
        elif true_count and not false_count and not null_count:
            group = "true_only"
        elif false_count and not true_count and not null_count:
            group = "false_only"
        else:
            group = "null_or_unexpected"
        vulnerable_python_groups[group]["distinct_criteria_strings"] += 1
        vulnerable_python_groups[group]["occurrences"] += occurrence_count

        if flags:
            exceptional_row = {
                **common_row,
                "structural_status": structural_status,
                "structural_error": parsed.error_message,
                "attention_categories": flags,
            }
            for flag in flags:
                examples = exceptional_examples_by_category[flag]
                if len(examples) < EXAMPLES_PER_EXCEPTION_CATEGORY:
                    examples.append(exceptional_row)

    total_occurrences = basic["total_occurrences"]
    total_distinct = basic["distinct_criteria_strings"]
    parser_attention = []
    for flag in PARSER_ATTENTION_CATEGORIES:
        parser_attention.append(
            {
                "category": flag,
                "occurrence_count": flag_occurrences[flag],
                "occurrence_percent": _rate(
                    flag_occurrences[flag], total_occurrences
                ),
                "distinct_criteria_string_count": flag_distinct[flag],
                "distinct_criteria_percent": _rate(
                    flag_distinct[flag], total_distinct
                ),
            }
        )

    exceptional_examples = []
    seen_exceptional_criteria: set[str] = set()
    for category in PARSER_ATTENTION_CATEGORIES:
        for example in exceptional_examples_by_category[category]:
            if example["criteria"] in seen_exceptional_criteria:
                continue
            exceptional_examples.append(example)
            seen_exceptional_criteria.add(example["criteria"])
            if len(exceptional_examples) >= EXCEPTION_EXAMPLE_LIMIT:
                break
        if len(exceptional_examples) >= EXCEPTION_EXAMPLE_LIMIT:
            break

    field_rows = {}
    for field in CPE23_ATTRIBUTE_NAMES:
        field_rows[field] = {
            basis: {
                category: field_profiles[field][basis][category]
                for category in ("star", "hyphen", "concrete", "empty")
            }
            for basis in ("occurrence", "distinct")
        }

    cardinality = {
        "criteria_occurrence_distribution": _counter_rows(
            criteria_occurrences,
            key_name="occurrence_count",
            count_name="distinct_criteria_string_count",
        ),
        "criteria_strings_occurring_once": criteria_occurrences[1],
        "criteria_strings_occurring_at_least_twice": (
            total_distinct - criteria_occurrences[1]
        ),
        "maximum_criteria_occurrence_count": max(
            criteria_occurrences, default=0
        ),
        "top_criteria_by_occurrence": top_occurrences.rows,
        "criteria_to_match_criteria_id_multiplicity_distribution": (
            _counter_rows(
                criteria_id_variants,
                key_name="distinct_match_criteria_id_count",
                count_name="distinct_criteria_string_count",
            )
        ),
        "criteria_strings_linked_to_multiple_match_criteria_ids": sum(
            count
            for variant_count, count in criteria_id_variants.items()
            if variant_count >= 2
        ),
        "maximum_match_criteria_ids_per_criteria": max(
            criteria_id_variants, default=0
        ),
        "top_criteria_by_match_criteria_id_multiplicity": (
            top_multi_ids.rows
        ),
    }
    field_profile = {
        "part_distribution": [
            {
                "part": part,
                "occurrence_count": part_occurrences[part],
                "distinct_criteria_string_count": part_distinct[part],
            }
            for part in ("a", "o", "h", "other_or_malformed")
        ],
        "version_distribution": [
            {
                "version_category": category,
                "occurrence_count": version_occurrences[category],
                "distinct_criteria_string_count": version_distinct[category],
            }
            for category in VERSION_CATEGORIES
        ],
        "all_field_token_distribution": field_rows,
    }
    range_profile = {
        "range_variant_count_distribution": _counter_rows(
            range_variants,
            key_name="distinct_range_tuple_count",
            count_name="distinct_criteria_string_count",
        ),
        "criteria_with_one_range_tuple": range_variants[1],
        "criteria_with_multiple_range_tuples": sum(
            count
            for variant_count, count in range_variants.items()
            if variant_count >= 2
        ),
        "maximum_range_tuples_per_criteria": max(range_variants, default=0),
        "top_criteria_by_range_multiplicity": top_ranges.rows,
    }
    exceptional = {
        "structural_status_distribution": [
            {
                "status": status.value,
                "occurrence_count": structural_occurrences[status.value],
                "occurrence_percent": _rate(
                    structural_occurrences[status.value], total_occurrences
                ),
                "distinct_criteria_string_count": structural_distinct[
                    status.value
                ],
                "distinct_criteria_percent": _rate(
                    structural_distinct[status.value], total_distinct
                ),
            }
            for status in CPE23StructuralStatus
        ],
        "parser_attention_categories": parser_attention,
        "representative_examples": exceptional_examples,
        "notes": [
            "Special-token counts for '*' and '-' are reported per field; "
            "their presence is not automatically classified as malformed.",
            "contains_escape_sequence is an observed parser-relevant form, "
            "not an error by itself.",
            "Attention categories may overlap, so their counts are not "
            "mutually exclusive.",
        ],
    }
    vulnerable = {
        "groups_derived_from_criteria_aggregates": vulnerable_python_groups,
        "top_both_criteria": top_both.rows,
    }
    return cardinality, field_profile, range_profile, exceptional | {
        "_vulnerable": vulnerable
    }


def _match_criteria_id_profiles(snapshot_pk: int) -> dict[str, Any]:
    match_table, record_table = _scope_sql()
    occurrence_distribution: Counter[int] = Counter()
    criteria_multiplicity: Counter[int] = Counter()
    top_multiple = _TopRows(
        EXAMPLE_LIMIT,
        lambda item: (
            -item["distinct_criteria_string_count"],
            -item["occurrence_count"],
            item["match_criteria_id"],
        ),
    )
    sql = f"""
        SELECT
            m.match_criteria_id,
            COUNT(*) AS occurrence_count,
            COUNT(DISTINCT m.criteria) AS criteria_count
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
        GROUP BY m.match_criteria_id
        ORDER BY m.match_criteria_id
    """
    for match_id, occurrence_count, criteria_count in _stream_query(
        sql, [snapshot_pk]
    ):
        occurrence_distribution[occurrence_count] += 1
        criteria_multiplicity[criteria_count] += 1
        if criteria_count > 1:
            top_multiple.add(
                {
                    "match_criteria_id": str(match_id),
                    "occurrence_count": occurrence_count,
                    "distinct_criteria_string_count": criteria_count,
                }
            )

    return {
        "match_criteria_id_occurrence_distribution": _counter_rows(
            occurrence_distribution,
            key_name="occurrence_count",
            count_name="distinct_match_criteria_id_count",
        ),
        "match_criteria_id_to_criteria_multiplicity_distribution": (
            _counter_rows(
                criteria_multiplicity,
                key_name="distinct_criteria_string_count",
                count_name="distinct_match_criteria_id_count",
            )
        ),
        "match_criteria_ids_linked_to_multiple_criteria_strings": sum(
            count
            for variant_count, count in criteria_multiplicity.items()
            if variant_count >= 2
        ),
        "maximum_criteria_strings_per_match_criteria_id": max(
            criteria_multiplicity, default=0
        ),
        "top_match_criteria_ids_by_criteria_multiplicity": top_multiple.rows,
    }


def _range_field_profile(snapshot_pk: int) -> dict[str, Any]:
    match_table, record_table = _scope_sql()
    presence_columns: list[str] = []
    for field in RANGE_FIELDS:
        presence_columns.extend(
            [
                f"COUNT(*) FILTER (WHERE m.{field} IS NULL)",
                f"COUNT(*) FILTER (WHERE m.{field} IS NOT NULL)",
                f"COUNT(*) FILTER (WHERE m.{field} = '')",
                (
                    "COUNT(*) FILTER "
                    f"(WHERE m.{field} IS NOT NULL AND m.{field} <> '')"
                ),
                (
                    "COUNT(DISTINCT m.criteria) FILTER "
                    f"(WHERE m.{field} IS NOT NULL)"
                ),
            ]
        )
    row = _fetch_one(
        f"""
        SELECT {", ".join(presence_columns)}
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
        """,
        [snapshot_pk],
    )
    boundary_fields: dict[str, Any] = {}
    offset = 0
    for field in RANGE_FIELDS:
        boundary_fields[field] = {
            "null_occurrences": row[offset],
            "present_occurrences": row[offset + 1],
            "empty_string_occurrences": row[offset + 2],
            "nonempty_string_occurrences": row[offset + 3],
            "distinct_criteria_strings_when_present": row[offset + 4],
        }
        offset += 5

    combinations = []
    rows = _fetch_all(
        f"""
        SELECT
            m.version_start_including IS NOT NULL AS start_including,
            m.version_start_excluding IS NOT NULL AS start_excluding,
            m.version_end_including IS NOT NULL AS end_including,
            m.version_end_excluding IS NOT NULL AS end_excluding,
            COUNT(*) AS occurrence_count,
            COUNT(DISTINCT m.criteria) AS distinct_criteria_count
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
        GROUP BY 1, 2, 3, 4
        ORDER BY 1, 2, 3, 4
        """,
        [snapshot_pk],
    )
    for *presence, occurrence_count, distinct_count in rows:
        present_fields = [
            field for field, is_present in zip(RANGE_FIELDS, presence) if is_present
        ]
        combinations.append(
            {
                "present_fields": present_fields,
                "label": " + ".join(present_fields) if present_fields else "none",
                "occurrence_count": occurrence_count,
                "distinct_criteria_string_count": distinct_count,
            }
        )
    empty_string_examples = _fetch_all(
        f"""
        SELECT
            r.cve_id,
            m.criteria,
            m.vulnerable,
            m.version_start_including,
            m.version_start_excluding,
            m.version_end_including,
            m.version_end_excluding,
            m.match_criteria_id
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
          AND (
              m.version_start_including = ''
              OR m.version_start_excluding = ''
              OR m.version_end_including = ''
              OR m.version_end_excluding = ''
          )
        ORDER BY
            r.cve_id,
            m.criteria,
            m.configuration_index,
            m.node_index,
            m.match_index
        LIMIT %s
        """,
        [snapshot_pk, EXAMPLE_LIMIT],
    )
    return {
        "boundary_field_presence": boundary_fields,
        "actual_field_combinations": combinations,
        "empty_boundary_string_examples": [
            {
                "cve_id": row[0],
                "criteria": row[1],
                "vulnerable": row[2],
                "version_start_including": row[3],
                "version_start_excluding": row[4],
                "version_end_including": row[5],
                "version_end_excluding": row[6],
                "match_criteria_id": str(row[7]),
            }
            for row in empty_string_examples
        ],
    }


def _version_range_cross(snapshot_pk: int) -> dict[str, Any]:
    match_table, record_table = _scope_sql()
    occurrence = {
        category: {"range_absent": 0, "range_present": 0}
        for category in VERSION_CATEGORIES
    }
    distinct = {
        category: {"range_absent": 0, "range_present": 0}
        for category in VERSION_CATEGORIES
    }
    unusual_criteria: dict[str, list[str]] = {
        "concrete": [],
        "hyphen": [],
    }
    criteria_used_with_both_range_states = 0
    previous_criteria: str | None = None
    previous_range_states = 0
    has_range_sql = """
        m.version_start_including IS NOT NULL
        OR m.version_start_excluding IS NOT NULL
        OR m.version_end_including IS NOT NULL
        OR m.version_end_excluding IS NOT NULL
    """
    sql = f"""
        SELECT
            m.criteria,
            ({has_range_sql}) AS has_range,
            COUNT(*) AS occurrence_count
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
        GROUP BY m.criteria, ({has_range_sql})
        ORDER BY m.criteria, ({has_range_sql})
    """
    for criteria, has_range, count in _stream_query(sql, [snapshot_pk]):
        if previous_criteria is not None and criteria != previous_criteria:
            if previous_range_states == 2:
                criteria_used_with_both_range_states += 1
            previous_range_states = 0
        previous_criteria = criteria
        previous_range_states += 1
        parsed = parse_cpe23_formatted_string(criteria)
        category = (
            _version_category(parsed.version_raw)
            if parsed.is_structurally_valid
            else "other"
        )
        range_key = "range_present" if has_range else "range_absent"
        occurrence[category][range_key] += count
        distinct[category][range_key] += 1
        if (
            has_range
            and category in unusual_criteria
            and len(unusual_criteria[category]) < EXAMPLE_LIMIT
        ):
            unusual_criteria[category].append(criteria)
    if previous_range_states == 2:
        criteria_used_with_both_range_states += 1

    examples = {
        category: _representative_matches(snapshot_pk, criteria)
        for category, criteria in unusual_criteria.items()
    }
    return {
        "occurrence_counts": occurrence,
        "distinct_criteria_cell_counts": distinct,
        "criteria_strings_used_with_both_range_absent_and_present": (
            criteria_used_with_both_range_states
        ),
        "notes": (
            "Distinct criteria counts are per cell. A criteria string used "
            "both with and without range fields is counted in both cells."
        ),
        "concrete_version_with_range_examples": examples["concrete"],
        "hyphen_version_with_range_examples": examples["hyphen"],
    }


def _representative_matches(
    snapshot_pk: int,
    criteria: Sequence[str],
) -> list[dict[str, Any]]:
    if not criteria:
        return []
    match_table, record_table = _scope_sql()
    rows = _fetch_all(
        f"""
        SELECT DISTINCT ON (m.criteria)
            m.criteria,
            r.cve_id,
            m.vulnerable,
            m.version_start_including,
            m.version_start_excluding,
            m.version_end_including,
            m.version_end_excluding,
            m.match_criteria_id
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        WHERE r.snapshot_id = %s
          AND m.criteria = ANY(%s)
        ORDER BY
            m.criteria,
            r.cve_id,
            m.configuration_index,
            m.node_index,
            m.match_index
        """,
        [snapshot_pk, list(criteria)],
    )
    return [
        {
            "criteria": row[0],
            "cve_id": row[1],
            "vulnerable": row[2],
            "version_start_including": row[3],
            "version_start_excluding": row[4],
            "version_end_including": row[5],
            "version_end_excluding": row[6],
            "match_criteria_id": str(row[7]),
        }
        for row in rows
    ]


def _criteria_range_details(
    snapshot_pk: int,
    criteria_rows: list[dict[str, Any]],
) -> None:
    criteria = [row["criteria"] for row in criteria_rows]
    if not criteria:
        return
    match_table, record_table = _scope_sql()
    rows = _fetch_all(
        f"""
        WITH variants AS (
            SELECT
                m.criteria,
                m.version_start_including,
                m.version_start_excluding,
                m.version_end_including,
                m.version_end_excluding,
                COUNT(*) AS occurrence_count,
                COUNT(DISTINCT m.cve_record_id) AS distinct_cve_count
            FROM {match_table} m
            JOIN {record_table} r ON r.id = m.cve_record_id
            WHERE r.snapshot_id = %s
              AND m.criteria = ANY(%s)
            GROUP BY 1, 2, 3, 4, 5
        ),
        ranked AS (
            SELECT
                variants.*,
                ROW_NUMBER() OVER (
                    PARTITION BY criteria
                    ORDER BY
                        occurrence_count DESC,
                        version_start_including NULLS FIRST,
                        version_start_excluding NULLS FIRST,
                        version_end_including NULLS FIRST,
                        version_end_excluding NULLS FIRST
                ) AS rank
            FROM variants
        )
        SELECT
            criteria,
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
            occurrence_count,
            distinct_cve_count
        FROM ranked
        WHERE rank <= %s
        ORDER BY criteria, rank
        """,
        [snapshot_pk, criteria, EXAMPLE_LIMIT],
    )
    details: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        details[row[0]].append(
            {
                "version_start_including": row[1],
                "version_start_excluding": row[2],
                "version_end_including": row[3],
                "version_end_excluding": row[4],
                "occurrence_count": row[5],
                "distinct_cve_count": row[6],
            }
        )
    for criterion in criteria_rows:
        criterion["representative_range_tuples"] = details[
            criterion["criteria"]
        ]


def _mapping_details(
    snapshot_pk: int,
    cardinality: dict[str, Any],
    match_id_profile: dict[str, Any],
) -> None:
    match_table, record_table = _scope_sql()
    criteria_rows = cardinality[
        "top_criteria_by_match_criteria_id_multiplicity"
    ]
    criteria = [row["criteria"] for row in criteria_rows]
    if criteria:
        rows = _fetch_all(
            f"""
            SELECT
                m.criteria,
                m.match_criteria_id,
                COUNT(*) AS occurrence_count
            FROM {match_table} m
            JOIN {record_table} r ON r.id = m.cve_record_id
            WHERE r.snapshot_id = %s
              AND m.criteria = ANY(%s)
            GROUP BY 1, 2
            ORDER BY 1, 3 DESC, 2
            """,
            [snapshot_pk, criteria],
        )
        by_criteria: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for criterion, match_id, count in rows:
            if len(by_criteria[criterion]) < EXAMPLE_LIMIT:
                by_criteria[criterion].append(
                    {
                        "match_criteria_id": str(match_id),
                        "occurrence_count": count,
                    }
                )
        for criterion in criteria_rows:
            criterion["representative_match_criteria_ids"] = by_criteria[
                criterion["criteria"]
            ]

    id_rows = match_id_profile[
        "top_match_criteria_ids_by_criteria_multiplicity"
    ]
    match_ids = [row["match_criteria_id"] for row in id_rows]
    if match_ids:
        rows = _fetch_all(
            f"""
            SELECT
                m.match_criteria_id,
                m.criteria,
                COUNT(*) AS occurrence_count
            FROM {match_table} m
            JOIN {record_table} r ON r.id = m.cve_record_id
            WHERE r.snapshot_id = %s
              AND m.match_criteria_id = ANY(%s::uuid[])
            GROUP BY 1, 2
            ORDER BY 1, 3 DESC, 2
            """,
            [snapshot_pk, match_ids],
        )
        by_id: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for match_id, criterion, count in rows:
            key = str(match_id)
            if len(by_id[key]) < EXAMPLE_LIMIT:
                by_id[key].append(
                    {"criteria": criterion, "occurrence_count": count}
                )
        for id_row in id_rows:
            id_row["representative_criteria_strings"] = by_id[
                id_row["match_criteria_id"]
            ]


def _vulnerable_profile(
    snapshot_pk: int,
    derived: dict[str, Any],
) -> dict[str, Any]:
    match_table, record_table = _scope_sql()
    rows = _fetch_all(
        f"""
        WITH criteria_usage AS MATERIALIZED (
            SELECT
                m.criteria,
                BOOL_OR(m.vulnerable IS TRUE) AS has_true,
                BOOL_OR(m.vulnerable IS FALSE) AS has_false,
                BOOL_OR(m.vulnerable IS NULL) AS has_null
            FROM {match_table} m
            JOIN {record_table} r ON r.id = m.cve_record_id
            WHERE r.snapshot_id = %s
            GROUP BY m.criteria
        )
        SELECT
            CASE
                WHEN u.has_true AND u.has_false THEN 'both'
                WHEN u.has_true AND NOT u.has_false AND NOT u.has_null
                    THEN 'true_only'
                WHEN u.has_false AND NOT u.has_true AND NOT u.has_null
                    THEN 'false_only'
                ELSE 'null_or_unexpected'
            END AS usage_group,
            COUNT(DISTINCT m.cve_record_id) AS distinct_cve_count
        FROM {match_table} m
        JOIN {record_table} r ON r.id = m.cve_record_id
        JOIN criteria_usage u ON u.criteria = m.criteria
        WHERE r.snapshot_id = %s
        GROUP BY 1
        ORDER BY 1
        """,
        [snapshot_pk, snapshot_pk],
    )
    groups = derived["groups_derived_from_criteria_aggregates"]
    for group, cve_count in rows:
        groups[group]["distinct_cve_count"] = cve_count
    for group in groups.values():
        group.setdefault("distinct_cve_count", 0)

    top_both = derived["top_both_criteria"]
    criteria = [row["criteria"] for row in top_both]
    if criteria:
        breakdown = _fetch_all(
            f"""
            SELECT
                m.criteria,
                m.vulnerable,
                COUNT(*) AS occurrence_count,
                COUNT(DISTINCT m.cve_record_id) AS distinct_cve_count
            FROM {match_table} m
            JOIN {record_table} r ON r.id = m.cve_record_id
            WHERE r.snapshot_id = %s
              AND m.criteria = ANY(%s)
            GROUP BY 1, 2
            ORDER BY 1, 2
            """,
            [snapshot_pk, criteria],
        )
        by_criteria: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for criterion, vulnerable, occurrence_count, cve_count in breakdown:
            by_criteria[criterion].append(
                {
                    "vulnerable": vulnerable,
                    "occurrence_count": occurrence_count,
                    "distinct_cve_count": cve_count,
                }
            )
        for row in top_both:
            row["vulnerable_breakdown"] = by_criteria[row["criteria"]]
    return derived


def _structure_entity_profile(snapshot_pk: int, entity: str) -> dict[str, Any]:
    _, record_table = _scope_sql()
    if entity == "configuration":
        entity_cte = f"""
            SELECT r.id AS cve_record_id, value AS entity
            FROM {record_table} r
            CROSS JOIN LATERAL jsonb_array_elements(
                COALESCE(r.configurations, '[]'::jsonb)
            ) AS value
            WHERE r.snapshot_id = %s
        """
    elif entity == "node":
        entity_cte = f"""
            SELECT r.id AS cve_record_id, node_value AS entity
            FROM {record_table} r
            CROSS JOIN LATERAL jsonb_array_elements(
                COALESCE(r.configurations, '[]'::jsonb)
            ) AS configurations(configuration_value)
            CROSS JOIN LATERAL jsonb_array_elements(
                COALESCE(configuration_value->'nodes', '[]'::jsonb)
            ) AS nodes(node_value)
            WHERE r.snapshot_id = %s
        """
    else:
        raise ValueError(f"Unsupported entity: {entity}")

    rows = _fetch_all(
        f"""
        WITH entities AS MATERIALIZED ({entity_cte}),
        dimensions AS (
            SELECT
                cve_record_id,
                'operator'::text AS dimension,
                COALESCE(entity->>'operator', %s) AS value
            FROM entities
            UNION ALL
            SELECT
                cve_record_id,
                'negate'::text AS dimension,
                CASE
                    WHEN entity ? 'negate' THEN COALESCE(
                        entity->>'negate', %s
                    )
                    ELSE %s
                END AS value
            FROM entities
        )
        SELECT
            dimension,
            value,
            COUNT(*) AS entity_count,
            COUNT(DISTINCT cve_record_id) AS distinct_cve_count
        FROM dimensions
        GROUP BY 1, 2
        ORDER BY 1, 2
        """,
        [snapshot_pk, NULL_VALUE, NULL_VALUE, NULL_VALUE],
    )
    profile: dict[str, list[dict[str, Any]]] = {
        "operator": [],
        "negate": [],
    }
    for dimension, value, entity_count, cve_count in rows:
        profile[dimension].append(
            {
                "value": value,
                "entity_count": entity_count,
                "distinct_cve_count": cve_count,
            }
        )
    profile["entity_count"] = sum(
        row["entity_count"] for row in profile["operator"]
    )
    return profile


def _match_structure_profile(snapshot_pk: int) -> dict[str, Any]:
    match_table, record_table = _scope_sql()
    rows = _fetch_all(
        f"""
        WITH scoped AS MATERIALIZED (
            SELECT m.*
            FROM {match_table} m
            JOIN {record_table} r ON r.id = m.cve_record_id
            WHERE r.snapshot_id = %s
        ),
        dimensions AS (
            SELECT
                vulnerable,
                'configuration_operator'::text AS dimension,
                COALESCE(configuration_operator, %s) AS value
            FROM scoped
            UNION ALL
            SELECT
                vulnerable,
                'configuration_negate',
                COALESCE(configuration_negate::text, %s)
            FROM scoped
            UNION ALL
            SELECT
                vulnerable,
                'node_operator',
                COALESCE(node_operator, %s)
            FROM scoped
            UNION ALL
            SELECT
                vulnerable,
                'node_negate',
                COALESCE(node_negate::text, %s)
            FROM scoped
            UNION ALL
            SELECT
                vulnerable,
                'node_or_and_other',
                CASE
                    WHEN node_operator = 'OR' THEN 'OR'
                    WHEN node_operator = 'AND' THEN 'AND'
                    ELSE COALESCE(node_operator, %s)
                END
            FROM scoped
            UNION ALL
            SELECT
                vulnerable,
                'configuration_or_node_negate_true',
                CASE
                    WHEN configuration_negate IS TRUE
                      OR node_negate IS TRUE THEN 'true'
                    ELSE 'false'
                END
            FROM scoped
        )
        SELECT
            dimension,
            value,
            CASE
                WHEN vulnerable IS TRUE THEN 'true'
                WHEN vulnerable IS FALSE THEN 'false'
                ELSE %s
            END AS vulnerable_value,
            COUNT(*) AS occurrence_count
        FROM dimensions
        GROUP BY 1, 2, 3
        ORDER BY 1, 2, 3
        """,
        [
            snapshot_pk,
            NULL_VALUE,
            NULL_VALUE,
            NULL_VALUE,
            NULL_VALUE,
            NULL_VALUE,
            NULL_VALUE,
        ],
    )
    dimensions: defaultdict[str, defaultdict[str, dict[str, int]]] = (
        defaultdict(lambda: defaultdict(dict))
    )
    for dimension, value, vulnerable, count in rows:
        dimensions[dimension][value][vulnerable] = count
    return {
        dimension: [
            {
                "value": value,
                "by_vulnerable": dict(sorted(vulnerable.items())),
                "occurrence_count": sum(vulnerable.values()),
            }
            for value, vulnerable in sorted(values.items())
        ]
        for dimension, values in sorted(dimensions.items())
    }


def _configuration_structure(snapshot_pk: int) -> dict[str, Any]:
    configuration = _structure_entity_profile(snapshot_pk, "configuration")
    node = _structure_entity_profile(snapshot_pk, "node")
    return {
        "source": (
            "All configuration/node entities are expanded read-only from "
            "NvdCveRecord.configurations JSON, including entities with no "
            "flattened cpeMatch. Occurrence relationships use NvdCpeMatch."
        ),
        "configuration_entities": configuration,
        "node_entities": node,
        "cpe_match_occurrence_dimensions": _match_structure_profile(
            snapshot_pk
        ),
    }


def _validate_profile(summary: dict[str, Any]) -> None:
    cardinality = summary["criteria_cardinality"]
    total = cardinality["total_occurrences"]
    distinct_criteria = cardinality["distinct_criteria_strings"]
    distinct_ids = cardinality["distinct_match_criteria_ids"]
    failures: list[str] = []

    if (
        cardinality["vulnerable_true_occurrences"]
        + cardinality["vulnerable_false_occurrences"]
        + cardinality["vulnerable_null_occurrences"]
        != total
    ):
        failures.append("vulnerable occurrence sum != total occurrences")
    if (
        cardinality["range_absent_occurrences"]
        + cardinality["range_present_occurrences"]
        != total
    ):
        failures.append("range presence sum != total occurrences")

    criteria_distribution = cardinality[
        "criteria_occurrence_distribution"
    ]
    if sum(
        row["distinct_criteria_string_count"]
        for row in criteria_distribution
    ) != distinct_criteria:
        failures.append("criteria occurrence distribution size mismatch")
    if sum(
        row["occurrence_count"] * row["distinct_criteria_string_count"]
        for row in criteria_distribution
    ) != total:
        failures.append("criteria occurrence distribution weight mismatch")

    id_distribution = cardinality[
        "match_criteria_id_occurrence_distribution"
    ]
    if sum(
        row["distinct_match_criteria_id_count"] for row in id_distribution
    ) != distinct_ids:
        failures.append("matchCriteriaId occurrence distribution size mismatch")
    if sum(
        row["occurrence_count"] * row["distinct_match_criteria_id_count"]
        for row in id_distribution
    ) != total:
        failures.append("matchCriteriaId occurrence distribution weight mismatch")

    for name in ("part_distribution", "version_distribution"):
        rows = summary["cpe_field_profile"][name]
        if sum(row["occurrence_count"] for row in rows) != total:
            failures.append(f"{name} occurrence sum mismatch")
        if sum(row["distinct_criteria_string_count"] for row in rows) != (
            distinct_criteria
        ):
            failures.append(f"{name} distinct criteria sum mismatch")

    range_profile = summary["version_range_profile"]
    combinations = range_profile["actual_field_combinations"]
    if sum(row["occurrence_count"] for row in combinations) != total:
        failures.append("range combination occurrence sum mismatch")
    for field, counts in range_profile["boundary_field_presence"].items():
        if counts["null_occurrences"] + counts["present_occurrences"] != total:
            failures.append(f"{field} NULL/present sum mismatch")
        if (
            counts["empty_string_occurrences"]
            + counts["nonempty_string_occurrences"]
            != counts["present_occurrences"]
        ):
            failures.append(f"{field} empty/nonempty sum mismatch")

    cross = summary["version_range_cross_analysis"]
    if sum(
        values[range_state]
        for values in cross["occurrence_counts"].values()
        for range_state in ("range_absent", "range_present")
    ) != total:
        failures.append("version/range occurrence cross-table sum mismatch")

    multiplicity = summary["criteria_range_multiplicity"]
    if sum(
        row["distinct_criteria_string_count"]
        for row in multiplicity["range_variant_count_distribution"]
    ) != distinct_criteria:
        failures.append("range variant distribution size mismatch")

    vulnerable_groups = summary["vulnerable_usage"][
        "groups_derived_from_criteria_aggregates"
    ].values()
    if sum(row["occurrences"] for row in vulnerable_groups) != total:
        failures.append("vulnerable usage group occurrence sum mismatch")
    if sum(
        row["distinct_criteria_strings"] for row in vulnerable_groups
    ) != distinct_criteria:
        failures.append("vulnerable usage group criteria sum mismatch")

    structural = summary["exceptional_cases"][
        "structural_status_distribution"
    ]
    if sum(row["occurrence_count"] for row in structural) != total:
        failures.append("structural status occurrence sum mismatch")
    if sum(
        row["distinct_criteria_string_count"] for row in structural
    ) != distinct_criteria:
        failures.append("structural status criteria sum mismatch")

    structure = summary["configuration_structure"]
    for entity_name in ("configuration_entities", "node_entities"):
        entity = structure[entity_name]
        for dimension in ("operator", "negate"):
            if sum(
                row["entity_count"] for row in entity[dimension]
            ) != entity["entity_count"]:
                failures.append(
                    f"{entity_name} {dimension} distribution mismatch"
                )
    for dimension, rows in structure[
        "cpe_match_occurrence_dimensions"
    ].items():
        if sum(row["occurrence_count"] for row in rows) != total:
            failures.append(f"{dimension} occurrence sum mismatch")

    if failures:
        raise NvdCpeMatchAnalysisError(
            "Analysis invariant validation failed: " + "; ".join(failures)
        )


def _collect_database_state() -> dict[str, Any]:
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            read_only = _fetch_one("SHOW transaction_read_only", [])[0]
            table_counts: dict[str, int] = {}
            for table in sorted(connection.introspection.table_names()):
                quoted = connection.ops.quote_name(table)
                cursor.execute(f"SELECT COUNT(*) FROM {quoted}")
                table_counts[table] = cursor.fetchone()[0]
            cursor.execute(
                f"""
                SELECT
                    snapshot_id,
                    status,
                    manifest_sha256,
                    content_sha256,
                    record_count,
                    configuration_count,
                    cpe_match_count
                FROM {_quoted_table(NvdCveSnapshot)}
                ORDER BY snapshot_id
                """
            )
            nvd_snapshots = [list(row) for row in cursor.fetchall()]

            cpe_snapshot_table = connection.ops.quote_name(
                "cpe_dictionary_cpedictionarysnapshot"
            )
            cursor.execute(
                f"""
                SELECT
                    snapshot_id,
                    status,
                    manifest_sha256,
                    content_sha256,
                    record_count,
                    active_count,
                    deprecated_count
                FROM {cpe_snapshot_table}
                ORDER BY snapshot_id
                """
            )
            cpe_snapshots = [list(row) for row in cursor.fetchall()]
    return {
        "transaction_read_only": read_only == "on",
        "table_counts": table_counts,
        "nvd_snapshot_metadata": nvd_snapshots,
        "cpe_dictionary_snapshot_metadata": cpe_snapshots,
    }


def _build_profile(snapshot: NvdCveSnapshot) -> dict[str, Any]:
    basic = _basic_cardinality(snapshot.pk)
    if basic["total_occurrences"] != snapshot.cpe_match_count:
        raise NvdCpeMatchAnalysisError(
            "Selected snapshot cpeMatch metadata does not match scoped rows."
        )

    cardinality, field_profile, criteria_range, exceptional = (
        _criteria_profiles(snapshot.pk, basic)
    )
    vulnerable_derived = exceptional.pop("_vulnerable")
    match_id_profile = _match_criteria_id_profiles(snapshot.pk)
    cardinality.update(match_id_profile)
    _mapping_details(snapshot.pk, cardinality, match_id_profile)

    range_fields = _range_field_profile(snapshot.pk)
    _criteria_range_details(
        snapshot.pk,
        criteria_range["top_criteria_by_range_multiplicity"],
    )
    version_range_cross = _version_range_cross(snapshot.pk)
    vulnerable = _vulnerable_profile(snapshot.pk, vulnerable_derived)
    structure = _configuration_structure(snapshot.pk)

    if (
        structure["configuration_entities"]["entity_count"]
        != snapshot.configuration_count
    ):
        raise NvdCpeMatchAnalysisError(
            "Expanded configuration count does not match snapshot metadata."
        )

    summary = {
        "analysis_scope": ANALYSIS_SCOPE,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_status": snapshot.status,
            "manifest_sha256": snapshot.manifest_sha256,
            "content_sha256": snapshot.content_sha256,
            "feed_count": snapshot.feed_count,
            "cve_count": snapshot.record_count,
            "configuration_count": snapshot.configuration_count,
            "node_count": structure["node_entities"]["entity_count"],
            "cpe_match_count": snapshot.cpe_match_count,
        },
        "storage_structure": _storage_structure(),
        "criteria_cardinality": {
            **basic,
            **cardinality,
        },
        "cpe_field_profile": field_profile,
        "version_range_profile": {
            "range_absent_occurrences": basic[
                "range_absent_occurrences"
            ],
            "range_present_occurrences": basic[
                "range_present_occurrences"
            ],
            "range_present_percent": _rate(
                basic["range_present_occurrences"],
                basic["total_occurrences"],
            ),
            **range_fields,
        },
        "version_range_cross_analysis": version_range_cross,
        "criteria_range_multiplicity": criteria_range,
        "vulnerable_usage": vulnerable,
        "configuration_structure": structure,
        "exceptional_cases": exceptional,
    }
    _validate_profile(summary)
    summary["validation"] = {"aggregate_invariants_passed": True}
    return summary


def analyze_nvd_cpe_matches(
    configured_snapshot_id: str | None,
) -> NvdCpeMatchAnalysis:
    before = _collect_database_state()
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute("SHOW transaction_read_only")
            if cursor.fetchone()[0] != "on":
                raise NvdCpeMatchAnalysisError(
                    "PostgreSQL did not enter a read-only transaction."
                )
        snapshot = select_nvd_cve_snapshot(configured_snapshot_id)
        summary = _build_profile(snapshot)

    after = _collect_database_state()
    state_unchanged = (
        before["table_counts"] == after["table_counts"]
        and before["nvd_snapshot_metadata"]
        == after["nvd_snapshot_metadata"]
        and before["cpe_dictionary_snapshot_metadata"]
        == after["cpe_dictionary_snapshot_metadata"]
    )
    summary["safety"] = {
        "database_queries_executed_in_read_only_transactions": (
            before["transaction_read_only"]
            and after["transaction_read_only"]
        ),
        "database_state_unchanged": state_unchanged,
        "before": before,
        "after": after,
        "protected_domains": [
            "NVD CVE snapshot and records",
            "CPE Dictionary snapshots and names",
            "Firmware/source artifacts",
            "SBOM documents and components",
            "Ground Truth and its relation tables",
        ],
    }
    if not state_unchanged:
        raise NvdCpeMatchAnalysisError(
            "Database state changed while the analysis was running."
        )
    return NvdCpeMatchAnalysis(summary=summary)


def _number(value: int) -> str:
    return f"{value:,}"


def _markdown(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _distribution_table(
    rows: Iterable[dict[str, Any]],
    columns: Sequence[tuple[str, str]],
) -> list[str]:
    headers = [label for _, label in columns]
    result = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---:" for _ in headers) + " |",
    ]
    for row in rows:
        cells = []
        for key, _ in columns:
            value = row[key]
            cells.append(_number(value) if isinstance(value, int) else _markdown(value))
        result.append("| " + " | ".join(cells) + " |")
    return result


def render_report(summary: dict[str, Any]) -> str:
    dataset = summary["dataset"]
    cardinality = summary["criteria_cardinality"]
    field_profile = summary["cpe_field_profile"]
    ranges = summary["version_range_profile"]
    cross = summary["version_range_cross_analysis"]
    multiplicity = summary["criteria_range_multiplicity"]
    vulnerable = summary["vulnerable_usage"]
    structure = summary["configuration_structure"]
    exceptional = summary["exceptional_cases"]
    safety = summary["safety"]
    lines = [
        f"# NVD CPE Match Criteria 사용 형태 전수 분석 — {dataset['snapshot_id']}",
        "",
        f"생성 시각(UTC): `{summary['generated_at_utc']}`",
        "",
        "> 이 보고서는 raw `criteria` 문자열을 고유 CPE로 간주하지 않는다. "
        "CPE Dictionary 비교, version 의미 해석, applicability 판정은 수행하지 않았다.",
        "",
        "## A. Dataset",
        "",
        f"- Snapshot ID/status: `{dataset['snapshot_id']}` / `{dataset['snapshot_status']}`",
        f"- CVE records: {_number(dataset['cve_count'])}",
        f"- Configurations: {_number(dataset['configuration_count'])}",
        f"- Nodes: {_number(dataset['node_count'])}",
        f"- CPE Match occurrences: {_number(dataset['cpe_match_count'])}",
        f"- Manifest SHA-256: `{dataset['manifest_sha256']}`",
        f"- Content SHA-256: `{dataset['content_sha256']}`",
        "",
        "저장 구조는 `NvdCpeMatch`가 CVE record를 FK로 참조하고, "
        "configuration/node/match index로 위치를 보존하는 flattened row이다. "
        "operator/negate는 configuration과 node에서 각 occurrence로 복사된다. "
        "range key가 없으면 NULL이며, 키가 있으면 빈 문자열도 그대로 저장된다. "
        "전체 필드 타입과 nullability는 `summary.json`의 `storage_structure`에 있다.",
        "",
        "## B. Criteria Cardinality",
        "",
        f"- Total occurrences: {_number(cardinality['total_occurrences'])}",
        f"- Distinct criteria strings: {_number(cardinality['distinct_criteria_strings'])}",
        f"- Distinct matchCriteriaIds: {_number(cardinality['distinct_match_criteria_ids'])}",
        f"- vulnerable=true: {_number(cardinality['vulnerable_true_occurrences'])}",
        f"- vulnerable=false: {_number(cardinality['vulnerable_false_occurrences'])}",
        f"- vulnerable=NULL/비정상: {_number(cardinality['vulnerable_null_occurrences'])}",
        f"- 한 번만 등장한 criteria: {_number(cardinality['criteria_strings_occurring_once'])}",
        f"- 2회 이상 등장한 criteria: {_number(cardinality['criteria_strings_occurring_at_least_twice'])}",
        f"- criteria 최대 occurrence: {_number(cardinality['maximum_criteria_occurrence_count'])}",
        "",
        "### Occurrence 상위 criteria strings",
        "",
        *_distribution_table(
            cardinality["top_criteria_by_occurrence"],
            (
                ("criteria", "criteria"),
                ("occurrence_count", "occurrences"),
                ("distinct_cve_count", "CVEs"),
                ("distinct_match_criteria_id_count", "matchCriteriaIds"),
                ("distinct_range_tuple_count", "range tuples"),
            ),
        ),
        "",
        f"동일 criteria가 여러 matchCriteriaId에 연결된 criteria 수는 "
        f"{_number(cardinality['criteria_strings_linked_to_multiple_match_criteria_ids'])}, "
        f"반대 방향(동일 ID→여러 criteria)의 ID 수는 "
        f"{_number(cardinality['match_criteria_ids_linked_to_multiple_criteria_strings'])}이다. "
        "양방향의 전체 multiplicity/occurrence 분포와 대표 매핑은 `summary.json`에 있다.",
        "",
        "## C. CPE Field Profile",
        "",
        "### part 분포",
        "",
        *_distribution_table(
            field_profile["part_distribution"],
            (
                ("part", "part"),
                ("occurrence_count", "occurrences"),
                ("distinct_criteria_string_count", "distinct criteria"),
            ),
        ),
        "",
        "### version field 분포",
        "",
        *_distribution_table(
            field_profile["version_distribution"],
            (
                ("version_category", "version 형태"),
                ("occurrence_count", "occurrences"),
                ("distinct_criteria_string_count", "distinct criteria"),
            ),
        ),
        "",
        "11개 모든 CPE field의 `*`/`-`/concrete/empty 분포는 "
        "`summary.json`의 `all_field_token_distribution`에 occurrence와 "
        "distinct criteria 기준으로 각각 기록했다.",
        "",
        "### 모든 CPE field의 raw token 형태 (occurrence 기준)",
        "",
        *_distribution_table(
            [
                {
                    "field": field,
                    **counts["occurrence"],
                }
                for field, counts in field_profile[
                    "all_field_token_distribution"
                ].items()
            ],
            (
                ("field", "field"),
                ("star", "`*`"),
                ("hyphen", "`-`"),
                ("concrete", "concrete"),
                ("empty", "empty"),
            ),
        ),
        "",
        "## D. Version Range Profile",
        "",
        f"- Range 없음: {_number(ranges['range_absent_occurrences'])}",
        f"- Range 있음: {_number(ranges['range_present_occurrences'])} "
        f"({ranges['range_present_percent']:.8f}%)",
        "",
        "### 실제 존재하는 range-field 조합",
        "",
        *_distribution_table(
            ranges["actual_field_combinations"],
            (
                ("label", "present fields"),
                ("occurrence_count", "occurrences"),
                ("distinct_criteria_string_count", "distinct criteria"),
            ),
        ),
        "",
        "빈 boundary 문자열 occurrence의 대표 사례(최대 20개)는 "
        "`summary.json`의 `empty_boundary_string_examples`에 있다.",
        "",
        "### Boundary field별 NULL/present/empty",
        "",
        *_distribution_table(
            [
                {"field": field, **counts}
                for field, counts in ranges[
                    "boundary_field_presence"
                ].items()
            ],
            (
                ("field", "field"),
                ("null_occurrences", "NULL"),
                ("present_occurrences", "present"),
                ("empty_string_occurrences", "empty string"),
                ("nonempty_string_occurrences", "non-empty"),
            ),
        ),
        "",
        "## E. Version × Range Cross Analysis",
        "",
        "### Occurrence 기준",
        "",
        "| Criteria version 형태 | Range 없음 | Range 있음 |",
        "| --- | ---: | ---: |",
    ]
    labels = {
        "star": "`*`",
        "concrete": "concrete",
        "hyphen": "`-`",
        "other": "기타/empty/malformed",
    }
    for category in VERSION_CATEGORIES:
        values = cross["occurrence_counts"][category]
        lines.append(
            f"| {labels[category]} | {_number(values['range_absent'])} | "
            f"{_number(values['range_present'])} |"
        )
    lines.extend(
        [
            "",
            "### Distinct criteria string 기준(셀별)",
            "",
            "| Criteria version 형태 | Range 없음 | Range 있음 |",
            "| --- | ---: | ---: |",
        ]
    )
    for category in VERSION_CATEGORIES:
        values = cross["distinct_criteria_cell_counts"][category]
        lines.append(
            f"| {labels[category]} | {_number(values['range_absent'])} | "
            f"{_number(values['range_present'])} |"
        )
    lines.extend(
        [
            "",
            "Concrete version+range와 `-`+range의 최대 20개 대표 occurrence는 "
            "CVE ID, criteria, vulnerable, 네 boundary, matchCriteriaId와 함께 "
            "`summary.json`에 수록했다(0건인 유형의 배열은 비어 있다).",
            f"동일 criteria가 range 없음과 있음 양쪽에서 사용된 경우는 "
            f"{_number(cross['criteria_strings_used_with_both_range_absent_and_present'])}개다.",
            "",
            "## F. Criteria × Range Multiplicity",
            "",
            f"- Range tuple 1종류인 criteria: {_number(multiplicity['criteria_with_one_range_tuple'])}",
            f"- Range tuple 2종류 이상인 criteria: {_number(multiplicity['criteria_with_multiple_range_tuples'])}",
            f"- 한 criteria의 최대 range tuple 종류: {_number(multiplicity['maximum_range_tuples_per_criteria'])}",
            "",
            "### Range variant가 많은 criteria 상위 20개",
            "",
            *_distribution_table(
                multiplicity["top_criteria_by_range_multiplicity"],
                (
                    ("criteria", "criteria"),
                    ("occurrence_count", "occurrences"),
                    ("distinct_cve_count", "CVEs"),
                    ("distinct_range_tuple_count", "range tuples"),
                ),
            ),
            "",
            "각 상위 사례의 대표 range tuple 최대 20개와 tuple별 "
            "occurrence/CVE 수는 `summary.json`에 있다.",
            "",
            "## G. Vulnerable Usage",
            "",
        ]
    )
    group_rows = [
        {"group": key, **vulnerable["groups_derived_from_criteria_aggregates"][key]}
        for key in ("true_only", "false_only", "both", "null_or_unexpected")
    ]
    lines.extend(
        [
            *_distribution_table(
                group_rows,
                (
                    ("group", "group"),
                    ("distinct_criteria_strings", "distinct criteria"),
                    ("occurrences", "occurrences"),
                    ("distinct_cve_count", "distinct CVEs"),
                ),
            ),
            "",
            "True/false 양쪽에서 사용된 상위 20개 criteria와 각 boolean별 "
            "occurrence/CVE breakdown은 `summary.json`에 있다.",
            "",
            "## H. Configuration Structure",
            "",
            f"원본 JSON 전체에서 configuration {_number(structure['configuration_entities']['entity_count'])}개, "
            f"node {_number(structure['node_entities']['entity_count'])}개를 집계했다. "
            "operator/negate의 entity 분포와 cpeMatch occurrence 기준 "
            "configuration/node operator × vulnerable, AND/OR, effective negate "
            "교차분포는 `summary.json`에 있다. 복잡한 구조를 취약 여부로 판정하지 않았다.",
            "",
            "### Node operator (전체 node entity 기준)",
            "",
            *_distribution_table(
                structure["node_entities"]["operator"],
                (
                    ("value", "operator"),
                    ("entity_count", "nodes"),
                    ("distinct_cve_count", "distinct CVEs"),
                ),
            ),
            "",
            "### Configuration operator (전체 configuration entity 기준)",
            "",
            *_distribution_table(
                structure["configuration_entities"]["operator"],
                (
                    ("value", "operator"),
                    ("entity_count", "configurations"),
                    ("distinct_cve_count", "distinct CVEs"),
                ),
            ),
            "",
            "### Configuration negate (전체 configuration entity 기준)",
            "",
            *_distribution_table(
                structure["configuration_entities"]["negate"],
                (
                    ("value", "negate"),
                    ("entity_count", "configurations"),
                    ("distinct_cve_count", "distinct CVEs"),
                ),
            ),
            "",
            "### Node negate (전체 node entity 기준)",
            "",
            *_distribution_table(
                structure["node_entities"]["negate"],
                (
                    ("value", "negate"),
                    ("entity_count", "nodes"),
                    ("distinct_cve_count", "distinct CVEs"),
                ),
            ),
            "",
            "### cpeMatch occurrence × node AND/OR × vulnerable",
            "",
            "| node operator | vulnerable=false | vulnerable=true | total |",
            "| --- | ---: | ---: | ---: |",
            *[
                "| {value} | {false_count} | {true_count} | {total_count} |".format(
                    value=_markdown(row["value"]),
                    false_count=_number(row["by_vulnerable"].get("false", 0)),
                    true_count=_number(row["by_vulnerable"].get("true", 0)),
                    total_count=_number(row["occurrence_count"]),
                )
                for row in structure["cpe_match_occurrence_dimensions"][
                    "node_or_and_other"
                ]
            ],
            "",
            "### cpeMatch occurrence × configuration operator × vulnerable",
            "",
            "| configuration operator | vulnerable=false | vulnerable=true | total |",
            "| --- | ---: | ---: | ---: |",
            *[
                "| {value} | {false_count} | {true_count} | {total_count} |".format(
                    value=_markdown(row["value"]),
                    false_count=_number(row["by_vulnerable"].get("false", 0)),
                    true_count=_number(row["by_vulnerable"].get("true", 0)),
                    total_count=_number(row["occurrence_count"]),
                )
                for row in structure["cpe_match_occurrence_dimensions"][
                    "configuration_operator"
                ]
            ],
            "",
            "### cpeMatch occurrence × configuration/node negate × vulnerable",
            "",
            "| negate 포함 | vulnerable=false | vulnerable=true | total |",
            "| --- | ---: | ---: | ---: |",
            *[
                "| {value} | {false_count} | {true_count} | {total_count} |".format(
                    value=_markdown(row["value"]),
                    false_count=_number(row["by_vulnerable"].get("false", 0)),
                    true_count=_number(row["by_vulnerable"].get("true", 0)),
                    total_count=_number(row["occurrence_count"]),
                )
                for row in structure["cpe_match_occurrence_dimensions"][
                    "configuration_or_node_negate_true"
                ]
            ],
            "",
            "## I. Exceptional Cases",
            "",
            "### Structural parser status",
            "",
            *_distribution_table(
                exceptional["structural_status_distribution"],
                (
                    ("status", "status"),
                    ("occurrence_count", "occurrences"),
                    ("occurrence_percent", "occurrence %"),
                    ("distinct_criteria_string_count", "distinct criteria"),
                    ("distinct_criteria_percent", "distinct %"),
                ),
            ),
            "",
            "### Parser-attention categories",
            "",
            *_distribution_table(
                exceptional["parser_attention_categories"],
                (
                    ("category", "category"),
                    ("occurrence_count", "occurrences"),
                    ("occurrence_percent", "occurrence %"),
                    (
                        "distinct_criteria_string_count",
                        "distinct criteria",
                    ),
                    ("distinct_criteria_percent", "distinct %"),
                ),
            ),
            "",
            "빈 vendor/product/version, escape sequence, embedded unescaped "
            "wildcard는 서로 겹칠 수 있는 parser-attention 유형으로 별도 집계했다. "
            "`*`와 `-`는 사용 위치를 보고할 뿐 자동 오류로 분류하지 않았다. "
            "유형별 비율과 대표 최대 30개 criteria는 `summary.json`에 있다.",
            "",
            "## J. Interpretation (다음 단계의 판단 근거)",
            "",
        ]
    )
    multi_range = multiplicity["criteria_with_multiple_range_tuples"]
    concrete_range = cross["occurrence_counts"]["concrete"]["range_present"]
    hyphen_range = cross["occurrence_counts"]["hyphen"]["range_present"]
    both = vulnerable["groups_derived_from_criteria_aggregates"]["both"]
    lines.extend(
        [
            "1. `criteria`는 raw 문자열의 반복 사용을 세는 안정적인 관측 단위이지만, "
            f"{_number(multi_range)}개 문자열이 여러 range tuple과 연결되어 있으므로 "
            "그 자체가 완전한 applicability condition인지 여부는 분리해 검토해야 한다.",
            f"2. Range field는 전체 occurrence의 {ranges['range_present_percent']:.8f}%에서 사용된다. "
            "빈도뿐 아니라 동일 criteria의 range multiplicity와 range 있음/없음 "
            "양쪽 사용을 함께 보아야 한다.",
            f"3. Concrete version+range는 {_number(concrete_range)}건, `-`+range는 "
            f"{_number(hyphen_range)}건 관측되었다. 0이 아닌 유형은 별도 예외 경로가 필요하다.",
            f"4. True/false 양쪽에 걸친 criteria는 {_number(both['distinct_criteria_strings'])}개다. "
            "따라서 vulnerable은 raw criteria identity와 독립된 occurrence/context 속성으로 "
            "보존하는 방안을 다음 단계에서 검토할 근거가 있다.",
            "5. 추천안(정의 확정 아님): 다음 단계의 후보 키를 최소한 "
            "`criteria`, 4-field range tuple, vulnerable, configuration/node context로 "
            "분해해 비교하고, matchCriteriaId의 양방향 다중 연결도 별도 식별자 특성으로 "
            "검증한다. 이번 결과로 deduplication artifact나 unique CPE catalog는 만들지 않았다.",
            "",
            "## Safety",
            "",
            f"- 모든 DB 집계 트랜잭션 READ ONLY: `{str(safety['database_queries_executed_in_read_only_transactions']).lower()}`",
            f"- 작업 전후 전체 DB table row count 및 NVD/CPE snapshot metadata 동일: "
            f"`{str(safety['database_state_unchanged']).lower()}`",
            f"- 내부 aggregate 합계 불변식 검증 통과: "
            f"`{str(summary['validation']['aggregate_invariants_passed']).lower()}`",
            "- CPE Dictionary membership/exact/family/deprecated 비교 query: 0건",
            "- Firmware/SBOM/Ground Truth 변경 query: 0건",
            "- 전체 작업 전후 table별 count는 `summary.json`의 `safety`에 기록했다.",
            "",
        ]
    )
    return "\n".join(lines)


def render_analysis(analysis: NvdCpeMatchAnalysis) -> dict[str, str]:
    return {
        "summary.json": json.dumps(
            analysis.summary,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        "report.md": render_report(analysis.summary),
    }


def write_analysis(
    analysis: NvdCpeMatchAnalysis,
    output_directory: Path,
) -> dict[str, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    rendered = render_analysis(analysis)
    paths: dict[str, Path] = {}
    for filename in OUTPUT_FILENAMES:
        target = output_directory / filename
        descriptor, temporary_name = tempfile.mkstemp(
            dir=output_directory,
            prefix=f".{filename}.",
            text=True,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(rendered[filename])
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_name, target)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
        paths[filename] = target
    return paths

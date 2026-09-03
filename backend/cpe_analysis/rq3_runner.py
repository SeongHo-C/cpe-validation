from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from django.db import connection, transaction

from cpe.cpe23_canonical import (
    CPE23Attribute,
    CPE23Name,
    CPE23ValueKind,
    parse_cpe23,
)
from cpe.matching import (
    AttributeRelation,
    CPEAttributeMatchStatus,
    compare_cpe_attribute_values,
    match_cpe_attributes,
)
from cpe.version_matching import VersionMatchResult, match_version_constraint
from nvd_cve.models import NvdCpeMatch, NvdCveRecord, NvdCveSnapshot
from sboms.models import Component


GROUND_TRUTH_RELATIVE_PATH = Path("research/ground_truth/ground_truth.csv")
NVD_SNAPSHOT_ID = "20260820T110357Z"

EXPECTED_INPUT_COUNTS = {
    "components": 2_038,
    "original_present": 2_038,
    "gt_cpe": 158,
    "gt_null": 1_880,
    "original_valid": 1_954,
    "original_invalid": 84,
    "gt_valid": 158,
    "gt_invalid": 0,
    "eligible_cves": 262_758,
    "eligible_vulnerable_leaves": 1_878_692,
}
EXPECTED_PRIMARY_METRICS = {
    "original_identified": 14_750,
    "gt_identified": 15_299,
    "COMMON": 14_697,
    "ADDED": 512,
    "REMOVED": 53,
    "INDETERMINATE": 1_747,
}
EXPECTED_GT_BEARING_METRICS = {
    "components": 158,
    "original_identified": 14_697,
    "gt_identified": 15_299,
    "COMMON": 14_697,
    "ADDED": 512,
    "REMOVED": 0,
    "INDETERMINATE": 1_688,
}
EXPECTED_ADDED_CAUSES = {
    "VENDOR_ONLY": 173,
    "MULTI_FIELD": 328,
    "VERSION_EXACT_ONLY": 10,
    "VERSION_RANGE_ONLY": 1,
}

IDENTITY_ATTRIBUTES = ("part", "vendor", "product")
ATTRIBUTES = (
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
RANGE_FIELDS = (
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
)
UNRESOLVED_LEAF_RESULTS = {
    "UNSUPPORTED_VERSION_COMPARISON",
    "INVALID_NVD_RANGE",
}
REQUIRED_GROUND_TRUTH_COLUMNS = {
    "firmware_vendor",
    "firmware_product",
    "firmware_version",
    "sbom_document_id",
    "component_id",
    "component_name",
    "component_version",
    "original_cpe",
    "ground_truth_cpe",
}
COMPARISON_FIELDS = (
    "component_id",
    "sbom_document_id",
    "firmware",
    "component_name",
    "component_version",
    "original_cpe",
    "gt_cpe",
    "cve_id",
    "original_status",
    "gt_status",
    "comparison_status",
    "reason",
    "original_unresolved_causes",
    "gt_unresolved_causes",
)
CAUSE_FIELDS = (
    "component_id",
    "sbom_document_id",
    "firmware",
    "component_name",
    "component_version",
    "original_cpe",
    "gt_cpe",
    "cve_id",
    "changed_fields",
    "cause_category",
    "witness_count",
    "minimal_blocker_cardinality",
    "minimal_blocker_signatures",
    "representative_nvd_cpe_match_id",
    "representative_criteria",
    *RANGE_FIELDS,
    "representative_blockers",
)


class RQ3RunnerError(RuntimeError):
    """Raised when an RQ3 fixed input or matching invariant is violated."""


@dataclass(frozen=True)
class ComponentInput:
    component_id: int
    sbom_document_id: int
    firmware: str
    component_name: str
    component_version: str
    original_cpe: str
    gt_cpe: str
    original_name: CPE23Name | None
    gt_name: CPE23Name | None


@dataclass(frozen=True)
class Binding:
    path: str
    component_id: int


@dataclass
class Aggregate:
    status: str = "UNRESOLVED"
    causes: set[str] = field(default_factory=set)
    evidence_leaf_count: int = 0


@dataclass(frozen=True)
class LeafEvidence:
    nvd_cpe_match_id: int
    criteria: str
    ranges: tuple[str | None, str | None, str | None, str | None]


@dataclass(frozen=True)
class RQ3RunResult:
    summary: dict[str, object]
    comparison_rows: tuple[dict[str, object], ...]
    added_cause_rows: tuple[dict[str, object], ...]


def _read_ground_truth(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise RQ3RunnerError(f"Ground Truth CSV does not exist: {path}")
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        columns = set(reader.fieldnames or ())
        missing = REQUIRED_GROUND_TRUTH_COLUMNS - columns
        if missing:
            raise RQ3RunnerError(
                "Ground Truth CSV is missing columns: " + ", ".join(sorted(missing))
            )
        rows = list(reader)
    component_ids = [row["component_id"] for row in rows]
    if len(component_ids) != len(set(component_ids)):
        raise RQ3RunnerError("Ground Truth CSV contains duplicate component_id values")
    return rows


def _has_unquoted_wildcard(value: str) -> bool:
    escaped = False
    for character in value:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character in "*?":
            return True
    return False


def _logical_literal(value: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\":
            index += 1
        result.append(value[index])
        index += 1
    return "".join(result).lower()


def _simple_identity(name: CPE23Name) -> tuple[str, str, str] | None:
    values: list[str] = []
    for attribute_name in IDENTITY_ATTRIBUTES:
        attribute = name.attribute(attribute_name)
        if (
            attribute.kind is not CPE23ValueKind.STRING
            or _has_unquoted_wildcard(attribute.canonical)
        ):
            return None
        values.append(_logical_literal(attribute.canonical))
    return values[0], values[1], values[2]


def _identity_matches(
    source: tuple[CPE23Attribute, CPE23Attribute, CPE23Attribute],
    target: CPE23Name,
) -> bool:
    return all(
        compare_cpe_attribute_values(source_attribute, target.attribute(name))
        in {AttributeRelation.EQUAL, AttributeRelation.SUPERSET}
        for name, source_attribute in zip(
            IDENTITY_ATTRIBUTES, source, strict=True
        )
    )


def _aggregate_result(
    aggregates: dict[str, dict[tuple[int, str], Aggregate]],
    path: str,
    component_id: int,
    cve_id: str,
    leaf_result: str,
) -> None:
    key = (component_id, cve_id)
    current = aggregates[path].get(key)
    if leaf_result == "MATCH":
        if current is None:
            aggregates[path][key] = Aggregate(
                status="MATCH", evidence_leaf_count=1
            )
        else:
            current.status = "MATCH"
            current.evidence_leaf_count += 1
    elif leaf_result in UNRESOLVED_LEAF_RESULTS:
        if current is None:
            aggregates[path][key] = Aggregate(
                status="UNRESOLVED",
                causes={leaf_result},
                evidence_leaf_count=1,
            )
        elif current.status != "MATCH":
            current.causes.add(leaf_result)
            current.evidence_leaf_count += 1


def _unresolved_reason(path: str, causes: set[str]) -> str:
    prefix = "ORIGINAL" if path == "ORIGINAL" else "GT"
    unsupported = "UNSUPPORTED_VERSION_COMPARISON" in causes
    invalid = "INVALID_NVD_RANGE" in causes
    if unsupported and invalid:
        return f"{prefix}_UNSUPPORTED_VERSION_AND_INVALID_NVD_RANGE"
    if unsupported:
        return f"{prefix}_UNSUPPORTED_VERSION"
    if invalid:
        return f"{prefix}_INVALID_NVD_RANGE"
    raise RQ3RunnerError(f"Unresolved relation has no cause: {path} {causes}")


def classify_relation(
    original_status: str,
    gt_status: str,
    original_causes: set[str] | None = None,
    gt_causes: set[str] | None = None,
) -> tuple[str, str]:
    """Apply the frozen RQ3 relation partition, including unresolved precedence."""
    original_causes = original_causes or set()
    gt_causes = gt_causes or set()
    if original_status == "MATCH" and gt_status == "MATCH":
        return "COMMON", "BOTH_MATCH"
    if original_status == "UNRESOLVED" or gt_status == "UNRESOLVED":
        if original_status == "UNRESOLVED" and gt_status == "UNRESOLVED":
            return "INDETERMINATE", "BOTH_UNRESOLVED"
        if original_status == "UNRESOLVED":
            return "INDETERMINATE", _unresolved_reason(
                "ORIGINAL", original_causes
            )
        return "INDETERMINATE", _unresolved_reason("GROUND_TRUTH", gt_causes)
    if gt_status == "MATCH":
        reason = (
            "ORIGINAL_INVALID_CPE"
            if original_status == "INVALID_ORIGINAL_CPE"
            else "ORIGINAL_NO_MATCH"
        )
        return "ADDED_AFTER_CORRECTION", reason
    if original_status == "MATCH":
        reason = "GT_NO_CPE" if gt_status == "NO_GT_CPE" else "GT_NO_MATCH"
        return "REMOVED_AFTER_CORRECTION", reason
    raise RQ3RunnerError(
        f"Comparison relation has no actionable status: {original_status}, {gt_status}"
    )


def _changed_fields(left: CPE23Name, right: CPE23Name) -> tuple[str, ...]:
    return tuple(
        attribute.upper()
        for attribute in ATTRIBUTES
        if (
            left.attribute(attribute).kind != right.attribute(attribute).kind
            or left.attribute(attribute).canonical
            != right.attribute(attribute).canonical
        )
    )


def _blocker_signature(fields: frozenset[str]) -> str:
    order = {
        "PART": 0,
        "VENDOR": 1,
        "PRODUCT": 2,
        "VERSION_EXACT": 3,
        "VERSION_RANGE": 3,
        "UPDATE": 4,
        "EDITION": 5,
        "LANGUAGE": 6,
        "SW_EDITION": 7,
        "TARGET_SW": 8,
        "TARGET_HW": 9,
        "OTHER": 10,
    }
    return "+".join(sorted(fields, key=lambda value: (order[value], value)))


def _cause_category(minimal_sets: set[frozenset[str]]) -> str:
    if len(minimal_sets) != 1:
        return "MULTIPLE_POSSIBLE_BLOCKERS"
    fields = next(iter(minimal_sets))
    if len(fields) > 1:
        return "MULTI_FIELD"
    field_name = next(iter(fields))
    return {
        "VERSION_EXACT": "VERSION_EXACT_ONLY",
        "VERSION_RANGE": "VERSION_RANGE_ONLY",
        "VENDOR": "VENDOR_ONLY",
        "PRODUCT": "PRODUCT_ONLY",
        "PART": "PART_ONLY",
        "UPDATE": "UPDATE_ONLY",
        "TARGET_SW": "TARGET_SW_ONLY",
        "TARGET_HW": "TARGET_HW_ONLY",
    }.get(field_name, "OTHER_SINGLE_FIELD")


def _replay_leaf(
    criteria: str,
    target: CPE23Name,
    ranges: tuple[str | None, str | None, str | None, str | None],
) -> tuple[str, frozenset[str]]:
    has_range = any(value is not None for value in ranges)
    attribute = match_cpe_attributes(criteria, target, ignore_version=has_range)
    if attribute.status not in {
        CPEAttributeMatchStatus.MATCH,
        CPEAttributeMatchStatus.NO_MATCH,
    }:
        return attribute.status.value, frozenset()
    blockers = {
        "VERSION_EXACT" if item.attribute == "version" else item.attribute.upper()
        for item in attribute.comparisons
        if item.relation not in {AttributeRelation.EQUAL, AttributeRelation.SUPERSET}
    }
    if blockers:
        return "NO_MATCH", frozenset(blockers)
    if not has_range:
        return "MATCH", frozenset()
    criteria_result = parse_cpe23(criteria)
    if not criteria_result.is_valid or criteria_result.name is None:
        raise RQ3RunnerError(f"Cannot replay invalid NVD criteria: {criteria}")
    version = match_version_constraint(
        criteria_result.name.attribute("version"),
        target.attribute("version"),
        version_start_including=ranges[0],
        version_start_excluding=ranges[1],
        version_end_including=ranges[2],
        version_end_excluding=ranges[3],
    )
    if version is VersionMatchResult.MATCH:
        return "MATCH", frozenset()
    if version is VersionMatchResult.NO_MATCH:
        return "NO_MATCH", frozenset({"VERSION_RANGE"})
    return version.value, frozenset()


def _additional_attribute_complexity(criteria: str) -> int:
    parsed = parse_cpe23(criteria)
    if not parsed.is_valid or parsed.name is None:
        raise RQ3RunnerError(f"Cannot inspect invalid NVD criteria: {criteria}")
    return sum(
        parsed.name.attribute(attribute).kind is not CPE23ValueKind.ANY
        for attribute in ATTRIBUTES[4:]
    )


def _write_csv(
    path: Path,
    fieldnames: Iterable[str],
    rows: Iterable[dict[str, object]],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=tuple(fieldnames), extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)


def _eligible_cte() -> tuple[str, str, str]:
    match_table = connection.ops.quote_name(NvdCpeMatch._meta.db_table)
    record_table = connection.ops.quote_name(NvdCveRecord._meta.db_table)
    sql = f"""
        WITH scoped AS MATERIALIZED (
            SELECT m.*
            FROM {match_table} m
            JOIN {record_table} r ON r.id = m.cve_record_id
            WHERE r.snapshot_id = %s
        ), eligible AS MATERIALIZED (
            SELECT cve_record_id
            FROM scoped
            GROUP BY cve_record_id
            HAVING NOT BOOL_OR(NOT COALESCE(vulnerable, FALSE))
               AND NOT BOOL_OR(
                    COALESCE(UPPER(configuration_operator) = 'AND', FALSE)
                    OR COALESCE(UPPER(node_operator) = 'AND', FALSE)
               )
               AND NOT BOOL_OR(
                    COALESCE(configuration_negate = TRUE, FALSE)
                    OR COALESCE(node_negate = TRUE, FALSE)
               )
        )
    """
    return sql, match_table, record_table


def _load_component_inputs(
    ground_truth_rows: list[dict[str, str]],
) -> list[ComponentInput]:
    component_ids = [int(row["component_id"]) for row in ground_truth_rows]
    components = {
        component.id: component
        for component in Component.objects.filter(id__in=component_ids)
        .select_related("sbom_document")
        .order_by("id")
    }
    if len(components) != len(component_ids):
        missing = sorted(set(component_ids) - set(components))
        raise RQ3RunnerError(
            f"Ground Truth component scope is missing from DB: {missing[:20]}"
        )

    result: list[ComponentInput] = []
    mismatches: list[str] = []
    for row in ground_truth_rows:
        component_id = int(row["component_id"])
        component = components[component_id]
        expected = {
            "sbom_document_id": str(component.sbom_document_id),
            "component_name": component.name,
            "component_version": component.version,
            "original_cpe": component.cpe,
        }
        for field_name, db_value in expected.items():
            if row[field_name] != db_value:
                mismatches.append(
                    f"component {component_id} {field_name}: CSV={row[field_name]!r}, "
                    f"DB={db_value!r}"
                )
        original = parse_cpe23(component.cpe)
        gt_cpe = row["ground_truth_cpe"].strip()
        gt = parse_cpe23(gt_cpe) if gt_cpe else None
        firmware = " ".join(
            value
            for value in (
                row["firmware_vendor"],
                row["firmware_product"],
                row["firmware_version"],
            )
            if value
        )
        result.append(
            ComponentInput(
                component_id=component_id,
                sbom_document_id=component.sbom_document_id,
                firmware=firmware,
                component_name=component.name,
                component_version=component.version,
                original_cpe=component.cpe,
                gt_cpe=gt_cpe,
                original_name=original.name if original.is_valid else None,
                gt_name=gt.name if gt is not None and gt.is_valid else None,
            )
        )
    if mismatches:
        raise RQ3RunnerError(
            "Canonical Ground Truth does not match DB Components: "
            + "; ".join(mismatches[:20])
        )
    return result


def _input_counts(components: list[ComponentInput]) -> dict[str, int]:
    return {
        "components": len(components),
        "original_present": sum(bool(row.original_cpe) for row in components),
        "gt_cpe": sum(bool(row.gt_cpe) for row in components),
        "gt_null": sum(not row.gt_cpe for row in components),
        "original_valid": sum(row.original_name is not None for row in components),
        "original_invalid": sum(row.original_name is None for row in components),
        "gt_valid": sum(row.gt_name is not None for row in components),
        "gt_invalid": sum(bool(row.gt_cpe) and row.gt_name is None for row in components),
    }


def _table_counts(nvd_snapshot_pk: int) -> dict[str, int]:
    return {
        "components": Component.objects.count(),
        "nvd_records": NvdCveRecord.objects.filter(
            snapshot_id=nvd_snapshot_pk
        ).count(),
        "nvd_cpe_matches": NvdCpeMatch.objects.filter(
            cve_record__snapshot_id=nvd_snapshot_pk
        ).count(),
    }


def _analyze_added_causes(
    comparison_rows: list[dict[str, object]],
    components: dict[int, ComponentInput],
    gt_evidence: dict[tuple[int, str], list[LeafEvidence]],
) -> tuple[list[dict[str, object]], Counter[str]]:
    relation_rows: list[dict[str, object]] = []
    added = [
        row
        for row in comparison_rows
        if row["comparison_status"] == "ADDED_AFTER_CORRECTION"
    ]
    for comparison in added:
        component_id = int(comparison["component_id"])
        component = components[component_id]
        if component.original_name is None or component.gt_name is None:
            raise RQ3RunnerError(
                "ADDED cause replay requires valid Original and GT CPEs: "
                f"component {component_id}"
            )
        key = component_id, str(comparison["cve_id"])
        evidence = gt_evidence.get(key, [])
        if not evidence:
            raise RQ3RunnerError(f"No GT MATCH witness for ADDED relation {key}")

        witnesses: list[dict[str, object]] = []
        for leaf in evidence:
            gt_result, gt_blockers = _replay_leaf(
                leaf.criteria, component.gt_name, leaf.ranges
            )
            original_result, blockers = _replay_leaf(
                leaf.criteria, component.original_name, leaf.ranges
            )
            if gt_result != "MATCH" or gt_blockers:
                raise RQ3RunnerError(f"GT witness replay failed for {key}")
            if original_result != "NO_MATCH" or not blockers:
                raise RQ3RunnerError(f"Original witness replay mismatch for {key}")
            witnesses.append(
                {
                    "leaf": leaf,
                    "blockers": blockers,
                    "complexity": _additional_attribute_complexity(leaf.criteria),
                }
            )

        minimum = min(len(row["blockers"]) for row in witnesses)
        minimal = {
            row["blockers"]
            for row in witnesses
            if len(row["blockers"]) == minimum
        }
        representative = min(
            witnesses,
            key=lambda row: (
                len(row["blockers"]),
                len(row["blockers"]) != 1,
                row["complexity"],
                any(row["leaf"].ranges),
                row["leaf"].nvd_cpe_match_id,
            ),
        )
        leaf = representative["leaf"]
        blockers = representative["blockers"]
        relation_rows.append(
            {
                **comparison,
                "changed_fields": ";".join(
                    _changed_fields(component.original_name, component.gt_name)
                ),
                "cause_category": _cause_category(minimal),
                "witness_count": len(witnesses),
                "minimal_blocker_cardinality": minimum,
                "minimal_blocker_signatures": " | ".join(
                    sorted(_blocker_signature(value) for value in minimal)
                ),
                "representative_nvd_cpe_match_id": leaf.nvd_cpe_match_id,
                "representative_criteria": leaf.criteria,
                **dict(zip(RANGE_FIELDS, leaf.ranges, strict=True)),
                "representative_blockers": _blocker_signature(blockers),
            }
        )
    return relation_rows, Counter(
        str(row["cause_category"]) for row in relation_rows
    )


def _run_matching(
    *,
    ground_truth_rows: list[dict[str, str]],
    nvd_snapshot_id: str,
    analyze_added_causes: bool,
    enforce_fixed_contract: bool,
    progress: Callable[[str], None],
) -> RQ3RunResult:
    eligible_cte, _match_table, record_table = _eligible_cte()
    aggregates: dict[str, dict[tuple[int, str], Aggregate]] = {
        "ORIGINAL": {},
        "GROUND_TRUTH": {},
    }
    gt_evidence: dict[tuple[int, str], list[LeafEvidence]] = defaultdict(list)

    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
            )
            cursor.execute("SHOW transaction_isolation")
            isolation = cursor.fetchone()[0]
            cursor.execute("SHOW transaction_read_only")
            read_only = cursor.fetchone()[0]

        nvd_snapshot = NvdCveSnapshot.objects.get(snapshot_id=nvd_snapshot_id)
        counts_before = _table_counts(nvd_snapshot.pk)
        component_rows = _load_component_inputs(ground_truth_rows)
        counts = _input_counts(component_rows)
        if enforce_fixed_contract:
            mismatches = {
                key: {"expected": value, "actual": counts.get(key)}
                for key, value in EXPECTED_INPUT_COUNTS.items()
                if key in counts and counts.get(key) != value
            }
            if mismatches:
                raise RQ3RunnerError(f"Fixed component input mismatch: {mismatches}")
        if counts["gt_invalid"]:
            raise RQ3RunnerError("Canonical Ground Truth contains invalid GT CPEs")

        with connection.cursor() as cursor:
            cursor.execute(
                eligible_cte
                + """
                SELECT
                    (SELECT COUNT(*) FROM eligible),
                    COUNT(*),
                    COUNT(DISTINCT s.criteria)
                FROM scoped s
                JOIN eligible e ON e.cve_record_id = s.cve_record_id
                WHERE s.vulnerable IS TRUE
                """,
                [nvd_snapshot.pk],
            )
            eligible_cves, eligible_leaves, distinct_criteria_count = cursor.fetchone()
            cursor.execute(
                eligible_cte
                + """
                SELECT DISTINCT s.criteria
                FROM scoped s
                JOIN eligible e ON e.cve_record_id = s.cve_record_id
                WHERE s.vulnerable IS TRUE
                ORDER BY s.criteria
                """,
                [nvd_snapshot.pk],
            )
            distinct_criteria = [row[0] for row in cursor.fetchall()]
        counts.update(
            {
                "eligible_cves": eligible_cves,
                "eligible_vulnerable_leaves": eligible_leaves,
                "distinct_criteria": distinct_criteria_count,
            }
        )
        if enforce_fixed_contract:
            for key in ("eligible_cves", "eligible_vulnerable_leaves"):
                if counts[key] != EXPECTED_INPUT_COUNTS[key]:
                    raise RQ3RunnerError(
                        f"Fixed eligible NVD scope mismatch for {key}: {counts[key]}"
                    )
        progress(
            f"Eligible scope: {eligible_cves:,} CVEs, "
            f"{eligible_leaves:,} vulnerable leaves"
        )

        criteria_identity: dict[
            str, tuple[CPE23Attribute, CPE23Attribute, CPE23Attribute]
        ] = {}
        exact_index: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        flexible_by_part: dict[str, list[str]] = defaultdict(list)
        globally_flexible: list[str] = []
        for raw in distinct_criteria:
            parsed = parse_cpe23(raw)
            if not parsed.is_valid or parsed.name is None:
                raise RQ3RunnerError(f"Invalid eligible NVD criteria: {raw}")
            name = parsed.name
            identity = tuple(name.attribute(attr) for attr in IDENTITY_ATTRIBUTES)
            criteria_identity[raw] = identity
            key = _simple_identity(name)
            if key is not None:
                exact_index[key].append(raw)
            else:
                part = name.attribute("part")
                if (
                    part.kind is CPE23ValueKind.STRING
                    and not _has_unquoted_wildcard(part.canonical)
                ):
                    flexible_by_part[_logical_literal(part.canonical)].append(raw)
                else:
                    globally_flexible.append(raw)
        if len(criteria_identity) != distinct_criteria_count:
            raise RQ3RunnerError("Eligible NVD criteria count changed during parsing")

        target_names: dict[str, CPE23Name] = {}
        target_bindings: dict[str, list[Binding]] = defaultdict(list)
        for component in component_rows:
            if component.original_name is not None:
                target_names[component.original_cpe] = component.original_name
                target_bindings[component.original_cpe].append(
                    Binding("ORIGINAL", component.component_id)
                )
            if component.gt_name is not None:
                target_names[component.gt_cpe] = component.gt_name
                target_bindings[component.gt_cpe].append(
                    Binding("GROUND_TRUTH", component.component_id)
                )

        criteria_to_targets: dict[str, list[str]] = defaultdict(list)
        for raw_target, target_name in target_names.items():
            key = _simple_identity(target_name)
            pool = (
                distinct_criteria
                if key is None
                else exact_index.get(key, [])
                + flexible_by_part.get(key[0], [])
                + globally_flexible
            )
            for raw in pool:
                if _identity_matches(criteria_identity[raw], target_name):
                    criteria_to_targets[raw].append(raw_target)

        candidate_criteria = sorted(criteria_to_targets)
        candidate_names: dict[str, CPE23Name] = {}
        for raw in candidate_criteria:
            parsed = parse_cpe23(raw)
            if not parsed.is_valid or parsed.name is None:
                raise RQ3RunnerError(f"Invalid candidate NVD criteria: {raw}")
            candidate_names[raw] = parsed.name
        progress(
            f"Candidate criteria: {len(candidate_criteria):,}; "
            f"target CPEs: {len(target_names):,}"
        )

        match_cache: dict[
            tuple[str, str, tuple[str | None, ...]],
            str,
        ] = {}
        candidate_leaf_rows = 0
        if candidate_criteria:
            with connection.cursor() as cursor:
                cursor.execute(
                    eligible_cte
                    + f"""
                    SELECT s.id, r.cve_id, s.criteria,
                           s.version_start_including,
                           s.version_start_excluding,
                           s.version_end_including,
                           s.version_end_excluding
                    FROM scoped s
                    JOIN eligible e ON e.cve_record_id = s.cve_record_id
                    JOIN {record_table} r ON r.id = s.cve_record_id
                    WHERE s.vulnerable IS TRUE
                      AND s.criteria = ANY(%s)
                    ORDER BY s.id
                    """,
                    [nvd_snapshot.pk, candidate_criteria],
                )
                while True:
                    rows = cursor.fetchmany(5_000)
                    if not rows:
                        break
                    for (
                        leaf_id,
                        cve_id,
                        criteria,
                        start_inc,
                        start_exc,
                        end_inc,
                        end_exc,
                    ) in rows:
                        candidate_leaf_rows += 1
                        ranges = (start_inc, start_exc, end_inc, end_exc)
                        has_range = any(value is not None for value in ranges)
                        criteria_name = candidate_names[criteria]
                        if (
                            has_range
                            and criteria_name.attribute("version").kind
                            is not CPE23ValueKind.ANY
                        ):
                            raise RQ3RunnerError(
                                "Unexpected concrete criteria version combined with "
                                f"an NVD range: {criteria}"
                            )
                        for target_cpe in criteria_to_targets[criteria]:
                            cache_key = (target_cpe, criteria, ranges)
                            leaf_result = match_cache.get(cache_key)
                            if leaf_result is None:
                                target_name = target_names[target_cpe]
                                attribute = match_cpe_attributes(
                                    criteria_name,
                                    target_name,
                                    ignore_version=has_range,
                                )
                                if attribute.status is CPEAttributeMatchStatus.NO_MATCH:
                                    leaf_result = "NO_MATCH"
                                elif attribute.status is not CPEAttributeMatchStatus.MATCH:
                                    raise RQ3RunnerError(
                                        "Unexpected CPE attribute matcher status: "
                                        f"{attribute.status.value}"
                                    )
                                elif not has_range:
                                    leaf_result = "MATCH"
                                else:
                                    leaf_result = match_version_constraint(
                                        criteria_name.attribute("version"),
                                        target_name.attribute("version"),
                                        version_start_including=start_inc,
                                        version_start_excluding=start_exc,
                                        version_end_including=end_inc,
                                        version_end_excluding=end_exc,
                                    ).value
                                match_cache[cache_key] = leaf_result
                            for binding in target_bindings[target_cpe]:
                                _aggregate_result(
                                    aggregates,
                                    binding.path,
                                    binding.component_id,
                                    cve_id,
                                    leaf_result,
                                )
                                if (
                                    analyze_added_causes
                                    and binding.path == "GROUND_TRUTH"
                                    and leaf_result == "MATCH"
                                ):
                                    gt_evidence[(binding.component_id, cve_id)].append(
                                        LeafEvidence(
                                            nvd_cpe_match_id=leaf_id,
                                            criteria=criteria,
                                            ranges=ranges,
                                        )
                                    )

        counts_after = _table_counts(nvd_snapshot.pk)
        if counts_before != counts_after:
            raise RQ3RunnerError("Database counts changed inside read-only transaction")

    component_by_id = {row.component_id: row for row in component_rows}
    keys_by_component: dict[int, set[str]] = defaultdict(set)
    for path in ("ORIGINAL", "GROUND_TRUTH"):
        for component_id, cve_id in aggregates[path]:
            keys_by_component[component_id].add(cve_id)

    comparison_rows: list[dict[str, object]] = []
    categories: Counter[str] = Counter()
    for component_id in sorted(component_by_id):
        component = component_by_id[component_id]
        for cve_id in sorted(keys_by_component[component_id]):
            original = aggregates["ORIGINAL"].get((component_id, cve_id))
            gt = aggregates["GROUND_TRUTH"].get((component_id, cve_id))
            original_status = (
                "INVALID_ORIGINAL_CPE"
                if component.original_name is None
                else original.status
                if original is not None
                else "NO_MATCH"
            )
            gt_status = (
                "NO_GT_CPE"
                if not component.gt_cpe
                else gt.status
                if gt is not None
                else "NO_MATCH"
            )
            category, reason = classify_relation(
                original_status,
                gt_status,
                original.causes if original else set(),
                gt.causes if gt else set(),
            )
            categories[category] += 1
            comparison_rows.append(
                {
                    "component_id": component_id,
                    "sbom_document_id": component.sbom_document_id,
                    "firmware": component.firmware,
                    "component_name": component.component_name,
                    "component_version": component.component_version,
                    "original_cpe": component.original_cpe,
                    "gt_cpe": component.gt_cpe,
                    "cve_id": cve_id,
                    "original_status": original_status,
                    "gt_status": gt_status,
                    "comparison_status": category,
                    "reason": reason,
                    "original_unresolved_causes": " | ".join(
                        sorted(original.causes if original else set())
                    ),
                    "gt_unresolved_causes": " | ".join(
                        sorted(gt.causes if gt else set())
                    ),
                }
            )

    original_identified = sum(
        aggregate.status == "MATCH" for aggregate in aggregates["ORIGINAL"].values()
    )
    gt_identified = sum(
        aggregate.status == "MATCH"
        for aggregate in aggregates["GROUND_TRUTH"].values()
    )
    primary = {
        "original_identified": original_identified,
        "gt_identified": gt_identified,
        "COMMON": categories["COMMON"],
        "ADDED": categories["ADDED_AFTER_CORRECTION"],
        "REMOVED": categories["REMOVED_AFTER_CORRECTION"],
        "INDETERMINATE": categories["INDETERMINATE"],
    }

    def group_metrics(component_ids: set[int]) -> dict[str, int]:
        rows = [
            row for row in comparison_rows if row["component_id"] in component_ids
        ]
        return {
            "components": len(component_ids),
            "original_identified": sum(
                aggregate.status == "MATCH" and key[0] in component_ids
                for key, aggregate in aggregates["ORIGINAL"].items()
            ),
            "gt_identified": sum(
                aggregate.status == "MATCH" and key[0] in component_ids
                for key, aggregate in aggregates["GROUND_TRUTH"].items()
            ),
            "COMMON": sum(row["comparison_status"] == "COMMON" for row in rows),
            "ADDED": sum(
                row["comparison_status"] == "ADDED_AFTER_CORRECTION" for row in rows
            ),
            "REMOVED": sum(
                row["comparison_status"] == "REMOVED_AFTER_CORRECTION" for row in rows
            ),
            "INDETERMINATE": sum(
                row["comparison_status"] == "INDETERMINATE" for row in rows
            ),
        }

    gt_bearing_ids = {
        row.component_id for row in component_rows if row.gt_cpe
    }
    gt_bearing = group_metrics(gt_bearing_ids)
    gt_null = group_metrics(set(component_by_id) - gt_bearing_ids)
    if enforce_fixed_contract:
        if primary != EXPECTED_PRIMARY_METRICS:
            raise RQ3RunnerError(
                f"RQ3 primary result mismatch: expected {EXPECTED_PRIMARY_METRICS}, "
                f"actual {primary}"
            )
        if gt_bearing != EXPECTED_GT_BEARING_METRICS:
            raise RQ3RunnerError(
                "RQ3 GT-bearing result mismatch: "
                f"expected {EXPECTED_GT_BEARING_METRICS}, actual {gt_bearing}"
            )

    cause_rows: list[dict[str, object]] = []
    cause_counts: Counter[str] = Counter()
    if analyze_added_causes:
        cause_rows, cause_counts = _analyze_added_causes(
            comparison_rows, component_by_id, gt_evidence
        )
        if enforce_fixed_contract:
            actual_nonzero = {
                key: value for key, value in cause_counts.items() if value
            }
            if actual_nonzero != EXPECTED_ADDED_CAUSES:
                raise RQ3RunnerError(
                    f"ADDED cause result mismatch: expected {EXPECTED_ADDED_CAUSES}, "
                    f"actual {actual_nonzero}"
                )

    checks = {
        "read_only_transaction": str(read_only).lower() in {"on", "true"},
        "repeatable_read_transaction": str(isolation).lower()
        == "repeatable read",
        "db_counts_unchanged": counts_before == counts_after,
        "comparison_partition": len(comparison_rows) == sum(categories.values()),
        "gt_null_has_no_gt_match": not any(
            key[0] not in gt_bearing_ids and aggregate.status == "MATCH"
            for key, aggregate in aggregates["GROUND_TRUTH"].items()
        ),
        "cause_partition": (
            not analyze_added_causes
            or len(cause_rows) == primary["ADDED"] == sum(cause_counts.values())
        ),
    }
    if not all(checks.values()):
        raise RQ3RunnerError(f"RQ3 consistency check failed: {checks}")

    summary: dict[str, object] = {
        "nvd_snapshot": nvd_snapshot_id,
        "ground_truth": str(GROUND_TRUTH_RELATIVE_PATH),
        "input_counts": counts,
        "primary_metrics": primary,
        "gt_cpe_bearing": gt_bearing,
        "gt_null": gt_null,
        "added_cause_counts": dict(sorted(cause_counts.items())),
        "candidate_criteria": len(candidate_criteria),
        "candidate_leaf_rows": candidate_leaf_rows,
        "policies": {
            "exclude_cve_with_and": True,
            "exclude_cve_with_vulnerable_false": True,
            "exclude_cve_with_negate_true": True,
            "gt_null_has_no_cpe_identification": True,
            "original_invalid_cpe_repair": False,
            "version_normalization_or_inference": False,
            "unsupported_version_is_no_match": False,
            "same_matcher_for_original_and_gt": True,
        },
        "transaction": {
            "isolation": isolation,
            "read_only": read_only,
            "db_counts_before": counts_before,
            "db_counts_after": counts_after,
            "db_write_count": 0,
        },
        "checks": checks,
    }
    return RQ3RunResult(
        summary=summary,
        comparison_rows=tuple(comparison_rows),
        added_cause_rows=tuple(cause_rows),
    )


def run_rq3_matching(
    *,
    ground_truth_csv: Path,
    output_directory: Path,
    nvd_snapshot_id: str = NVD_SNAPSHOT_ID,
    analyze_added_causes: bool = False,
    enforce_fixed_contract: bool = True,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Run the frozen RQ3 contract and write only the canonical result files."""
    progress = progress or (lambda _message: None)
    if output_directory.exists() and any(output_directory.iterdir()):
        raise RQ3RunnerError(
            f"Output directory must be absent or empty: {output_directory}"
        )
    ground_truth_rows = _read_ground_truth(ground_truth_csv)
    if enforce_fixed_contract and len(ground_truth_rows) != EXPECTED_INPUT_COUNTS["components"]:
        raise RQ3RunnerError(
            f"Expected 2,038 Ground Truth rows, found {len(ground_truth_rows)}"
        )
    result = _run_matching(
        ground_truth_rows=ground_truth_rows,
        nvd_snapshot_id=nvd_snapshot_id,
        analyze_added_causes=analyze_added_causes,
        enforce_fixed_contract=enforce_fixed_contract,
        progress=progress,
    )
    output_directory.mkdir(parents=True, exist_ok=True)
    _write_csv(
        output_directory / "component_cve_comparison.csv",
        COMPARISON_FIELDS,
        result.comparison_rows,
    )
    if analyze_added_causes:
        _write_csv(
            output_directory / "added_relation_cause.csv",
            CAUSE_FIELDS,
            result.added_cause_rows,
        )
        cause_counts = result.summary["added_cause_counts"]
        _write_csv(
            output_directory / "added_cause_summary.csv",
            ("cause_category", "component_cve_relations"),
            (
                {
                    "cause_category": category,
                    "component_cve_relations": count,
                }
                for category, count in cause_counts.items()
            ),
        )
    (output_directory / "summary.json").write_text(
        json.dumps(result.summary, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return result.summary

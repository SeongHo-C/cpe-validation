from __future__ import annotations

import csv
import json
import math
import statistics
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from django.db import transaction
from django.utils import timezone

from cpe_analysis.models import (
    CPEAnalysisOutcome,
    CPEAnalysisQueryResult,
    CPEAnalysisRun,
    CPEAnalysisRunStatus,
)
from sboms.models import Component


FLOAT_TOLERANCE = 1e-12
REQUIRED_ARTIFACT_FILES = (
    "per_query_results.csv",
    "aggregate_metrics.json",
    "input_manifest.json",
    "summary.json",
)
REQUIRED_PER_QUERY_COLUMNS = frozenset(
    {
        "component_id",
        "algorithm_id",
        "target_score",
        "better_count",
        "tie_size",
        "best_rank",
        "worst_rank",
        "outcome",
        "top_group_hit",
        "top1_success",
        "recall_at_5_success",
        "recall_at_10_success",
        "reciprocal_rank",
    }
)


class BenchmarkResultImportError(RuntimeError):
    """Raised when an artifact cannot be imported safely."""


class BenchmarkArtifactValidationError(BenchmarkResultImportError):
    """Raised when a benchmark artifact violates its result contract."""


class ExistingAnalysisRunError(BenchmarkResultImportError):
    """Raised when an algorithm already has a persisted analysis run."""


@dataclass(frozen=True)
class ExpectedBenchmarkIdentity:
    algorithm_id: str
    query_count: int
    candidate_family_count: int
    top1_count: int
    recall_at_5_count: int
    recall_at_10_count: int
    mrr: float
    unique_correct_count: int
    ambiguous_count: int
    not_top_group_count: int


VERIFIED_LEVENSHTEIN_IDENTITY = ExpectedBenchmarkIdentity(
    algorithm_id="length_normalized_levenshtein",
    query_count=158,
    candidate_family_count=181_484,
    top1_count=63,
    recall_at_5_count=124,
    recall_at_10_count=127,
    mrr=0.5565417164607827,
    unique_correct_count=63,
    ambiguous_count=55,
    not_top_group_count=40,
)


VERIFIED_JARO_WINKLER_IDENTITY = ExpectedBenchmarkIdentity(
    algorithm_id="jaro_winkler",
    query_count=158,
    candidate_family_count=181_484,
    top1_count=69,
    recall_at_5_count=134,
    recall_at_10_count=140,
    mrr=0.6082612255091588,
    unique_correct_count=69,
    ambiguous_count=51,
    not_top_group_count=38,
)


VERIFIED_CHARACTER_TRIGRAM_DICE_IDENTITY = ExpectedBenchmarkIdentity(
    algorithm_id="character_trigram_dice",
    query_count=158,
    candidate_family_count=181_484,
    top1_count=79,
    recall_at_5_count=136,
    recall_at_10_count=142,
    mrr=0.6523244057752082,
    unique_correct_count=79,
    ambiguous_count=55,
    not_top_group_count=24,
)


@dataclass(frozen=True)
class QueryResultRecord:
    component_id: int
    algorithm_id: str
    target_score: float
    better_count: int
    tie_size: int
    best_rank: int
    worst_rank: int
    outcome: str


@dataclass(frozen=True)
class BenchmarkMetrics:
    query_count: int
    top1_count: int
    recall_at_5_count: int
    recall_at_10_count: int
    mrr: float
    unique_correct_count: int
    ambiguous_count: int
    not_top_group_count: int
    top_group_hit_count: int

    @property
    def top1_accuracy(self) -> float:
        return self.top1_count / self.query_count

    @property
    def recall_at_5(self) -> float:
        return self.recall_at_5_count / self.query_count

    @property
    def recall_at_10(self) -> float:
        return self.recall_at_10_count / self.query_count


@dataclass(frozen=True)
class ValidatedBenchmark:
    algorithm_id: str
    candidate_family_count: int
    records: tuple[QueryResultRecord, ...]
    metrics: BenchmarkMetrics


@dataclass(frozen=True)
class PersistenceResult:
    run_id: int | None
    inserted_query_results: int
    component_coverage: int
    metrics: BenchmarkMetrics
    dry_run: bool


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BenchmarkArtifactValidationError(
            f"Could not read valid JSON from {path}."
        ) from error
    if not isinstance(value, dict):
        raise BenchmarkArtifactValidationError(
            f"Expected a JSON object in {path}."
        )
    return value


def _parse_integer(value: str, *, field: str, row_number: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has invalid integer {field}={value!r}."
        ) from error
    return parsed


def _parse_float(value: str, *, field: str, row_number: int) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as error:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has invalid float {field}={value!r}."
        ) from error
    if not math.isfinite(parsed):
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has non-finite {field}."
        )
    return parsed


def _parse_boolean(value: str, *, field: str, row_number: int) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise BenchmarkArtifactValidationError(
        f"Row {row_number} has invalid boolean {field}={value!r}."
    )


def _floats_equal(left: float, right: float) -> bool:
    return abs(left - right) <= FLOAT_TOLERANCE


def _require_equal(
    *,
    label: str,
    observed: object,
    expected: object,
) -> None:
    if observed != expected:
        raise BenchmarkArtifactValidationError(
            f"{label} mismatch: observed {observed!r}, expected "
            f"{expected!r}."
        )


def _require_float_equal(
    *,
    label: str,
    observed: object,
    expected: float,
) -> None:
    try:
        value = float(observed)
    except (TypeError, ValueError) as error:
        raise BenchmarkArtifactValidationError(
            f"{label} is not numeric: {observed!r}."
        ) from error
    if not math.isfinite(value) or not _floats_equal(value, expected):
        raise BenchmarkArtifactValidationError(
            f"{label} mismatch: observed {value!r}, expected "
            f"{expected!r}."
        )


def calculate_metrics(
    records: Iterable[QueryResultRecord],
) -> BenchmarkMetrics:
    rows = tuple(records)
    if not rows:
        raise BenchmarkArtifactValidationError(
            "A benchmark must contain at least one per-query row."
        )
    outcome_counts = Counter(row.outcome for row in rows)
    return BenchmarkMetrics(
        query_count=len(rows),
        top1_count=sum(row.worst_rank == 1 for row in rows),
        recall_at_5_count=sum(row.worst_rank <= 5 for row in rows),
        recall_at_10_count=sum(row.worst_rank <= 10 for row in rows),
        mrr=statistics.fmean(1 / row.worst_rank for row in rows),
        unique_correct_count=outcome_counts[
            CPEAnalysisOutcome.UNIQUE_CORRECT
        ],
        ambiguous_count=outcome_counts[
            CPEAnalysisOutcome.CORRECT_BUT_AMBIGUOUS
        ],
        not_top_group_count=outcome_counts[
            CPEAnalysisOutcome.NOT_TOP_GROUP
        ],
        top_group_hit_count=sum(row.best_rank == 1 for row in rows),
    )


def _validate_row(
    raw: Mapping[str, str],
    *,
    row_number: int,
) -> QueryResultRecord:
    component_id = _parse_integer(
        raw["component_id"],
        field="component_id",
        row_number=row_number,
    )
    target_score = _parse_float(
        raw["target_score"],
        field="target_score",
        row_number=row_number,
    )
    better_count = _parse_integer(
        raw["better_count"],
        field="better_count",
        row_number=row_number,
    )
    tie_size = _parse_integer(
        raw["tie_size"],
        field="tie_size",
        row_number=row_number,
    )
    best_rank = _parse_integer(
        raw["best_rank"],
        field="best_rank",
        row_number=row_number,
    )
    worst_rank = _parse_integer(
        raw["worst_rank"],
        field="worst_rank",
        row_number=row_number,
    )
    outcome = raw["outcome"]
    algorithm_id = raw["algorithm_id"]

    if component_id < 1:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has non-positive component_id."
        )
    if better_count < 0:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has negative better_count."
        )
    if tie_size < 1 or best_rank < 1 or worst_rank < 1:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has a non-positive tie size or rank."
        )
    if best_rank != better_count + 1:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} violates best_rank=better_count+1."
        )
    if worst_rank != better_count + tie_size:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} violates "
            "worst_rank=better_count+tie_size."
        )
    if best_rank > worst_rank:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has best_rank>worst_rank."
        )

    if outcome == CPEAnalysisOutcome.UNIQUE_CORRECT:
        outcome_valid = best_rank == 1 and worst_rank == 1
    elif outcome == CPEAnalysisOutcome.CORRECT_BUT_AMBIGUOUS:
        outcome_valid = best_rank == 1 and worst_rank > 1
    elif outcome == CPEAnalysisOutcome.NOT_TOP_GROUP:
        outcome_valid = best_rank > 1
    else:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has unsupported outcome {outcome!r}."
        )
    if not outcome_valid:
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} violates {outcome} rank semantics."
        )

    derived_values = {
        "top_group_hit": best_rank == 1,
        "top1_success": worst_rank == 1,
        "recall_at_5_success": worst_rank <= 5,
        "recall_at_10_success": worst_rank <= 10,
    }
    for field, expected in derived_values.items():
        observed = _parse_boolean(
            raw[field],
            field=field,
            row_number=row_number,
        )
        if observed != expected:
            raise BenchmarkArtifactValidationError(
                f"Row {row_number} has inconsistent derived {field}."
            )
    reciprocal_rank = _parse_float(
        raw["reciprocal_rank"],
        field="reciprocal_rank",
        row_number=row_number,
    )
    if not _floats_equal(reciprocal_rank, 1 / worst_rank):
        raise BenchmarkArtifactValidationError(
            f"Row {row_number} has inconsistent reciprocal_rank."
        )

    return QueryResultRecord(
        component_id=component_id,
        algorithm_id=algorithm_id,
        target_score=target_score,
        better_count=better_count,
        tie_size=tie_size,
        best_rank=best_rank,
        worst_rank=worst_rank,
        outcome=outcome,
    )


def _validate_aggregate(
    aggregate: Mapping[str, object],
    *,
    algorithm_id: str,
    candidate_family_count: int,
    metrics: BenchmarkMetrics,
) -> None:
    integer_expectations = {
        "query_count": metrics.query_count,
        "candidate_family_count": candidate_family_count,
        "top1_success_count": metrics.top1_count,
        "recall_at_5_success_count": metrics.recall_at_5_count,
        "recall_at_10_success_count": metrics.recall_at_10_count,
        "unique_correct_count": metrics.unique_correct_count,
        "correct_but_ambiguous_count": metrics.ambiguous_count,
        "not_top_group_count": metrics.not_top_group_count,
        "top_group_hit_count": metrics.top_group_hit_count,
    }
    _require_equal(
        label="aggregate algorithm_id",
        observed=aggregate.get("algorithm_id"),
        expected=algorithm_id,
    )
    for field, expected in integer_expectations.items():
        _require_equal(
            label=f"aggregate {field}",
            observed=aggregate.get(field),
            expected=expected,
        )
    float_expectations = {
        "top1_accuracy": metrics.top1_accuracy,
        "recall_at_5": metrics.recall_at_5,
        "recall_at_10": metrics.recall_at_10,
        "mrr": metrics.mrr,
    }
    for field, expected in float_expectations.items():
        _require_float_equal(
            label=f"aggregate {field}",
            observed=aggregate.get(field),
            expected=expected,
        )


def _algorithm_id_from_manifest_value(value: object) -> str:
    if isinstance(value, dict):
        algorithm_id = value.get("algorithm_id")
    elif isinstance(value, str):
        algorithm_id = value
    else:
        raise BenchmarkArtifactValidationError(
            "input_manifest algorithm must be an algorithm ID or object."
        )
    if not isinstance(algorithm_id, str) or not algorithm_id:
        raise BenchmarkArtifactValidationError(
            "input_manifest algorithm ID must be a non-empty string."
        )
    return algorithm_id


def _resolve_manifest_algorithm_id(
    input_manifest: Mapping[str, object],
) -> str:
    direct_algorithm_id = input_manifest.get("algorithm_id")
    if direct_algorithm_id is not None and (
        not isinstance(direct_algorithm_id, str)
        or not direct_algorithm_id
    ):
        raise BenchmarkArtifactValidationError(
            "input_manifest algorithm_id must be a non-empty string."
        )

    legacy_algorithm_id = None
    if "algorithm" in input_manifest:
        legacy_algorithm_id = _algorithm_id_from_manifest_value(
            input_manifest["algorithm"]
        )

    if direct_algorithm_id is None and legacy_algorithm_id is None:
        raise BenchmarkArtifactValidationError(
            "input_manifest must define algorithm_id or algorithm."
        )
    if (
        direct_algorithm_id is not None
        and legacy_algorithm_id is not None
        and direct_algorithm_id != legacy_algorithm_id
    ):
        raise BenchmarkArtifactValidationError(
            "input_manifest algorithm_id conflicts with algorithm."
        )
    return direct_algorithm_id or legacy_algorithm_id


def load_and_validate_benchmark(
    artifact_directory: Path,
) -> ValidatedBenchmark:
    artifact_directory = artifact_directory.resolve()
    missing = [
        name
        for name in REQUIRED_ARTIFACT_FILES
        if not (artifact_directory / name).is_file()
    ]
    if missing:
        raise BenchmarkArtifactValidationError(
            f"Missing required artifact files: {', '.join(missing)}."
        )

    aggregate = _load_json_object(
        artifact_directory / "aggregate_metrics.json"
    )
    input_manifest = _load_json_object(
        artifact_directory / "input_manifest.json"
    )
    summary = _load_json_object(artifact_directory / "summary.json")

    per_query_path = artifact_directory / "per_query_results.csv"
    try:
        with per_query_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            columns = frozenset(reader.fieldnames or ())
            missing_columns = REQUIRED_PER_QUERY_COLUMNS - columns
            if missing_columns:
                raise BenchmarkArtifactValidationError(
                    "per_query_results.csv is missing columns: "
                    + ", ".join(sorted(missing_columns))
                    + "."
                )
            records = tuple(
                _validate_row(raw, row_number=row_number)
                for row_number, raw in enumerate(reader, start=2)
            )
    except OSError as error:
        raise BenchmarkArtifactValidationError(
            f"Could not read {per_query_path}."
        ) from error

    if not records:
        raise BenchmarkArtifactValidationError(
            "per_query_results.csv contains no result rows."
        )
    component_ids = [record.component_id for record in records]
    duplicate_component_ids = sorted(
        component_id
        for component_id, count in Counter(component_ids).items()
        if count > 1
    )
    if duplicate_component_ids:
        raise BenchmarkArtifactValidationError(
            "Duplicate component IDs in per-query results: "
            + ", ".join(map(str, duplicate_component_ids))
            + "."
        )
    algorithm_ids = {record.algorithm_id for record in records}
    if len(algorithm_ids) != 1:
        raise BenchmarkArtifactValidationError(
            "Per-query rows do not have one algorithm_id."
        )
    algorithm_id = next(iter(algorithm_ids))
    try:
        candidate_family_count = int(aggregate["candidate_family_count"])
    except (KeyError, TypeError, ValueError) as error:
        raise BenchmarkArtifactValidationError(
            "aggregate candidate_family_count is invalid."
        ) from error
    metrics = calculate_metrics(records)
    _validate_aggregate(
        aggregate,
        algorithm_id=algorithm_id,
        candidate_family_count=candidate_family_count,
        metrics=metrics,
    )

    manifest_algorithm_id = _resolve_manifest_algorithm_id(input_manifest)
    manifest_expectations = {
        "input_manifest algorithm_id": (
            manifest_algorithm_id,
            algorithm_id,
        ),
        "input_manifest query_count": (
            input_manifest.get("query_count"),
            metrics.query_count,
        ),
        "input_manifest candidate_family_count": (
            input_manifest.get("candidate_family_count"),
            candidate_family_count,
        ),
        "input_manifest version_used": (
            input_manifest.get("version_used"),
            False,
        ),
    }
    for label, (observed, expected) in manifest_expectations.items():
        _require_equal(
            label=label,
            observed=observed,
            expected=expected,
        )

    _require_equal(
        label="summary algorithm_id",
        observed=summary.get("algorithm_id"),
        expected=algorithm_id,
    )
    summary_dataset = summary.get("dataset")
    if summary_dataset is not None and not isinstance(
        summary_dataset,
        dict,
    ):
        raise BenchmarkArtifactValidationError(
            "summary dataset must be an object."
        )
    if summary_dataset is not None:
        _require_equal(
            label="summary query count",
            observed=summary_dataset.get("queries"),
            expected=metrics.query_count,
        )
        _require_equal(
            label="summary candidate family count",
            observed=summary_dataset.get("candidate_families"),
            expected=candidate_family_count,
        )
    summary_aggregate = summary.get("aggregate_metrics")
    if not isinstance(summary_aggregate, dict):
        raise BenchmarkArtifactValidationError(
            "summary aggregate_metrics must be an object."
        )
    _validate_aggregate(
        summary_aggregate,
        algorithm_id=algorithm_id,
        candidate_family_count=candidate_family_count,
        metrics=metrics,
    )

    return ValidatedBenchmark(
        algorithm_id=algorithm_id,
        candidate_family_count=candidate_family_count,
        records=records,
        metrics=metrics,
    )


def validate_expected_identity(
    benchmark: ValidatedBenchmark,
    expected: ExpectedBenchmarkIdentity,
) -> None:
    checks = {
        "algorithm_id": (benchmark.algorithm_id, expected.algorithm_id),
        "query_count": (
            benchmark.metrics.query_count,
            expected.query_count,
        ),
        "candidate_family_count": (
            benchmark.candidate_family_count,
            expected.candidate_family_count,
        ),
        "top1_count": (
            benchmark.metrics.top1_count,
            expected.top1_count,
        ),
        "recall_at_5_count": (
            benchmark.metrics.recall_at_5_count,
            expected.recall_at_5_count,
        ),
        "recall_at_10_count": (
            benchmark.metrics.recall_at_10_count,
            expected.recall_at_10_count,
        ),
        "unique_correct_count": (
            benchmark.metrics.unique_correct_count,
            expected.unique_correct_count,
        ),
        "ambiguous_count": (
            benchmark.metrics.ambiguous_count,
            expected.ambiguous_count,
        ),
        "not_top_group_count": (
            benchmark.metrics.not_top_group_count,
            expected.not_top_group_count,
        ),
    }
    for label, (observed, expected_value) in checks.items():
        _require_equal(
            label=f"verified identity {label}",
            observed=observed,
            expected=expected_value,
        )
    _require_float_equal(
        label="verified identity mrr",
        observed=benchmark.metrics.mrr,
        expected=expected.mrr,
    )


def validate_component_coverage(
    benchmark: ValidatedBenchmark,
) -> dict[int, Component]:
    component_ids = [record.component_id for record in benchmark.records]
    components = Component.objects.in_bulk(component_ids)
    missing = sorted(set(component_ids) - components.keys())
    if missing:
        raise BenchmarkArtifactValidationError(
            "Artifact references missing Component IDs: "
            + ", ".join(map(str, missing))
            + "."
        )
    return components


def _existing_runs(algorithm_id: str) -> list[dict[str, object]]:
    return list(
        CPEAnalysisRun.objects.filter(algorithm_id=algorithm_id)
        .values(
            "id",
            "status",
            "query_count",
            "candidate_family_count",
            "unique_correct_count",
            "ambiguous_count",
            "not_top_group_count",
        )
        .order_by("id")
    )


def _raise_if_existing_run(algorithm_id: str) -> None:
    existing = _existing_runs(algorithm_id)
    if existing:
        details = []
        for row in existing:
            result_count = CPEAnalysisQueryResult.objects.filter(
                run_id=row["id"]
            ).count()
            details.append({**row, "query_result_count": result_count})
        raise ExistingAnalysisRunError(
            f"Refusing duplicate import for {algorithm_id}: {details!r}."
        )


def calculate_database_metrics(run: CPEAnalysisRun) -> BenchmarkMetrics:
    rows = tuple(
        QueryResultRecord(
            component_id=component_id,
            algorithm_id=run.algorithm_id,
            target_score=target_score,
            better_count=better_count,
            tie_size=tie_size,
            best_rank=best_rank,
            worst_rank=worst_rank,
            outcome=outcome,
        )
        for (
            component_id,
            target_score,
            better_count,
            tie_size,
            best_rank,
            worst_rank,
            outcome,
        ) in run.query_results.order_by("component_id").values_list(
            "component_id",
            "target_score",
            "better_count",
            "tie_size",
            "best_rank",
            "worst_rank",
            "outcome",
        )
    )
    return calculate_metrics(rows)


def _validate_run_aggregate(
    run: CPEAnalysisRun,
    metrics: BenchmarkMetrics,
) -> None:
    integer_checks = {
        "query_count": metrics.query_count,
        "unique_correct_count": metrics.unique_correct_count,
        "ambiguous_count": metrics.ambiguous_count,
        "not_top_group_count": metrics.not_top_group_count,
    }
    for field, expected in integer_checks.items():
        if getattr(run, field) != expected:
            raise BenchmarkResultImportError(
                f"Persisted Run {field} does not match QueryResults."
            )
    float_checks = {
        "top1_accuracy": metrics.top1_accuracy,
        "recall_at_5": metrics.recall_at_5,
        "recall_at_10": metrics.recall_at_10,
        "mrr": metrics.mrr,
    }
    for field, expected in float_checks.items():
        value = getattr(run, field)
        if value is None or not _floats_equal(value, expected):
            raise BenchmarkResultImportError(
                f"Persisted Run {field} does not match QueryResults."
            )


def import_benchmark_results(
    artifact_directory: Path,
    *,
    expected_identity: ExpectedBenchmarkIdentity,
    run_parameters: Mapping[str, object] | None = None,
    dry_run: bool = False,
) -> PersistenceResult:
    benchmark = load_and_validate_benchmark(artifact_directory)
    validate_expected_identity(benchmark, expected_identity)
    components = validate_component_coverage(benchmark)
    _raise_if_existing_run(benchmark.algorithm_id)

    if dry_run:
        return PersistenceResult(
            run_id=None,
            inserted_query_results=0,
            component_coverage=len(components),
            metrics=benchmark.metrics,
            dry_run=True,
        )

    with transaction.atomic():
        # Lock any matching rows and repeat the idempotency check inside the
        # write transaction. The first import is expected to find none.
        tuple(
            CPEAnalysisRun.objects.select_for_update().filter(
                algorithm_id=benchmark.algorithm_id
            )
        )
        _raise_if_existing_run(benchmark.algorithm_id)

        metrics = benchmark.metrics
        run = CPEAnalysisRun(
            algorithm_id=benchmark.algorithm_id,
            status=CPEAnalysisRunStatus.COMPLETED,
            parameters=dict(run_parameters or {}),
            query_count=metrics.query_count,
            candidate_family_count=benchmark.candidate_family_count,
            top1_accuracy=metrics.top1_accuracy,
            recall_at_5=metrics.recall_at_5,
            recall_at_10=metrics.recall_at_10,
            mrr=metrics.mrr,
            unique_correct_count=metrics.unique_correct_count,
            ambiguous_count=metrics.ambiguous_count,
            not_top_group_count=metrics.not_top_group_count,
            completed_at=timezone.now(),
        )
        run.full_clean()
        run.save()

        query_results = [
            CPEAnalysisQueryResult(
                run=run,
                component=components[record.component_id],
                target_score=record.target_score,
                better_count=record.better_count,
                tie_size=record.tie_size,
                best_rank=record.best_rank,
                worst_rank=record.worst_rank,
                outcome=record.outcome,
            )
            for record in benchmark.records
        ]
        for query_result in query_results:
            query_result.full_clean()
        CPEAnalysisQueryResult.objects.bulk_create(query_results)

        database_metrics = calculate_database_metrics(run)
        _validate_run_aggregate(run, database_metrics)
        if database_metrics != metrics:
            raise BenchmarkResultImportError(
                "Persisted QueryResult metrics do not match the artifact."
            )

        return PersistenceResult(
            run_id=run.pk,
            inserted_query_results=len(query_results),
            component_coverage=len(components),
            metrics=database_metrics,
            dry_run=False,
        )

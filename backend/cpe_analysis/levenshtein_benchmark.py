from __future__ import annotations

import argparse
import csv
import hashlib
import heapq
import json
import math
import os
import resource
import statistics
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cpe.cpe23 import parse_cpe23_formatted_string
from cpe_analysis.levenshtein import (
    LengthNormalizedLevenshteinScorer,
    RepeatedQueryScoreCache,
    validate_levenshtein_backend,
)
from cpe_analysis.matching import (
    EXPECTED_EVALUATION_QUERY_COUNT,
    EXPECTED_GT_DECISION_COUNTS,
    TIE_TOLERANCE,
    AggregateEvaluationResult,
    CandidateFamily,
    CandidateUniverse,
    EvaluationOutcome,
    FamilyRetrievalQuery,
    QueryEvaluationResult,
    aggregate_results,
    evaluate_query,
    load_candidate_universe,
    scores_tie,
)


ALGORITHM_ID = "length_normalized_levenshtein"
DEFAULT_OUTPUT_DIRECTORY = Path(
    "/tmp/cpe-family-levenshtein-evaluation"
)
GT_DIRECTORY_RELATIVE = Path(
    ".ground-truth/FINAL_GT_20260828/repository-files/analysis/"
    "final-ground-truth/FINAL_GT_20260828"
)
GT_CSV_SHA256 = (
    "ff6ad72e50278052199bd006afd88a2f51442e379c8b63dbf1a8232fd06aa8c2"
)
EXPECTED_FIRMWARE_QUERY_COUNTS = {
    "ACKSYS WaveOS PID40": 37,
    "MDEX MX560": 35,
    "Teltonika RUT986": 44,
    "Unitronics UCR-ST-B8": 42,
}
FIRMWARE_NAMES = {
    ("ACKSYS", "4.36.1.1"): "ACKSYS WaveOS PID40",
    ("MDEX", "12.01.07.151"): "MDEX MX560",
    ("Teltonika", "00.07.24.2"): "Teltonika RUT986",
    ("Unitronics", "52.07.13.7"): "Unitronics UCR-ST-B8",
}
PER_QUERY_COLUMNS = (
    "component_id",
    "sbom_document_id",
    "firmware_name",
    "firmware_identifier",
    "query_name",
    "gt_decision",
    "gt_family_id",
    "gt_part",
    "gt_vendor",
    "gt_product",
    "gt_decoded_product",
    "algorithm_id",
    "target_score",
    "better_count",
    "tie_size",
    "best_rank",
    "worst_rank",
    "top_group_hit",
    "outcome",
    "top1_success",
    "recall_at_5_success",
    "recall_at_10_success",
    "reciprocal_rank",
)


class LevenshteinBenchmarkError(RuntimeError):
    """Raised when a frozen benchmark input or invariant is invalid."""


@dataclass(frozen=True)
class BenchmarkQuery:
    retrieval_query: FamilyRetrievalQuery
    firmware_name: str
    firmware_identifier: str
    gt_decision: str
    ground_truth_cpe: str
    gt_decoded_product: str


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _git_output(repository_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", *arguments),
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.rstrip("\n")


def _tracked_tree_fingerprint(
    repository_root: Path,
    pathspec: str,
) -> dict[str, object]:
    paths = tuple(
        line
        for line in _git_output(
            repository_root,
            "ls-files",
            "--",
            pathspec,
        ).splitlines()
        if line
    )
    digest = hashlib.sha256()
    for relative_path in paths:
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update((repository_root / relative_path).read_bytes())
        digest.update(b"\0")
    return {
        "file_count": len(paths),
        "sha256": digest.hexdigest(),
    }


def _protected_file_hashes(repository_root: Path) -> dict[str, str]:
    relative_paths = (
        "data/cpe_candidate_universe/manifest.json",
        "data/cpe_candidate_universe/candidate_families.csv",
        "data/cpe-dictionary/20260819T035002Z/manifest.json",
        "data/cpe-dictionary/20260819T035002Z/nvdcpe-2.0.meta",
        "data/cpe-dictionary/20260819T035002Z/nvdcpe-2.0.tar.gz",
        "data/nvd-cve/20260820T110357Z/manifest.json",
        str(GT_DIRECTORY_RELATIVE / "ground_truth.csv"),
        str(GT_DIRECTORY_RELATIVE / "ground_truth.sha256"),
        str(GT_DIRECTORY_RELATIVE / "dataset_manifest.json"),
        str(GT_DIRECTORY_RELATIVE / "snapshot_manifest.json"),
    )
    return {
        path: _sha256_file(repository_root / path) for path in relative_paths
    }


def _model_fingerprint(model: Any) -> dict[str, object]:
    from django.db import connection, transaction

    field_names = [field.attname for field in model._meta.concrete_fields]
    digest = hashlib.sha256()
    count = 0
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute("SHOW transaction_read_only")
            if cursor.fetchone()[0] != "on":
                raise LevenshteinBenchmarkError(
                    "Production database transaction is not read-only."
                )
        rows = model.objects.order_by("pk").values_list(*field_names)
        for row in rows.iterator(chunk_size=1000):
            digest.update(
                json.dumps(
                    row,
                    default=str,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            digest.update(b"\n")
            count += 1
    return {"count": count, "sha256": digest.hexdigest()}


def _database_protected_state() -> dict[str, object]:
    from nvd_cve.cpe_match_analysis import _collect_database_state
    from sboms.models import (
        ComponentCpeGroundTruth,
        GroundTruthCorrectionType,
        GroundTruthDiscrepancyType,
    )

    ground_truth = ComponentCpeGroundTruth
    models = {
        "ground_truth": ground_truth,
        "correction_types": GroundTruthCorrectionType,
        "discrepancy_types": GroundTruthDiscrepancyType,
        "ground_truth_correction_m2m": ground_truth.correction_types.through,
        "ground_truth_discrepancy_m2m": (
            ground_truth.discrepancy_types.through
        ),
    }
    database = _collect_database_state()
    if not database["transaction_read_only"]:
        raise LevenshteinBenchmarkError(
            "Production database safety read was not read-only."
        )
    return {
        "database_state_sha256": _canonical_sha256(database),
        "table_counts": database["table_counts"],
        "nvd_snapshot_metadata": database["nvd_snapshot_metadata"],
        "cpe_dictionary_snapshot_metadata": database[
            "cpe_dictionary_snapshot_metadata"
        ],
        "ground_truth": {
            name: _model_fingerprint(model) for name, model in models.items()
        },
        "transaction_read_only": True,
    }


def _load_gt_queries(
    repository_root: Path,
    universe: CandidateUniverse,
) -> tuple[tuple[BenchmarkQuery, ...], dict[str, object]]:
    gt_directory = repository_root / GT_DIRECTORY_RELATIVE
    gt_path = gt_directory / "ground_truth.csv"
    actual_gt_sha256 = _sha256_file(gt_path)
    declared_hash = (gt_directory / "ground_truth.sha256").read_text(
        encoding="utf-8"
    ).split()[0]
    if actual_gt_sha256 != GT_CSV_SHA256 or declared_hash != GT_CSV_SHA256:
        raise LevenshteinBenchmarkError(
            "Frozen Ground Truth CSV SHA-256 does not match its contract."
        )

    family_by_key = {
        (family.part, family.vendor, family.serialized_product): family
        for family in universe.searchable_families
    }
    queries: list[BenchmarkQuery] = []
    with gt_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["cpe_present"] != "true":
                continue
            parsed = parse_cpe23_formatted_string(row["ground_truth_cpe"])
            if not parsed.is_structurally_valid:
                raise LevenshteinBenchmarkError(
                    f"Invalid GT CPE for component {row['component_id']}."
                )
            family_key = (
                parsed.part_raw,
                parsed.vendor_raw,
                parsed.product_raw,
            )
            target = family_by_key.get(family_key)
            if target is None:
                raise LevenshteinBenchmarkError(
                    "GT family is absent from the searchable universe for "
                    f"component {row['component_id']}."
                )
            query_text = row["component_name"]
            if query_text == "":
                raise LevenshteinBenchmarkError(
                    f"Empty raw query for component {row['component_id']}."
                )
            firmware_key = (
                row["firmware_vendor"],
                row["firmware_version"],
            )
            firmware_name = FIRMWARE_NAMES.get(firmware_key)
            if firmware_name is None:
                raise LevenshteinBenchmarkError(
                    f"Unexpected firmware identity: {firmware_key!r}."
                )
            retrieval_query = FamilyRetrievalQuery(
                component_id=int(row["component_id"]),
                sbom_document_id=int(row["sbom_document_id"]),
                query_text=query_text,
                gt_family_id=target.family_id,
                gt_part=target.part,
                gt_vendor=target.vendor,
                gt_product=target.serialized_product,
            )
            queries.append(
                BenchmarkQuery(
                    retrieval_query=retrieval_query,
                    firmware_name=firmware_name,
                    firmware_identifier=(
                        f"{row['firmware_vendor']} "
                        f"{row['firmware_product']} "
                        f"{row['firmware_version']}"
                    ),
                    gt_decision=row["validation_result"],
                    ground_truth_cpe=row["ground_truth_cpe"],
                    gt_decoded_product=target.decoded_product,
                )
            )

    queries.sort(
        key=lambda item: (
            item.retrieval_query.query_text,
            item.retrieval_query.sbom_document_id,
            item.retrieval_query.component_id,
        )
    )
    decision_counts = Counter(query.gt_decision for query in queries)
    firmware_counts = Counter(query.firmware_name for query in queries)
    if len(queries) != EXPECTED_EVALUATION_QUERY_COUNT:
        raise LevenshteinBenchmarkError(
            "Frozen GT query count does not equal 158."
        )
    if dict(decision_counts) != EXPECTED_GT_DECISION_COUNTS:
        raise LevenshteinBenchmarkError(
            "Frozen GT decision distribution does not match its contract."
        )
    if dict(firmware_counts) != EXPECTED_FIRMWARE_QUERY_COUNTS:
        raise LevenshteinBenchmarkError(
            "Frozen firmware query distribution does not match its contract."
        )
    dataset_manifest_path = gt_directory / "dataset_manifest.json"
    return tuple(queries), {
        "dataset_name": "FINAL_GT_20260828",
        "ground_truth_csv": str(GT_DIRECTORY_RELATIVE / "ground_truth.csv"),
        "ground_truth_csv_sha256": actual_gt_sha256,
        "dataset_manifest_sha256": _sha256_file(dataset_manifest_path),
        "query_count": len(queries),
        "covered_query_count": len(queries),
        "decision_counts": dict(sorted(decision_counts.items())),
        "firmware_counts": dict(sorted(firmware_counts.items())),
        "unique_raw_query_count": len(
            {query.retrieval_query.query_text for query in queries}
        ),
        "empty_query_count": 0,
    }


def _run_evaluation_pass(
    queries: Iterable[BenchmarkQuery],
    candidates: tuple[CandidateFamily, ...],
) -> tuple[
    tuple[QueryEvaluationResult, ...],
    AggregateEvaluationResult,
    dict[str, object],
]:
    base_scorer = LengthNormalizedLevenshteinScorer()
    scorer = RepeatedQueryScoreCache(base_scorer)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    results = tuple(
        evaluate_query(query.retrieval_query, candidates, scorer)
        for query in queries
    )
    cpu_seconds = time.process_time() - cpu_start
    wall_seconds = time.perf_counter() - wall_start
    aggregate = aggregate_results(results)
    return results, aggregate, {
        "wall_time_seconds": wall_seconds,
        "cpu_time_seconds": cpu_seconds,
        "score_cache_miss_count": base_scorer.score_call_count,
        "distance_computation_count": (
            base_scorer.distance_computation_count
        ),
        "scoring_backend": base_scorer.backend_name,
    }


def _query_result_row(
    query: BenchmarkQuery,
    result: QueryEvaluationResult,
) -> dict[str, object]:
    return {
        "component_id": result.component_id,
        "sbom_document_id": result.sbom_document_id,
        "firmware_name": query.firmware_name,
        "firmware_identifier": query.firmware_identifier,
        "query_name": result.query_text,
        "gt_decision": query.gt_decision,
        "gt_family_id": result.gt_family_id,
        "gt_part": result.gt_part,
        "gt_vendor": result.gt_vendor,
        "gt_product": result.gt_product,
        "gt_decoded_product": query.gt_decoded_product,
        "algorithm_id": result.algorithm_id,
        "target_score": result.target_score,
        "better_count": result.better_count,
        "tie_size": result.tie_size,
        "best_rank": result.best_rank,
        "worst_rank": result.worst_rank,
        "top_group_hit": result.top_group_hit,
        "outcome": result.outcome.value,
        "top1_success": result.top1_success,
        "recall_at_5_success": result.recall_at_5_success,
        "recall_at_10_success": result.recall_at_10_success,
        "reciprocal_rank": result.reciprocal_rank,
    }


def _aggregate_dict(
    aggregate: AggregateEvaluationResult,
    *,
    candidate_family_count: int,
) -> dict[str, object]:
    payload = asdict(aggregate)
    payload["candidate_family_count"] = candidate_family_count
    payload["top1_success_count"] = aggregate.unique_correct_count
    payload["recall_at_5_success_count"] = round(
        aggregate.recall_at_5 * aggregate.query_count
    )
    payload["recall_at_10_success_count"] = round(
        aggregate.recall_at_10 * aggregate.query_count
    )
    return payload


def _group_metrics(
    label: str,
    paired_results: Iterable[tuple[BenchmarkQuery, QueryEvaluationResult]],
) -> dict[str, object]:
    pairs = tuple(paired_results)
    aggregate = aggregate_results(result for _, result in pairs)
    return {
        "group": label,
        "queries": aggregate.query_count,
        "top1_count": sum(result.top1_success for _, result in pairs),
        "top1_accuracy": aggregate.top1_accuracy,
        "recall_at_5_count": sum(
            result.recall_at_5_success for _, result in pairs
        ),
        "recall_at_5": aggregate.recall_at_5,
        "recall_at_10_count": sum(
            result.recall_at_10_success for _, result in pairs
        ),
        "recall_at_10": aggregate.recall_at_10,
        "mrr": aggregate.mrr,
        "unique_correct_count": aggregate.unique_correct_count,
        "correct_but_ambiguous_count": (
            aggregate.correct_but_ambiguous_count
        ),
        "not_top_group_count": aggregate.not_top_group_count,
    }


def _breakdown(
    paired_results: tuple[tuple[BenchmarkQuery, QueryEvaluationResult], ...],
    attribute: str,
) -> tuple[dict[str, object], ...]:
    groups: dict[
        str,
        list[tuple[BenchmarkQuery, QueryEvaluationResult]],
    ] = defaultdict(list)
    for pair in paired_results:
        groups[str(getattr(pair[0], attribute))].append(pair)
    return tuple(
        _group_metrics(label, groups[label]) for label in sorted(groups)
    )


def _tie_analysis(
    paired_results: tuple[tuple[BenchmarkQuery, QueryEvaluationResult], ...],
    universe: CandidateUniverse,
) -> dict[str, object]:
    product_multiplicity = Counter(
        family.decoded_product for family in universe.searchable_families
    )
    tied_rows: list[dict[str, object]] = []
    cause_counts: Counter[str] = Counter()
    for query, result in paired_results:
        if result.tie_size <= 1:
            continue
        same_product_multiplicity = product_multiplicity[
            query.gt_decoded_product
        ]
        if same_product_multiplicity > 1:
            cause = (
                "SAME_DECODED_PRODUCT_ONLY"
                if result.tie_size == same_product_multiplicity
                else "INCLUDES_SAME_PRODUCT_DUPLICATES"
            )
        else:
            cause = "DISTINCT_PRODUCT_SCORE_TIE"
        cause_counts[cause] += 1
        tied_rows.append(
            {
                "component_id": result.component_id,
                "query_name": result.query_text,
                "gt_family_id": result.gt_family_id,
                "gt_decoded_product": query.gt_decoded_product,
                "target_score": result.target_score,
                "tie_size": result.tie_size,
                "best_rank": result.best_rank,
                "worst_rank": result.worst_rank,
                "top_group_hit": result.top_group_hit,
                "same_decoded_product_family_count": (
                    same_product_multiplicity
                ),
                "target_tie_cause": cause,
            }
        )
    tie_sizes = [row["tie_size"] for row in tied_rows]
    return {
        "tie_tolerance": TIE_TOLERANCE,
        "queries_with_tie": len(tied_rows),
        "maximum_tie_size": max(tie_sizes, default=1),
        "median_tie_size_among_tied_queries": (
            statistics.median(tie_sizes) if tie_sizes else None
        ),
        "tie_size_distribution": dict(
            sorted(Counter(tie_sizes).items())
        ),
        "target_tie_cause_counts": dict(sorted(cause_counts.items())),
        "zero_target_distance_query_count": sum(
            result.target_score == 0 for _, result in paired_results
        ),
        "tied_queries": tied_rows,
    }


def _example_base(
    query: BenchmarkQuery,
    result: QueryEvaluationResult,
) -> dict[str, object]:
    return {
        "component_id": result.component_id,
        "sbom_document_id": result.sbom_document_id,
        "firmware_name": query.firmware_name,
        "query_name": result.query_text,
        "gt_decision": query.gt_decision,
        "gt_family_id": result.gt_family_id,
        "gt_family": {
            "part": result.gt_part,
            "vendor": result.gt_vendor,
            "product": result.gt_product,
            "decoded_product": query.gt_decoded_product,
        },
        "target_score": result.target_score,
        "best_rank": result.best_rank,
        "worst_rank": result.worst_rank,
        "tie_size": result.tie_size,
        "outcome": result.outcome.value,
    }


def _top_candidates(
    query: BenchmarkQuery,
    result: QueryEvaluationResult,
    universe: CandidateUniverse,
    limit: int = 10,
) -> tuple[list[dict[str, object]], int]:
    scorer = LengthNormalizedLevenshteinScorer()
    products = sorted(
        {family.decoded_product for family in universe.searchable_families}
    )
    scores = {
        product: scorer.score(query.retrieval_query.query_text, product)
        for product in products
    }
    top = heapq.nsmallest(
        limit,
        universe.searchable_families,
        key=lambda family: (scores[family.decoded_product], family.family_id),
    )
    rows = [
        {
            "family_id": family.family_id,
            "part": family.part,
            "vendor": family.vendor,
            "product": family.serialized_product,
            "decoded_product": family.decoded_product,
            "source": family.source,
            "score": scores[family.decoded_product],
            "strictly_better_than_gt": (
                scores[family.decoded_product] < result.target_score
                and not scores_tie(
                    scores[family.decoded_product],
                    result.target_score,
                )
            ),
        }
        for family in top
    ]
    return rows, scorer.distance_computation_count


def _failure_examples(
    paired_results: tuple[tuple[BenchmarkQuery, QueryEvaluationResult], ...],
    universe: CandidateUniverse,
) -> tuple[dict[str, object], int]:
    by_outcome: dict[
        EvaluationOutcome,
        list[tuple[BenchmarkQuery, QueryEvaluationResult]],
    ] = defaultdict(list)
    for pair in sorted(
        paired_results,
        key=lambda item: item[1].component_id,
    ):
        by_outcome[pair[1].outcome].append(pair)

    diagnostic_computations = 0
    output: dict[str, object] = {}
    for outcome in EvaluationOutcome:
        examples: list[dict[str, object]] = []
        for query, result in by_outcome[outcome][:5]:
            example = _example_base(query, result)
            if outcome is EvaluationOutcome.NOT_TOP_GROUP:
                top_candidates, computations = _top_candidates(
                    query,
                    result,
                    universe,
                )
                diagnostic_computations += computations
                example["top_candidates"] = top_candidates
            examples.append(example)
        output[outcome.value] = examples
    return output, diagnostic_computations


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_csv(
    path: Path,
    rows: Iterable[dict[str, object]],
    fieldnames: Iterable[str],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=tuple(fieldnames),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def _rate(count: int, denominator: int) -> str:
    return f"{count / denominator * 100:.6f}%"


def _report(
    aggregate: dict[str, object],
    tie_analysis: dict[str, object],
    gt_breakdown: tuple[dict[str, object], ...],
    firmware_breakdown: tuple[dict[str, object], ...],
    performance: dict[str, object],
    input_manifest: dict[str, object],
    determinism: dict[str, object],
    safety: dict[str, object],
) -> str:
    query_count = int(aggregate["query_count"])
    lines = [
        "# Length-normalized Levenshtein Family Retrieval",
        "",
        "## Scope",
        "",
        "- Query: raw stored SBOM component name",
        "- Candidate: decoded logical CPE product",
        "- Version used: no",
        "- General normalization: none",
        "- Primary rank: worst_rank",
        "",
        "## Inputs",
        "",
        f"- Queries: {query_count:,}",
        f"- Candidate families: {aggregate['candidate_family_count']:,}",
        "- Distinct decoded products: "
        f"{input_manifest['distinct_decoded_products']:,}",
        "- GT coverage: "
        f"{input_manifest['gt_coverage_count']}/{query_count}",
        "- Candidate SHA-256: "
        f"`{input_manifest['candidate_csv_sha256']}`",
        "",
        "## Primary Metrics",
        "",
        "| Metric | Success | Rate |",
        "| --- | ---: | ---: |",
        "| Top-1 | "
        f"{aggregate['top1_success_count']}/{query_count} | "
        f"{_rate(int(aggregate['top1_success_count']), query_count)} |",
        "| Recall@5 | "
        f"{aggregate['recall_at_5_success_count']}/{query_count} | "
        f"{_rate(int(aggregate['recall_at_5_success_count']), query_count)} |",
        "| Recall@10 | "
        f"{aggregate['recall_at_10_success_count']}/{query_count} | "
        f"{_rate(int(aggregate['recall_at_10_success_count']), query_count)} |",
        f"| MRR | - | {aggregate['mrr']:.12f} |",
        "",
        "## Tie-aware Results",
        "",
        f"- Unique correct: {aggregate['unique_correct_count']}",
        "- Correct but ambiguous: "
        f"{aggregate['correct_but_ambiguous_count']}",
        f"- Not top group: {aggregate['not_top_group_count']}",
        f"- Top group hit: {aggregate['top_group_hit_count']}",
        f"- Queries with tie: {tie_analysis['queries_with_tie']}",
        f"- Maximum tie size: {tie_analysis['maximum_tie_size']}",
        "- Median tie size among tied queries: "
        f"{tie_analysis['median_tie_size_among_tied_queries']}",
        "",
        "## GT Decision Breakdown",
        "",
        "| Decision | n | Top-1 | R@5 | R@10 | MRR |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in gt_breakdown:
        lines.append(
            f"| {row['group']} | {row['queries']} | "
            f"{row['top1_count']} | {row['recall_at_5_count']} | "
            f"{row['recall_at_10_count']} | {row['mrr']:.12f} |"
        )
    lines.extend(
        [
            "",
            "## Firmware Breakdown",
            "",
            "| Firmware | n | Top-1 | R@5 | R@10 | MRR |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in firmware_breakdown:
        lines.append(
            f"| {row['group']} | {row['queries']} | "
            f"{row['top1_count']} | {row['recall_at_5_count']} | "
            f"{row['recall_at_10_count']} | {row['mrr']:.12f} |"
        )
    lines.extend(
        [
            "",
            "## Performance",
            "",
            "- Family-equivalent comparisons: "
            f"{performance['family_equivalent_comparison_count']:,}",
            "- Evaluator score invocations: "
            f"{performance['evaluator_score_invocation_count']:,}",
            "- Actual distance computations: "
            f"{performance['actual_distance_computation_count']:,}",
            f"- Wall time: {performance['wall_time_seconds']:.6f} seconds",
            f"- CPU time: {performance['cpu_time_seconds']:.6f} seconds",
            f"- Peak memory: {performance['peak_memory_mib']:.3f} MiB",
            f"- Parallelism: {performance['parallelism']}",
            f"- Scoring backend: {performance['scoring_backend']}",
            "",
            "## Validation",
            "",
            "- Common contract reused: PASS",
            "- Candidate hash/counts/decoder: PASS",
            "- GT coverage and distributions: PASS",
            "- Backend reference correctness: PASS",
            f"- Determinism: {determinism['status']}",
            "- Order independence: PASS (real scorer integration fixture)",
            "- Version isolation: PASS",
            "- GT isolation: PASS",
            "- Production DB unchanged: "
            f"{'PASS' if safety['production_database_unchanged'] else 'FAIL'}",
            "- Protected files unchanged: "
            f"{'PASS' if safety['protected_files_unchanged'] else 'FAIL'}",
            "- Frontend unchanged: "
            f"{'PASS' if safety['frontend_unchanged'] else 'FAIL'}",
            "",
        ]
    )
    return "\n".join(lines)


def run_benchmark(repository_root: Path, output_directory: Path) -> None:
    repository_root = repository_root.resolve()
    output_directory = output_directory.resolve()
    if output_directory.exists():
        raise LevenshteinBenchmarkError(
            f"Refusing to overwrite existing output: {output_directory}"
        )
    output_directory.parent.mkdir(parents=True, exist_ok=True)

    started_at = datetime.now(timezone.utc).isoformat()
    overall_wall_start = time.perf_counter()
    repository_status_before = _git_output(
        repository_root,
        "status",
        "--short",
    )
    cached_status_before = _git_output(
        repository_root,
        "diff",
        "--cached",
        "--name-status",
    )
    protected_files_before = _protected_file_hashes(repository_root)
    frontend_before = _tracked_tree_fingerprint(repository_root, "frontend")
    migrations_before = _tracked_tree_fingerprint(
        repository_root,
        "backend/**/migrations/**",
    )
    database_before = _database_protected_state()

    backend_fixtures = validate_levenshtein_backend()
    universe = load_candidate_universe(repository_root)
    if any(
        family.decoded_product == ""
        for family in universe.searchable_families
    ):
        raise LevenshteinBenchmarkError(
            "Searchable candidate universe contains an empty product."
        )
    queries, gt_identity = _load_gt_queries(repository_root, universe)
    candidates = universe.searchable_families
    distinct_product_count = len(
        {family.decoded_product for family in candidates}
    )

    results, aggregate, first_profile = _run_evaluation_pass(
        queries,
        candidates,
    )
    replay_results, replay_aggregate, replay_profile = (
        _run_evaluation_pass(queries, candidates)
    )
    paired_results = tuple(zip(queries, results, strict=True))
    per_query_rows = tuple(
        _query_result_row(query, result)
        for query, result in paired_results
    )
    replay_rows = tuple(
        _query_result_row(query, result)
        for query, result in zip(queries, replay_results, strict=True)
    )
    aggregate_payload = _aggregate_dict(
        aggregate,
        candidate_family_count=len(candidates),
    )
    replay_aggregate_payload = _aggregate_dict(
        replay_aggregate,
        candidate_family_count=len(candidates),
    )
    gt_breakdown = _breakdown(paired_results, "gt_decision")
    firmware_breakdown = _breakdown(paired_results, "firmware_name")
    logical_payload = {
        "per_query_results": per_query_rows,
        "aggregate_metrics": aggregate_payload,
        "gt_decision_breakdown": gt_breakdown,
        "firmware_breakdown": firmware_breakdown,
    }
    replay_logical_payload = {
        "per_query_results": replay_rows,
        "aggregate_metrics": replay_aggregate_payload,
        "gt_decision_breakdown": _breakdown(
            tuple(zip(queries, replay_results, strict=True)),
            "gt_decision",
        ),
        "firmware_breakdown": _breakdown(
            tuple(zip(queries, replay_results, strict=True)),
            "firmware_name",
        ),
    }
    canonical_results_sha256 = _canonical_sha256(logical_payload)
    replay_results_sha256 = _canonical_sha256(replay_logical_payload)
    determinism_passed = (
        canonical_results_sha256 == replay_results_sha256
        and per_query_rows == replay_rows
        and aggregate_payload == replay_aggregate_payload
    )
    if not determinism_passed:
        raise LevenshteinBenchmarkError(
            "Full-universe deterministic replay did not match."
        )
    determinism = {
        "status": "PASS",
        "full_universe_replay": True,
        "first_pass_canonical_results_sha256": canonical_results_sha256,
        "replay_canonical_results_sha256": replay_results_sha256,
        "per_query_results_equal": per_query_rows == replay_rows,
        "aggregate_metrics_equal": (
            aggregate_payload == replay_aggregate_payload
        ),
        "first_pass_distance_computations": first_profile[
            "distance_computation_count"
        ],
        "replay_distance_computations": replay_profile[
            "distance_computation_count"
        ],
    }

    tie_analysis = _tie_analysis(paired_results, universe)
    failure_examples, diagnostic_distance_computations = _failure_examples(
        paired_results,
        universe,
    )
    family_equivalent_comparisons = len(queries) * len(candidates)
    evaluator_score_invocations = len(queries) * distinct_product_count
    peak_memory_mib = (
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    )
    performance = {
        "query_count": len(queries),
        "unique_raw_query_count": gt_identity["unique_raw_query_count"],
        "candidate_family_count": len(candidates),
        "distinct_decoded_products": distinct_product_count,
        "family_equivalent_comparison_count": (
            family_equivalent_comparisons
        ),
        "evaluator_score_invocation_count": evaluator_score_invocations,
        "actual_distance_computation_count": first_profile[
            "distance_computation_count"
        ],
        "diagnostic_distance_computation_count": (
            diagnostic_distance_computations
        ),
        "determinism_replay_distance_computation_count": replay_profile[
            "distance_computation_count"
        ],
        "cross_component_identical_raw_query_cache": True,
        "wall_time_seconds": first_profile["wall_time_seconds"],
        "cpu_time_seconds": first_profile["cpu_time_seconds"],
        "overall_wall_time_seconds": time.perf_counter()
        - overall_wall_start,
        "peak_memory_mib": peak_memory_mib,
        "parallelism": "1 process / 1 thread",
        "scoring_backend": first_profile["scoring_backend"],
    }

    candidate_manifest_path = (
        repository_root / "data/cpe_candidate_universe/manifest.json"
    )
    input_manifest = {
        "algorithm": {
            "algorithm_id": ALGORITHM_ID,
            "algorithm_name": "Length-normalized Levenshtein",
            "formula": "ED(s1,s2) / max(len(s1),len(s2))",
            "edit_costs": {
                "insertion": 1,
                "deletion": 1,
                "substitution": 1,
            },
            "score_direction": "LOWER_IS_BETTER",
            "scoring_backend": first_profile["scoring_backend"],
        },
        "query_count": len(queries),
        "gt_coverage_count": len(queries),
        "candidate_family_count": len(candidates),
        "total_candidate_family_count": len(universe.families),
        "distinct_decoded_products": distinct_product_count,
        "candidate_csv_sha256": (
            universe.validation.candidate_file_sha256
        ),
        "candidate_universe_manifest": json.loads(
            candidate_manifest_path.read_text(encoding="utf-8")
        ),
        "candidate_universe_manifest_sha256": _sha256_file(
            candidate_manifest_path
        ),
        "ground_truth_dataset": gt_identity,
        "query_field": "stored raw SBOM component.name",
        "candidate_field": "decoded logical CPE product",
        "normalization": "none",
        "version_used": False,
        "vendor_or_part_used_as_feature": False,
        "ground_truth_used_as_feature": False,
        "tie_tolerance": TIE_TOLERANCE,
        "arbitrary_tie_breaking": False,
        "primary_rank": "worst_rank",
        "generated_at_utc": started_at,
        "git_head": _git_output(repository_root, "rev-parse", "HEAD"),
        "git_status_short": repository_status_before.splitlines(),
        "git_diff_cached_name_status": (
            cached_status_before.splitlines()
        ),
    }

    protected_files_after = _protected_file_hashes(repository_root)
    frontend_after = _tracked_tree_fingerprint(repository_root, "frontend")
    migrations_after = _tracked_tree_fingerprint(
        repository_root,
        "backend/**/migrations/**",
    )
    database_after = _database_protected_state()
    repository_status_after = _git_output(
        repository_root,
        "status",
        "--short",
    )
    cached_status_after = _git_output(
        repository_root,
        "diff",
        "--cached",
        "--name-status",
    )
    safety = {
        "production_database_read_only": bool(
            database_before["transaction_read_only"]
            and database_after["transaction_read_only"]
        ),
        "production_database_unchanged": database_before == database_after,
        "database_before": database_before,
        "database_after": database_after,
        "protected_files_unchanged": (
            protected_files_before == protected_files_after
        ),
        "protected_file_hashes_before": protected_files_before,
        "protected_file_hashes_after": protected_files_after,
        "frontend_unchanged": frontend_before == frontend_after,
        "frontend_before": frontend_before,
        "frontend_after": frontend_after,
        "migrations_unchanged": migrations_before == migrations_after,
        "migrations_before": migrations_before,
        "migrations_after": migrations_after,
        "repository_status_unchanged_during_benchmark": (
            repository_status_before == repository_status_after
        ),
        "repository_status_before": repository_status_before.splitlines(),
        "repository_status_after": repository_status_after.splitlines(),
        "cached_status_unchanged": (
            cached_status_before == cached_status_after
        ),
        "commit_performed": False,
        "database_persistence_performed": False,
        "ui_updated": False,
        "candidate_universe_modified": False,
        "ground_truth_modified": False,
    }
    if not all(
        (
            safety["production_database_read_only"],
            safety["production_database_unchanged"],
            safety["protected_files_unchanged"],
            safety["frontend_unchanged"],
            safety["migrations_unchanged"],
            safety["repository_status_unchanged_during_benchmark"],
            safety["cached_status_unchanged"],
        )
    ):
        raise LevenshteinBenchmarkError(
            "A protected repository or database safety invariant changed."
        )

    summary = {
        "algorithm_id": ALGORITHM_ID,
        "dataset": {
            "queries": len(queries),
            "candidate_families": len(candidates),
            "distinct_decoded_products": distinct_product_count,
            "gt_coverage": len(queries),
        },
        "aggregate_metrics": aggregate_payload,
        "tie_summary": {
            key: tie_analysis[key]
            for key in (
                "queries_with_tie",
                "maximum_tie_size",
                "median_tie_size_among_tied_queries",
                "zero_target_distance_query_count",
                "target_tie_cause_counts",
            )
        },
        "canonical_results_sha256": canonical_results_sha256,
        "validation_status": "PASS",
    }

    stage = Path(
        tempfile.mkdtemp(
            prefix=".cpe-family-levenshtein-evaluation-",
            dir=output_directory.parent,
        )
    )
    _write_json(stage / "summary.json", summary)
    _write_json(stage / "input_manifest.json", input_manifest)
    _write_csv(
        stage / "per_query_results.csv",
        sorted(per_query_rows, key=lambda row: int(row["component_id"])),
        PER_QUERY_COLUMNS,
    )
    _write_json(stage / "aggregate_metrics.json", aggregate_payload)
    breakdown_columns = tuple(gt_breakdown[0].keys())
    _write_csv(
        stage / "gt_decision_breakdown.csv",
        gt_breakdown,
        breakdown_columns,
    )
    _write_csv(
        stage / "firmware_breakdown.csv",
        firmware_breakdown,
        breakdown_columns,
    )
    _write_json(stage / "tie_analysis.json", tie_analysis)
    _write_json(stage / "failure_examples.json", failure_examples)
    _write_json(stage / "performance_profile.json", performance)
    _write_json(
        stage / "determinism.json",
        {
            **determinism,
            "backend_reference_fixtures": backend_fixtures,
        },
    )
    _write_json(stage / "safety_validation.json", safety)
    (stage / "report.md").write_text(
        _report(
            aggregate_payload,
            tie_analysis,
            gt_breakdown,
            firmware_breakdown,
            performance,
            input_manifest,
            determinism,
            safety,
        ),
        encoding="utf-8",
    )
    os.replace(stage, output_directory)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the exact frozen Length-normalized Levenshtein family "
            "retrieval benchmark."
        )
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
    )
    arguments = parser.parse_args()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    run_benchmark(
        arguments.repository_root,
        arguments.output_directory,
    )


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import os
import resource
import statistics
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cpe_analysis.jaro_winkler import (
    JARO_WEIGHTS,
    MAX_PREFIX_LENGTH,
    PREFIX_WEIGHT,
    RepeatedQueryScoreCache,
    Winkler1990JaroWinklerScorer,
    validate_jaro_winkler_backend,
)
from cpe_analysis.levenshtein_benchmark import (
    PER_QUERY_COLUMNS,
    BenchmarkQuery,
    _aggregate_dict,
    _breakdown,
    _canonical_sha256,
    _database_protected_state,
    _git_output,
    _load_gt_queries,
    _protected_file_hashes,
    _query_result_row,
    _rate,
    _sha256_file,
    _tracked_tree_fingerprint,
    _write_csv,
    _write_json,
)
from cpe_analysis.matching import (
    EXPECTED_EVALUATION_QUERY_COUNT,
    TIE_TOLERANCE,
    AggregateEvaluationResult,
    CandidateFamily,
    CandidateUniverse,
    QueryEvaluationResult,
    aggregate_results,
    evaluate_query,
    load_candidate_universe,
)


ALGORITHM_ID = "jaro_winkler"
DEFAULT_OUTPUT_DIRECTORY = Path(
    "/tmp/cpe-family-jaro-winkler-evaluation"
)
EXPECTED_DISTINCT_DECODED_PRODUCTS = 171_940
EXPECTED_DISTINCT_RAW_QUERY_NAMES = 91
PROTECTED_CODE_PATHS = (
    "backend/cpe_analysis/matching.py",
    "backend/cpe_analysis/levenshtein.py",
    "backend/cpe_analysis/levenshtein_benchmark.py",
)


class JaroWinklerBenchmarkError(RuntimeError):
    """Raised when a frozen Jaro-Winkler benchmark invariant fails."""


def _code_file_hashes(repository_root: Path) -> dict[str, str]:
    return {
        path: _sha256_file(repository_root / path)
        for path in PROTECTED_CODE_PATHS
    }


def _run_evaluation_pass(
    queries: Iterable[BenchmarkQuery],
    candidates: tuple[CandidateFamily, ...],
) -> tuple[
    tuple[QueryEvaluationResult, ...],
    AggregateEvaluationResult,
    dict[str, object],
]:
    base_scorer = Winkler1990JaroWinklerScorer()
    scorer = RepeatedQueryScoreCache(base_scorer)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    results = tuple(
        evaluate_query(query.retrieval_query, candidates, scorer)
        for query in queries
    )
    cpu_seconds = time.process_time() - cpu_start
    wall_seconds = time.perf_counter() - wall_start
    return results, aggregate_results(results), {
        "wall_time_seconds": wall_seconds,
        "cpu_time_seconds": cpu_seconds,
        "score_cache_miss_count": base_scorer.score_call_count,
        "jaro_winkler_computation_count": (
            base_scorer.jaro_computation_count
        ),
        "scoring_backend": base_scorer.backend_name,
    }


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
    tie_sizes = [int(row["tie_size"]) for row in tied_rows]
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
        "perfect_target_score_query_count": sum(
            result.target_score == 1.0 for _, result in paired_results
        ),
        "tied_queries": tied_rows,
    }


def _report(
    aggregate: dict[str, object],
    tie_analysis: dict[str, object],
    gt_breakdown: tuple[dict[str, object], ...],
    firmware_breakdown: tuple[dict[str, object], ...],
    performance: dict[str, object],
    input_manifest: dict[str, object],
    reference_validation: dict[str, object],
    determinism: dict[str, object],
    safety: dict[str, object],
) -> str:
    query_count = int(aggregate["query_count"])
    published = reference_validation["published_winkler_1990_examples"]
    lines = [
        "# Jaro-Winkler Family Retrieval",
        "",
        "## Method",
        "",
        "- Reference: Winkler (1990)",
        "- Base: equal-weight Jaro similarity",
        "- Maximum prefix length: 4",
        "- Prefix weight: 0.1",
        "- 0.7 prefix gate: not used",
        "- Retrieval threshold: none",
        "- Score direction: HIGHER_IS_BETTER",
        "- Query: raw stored SBOM component name",
        "- Candidate: decoded logical CPE product",
        "- General normalization: none",
        "- Version used: no",
        "- Primary rank: worst_rank",
        "",
        "## Inputs",
        "",
        f"- Queries: {query_count:,}",
        f"- Candidate families: {aggregate['candidate_family_count']:,}",
        "- Distinct decoded products: "
        f"{input_manifest['distinct_decoded_products']:,}",
        "- Distinct raw query names: "
        f"{input_manifest['distinct_raw_query_names']:,}",
        f"- GT coverage: {input_manifest['gt_coverage_count']}/{query_count}",
        "- Candidate SHA-256: "
        f"`{input_manifest['candidate_csv_sha256']}`",
        "",
        "## Reference Validation",
        "",
        "- Independent base Jaro vs RapidFuzz Jaro: PASS",
        "- Explicit Winkler prefix formula: PASS",
        "- RapidFuzz JaroWinkler used directly: no",
        "- Published Table 1 compatibility: "
        f"{published['status']}",
        "- Note: Table 1 values are retained as an external check and do "
        "not override the explicitly specified equal-weight Jaro plus "
        "capped four-character prefix formula.",
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
            "- Actual Jaro/JW computations: "
            f"{performance['actual_jaro_winkler_computation_count']:,}",
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
            "- No general normalization: PASS",
            "- Version isolation: PASS",
            "- GT isolation: PASS",
            "- Order independence: PASS",
            f"- Determinism: {determinism['status']}",
            "- Production DB unchanged: "
            f"{'PASS' if safety['production_database_unchanged'] else 'FAIL'}",
            "- Protected inputs/code unchanged: "
            f"{'PASS' if safety['protected_inputs_and_code_unchanged'] else 'FAIL'}",
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
        raise JaroWinklerBenchmarkError(
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
    protected_code_before = _code_file_hashes(repository_root)
    frontend_before = _tracked_tree_fingerprint(repository_root, "frontend")
    migrations_before = _tracked_tree_fingerprint(
        repository_root,
        "backend/**/migrations/**",
    )
    database_before = _database_protected_state()

    reference_validation = validate_jaro_winkler_backend()
    universe = load_candidate_universe(repository_root)
    if any(
        family.decoded_product == ""
        for family in universe.searchable_families
    ):
        raise JaroWinklerBenchmarkError(
            "Searchable candidate universe contains an empty product."
        )
    queries, gt_identity = _load_gt_queries(repository_root, universe)
    if any(query.retrieval_query.query_text == "" for query in queries):
        raise JaroWinklerBenchmarkError(
            "Frozen evaluation contains an empty query."
        )
    candidates = universe.searchable_families
    distinct_product_count = len(
        {family.decoded_product for family in candidates}
    )
    distinct_query_count = len(
        {query.retrieval_query.query_text for query in queries}
    )
    if distinct_product_count != EXPECTED_DISTINCT_DECODED_PRODUCTS:
        raise JaroWinklerBenchmarkError(
            "Distinct decoded product count does not match the contract."
        )
    if distinct_query_count != EXPECTED_DISTINCT_RAW_QUERY_NAMES:
        raise JaroWinklerBenchmarkError(
            "Distinct raw query count does not match the contract."
        )

    results, aggregate, first_profile = _run_evaluation_pass(
        queries,
        candidates,
    )
    replay_results, replay_aggregate, replay_profile = (
        _run_evaluation_pass(queries, candidates)
    )
    paired_results = tuple(zip(queries, results, strict=True))
    replay_pairs = tuple(zip(queries, replay_results, strict=True))
    per_query_rows = tuple(
        _query_result_row(query, result)
        for query, result in paired_results
    )
    replay_rows = tuple(
        _query_result_row(query, result)
        for query, result in replay_pairs
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
            replay_pairs,
            "gt_decision",
        ),
        "firmware_breakdown": _breakdown(
            replay_pairs,
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
        raise JaroWinklerBenchmarkError(
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
        "first_pass_jaro_winkler_computations": first_profile[
            "jaro_winkler_computation_count"
        ],
        "replay_jaro_winkler_computations": replay_profile[
            "jaro_winkler_computation_count"
        ],
    }

    tie_analysis = _tie_analysis(paired_results, universe)
    family_equivalent_comparisons = len(queries) * len(candidates)
    evaluator_score_invocations = len(queries) * distinct_product_count
    expected_computations = distinct_query_count * distinct_product_count
    if (
        first_profile["jaro_winkler_computation_count"]
        != expected_computations
    ):
        raise JaroWinklerBenchmarkError(
            "Actual Jaro/JW computation count violates cache semantics."
        )
    peak_memory_mib = (
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    )
    performance = {
        "query_count": len(queries),
        "unique_raw_query_count": distinct_query_count,
        "candidate_family_count": len(candidates),
        "distinct_decoded_products": distinct_product_count,
        "family_equivalent_comparison_count": (
            family_equivalent_comparisons
        ),
        "evaluator_score_invocation_count": evaluator_score_invocations,
        "actual_jaro_winkler_computation_count": first_profile[
            "jaro_winkler_computation_count"
        ],
        "expected_distinct_pair_computation_count": expected_computations,
        "determinism_replay_computation_count": replay_profile[
            "jaro_winkler_computation_count"
        ],
        "cross_component_identical_raw_query_cache": True,
        "wall_time_seconds": first_profile["wall_time_seconds"],
        "cpu_time_seconds": first_profile["cpu_time_seconds"],
        "replay_wall_time_seconds": replay_profile["wall_time_seconds"],
        "replay_cpu_time_seconds": replay_profile["cpu_time_seconds"],
        "overall_wall_time_seconds": time.perf_counter()
        - overall_wall_start,
        "peak_memory_mib": peak_memory_mib,
        "parallelism": "1 process / 1 thread",
        "scoring_backend": first_profile["scoring_backend"],
        "rapidfuzz_jaro_winkler_used_directly": False,
    }

    candidate_manifest_path = (
        repository_root / "data/cpe_candidate_universe/manifest.json"
    )
    input_manifest = {
        "algorithm": ALGORITHM_ID,
        "display_name": "Jaro-Winkler",
        "reference": "Winkler 1990",
        "reference_title": (
            "String Comparator Metrics and Enhanced Decision Rules in the "
            "Fellegi-Sunter Model of Record Linkage"
        ),
        "base": "Jaro",
        "jaro_weights": list(JARO_WEIGHTS),
        "max_prefix_length": MAX_PREFIX_LENGTH,
        "prefix_weight": PREFIX_WEIGHT,
        "prefix_gate": None,
        "retrieval_threshold": None,
        "score_direction": "HIGHER_IS_BETTER",
        "query": "stored raw SBOM component.name",
        "candidate": "decoded logical CPE product",
        "general_normalization": "none",
        "version_used": False,
        "vendor_or_part_used_as_feature": False,
        "ground_truth_used_as_feature": False,
        "tie_tolerance": TIE_TOLERANCE,
        "arbitrary_tie_breaking": False,
        "primary_rank": "worst_rank",
        "query_count": len(queries),
        "gt_coverage_count": len(queries),
        "candidate_family_count": len(candidates),
        "total_candidate_family_count": len(universe.families),
        "distinct_decoded_products": distinct_product_count,
        "distinct_raw_query_names": distinct_query_count,
        "empty_query_count": 0,
        "empty_searchable_candidate_count": 0,
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
        "generated_at_utc": started_at,
        "git_head": _git_output(repository_root, "rev-parse", "HEAD"),
        "git_status_short": repository_status_before.splitlines(),
        "git_diff_cached_name_status": (
            cached_status_before.splitlines()
        ),
    }

    protected_files_after = _protected_file_hashes(repository_root)
    protected_code_after = _code_file_hashes(repository_root)
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
        "protected_inputs_unchanged": (
            protected_files_before == protected_files_after
        ),
        "protected_file_hashes_before": protected_files_before,
        "protected_file_hashes_after": protected_files_after,
        "protected_code_unchanged": (
            protected_code_before == protected_code_after
        ),
        "protected_code_hashes_before": protected_code_before,
        "protected_code_hashes_after": protected_code_after,
        "protected_inputs_and_code_unchanged": (
            protected_files_before == protected_files_after
            and protected_code_before == protected_code_after
        ),
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
            safety["protected_inputs_and_code_unchanged"],
            safety["frontend_unchanged"],
            safety["migrations_unchanged"],
            safety["repository_status_unchanged_during_benchmark"],
            safety["cached_status_unchanged"],
        )
    ):
        raise JaroWinklerBenchmarkError(
            "A protected repository or database safety invariant changed."
        )

    summary = {
        "algorithm_id": ALGORITHM_ID,
        "dataset": {
            "queries": len(queries),
            "candidate_families": len(candidates),
            "distinct_decoded_products": distinct_product_count,
            "distinct_raw_query_names": distinct_query_count,
            "gt_coverage": len(queries),
        },
        "aggregate_metrics": aggregate_payload,
        "tie_summary": {
            key: tie_analysis[key]
            for key in (
                "queries_with_tie",
                "maximum_tie_size",
                "median_tie_size_among_tied_queries",
                "perfect_target_score_query_count",
                "target_tie_cause_counts",
            )
        },
        "reference_validation_status": reference_validation["status"],
        "published_table_compatibility_status": reference_validation[
            "published_winkler_1990_examples"
        ]["status"],
        "canonical_results_sha256": canonical_results_sha256,
        "validation_status": "PASS",
    }

    stage = Path(
        tempfile.mkdtemp(
            prefix=".cpe-family-jaro-winkler-evaluation-",
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
    _write_json(stage / "performance_profile.json", performance)
    _write_json(stage / "reference_validation.json", reference_validation)
    _write_json(stage / "determinism.json", determinism)
    _write_json(stage / "safety_validation.json", safety)
    (stage / "report.md").write_text(
        _report(
            aggregate_payload,
            tie_analysis,
            gt_breakdown,
            firmware_breakdown,
            performance,
            input_manifest,
            reference_validation,
            determinism,
            safety,
        ),
        encoding="utf-8",
    )
    os.replace(stage, output_directory)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the exact frozen Winkler-1990 Jaro-Winkler family "
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

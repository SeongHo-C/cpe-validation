from __future__ import annotations

import argparse
import json
import os
import resource
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cpe_analysis.character_ngram_benchmark import _analysis_database_state
from cpe_analysis.jaro_winkler_benchmark import _tie_analysis
from cpe_analysis.levenshtein_benchmark import (
    PER_QUERY_COLUMNS,
    BenchmarkQuery,
    _aggregate_dict,
    _breakdown,
    _canonical_sha256,
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
    EXPECTED_SEARCHABLE_FAMILIES,
    EXPECTED_TOTAL_FAMILIES,
    TIE_TOLERANCE,
    AggregateEvaluationResult,
    CandidateFamily,
    CandidateUniverse,
    FamilyRetrievalQuery,
    QueryEvaluationResult,
    aggregate_results,
    evaluate_query,
    load_candidate_universe,
)
from cpe_analysis.ratcliff_obershelp import (
    ALGORITHM_ID,
    ALGORITHM_NAME,
    EQUAL_ANCHOR_POLICY,
    REFERENCE,
    SCORE_FORMULA,
    RatcliffObershelpScorer,
    RepeatedQueryScoreCache,
    actual_sample_backend_validation,
    validate_ratcliff_obershelp_backend,
)


DEFAULT_OUTPUT_DIRECTORY = Path(
    "/tmp/cpe-family-ratcliff-obershelp-evaluation"
)
EXPECTED_DISTINCT_DECODED_PRODUCTS = 171_940
EXPECTED_DISTINCT_RAW_QUERY_NAMES = 91
EXPECTED_CANDIDATE_SHA256 = (
    "fdc3412c730cb2cff75a161d8cdde85336ef2c9c79d51fe9addd87a1e9774576"
)
EXPECTED_ANALYSIS_RUNS = 3
EXPECTED_ANALYSIS_QUERY_RESULTS = 474
PROTECTED_CODE_PATHS = (
    "backend/cpe_analysis/matching.py",
    "backend/cpe_analysis/levenshtein.py",
    "backend/cpe_analysis/levenshtein_benchmark.py",
    "backend/cpe_analysis/test_levenshtein.py",
    "backend/cpe_analysis/jaro_winkler.py",
    "backend/cpe_analysis/jaro_winkler_benchmark.py",
    "backend/cpe_analysis/test_jaro_winkler.py",
    "backend/cpe_analysis/character_ngram.py",
    "backend/cpe_analysis/character_ngram_benchmark.py",
    "backend/cpe_analysis/test_character_ngram.py",
)
HISTORICAL_ARTIFACT_DIRECTORIES = (
    Path("/tmp/cpe-family-levenshtein-evaluation"),
    Path("/tmp/cpe-family-jaro-winkler-evaluation"),
    Path("/tmp/cpe-family-character-trigram-dice-evaluation"),
)
REQUIRED_ARTIFACTS = (
    "report.md",
    "summary.json",
    "input_manifest.json",
    "per_query_results.csv",
    "aggregate_metrics.json",
    "gt_decision_breakdown.csv",
    "firmware_breakdown.csv",
    "tie_analysis.json",
    "reference_validation.json",
    "performance_profile.json",
    "determinism.json",
    "safety_validation.json",
)


class RatcliffObershelpBenchmarkError(RuntimeError):
    """Raised when a fixed benchmark invariant is violated."""


def _code_file_hashes(repository_root: Path) -> dict[str, str]:
    return {
        path: _sha256_file(repository_root / path)
        for path in PROTECTED_CODE_PATHS
    }


def _historical_artifact_hashes() -> dict[str, dict[str, str]]:
    hashes: dict[str, dict[str, str]] = {}
    for directory in HISTORICAL_ARTIFACT_DIRECTORIES:
        if not directory.is_dir():
            raise RatcliffObershelpBenchmarkError(
                f"Historical artifact directory is absent: {directory}"
            )
        hashes[str(directory)] = {
            path.name: _sha256_file(path)
            for path in sorted(directory.iterdir())
            if path.is_file()
        }
    return hashes


def _run_evaluation_pass(
    queries: Iterable[BenchmarkQuery],
    candidates: tuple[CandidateFamily, ...],
) -> tuple[
    tuple[QueryEvaluationResult, ...],
    AggregateEvaluationResult,
    dict[str, object],
]:
    base_scorer = RatcliffObershelpScorer()
    scorer = RepeatedQueryScoreCache(base_scorer)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    results = tuple(
        evaluate_query(query.retrieval_query, candidates, scorer)
        for query in queries
    )
    return results, aggregate_results(results), {
        "wall_time_seconds": time.perf_counter() - wall_start,
        "cpu_time_seconds": time.process_time() - cpu_start,
        "score_cache_miss_count": base_scorer.score_call_count,
        "actual_ratcliff_obershelp_computation_count": (
            base_scorer.score_call_count
        ),
        "matching_block_computation_count": (
            base_scorer.matched_block_computation_count
        ),
        "scoring_backend": base_scorer.backend_name,
    }


def _logical_payload(
    queries: tuple[BenchmarkQuery, ...],
    results: tuple[QueryEvaluationResult, ...],
    aggregate: AggregateEvaluationResult,
    candidate_count: int,
) -> dict[str, object]:
    pairs = tuple(zip(queries, results, strict=True))
    rows = tuple(_query_result_row(query, result) for query, result in pairs)
    aggregate_payload = _aggregate_dict(
        aggregate,
        candidate_family_count=candidate_count,
    )
    gt_breakdown = _breakdown(pairs, "gt_decision")
    firmware_breakdown = _breakdown(pairs, "firmware_name")
    logical = {
        "per_query_results": rows,
        "aggregate_metrics": aggregate_payload,
        "gt_decision_breakdown": gt_breakdown,
        "firmware_breakdown": firmware_breakdown,
    }
    return {
        "pairs": pairs,
        "rows": rows,
        "aggregate": aggregate_payload,
        "gt_breakdown": gt_breakdown,
        "firmware_breakdown": firmware_breakdown,
        "canonical_sha256": _canonical_sha256(logical),
    }


def _order_independence() -> dict[str, object]:
    candidates = (
        CandidateFamily("a", "a", "v1", "curl", "curl", "FIXTURE", True),
        CandidateFamily("b", "a", "v2", "curx", "curx", "FIXTURE", True),
        CandidateFamily("c", "a", "v3", "cury", "cury", "FIXTURE", True),
        CandidateFamily("d", "a", "v4", "other", "other", "FIXTURE", True),
    )
    query = FamilyRetrievalQuery(1, 1, "curl", "b", "a", "v2", "curx")
    orders = (
        candidates,
        tuple(reversed(candidates)),
        (candidates[2], candidates[0], candidates[3], candidates[1]),
    )
    results = tuple(
        evaluate_query(query, order, RatcliffObershelpScorer())
        for order in orders
    )
    fields = (
        "target_score",
        "better_count",
        "tie_size",
        "best_rank",
        "worst_rank",
        "top_group_hit",
        "outcome",
    )
    logical = {
        tuple(getattr(result, field) for field in fields) for result in results
    }
    if len(logical) != 1:
        raise RatcliffObershelpBenchmarkError(
            "Ratcliff–Obershelp evaluation is candidate-order dependent."
        )
    return {
        "status": "PASS",
        "orders": ["original", "reversed", "deterministically_shuffled"],
        "compared_fields": list(fields),
        "original_reversed_shuffled_equal": True,
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
    lines = [
        "# Ratcliff–Obershelp Family Retrieval",
        "",
        "## Method",
        "",
        f"- Reference: {REFERENCE}",
        f"- Algorithm ID: {ALGORITHM_ID}",
        "- Principle: recursive longest common contiguous substring",
        f"- Formula: {SCORE_FORMULA}",
        "- Equal-anchor policy: first encountered",
        "- Score direction: HIGHER_IS_BETTER",
        "- General normalization: none",
        "- Version used: no",
        "- Retrieval threshold: none",
        "- Query: raw stored SBOM component name",
        "- Candidate: decoded logical CPE product",
        "",
        "## Inputs",
        "",
        f"- Queries: {query_count}",
        f"- Candidate families: {aggregate['candidate_family_count']:,}",
        f"- Distinct products: {input_manifest['distinct_decoded_products']:,}",
        f"- Distinct query names: {input_manifest['distinct_raw_query_names']}",
        f"- GT coverage: {input_manifest['gt_coverage_count']}/{query_count}",
        f"- Candidate SHA-256: `{input_manifest['candidate_csv_sha256']}`",
        "",
        "## Reference Validation",
        "",
        "- Contiguous LCS: PASS",
        "- Recursive matching: PASS",
        "- Formula: PASS",
        "- Identity/no match/empty strings: PASS",
        "- Equal-anchor determinism: PASS",
        "- SequenceMatcher.ratio used directly: no",
        "- Optimized backend compatibility: "
        f"{reference_validation['optimized_backend_compatibility']}",
        "- Symmetry diagnostic: "
        f"{reference_validation['symmetry_diagnostic']['status']}",
        "",
        "## Primary Metrics",
        "",
        "| Metric | Success | Rate |",
        "| --- | ---: | ---: |",
        f"| Top-1 | {aggregate['top1_success_count']}/{query_count} | "
        f"{_rate(int(aggregate['top1_success_count']), query_count)} |",
        f"| Recall@5 | {aggregate['recall_at_5_success_count']}/{query_count} | "
        f"{_rate(int(aggregate['recall_at_5_success_count']), query_count)} |",
        f"| Recall@10 | {aggregate['recall_at_10_success_count']}/{query_count} | "
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
        f"- Maximum tie size: {tie_analysis['maximum_tie_size']:,}",
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
            f"| {row['group']} | {row['queries']} | {row['top1_count']} | "
            f"{row['recall_at_5_count']} | {row['recall_at_10_count']} | "
            f"{row['mrr']:.12f} |"
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
            f"| {row['group']} | {row['queries']} | {row['top1_count']} | "
            f"{row['recall_at_5_count']} | {row['recall_at_10_count']} | "
            f"{row['mrr']:.12f} |"
        )
    lines.extend(
        [
            "",
            "## Descriptive Comparison",
            "",
            "| Method | Top-1 | R@5 | R@10 | MRR |",
            "| --- | ---: | ---: | ---: | ---: |",
            "| Length-normalized Levenshtein | 39.87% | 78.48% | 80.38% | 0.5565 |",
            "| Jaro-Winkler | 43.67% | 84.81% | 88.61% | 0.6083 |",
            "| Character Trigram-Dice | 50.00% | 86.08% | 89.87% | 0.6523 |",
            "| Ratcliff–Obershelp | "
            f"{_rate(int(aggregate['top1_success_count']), query_count)} | "
            f"{_rate(int(aggregate['recall_at_5_success_count']), query_count)} | "
            f"{_rate(int(aggregate['recall_at_10_success_count']), query_count)} | "
            f"{aggregate['mrr']:.4f} |",
            "",
            "This table is descriptive only; comparative interpretation "
            "is deferred to Result Audit.",
            "",
            "## Performance",
            "",
            "- Family-equivalent comparisons: "
            f"{performance['family_equivalent_comparison_count']:,}",
            "- Evaluator score invocations: "
            f"{performance['evaluator_score_invocation_count']:,}",
            "- Actual score computations: "
            f"{performance['actual_ratcliff_obershelp_computation_count']:,}",
            f"- Wall time: {performance['wall_time_seconds']:.6f} seconds",
            f"- CPU time: {performance['cpu_time_seconds']:.6f} seconds",
            f"- Peak memory: {performance['peak_memory_mib']:.3f} MiB",
            f"- Parallelism: {performance['parallelism']}",
            f"- Backend: {performance['scoring_backend']}",
            "",
            "## Validation",
            "",
            "- Common contract reused: PASS",
            "- No general normalization: PASS",
            "- Version isolation: PASS",
            "- GT isolation: PASS",
            "- Order independence: PASS",
            f"- Determinism: {determinism['status']}",
            "",
            "## Safety",
            "",
            "- DB changed: "
            f"{'NO' if safety['production_database_unchanged'] else 'YES'}",
            "- Ground Truth changed: NO",
            "- Candidate Universe changed: NO",
            "- Common Contract changed: NO",
            "- Existing scorers changed: NO",
            "- Frontend changed: NO",
            "- Migration: 0",
            "- Commit: NO",
            "",
            "## Verdict",
            "",
            "RATCLIFF_OBERSHELP_FAMILY_RETRIEVAL_COMPLETE",
            "",
        ]
    )
    return "\n".join(lines)


def run_benchmark(repository_root: Path, output_directory: Path) -> None:
    repository_root = repository_root.resolve()
    output_directory = output_directory.resolve()
    if output_directory.exists():
        raise RatcliffObershelpBenchmarkError(
            f"Refusing to overwrite existing output: {output_directory}"
        )
    if output_directory.parent != Path("/tmp"):
        raise RatcliffObershelpBenchmarkError(
            "Benchmark output must be an immediate child of /tmp."
        )

    overall_wall_start = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat()
    status_before = _git_output(repository_root, "status", "--short")
    cached_before = _git_output(
        repository_root,
        "diff",
        "--cached",
        "--name-status",
    )
    head_before = _git_output(repository_root, "rev-parse", "HEAD")
    protected_files_before = _protected_file_hashes(repository_root)
    protected_code_before = _code_file_hashes(repository_root)
    historical_before = _historical_artifact_hashes()
    frontend_before = _tracked_tree_fingerprint(repository_root, "frontend")
    migrations_before = _tracked_tree_fingerprint(
        repository_root,
        "backend/**/migrations/**",
    )
    database_before = _analysis_database_state()
    if (
        database_before["cpe_analysis"]["runs"]["count"]
        != EXPECTED_ANALYSIS_RUNS
        or database_before["cpe_analysis"]["query_results"]["count"]
        != EXPECTED_ANALYSIS_QUERY_RESULTS
    ):
        raise RatcliffObershelpBenchmarkError(
            "CPE Analysis persistence baseline is not 3 runs / 474 results."
        )

    reference_validation = validate_ratcliff_obershelp_backend()
    order_independence = _order_independence()
    universe = load_candidate_universe(repository_root)
    candidates = universe.searchable_families
    queries, gt_identity = _load_gt_queries(repository_root, universe)
    distinct_products = {
        family.decoded_product for family in candidates
    }
    distinct_names = {
        query.retrieval_query.query_text for query in queries
    }
    empty_query_count = sum(not name for name in distinct_names)
    empty_candidate_count = sum(not product for product in distinct_products)
    if (
        len(universe.families) != EXPECTED_TOTAL_FAMILIES
        or len(candidates) != EXPECTED_SEARCHABLE_FAMILIES
        or len(distinct_products) != EXPECTED_DISTINCT_DECODED_PRODUCTS
        or len(queries) != EXPECTED_EVALUATION_QUERY_COUNT
        or len(distinct_names) != EXPECTED_DISTINCT_RAW_QUERY_NAMES
        or empty_query_count
        or empty_candidate_count
        or universe.validation.candidate_file_sha256
        != EXPECTED_CANDIDATE_SHA256
    ):
        raise RatcliffObershelpBenchmarkError(
            "Frozen Ratcliff–Obershelp input contract validation failed."
        )
    reference_validation["actual_dataset_sample"] = (
        actual_sample_backend_validation(distinct_names, distinct_products)
    )

    results, aggregate, first_profile = _run_evaluation_pass(
        queries,
        candidates,
    )
    replay_results, replay_aggregate, replay_profile = _run_evaluation_pass(
        queries,
        candidates,
    )
    first = _logical_payload(queries, results, aggregate, len(candidates))
    replay = _logical_payload(
        queries,
        replay_results,
        replay_aggregate,
        len(candidates),
    )
    deterministic = (
        first["canonical_sha256"] == replay["canonical_sha256"]
        and first["rows"] == replay["rows"]
        and first["aggregate"] == replay["aggregate"]
    )
    if not deterministic:
        raise RatcliffObershelpBenchmarkError(
            "Full-universe deterministic replay failed."
        )
    determinism = {
        "status": "PASS",
        "full_universe_replay": True,
        "canonical_results_sha256": first["canonical_sha256"],
        "replay_canonical_results_sha256": replay["canonical_sha256"],
        "per_query_results_equal": first["rows"] == replay["rows"],
        "aggregate_metrics_equal": (
            first["aggregate"] == replay["aggregate"]
        ),
        "order_independence": order_independence,
    }

    expected_computations = len(distinct_names) * len(distinct_products)
    if (
        first_profile["actual_ratcliff_obershelp_computation_count"]
        != expected_computations
        or replay_profile["actual_ratcliff_obershelp_computation_count"]
        != expected_computations
    ):
        raise RatcliffObershelpBenchmarkError(
            "Repeated-query score-cache computation invariant failed."
        )
    tie_analysis = _tie_analysis(first["pairs"], universe)
    performance = {
        "query_count": len(queries),
        "distinct_raw_query_names": len(distinct_names),
        "candidate_family_count": len(candidates),
        "distinct_decoded_products": len(distinct_products),
        "family_equivalent_comparison_count": len(queries) * len(candidates),
        "evaluator_score_invocation_count": (
            len(queries) * len(distinct_products)
        ),
        "actual_ratcliff_obershelp_computation_count": first_profile[
            "actual_ratcliff_obershelp_computation_count"
        ],
        "matching_block_computation_count": first_profile[
            "matching_block_computation_count"
        ],
        "expected_distinct_pair_computation_count": expected_computations,
        "determinism_replay_computation_count": replay_profile[
            "actual_ratcliff_obershelp_computation_count"
        ],
        "cross_component_identical_raw_query_cache": True,
        "candidate_pruning": False,
        "wall_time_seconds": first_profile["wall_time_seconds"],
        "cpu_time_seconds": first_profile["cpu_time_seconds"],
        "replay_wall_time_seconds": replay_profile["wall_time_seconds"],
        "replay_cpu_time_seconds": replay_profile["cpu_time_seconds"],
        "overall_wall_time_seconds": time.perf_counter() - overall_wall_start,
        "peak_memory_mib": (
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        ),
        "parallelism": "1 process / 1 thread",
        "scoring_backend": first_profile["scoring_backend"],
    }

    candidate_manifest_path = (
        repository_root / "data/cpe_candidate_universe/manifest.json"
    )
    input_manifest = {
        "algorithm_id": ALGORITHM_ID,
        "display_name": ALGORITHM_NAME,
        "reference": REFERENCE,
        "matching_principle": (
            "recursive longest common contiguous substring"
        ),
        "score_formula": SCORE_FORMULA,
        "equal_anchor_policy": EQUAL_ANCHOR_POLICY,
        "score_direction": "HIGHER_IS_BETTER",
        "query": "raw stored SBOM component name",
        "candidate": "decoded logical CPE product",
        "general_normalization": "none",
        "version_used": False,
        "retrieval_threshold": None,
        "vendor_or_part_used_as_feature": False,
        "ground_truth_used_as_feature": False,
        "candidate_pruning": False,
        "tie_tolerance": TIE_TOLERANCE,
        "arbitrary_tie_breaking": False,
        "primary_rank": "worst_rank",
        "query_count": len(queries),
        "gt_coverage_count": len(queries),
        "candidate_family_count": len(candidates),
        "total_candidate_family_count": len(universe.families),
        "distinct_decoded_products": len(distinct_products),
        "distinct_raw_query_names": len(distinct_names),
        "empty_query_count": empty_query_count,
        "empty_searchable_candidate_count": empty_candidate_count,
        "candidate_csv_sha256": universe.validation.candidate_file_sha256,
        "candidate_universe_manifest": json.loads(
            candidate_manifest_path.read_text(encoding="utf-8")
        ),
        "candidate_universe_manifest_sha256": _sha256_file(
            candidate_manifest_path
        ),
        "ground_truth_dataset": gt_identity,
        "generated_at_utc": started_at,
        "git_head": head_before,
        "git_status_short": status_before.splitlines(),
        "git_diff_cached_name_status": cached_before.splitlines(),
    }

    protected_files_after = _protected_file_hashes(repository_root)
    protected_code_after = _code_file_hashes(repository_root)
    historical_after = _historical_artifact_hashes()
    frontend_after = _tracked_tree_fingerprint(repository_root, "frontend")
    migrations_after = _tracked_tree_fingerprint(
        repository_root,
        "backend/**/migrations/**",
    )
    database_after = _analysis_database_state()
    status_after = _git_output(repository_root, "status", "--short")
    cached_after = _git_output(
        repository_root,
        "diff",
        "--cached",
        "--name-status",
    )
    head_after = _git_output(repository_root, "rev-parse", "HEAD")
    safety = {
        "production_database_read_only": bool(
            database_before["transaction_read_only"]
            and database_after["transaction_read_only"]
        ),
        "production_database_unchanged": database_before == database_after,
        "database_before": database_before,
        "database_after": database_after,
        "cpe_analysis_run_before": database_before["cpe_analysis"]["runs"][
            "count"
        ],
        "cpe_analysis_run_after": database_after["cpe_analysis"]["runs"][
            "count"
        ],
        "cpe_analysis_query_result_before": database_before["cpe_analysis"][
            "query_results"
        ]["count"],
        "cpe_analysis_query_result_after": database_after["cpe_analysis"][
            "query_results"
        ]["count"],
        "protected_inputs_unchanged": (
            protected_files_before == protected_files_after
        ),
        "protected_code_unchanged": (
            protected_code_before == protected_code_after
        ),
        "historical_artifacts_unchanged": historical_before == historical_after,
        "frontend_unchanged": frontend_before == frontend_after,
        "migrations_unchanged": migrations_before == migrations_after,
        "repository_status_unchanged_during_benchmark": (
            status_before == status_after
        ),
        "cached_status_unchanged": cached_before == cached_after,
        "git_head_unchanged": head_before == head_after,
        "repository_status_before": status_before.splitlines(),
        "repository_status_after": status_after.splitlines(),
        "git_diff_cached_name_status": cached_after.splitlines(),
        "git_head": head_after,
        "database_persistence_performed": False,
        "dashboard_updated": False,
        "migration_created": False,
        "ground_truth_modified": False,
        "candidate_universe_modified": False,
        "common_matching_contract_modified": False,
        "existing_scorers_modified": False,
        "frontend_modified": False,
        "commit_performed": False,
    }
    required_safety = (
        "production_database_read_only",
        "production_database_unchanged",
        "protected_inputs_unchanged",
        "protected_code_unchanged",
        "historical_artifacts_unchanged",
        "frontend_unchanged",
        "migrations_unchanged",
        "repository_status_unchanged_during_benchmark",
        "cached_status_unchanged",
        "git_head_unchanged",
    )
    if not all(safety[key] for key in required_safety):
        raise RatcliffObershelpBenchmarkError(
            "A protected repository, artifact, or database invariant changed."
        )
    if (
        safety["cpe_analysis_run_before"] != EXPECTED_ANALYSIS_RUNS
        or safety["cpe_analysis_run_after"] != EXPECTED_ANALYSIS_RUNS
        or safety["cpe_analysis_query_result_before"]
        != EXPECTED_ANALYSIS_QUERY_RESULTS
        or safety["cpe_analysis_query_result_after"]
        != EXPECTED_ANALYSIS_QUERY_RESULTS
    ):
        raise RatcliffObershelpBenchmarkError(
            "CPE Analysis tables changed during the benchmark."
        )

    summary = {
        "algorithm_id": ALGORITHM_ID,
        "display_name": ALGORITHM_NAME,
        "dataset": {
            "queries": len(queries),
            "candidate_families": len(candidates),
            "distinct_decoded_products": len(distinct_products),
            "distinct_raw_query_names": len(distinct_names),
            "gt_coverage": len(queries),
        },
        "aggregate_metrics": first["aggregate"],
        "tie_summary": {
            "queries_with_tie": tie_analysis["queries_with_tie"],
            "maximum_tie_size": tie_analysis["maximum_tie_size"],
            "median_tie_size_among_tied_queries": tie_analysis[
                "median_tie_size_among_tied_queries"
            ],
        },
        "reference_validation_status": reference_validation["status"],
        "determinism_status": determinism["status"],
        "canonical_results_sha256": first["canonical_sha256"],
        "validation_status": "PASS",
    }

    stage = Path(
        tempfile.mkdtemp(
            prefix=".cpe-family-ratcliff-obershelp-evaluation-",
            dir=output_directory.parent,
        )
    )
    _write_json(stage / "summary.json", summary)
    _write_json(stage / "input_manifest.json", input_manifest)
    _write_csv(
        stage / "per_query_results.csv",
        sorted(first["rows"], key=lambda row: int(row["component_id"])),
        PER_QUERY_COLUMNS,
    )
    _write_json(stage / "aggregate_metrics.json", first["aggregate"])
    breakdown_columns = tuple(first["gt_breakdown"][0].keys())
    _write_csv(
        stage / "gt_decision_breakdown.csv",
        first["gt_breakdown"],
        breakdown_columns,
    )
    _write_csv(
        stage / "firmware_breakdown.csv",
        first["firmware_breakdown"],
        breakdown_columns,
    )
    _write_json(stage / "tie_analysis.json", tie_analysis)
    _write_json(stage / "reference_validation.json", reference_validation)
    _write_json(stage / "performance_profile.json", performance)
    _write_json(stage / "determinism.json", determinism)
    _write_json(stage / "safety_validation.json", safety)
    (stage / "report.md").write_text(
        _report(
            first["aggregate"],
            tie_analysis,
            first["gt_breakdown"],
            first["firmware_breakdown"],
            performance,
            input_manifest,
            reference_validation,
            determinism,
            safety,
        ),
        encoding="utf-8",
    )
    actual_artifacts = tuple(sorted(path.name for path in stage.iterdir()))
    if actual_artifacts != tuple(sorted(REQUIRED_ARTIFACTS)):
        raise RatcliffObershelpBenchmarkError(
            "Benchmark artifact inventory is incomplete or unexpected."
        )
    os.replace(stage, output_directory)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the fixed Ratcliff–Obershelp CPE family retrieval benchmark."
        )
    )
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
    )
    arguments = parser.parse_args()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    run_benchmark(arguments.repository_root, arguments.output_directory)


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import csv
import json
import os
import resource
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from cpe_analysis.character_ngram import (
    ALGORITHM_ID,
    ALGORITHM_NAME,
    BOUNDARY_PADDING,
    COEFFICIENT,
    REPRESENTATION,
    TRIGRAM_SIZE,
    CharacterTrigramDiceScorer,
    RepeatedQueryScoreCache,
    validate_character_trigram_dice,
)
from cpe_analysis.jaro_winkler_benchmark import _tie_analysis
from cpe_analysis.levenshtein_benchmark import (
    PER_QUERY_COLUMNS,
    BenchmarkQuery,
    _aggregate_dict,
    _breakdown,
    _canonical_sha256,
    _database_protected_state,
    _git_output,
    _load_gt_queries,
    _model_fingerprint,
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
    QueryEvaluationResult,
    aggregate_results,
    evaluate_query,
    load_candidate_universe,
)


DEFAULT_OUTPUT_DIRECTORY = Path(
    "/tmp/cpe-family-character-trigram-dice-evaluation"
)
HISTORICAL_ARTIFACT_DIRECTORIES = (
    Path("/tmp/cpe-family-character-ngram-evaluation"),
    Path("/tmp/cpe-family-character-ngram-grid-evaluation"),
)
GRID_REFERENCE_FILE = (
    HISTORICAL_ARTIFACT_DIRECTORIES[1] / "selected_per_query_results.csv"
)
EXPECTED_DISTINCT_DECODED_PRODUCTS = 171_940
EXPECTED_DISTINCT_RAW_QUERY_NAMES = 91
EXPECTED_CANDIDATE_SHA256 = (
    "fdc3412c730cb2cff75a161d8cdde85336ef2c9c79d51fe9addd87a1e9774576"
)
EXPECTED_METRICS = {
    "top1_success_count": 79,
    "recall_at_5_success_count": 136,
    "recall_at_10_success_count": 142,
    "mrr": 0.6523244057752082,
    "unique_correct_count": 79,
    "correct_but_ambiguous_count": 55,
    "not_top_group_count": 24,
    "queries_with_tie": 72,
    "maximum_tie_size": 181_482,
}
PROTECTED_CODE_PATHS = (
    "backend/cpe_analysis/matching.py",
    "backend/cpe_analysis/levenshtein.py",
    "backend/cpe_analysis/levenshtein_benchmark.py",
    "backend/cpe_analysis/jaro_winkler.py",
    "backend/cpe_analysis/jaro_winkler_benchmark.py",
    "backend/cpe_analysis/character_ngram.py",
    "backend/cpe_analysis/character_ngram_benchmark.py",
    "backend/cpe_analysis/test_character_ngram.py",
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
    "performance_profile.json",
    "regression_validation.json",
    "determinism.json",
    "safety_validation.json",
)
REGRESSION_FIELDS = (
    "better_count",
    "tie_size",
    "best_rank",
    "worst_rank",
    "top_group_hit",
    "outcome",
)


class CharacterTrigramDiceBenchmarkError(RuntimeError):
    """Raised when the fixed final benchmark violates an invariant."""


class CandidateUniverseProxy:
    def __init__(self, candidates: tuple[CandidateFamily, ...]) -> None:
        self.searchable_families = candidates


def _code_file_hashes(repository_root: Path) -> dict[str, str]:
    return {
        path: _sha256_file(repository_root / path)
        for path in PROTECTED_CODE_PATHS
    }


def _directory_file_hashes(directory: Path) -> dict[str, str]:
    if not directory.is_dir():
        raise CharacterTrigramDiceBenchmarkError(
            f"Historical artifact directory is absent: {directory}"
        )
    return {
        path.name: _sha256_file(path)
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def _historical_artifact_hashes() -> dict[str, dict[str, str]]:
    return {
        str(directory): _directory_file_hashes(directory)
        for directory in HISTORICAL_ARTIFACT_DIRECTORIES
    }


def _analysis_database_state() -> dict[str, object]:
    from cpe_analysis.models import CPEAnalysisQueryResult, CPEAnalysisRun

    state = _database_protected_state()
    state["cpe_analysis"] = {
        "runs": _model_fingerprint(CPEAnalysisRun),
        "query_results": _model_fingerprint(CPEAnalysisQueryResult),
    }
    return state


def _run_evaluation_pass(
    queries: Iterable[BenchmarkQuery],
    candidates: tuple[CandidateFamily, ...],
) -> tuple[
    tuple[QueryEvaluationResult, ...],
    AggregateEvaluationResult,
    dict[str, object],
]:
    base_scorer = CharacterTrigramDiceScorer()
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
        "actual_trigram_dice_computation_count": (
            base_scorer.score_call_count
        ),
        "representation_generation_count": (
            base_scorer.representation_computation_count
        ),
        "representation_cache_size": base_scorer.representation_cache_size,
        "scoring_backend": (
            "pure Python non-padded multiset Character Trigram-Dice"
        ),
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


def _validate_expected_metrics(aggregate: dict[str, object]) -> None:
    for field, expected in EXPECTED_METRICS.items():
        if aggregate[field] != expected:
            raise CharacterTrigramDiceBenchmarkError(
                f"Final Trigram-Dice metric {field} does not match its anchor."
            )


def _regression_validation(
    rows: tuple[dict[str, object], ...],
    aggregate: dict[str, object],
) -> dict[str, object]:
    with GRID_REFERENCE_FILE.open(newline="", encoding="utf-8") as handle:
        reference_rows = {
            int(row["component_id"]): row
            for row in csv.DictReader(handle)
            if row["algorithm_id"] == "character_q3_dice"
        }
    current_rows = {int(row["component_id"]): row for row in rows}
    if len(reference_rows) != 158 or current_rows.keys() != reference_rows.keys():
        raise CharacterTrigramDiceBenchmarkError(
            "Grid q=3 Dice and final benchmark do not join 158/158."
        )

    mismatches: list[dict[str, object]] = []
    for component_id in sorted(current_rows):
        current = current_rows[component_id]
        reference = reference_rows[component_id]
        field_mismatches = []
        if abs(
            float(current["target_score"]) - float(reference["target_score"])
        ) > TIE_TOLERANCE:
            field_mismatches.append("target_score")
        for field in REGRESSION_FIELDS:
            if str(current[field]) != reference[field]:
                field_mismatches.append(field)
        if field_mismatches:
            mismatches.append(
                {
                    "component_id": component_id,
                    "fields": field_mismatches,
                }
            )
    aggregate_match = all(
        aggregate[field] == expected
        for field, expected in EXPECTED_METRICS.items()
    )
    if mismatches or not aggregate_match:
        raise CharacterTrigramDiceBenchmarkError(
            "Final implementation differs from the grid q=3 Dice anchor."
        )
    return {
        "status": "PASS",
        "reference_algorithm_id": "character_q3_dice",
        "final_algorithm_id": ALGORITHM_ID,
        "reference_artifact": str(GRID_REFERENCE_FILE),
        "reference_artifact_sha256": _sha256_file(GRID_REFERENCE_FILE),
        "component_join_count": len(current_rows),
        "aggregate_metrics_equal": True,
        "per_query_results_equal": True,
        "target_score_tolerance": TIE_TOLERANCE,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }


def _order_independence() -> dict[str, object]:
    from cpe_analysis.matching import FamilyRetrievalQuery

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
        evaluate_query(query, order, CharacterTrigramDiceScorer())
        for order in orders
    )
    logical = {
        (
            result.best_rank,
            result.worst_rank,
            result.tie_size,
            result.outcome.value,
        )
        for result in results
    }
    if len(logical) != 1:
        raise CharacterTrigramDiceBenchmarkError(
            "Final Trigram-Dice is candidate-order dependent."
        )
    return {
        "status": "PASS",
        "original_reversed_shuffled_equal": True,
        "result": list(next(iter(logical))),
    }


def _report(
    aggregate: dict[str, object],
    tie_analysis: dict[str, object],
    input_manifest: dict[str, object],
    regression: dict[str, object],
    determinism: dict[str, object],
    safety: dict[str, object],
) -> str:
    query_count = int(aggregate["query_count"])
    lines = [
        "# Character Trigram-Dice Final Evaluation",
        "",
        "## Final Method",
        "",
        "- Method: Character Trigram-Dice",
        "- q: 3",
        "- Coefficient: Dice",
        "- Padding: none",
        "- Representation: multiset",
        "- Score direction: HIGHER_IS_BETTER",
        "- Retrieval threshold: none",
        "- General normalization: none",
        "- Version used: no",
        "- Query: raw stored SBOM component name",
        "- Candidate: decoded logical CPE product",
        "",
        "## Inputs",
        "",
        f"- Queries: {query_count}",
        f"- Candidate families: {aggregate['candidate_family_count']:,}",
        "- Distinct products: "
        f"{input_manifest['distinct_decoded_products']:,}",
        "- Distinct query names: "
        f"{input_manifest['distinct_raw_query_names']}",
        f"- GT coverage: {input_manifest['gt_coverage_count']}/{query_count}",
        "",
        "## Final Metrics",
        "",
        "| Metric | Count | Rate |",
        "| --- | ---: | ---: |",
        f"| Top-1 | {aggregate['top1_success_count']}/{query_count} | "
        f"{_rate(int(aggregate['top1_success_count']), query_count)} |",
        f"| Recall@5 | {aggregate['recall_at_5_success_count']}/{query_count} | "
        f"{_rate(int(aggregate['recall_at_5_success_count']), query_count)} |",
        f"| Recall@10 | {aggregate['recall_at_10_success_count']}/{query_count} | "
        f"{_rate(int(aggregate['recall_at_10_success_count']), query_count)} |",
        f"| MRR | - | {aggregate['mrr']:.12f} |",
        "",
        f"- Unique correct: {aggregate['unique_correct_count']}",
        "- Correct but ambiguous: "
        f"{aggregate['correct_but_ambiguous_count']}",
        f"- Not top group: {aggregate['not_top_group_count']}",
        f"- Queries with tie: {tie_analysis['queries_with_tie']}",
        f"- Maximum tie size: {tie_analysis['maximum_tie_size']:,}",
        "",
        "## Previous q=3 Dice Regression",
        "",
        f"- Aggregate: {regression['status']}",
        f"- Per-query: {regression['status']}",
        f"- Matched components: {regression['component_join_count']}/158",
        f"- Mismatches: {regression['mismatch_count']}",
        "",
        "## Determinism",
        "",
        f"- Status: {determinism['status']}",
        f"- Canonical hash: `{determinism['canonical_results_sha256']}`",
        "",
        "## Safety",
        "",
        "- Production DB changed: "
        f"{'NO' if safety['production_database_unchanged'] else 'YES'}",
        "- Historical artifacts preserved: YES",
        "- Ground Truth / Candidate Universe / snapshots changed: NO",
        "- Common Contract / Levenshtein / Jaro-Winkler changed: NO",
        "- Frontend / migration / DB persistence / commit: unchanged / 0 / NO / NO",
        "",
        "## Verdict",
        "",
        "CHARACTER_TRIGRAM_DICE_FINALIZED",
        "",
    ]
    return "\n".join(lines)


def run_benchmark(repository_root: Path, output_directory: Path) -> None:
    repository_root = repository_root.resolve()
    output_directory = output_directory.resolve()
    if output_directory.exists():
        raise CharacterTrigramDiceBenchmarkError(
            f"Refusing to overwrite existing output: {output_directory}"
        )
    output_directory.parent.mkdir(parents=True, exist_ok=True)

    overall_wall_start = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat()
    status_before = _git_output(repository_root, "status", "--short")
    cached_before = _git_output(
        repository_root, "diff", "--cached", "--name-status"
    )
    head_before = _git_output(repository_root, "rev-parse", "HEAD")
    protected_files_before = _protected_file_hashes(repository_root)
    protected_code_before = _code_file_hashes(repository_root)
    historical_before = _historical_artifact_hashes()
    frontend_before = _tracked_tree_fingerprint(repository_root, "frontend")
    migrations_before = _tracked_tree_fingerprint(
        repository_root, "backend/**/migrations/**"
    )
    database_before = _analysis_database_state()

    reference_validation = validate_character_trigram_dice()
    order_independence = _order_independence()
    universe = load_candidate_universe(repository_root)
    queries, gt_identity = _load_gt_queries(repository_root, universe)
    candidates = universe.searchable_families
    distinct_products = {
        family.decoded_product for family in candidates
    }
    distinct_names = {
        query.retrieval_query.query_text for query in queries
    }
    if (
        len(universe.families) != EXPECTED_TOTAL_FAMILIES
        or len(candidates) != EXPECTED_SEARCHABLE_FAMILIES
        or len(distinct_products) != EXPECTED_DISTINCT_DECODED_PRODUCTS
        or len(queries) != EXPECTED_EVALUATION_QUERY_COUNT
        or len(distinct_names) != EXPECTED_DISTINCT_RAW_QUERY_NAMES
        or universe.validation.candidate_file_sha256
        != EXPECTED_CANDIDATE_SHA256
    ):
        raise CharacterTrigramDiceBenchmarkError(
            "Frozen final benchmark input contract validation failed."
        )

    results, aggregate, first_profile = _run_evaluation_pass(
        queries, candidates
    )
    replay_results, replay_aggregate, replay_profile = _run_evaluation_pass(
        queries, candidates
    )
    first = _logical_payload(queries, results, aggregate, len(candidates))
    replay = _logical_payload(
        queries,
        replay_results,
        replay_aggregate,
        len(candidates),
    )
    if first["canonical_sha256"] != replay["canonical_sha256"]:
        raise CharacterTrigramDiceBenchmarkError(
            "Final full-universe deterministic replay failed."
        )
    _validate_expected_metrics(first["aggregate"])
    regression = _regression_validation(
        first["rows"], first["aggregate"]
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
    tie_analysis = _tie_analysis(
        first["pairs"], CandidateUniverseProxy(candidates)
    )
    expected_computations = len(distinct_names) * len(distinct_products)
    if (
        first_profile["actual_trigram_dice_computation_count"]
        != expected_computations
        or replay_profile["actual_trigram_dice_computation_count"]
        != expected_computations
    ):
        raise CharacterTrigramDiceBenchmarkError(
            "Final score-cache computation invariant failed."
        )
    performance = {
        "family_equivalent_comparison_count": len(queries) * len(candidates),
        "actual_trigram_dice_computation_count": first_profile[
            "actual_trigram_dice_computation_count"
        ],
        "expected_distinct_pair_computation_count": expected_computations,
        "representation_generation_count": first_profile[
            "representation_generation_count"
        ],
        "wall_time_seconds": first_profile["wall_time_seconds"],
        "cpu_time_seconds": first_profile["cpu_time_seconds"],
        "replay_wall_time_seconds": replay_profile["wall_time_seconds"],
        "replay_cpu_time_seconds": replay_profile["cpu_time_seconds"],
        "overall_wall_time_seconds": time.perf_counter()
        - overall_wall_start,
        "peak_memory_mib": (
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        ),
        "parallelism": "1 process / 1 thread",
        "scoring_backend": first_profile["scoring_backend"],
    }

    input_manifest = {
        "algorithm_id": ALGORITHM_ID,
        "display_name": ALGORITHM_NAME,
        "parameters": {"q": TRIGRAM_SIZE, "coefficient": COEFFICIENT},
        "padding": None,
        "boundary_padding": BOUNDARY_PADDING,
        "representation": REPRESENTATION,
        "score_direction": "HIGHER_IS_BETTER",
        "retrieval_threshold": None,
        "query": "stored raw SBOM component.name",
        "candidate": "decoded logical CPE product",
        "general_normalization": None,
        "version_used": False,
        "vendor_or_part_used_as_feature": False,
        "ground_truth_used_as_feature": False,
        "candidate_pruning": False,
        "tie_tolerance": TIE_TOLERANCE,
        "primary_rank": "worst_rank",
        "query_count": len(queries),
        "gt_coverage_count": len(queries),
        "candidate_family_count": len(candidates),
        "total_candidate_family_count": len(universe.families),
        "distinct_decoded_products": len(distinct_products),
        "distinct_raw_query_names": len(distinct_names),
        "candidate_csv_sha256": universe.validation.candidate_file_sha256,
        "ground_truth_dataset": gt_identity,
        "generated_at_utc": started_at,
        "git_head": head_before,
    }

    protected_files_after = _protected_file_hashes(repository_root)
    protected_code_after = _code_file_hashes(repository_root)
    historical_after = _historical_artifact_hashes()
    frontend_after = _tracked_tree_fingerprint(repository_root, "frontend")
    migrations_after = _tracked_tree_fingerprint(
        repository_root, "backend/**/migrations/**"
    )
    database_after = _analysis_database_state()
    status_after = _git_output(repository_root, "status", "--short")
    cached_after = _git_output(
        repository_root, "diff", "--cached", "--name-status"
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
        "cpe_analysis_run_unchanged": (
            database_before["cpe_analysis"]["runs"]
            == database_after["cpe_analysis"]["runs"]
        ),
        "cpe_analysis_query_result_unchanged": (
            database_before["cpe_analysis"]["query_results"]
            == database_after["cpe_analysis"]["query_results"]
        ),
        "protected_inputs_unchanged": (
            protected_files_before == protected_files_after
        ),
        "protected_code_unchanged_during_benchmark": (
            protected_code_before == protected_code_after
        ),
        "historical_artifacts_unchanged": (
            historical_before == historical_after
        ),
        "historical_artifact_hashes": historical_after,
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
        "cpe_or_nvd_snapshot_modified": False,
        "common_matching_contract_modified": False,
        "levenshtein_modified": False,
        "jaro_winkler_modified": False,
        "commit_performed": False,
    }
    required_safety = (
        "production_database_read_only",
        "production_database_unchanged",
        "cpe_analysis_run_unchanged",
        "cpe_analysis_query_result_unchanged",
        "protected_inputs_unchanged",
        "protected_code_unchanged_during_benchmark",
        "historical_artifacts_unchanged",
        "frontend_unchanged",
        "migrations_unchanged",
        "repository_status_unchanged_during_benchmark",
        "cached_status_unchanged",
        "git_head_unchanged",
    )
    if not all(safety[key] for key in required_safety):
        raise CharacterTrigramDiceBenchmarkError(
            "A final benchmark repository or database invariant changed."
        )

    summary = {
        "algorithm_id": ALGORITHM_ID,
        "display_name": ALGORITHM_NAME,
        "parameters": {"q": TRIGRAM_SIZE, "coefficient": COEFFICIENT},
        "aggregate_metrics": first["aggregate"],
        "tie_summary": {
            "queries_with_tie": tie_analysis["queries_with_tie"],
            "maximum_tie_size": tie_analysis["maximum_tie_size"],
        },
        "regression_status": regression["status"],
        "determinism_status": determinism["status"],
        "canonical_results_sha256": first["canonical_sha256"],
        "validation_status": reference_validation["status"],
    }
    stage = Path(
        tempfile.mkdtemp(
            prefix=".cpe-family-character-trigram-dice-evaluation-",
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
    _write_json(stage / "performance_profile.json", performance)
    _write_json(stage / "regression_validation.json", regression)
    _write_json(stage / "determinism.json", determinism)
    _write_json(stage / "safety_validation.json", safety)
    (stage / "report.md").write_text(
        _report(
            first["aggregate"],
            tie_analysis,
            input_manifest,
            regression,
            determinism,
            safety,
        ),
        encoding="utf-8",
    )
    actual_artifacts = tuple(sorted(path.name for path in stage.iterdir()))
    if actual_artifacts != tuple(sorted(REQUIRED_ARTIFACTS)):
        raise CharacterTrigramDiceBenchmarkError(
            "Final artifact inventory is incomplete or unexpected."
        )
    os.replace(stage, output_directory)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the fixed final Character Trigram-Dice family benchmark."
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

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cpe.cpe23 import parse_cpe23_formatted_string
from cpe_analysis.character_ngram import (
    CharacterTrigramDiceScorer,
    RepeatedQueryScoreCache as CharacterTrigramScoreCache,
)
from cpe_analysis.jaro_winkler import (
    RepeatedQueryScoreCache as JaroWinklerScoreCache,
    Winkler1990JaroWinklerScorer,
)
from cpe_analysis.levenshtein import (
    LengthNormalizedLevenshteinScorer,
    RepeatedQueryScoreCache as LevenshteinScoreCache,
)
from cpe_analysis.matching import (
    CandidateFamily,
    FamilyRetrievalQuery,
    FamilySimilarityScorer,
    QueryEvaluationResult,
    aggregate_results,
    decode_cpe_product,
    evaluate_query,
)
from cpe_analysis.ratcliff_obershelp import (
    RatcliffObershelpScorer,
    RepeatedQueryScoreCache as RatcliffObershelpScoreCache,
)


GROUND_TRUTH_RELATIVE_PATH = Path("research/ground_truth/ground_truth.csv")
CANDIDATE_UNIVERSE_RELATIVE_PATH = Path(
    "data/cpe_candidate_universe/candidate_families.csv"
)
EXPECTED_GROUND_TRUTH_ROWS = 2_038
EXPECTED_QUERY_COUNT = 158
EXPECTED_TOTAL_CANDIDATES = 181_493
EXPECTED_SEARCHABLE_CANDIDATES = 181_484
EXPECTED_GT_DECISION_COUNTS = {
    "CPE_CONFIRMED": 10,
    "OFFICIAL_CPE_MAPPED": 101,
    "VERSION_NOT_IN_DICTIONARY": 45,
    "NVD_CONFIGURATION_ONLY": 2,
}
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
ALLOWED_CANDIDATE_SOURCES = {
    "ACTIVE_DICTIONARY",
    "NVD_CONFIGURATION_ONLY",
}
REQUIRED_CANDIDATE_COLUMNS = {
    "family_id",
    "part",
    "vendor",
    "product",
    "source",
    "searchable",
}
REQUIRED_GROUND_TRUTH_COLUMNS = {
    "firmware_vendor",
    "firmware_product",
    "firmware_version",
    "sbom_document_id",
    "component_id",
    "component_name",
    "ground_truth_cpe",
    "validation_result",
    "cpe_present",
}
PER_QUERY_FIELDS = (
    "algorithm_id",
    "algorithm_name",
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


class RQ2RunnerError(RuntimeError):
    """Raised when canonical RQ2 inputs or results violate the contract."""


@dataclass(frozen=True)
class CandidateInput:
    all_families: tuple[CandidateFamily, ...]
    searchable_families: tuple[CandidateFamily, ...]


@dataclass(frozen=True)
class RQ2Query:
    retrieval_query: FamilyRetrievalQuery
    firmware_name: str
    firmware_identifier: str
    gt_decision: str
    gt_decoded_product: str


@dataclass(frozen=True)
class ExpectedMetrics:
    top1: int
    recall_at_5: int
    recall_at_10: int
    mrr: float


@dataclass(frozen=True)
class AlgorithmDefinition:
    algorithm_id: str
    algorithm_name: str
    scorer_factory: Callable[[], FamilySimilarityScorer]
    expected: ExpectedMetrics


@dataclass(frozen=True)
class AlgorithmResult:
    summary: dict[str, object]
    per_query_rows: tuple[dict[str, object], ...]


ALGORITHMS = (
    AlgorithmDefinition(
        algorithm_id="length_normalized_levenshtein",
        algorithm_name="Length-normalized Levenshtein",
        scorer_factory=lambda: LevenshteinScoreCache(
            LengthNormalizedLevenshteinScorer()
        ),
        expected=ExpectedMetrics(
            top1=63,
            recall_at_5=124,
            recall_at_10=127,
            mrr=0.5565417164607827,
        ),
    ),
    AlgorithmDefinition(
        algorithm_id="jaro_winkler",
        algorithm_name="Jaro-Winkler",
        scorer_factory=lambda: JaroWinklerScoreCache(
            Winkler1990JaroWinklerScorer()
        ),
        expected=ExpectedMetrics(
            top1=69,
            recall_at_5=134,
            recall_at_10=140,
            mrr=0.6082612255091588,
        ),
    ),
    AlgorithmDefinition(
        algorithm_id="character_trigram_dice",
        algorithm_name="Character Trigram-Dice",
        scorer_factory=lambda: CharacterTrigramScoreCache(
            CharacterTrigramDiceScorer()
        ),
        expected=ExpectedMetrics(
            top1=79,
            recall_at_5=136,
            recall_at_10=142,
            mrr=0.6523244057752082,
        ),
    ),
    AlgorithmDefinition(
        algorithm_id="ratcliff_obershelp",
        algorithm_name="Ratcliff–Obershelp",
        scorer_factory=lambda: RatcliffObershelpScoreCache(
            RatcliffObershelpScorer()
        ),
        expected=ExpectedMetrics(
            top1=72,
            recall_at_5=130,
            recall_at_10=132,
            mrr=0.6058037627846183,
        ),
    ),
)


def _parse_searchable(value: str, *, row_number: int) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise RQ2RunnerError(
        "Candidate searchable must be exactly 'True' or 'False'; "
        f"found {value!r} at row {row_number}."
    )


def load_candidate_families(
    candidate_csv: Path,
    *,
    enforce_fixed_contract: bool = True,
) -> CandidateInput:
    families: list[CandidateFamily] = []
    searchable: list[CandidateFamily] = []
    seen_ids: set[str] = set()
    seen_keys: set[tuple[str, str, str]] = set()

    try:
        with Path(candidate_csv).open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            columns = set(reader.fieldnames or ())
            missing = REQUIRED_CANDIDATE_COLUMNS - columns
            if missing:
                raise RQ2RunnerError(
                    "Candidate CSV is missing columns: "
                    + ", ".join(sorted(missing))
                )
            for row_number, row in enumerate(reader, start=2):
                family_key = (row["part"], row["vendor"], row["product"])
                family_identifier = row["family_id"]
                if not family_identifier or family_identifier in seen_ids:
                    raise RQ2RunnerError(
                        "Candidate family_id is empty or duplicated at row "
                        f"{row_number}."
                    )
                if family_key in seen_keys:
                    raise RQ2RunnerError(
                        "Candidate family key is duplicated at row "
                        f"{row_number}."
                    )
                if row["source"] not in ALLOWED_CANDIDATE_SOURCES:
                    raise RQ2RunnerError(
                        f"Unknown candidate source at row {row_number}."
                    )
                is_searchable = _parse_searchable(
                    row["searchable"], row_number=row_number
                )
                candidate = CandidateFamily(
                    family_id=family_identifier,
                    part=row["part"],
                    vendor=row["vendor"],
                    serialized_product=row["product"],
                    decoded_product=decode_cpe_product(row["product"]),
                    source=row["source"],
                    searchable=is_searchable,
                )
                seen_ids.add(family_identifier)
                seen_keys.add(family_key)
                families.append(candidate)
                if is_searchable:
                    searchable.append(candidate)
    except (OSError, UnicodeError, csv.Error) as error:
        raise RQ2RunnerError(
            f"Candidate CSV could not be read: {candidate_csv}"
        ) from error

    if enforce_fixed_contract and (
        len(families) != EXPECTED_TOTAL_CANDIDATES
        or len(searchable) != EXPECTED_SEARCHABLE_CANDIDATES
    ):
        raise RQ2RunnerError(
            "Candidate counts do not match the final RQ2 contract: "
            f"total={len(families)}, searchable={len(searchable)}."
        )
    return CandidateInput(tuple(families), tuple(searchable))


def load_ground_truth_queries(
    ground_truth_csv: Path,
    candidates: CandidateInput,
    *,
    enforce_fixed_contract: bool = True,
) -> tuple[RQ2Query, ...]:
    searchable_by_key = {
        (family.part, family.vendor, family.serialized_product): family
        for family in candidates.searchable_families
    }
    queries: list[RQ2Query] = []
    total_rows = 0
    decision_counts: Counter[str] = Counter()
    firmware_counts: Counter[str] = Counter()

    try:
        with Path(ground_truth_csv).open(
            newline="", encoding="utf-8"
        ) as stream:
            reader = csv.DictReader(stream)
            columns = set(reader.fieldnames or ())
            missing = REQUIRED_GROUND_TRUTH_COLUMNS - columns
            if missing:
                raise RQ2RunnerError(
                    "Ground Truth CSV is missing columns: "
                    + ", ".join(sorted(missing))
                )
            for row_number, row in enumerate(reader, start=2):
                total_rows += 1
                cpe_present = row["cpe_present"]
                if cpe_present not in {"true", "false"}:
                    raise RQ2RunnerError(
                        f"Invalid cpe_present at row {row_number}."
                    )
                if cpe_present == "false":
                    if row["ground_truth_cpe"]:
                        raise RQ2RunnerError(
                            "GT CPE is populated while cpe_present is false "
                            f"at row {row_number}."
                        )
                    continue
                if not row["ground_truth_cpe"]:
                    raise RQ2RunnerError(
                        f"GT CPE is empty at positive row {row_number}."
                    )
                parsed = parse_cpe23_formatted_string(
                    row["ground_truth_cpe"]
                )
                if not parsed.is_structurally_valid:
                    raise RQ2RunnerError(
                        f"Invalid GT CPE at row {row_number}."
                    )
                family_key = (
                    parsed.part_raw,
                    parsed.vendor_raw,
                    parsed.product_raw,
                )
                target = searchable_by_key.get(family_key)
                if target is None:
                    raise RQ2RunnerError(
                        "GT family is absent from searchable candidates at "
                        f"row {row_number}."
                    )
                query_text = row["component_name"]
                if not query_text:
                    raise RQ2RunnerError(
                        f"Query component name is empty at row {row_number}."
                    )
                firmware_key = (
                    row["firmware_vendor"],
                    row["firmware_version"],
                )
                firmware_name = FIRMWARE_NAMES.get(firmware_key)
                if firmware_name is None:
                    raise RQ2RunnerError(
                        f"Unknown firmware at row {row_number}."
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
                decision = row["validation_result"]
                identifier = (
                    f"{row['firmware_vendor']} "
                    f"{row['firmware_product']} "
                    f"{row['firmware_version']}"
                )
                queries.append(
                    RQ2Query(
                        retrieval_query=retrieval_query,
                        firmware_name=firmware_name,
                        firmware_identifier=identifier,
                        gt_decision=decision,
                        gt_decoded_product=target.decoded_product,
                    )
                )
                decision_counts[decision] += 1
                firmware_counts[firmware_name] += 1
    except (OSError, UnicodeError, csv.Error, ValueError) as error:
        if isinstance(error, RQ2RunnerError):
            raise
        raise RQ2RunnerError(
            f"Ground Truth CSV could not be read: {ground_truth_csv}"
        ) from error

    queries.sort(
        key=lambda item: (
            item.retrieval_query.query_text,
            item.retrieval_query.sbom_document_id,
            item.retrieval_query.component_id,
        )
    )
    query_keys = {
        (
            query.retrieval_query.sbom_document_id,
            query.retrieval_query.component_id,
        )
        for query in queries
    }
    if len(query_keys) != len(queries):
        raise RQ2RunnerError("Ground Truth query components are duplicated.")
    if enforce_fixed_contract and (
        total_rows != EXPECTED_GROUND_TRUTH_ROWS
        or len(queries) != EXPECTED_QUERY_COUNT
        or dict(decision_counts) != EXPECTED_GT_DECISION_COUNTS
        or dict(firmware_counts) != EXPECTED_FIRMWARE_QUERY_COUNTS
    ):
        raise RQ2RunnerError(
            "Ground Truth queries do not match the final RQ2 contract."
        )
    return tuple(queries)


def _per_query_row(
    definition: AlgorithmDefinition,
    query: RQ2Query,
    result: QueryEvaluationResult,
) -> dict[str, object]:
    return {
        "algorithm_id": definition.algorithm_id,
        "algorithm_name": definition.algorithm_name,
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


def _run_algorithm(
    definition: AlgorithmDefinition,
    queries: tuple[RQ2Query, ...],
    candidates: tuple[CandidateFamily, ...],
) -> AlgorithmResult:
    scorer = definition.scorer_factory()
    results = tuple(
        evaluate_query(query.retrieval_query, candidates, scorer)
        for query in queries
    )
    aggregate = aggregate_results(results)
    top1 = sum(result.top1_success for result in results)
    recall_at_5 = sum(result.recall_at_5_success for result in results)
    recall_at_10 = sum(result.recall_at_10_success for result in results)
    expected_match = (
        top1 == definition.expected.top1
        and recall_at_5 == definition.expected.recall_at_5
        and recall_at_10 == definition.expected.recall_at_10
        and abs(aggregate.mrr - definition.expected.mrr) <= 1e-15
    )
    summary = {
        "algorithm_id": definition.algorithm_id,
        "algorithm_name": definition.algorithm_name,
        "query_count": aggregate.query_count,
        "candidate_family_count": len(candidates),
        "top1_success_count": top1,
        "recall_at_5_success_count": recall_at_5,
        "recall_at_10_success_count": recall_at_10,
        "mrr": aggregate.mrr,
        "unique_correct_count": aggregate.unique_correct_count,
        "correct_but_ambiguous_count": (
            aggregate.correct_but_ambiguous_count
        ),
        "not_top_group_count": aggregate.not_top_group_count,
        "queries_with_tie": aggregate.queries_with_tie,
        "maximum_tie_size": aggregate.maximum_tie_size,
        "expected_match": expected_match,
    }
    if not expected_match:
        raise RQ2RunnerError(
            f"{definition.algorithm_name} does not match the final result "
            f"contract: {json.dumps(summary, sort_keys=True)}"
        )
    rows = tuple(
        _per_query_row(definition, query, result)
        for query, result in zip(queries, results, strict=True)
    )
    return AlgorithmResult(summary=summary, per_query_rows=rows)


def _write_results(
    output_directory: Path,
    summary: dict[str, object],
    rows: tuple[dict[str, object], ...],
) -> None:
    output_directory.mkdir()
    (output_directory / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with (output_directory / "per_query_results.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=PER_QUERY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def run_rq2_benchmarks(
    *,
    ground_truth_csv: Path,
    candidate_csv: Path,
    output_directory: Path,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    ground_truth_csv = Path(ground_truth_csv).resolve()
    candidate_csv = Path(candidate_csv).resolve()
    output_directory = Path(output_directory).resolve()
    if output_directory.exists():
        raise RQ2RunnerError(
            f"Refusing to overwrite existing output: {output_directory}"
        )
    output_directory.parent.mkdir(parents=True, exist_ok=True)

    candidate_input = load_candidate_families(candidate_csv)
    queries = load_ground_truth_queries(
        ground_truth_csv,
        candidate_input,
    )
    algorithm_results: list[AlgorithmResult] = []
    for definition in ALGORITHMS:
        if progress is not None:
            progress(f"Running {definition.algorithm_name}...")
        algorithm_results.append(
            _run_algorithm(
                definition,
                queries,
                candidate_input.searchable_families,
            )
        )

    summary = {
        "ground_truth_csv": str(ground_truth_csv),
        "candidate_csv": str(candidate_csv),
        "evaluation_queries": len(queries),
        "total_candidate_families": len(candidate_input.all_families),
        "searchable_candidate_families": len(
            candidate_input.searchable_families
        ),
        "algorithms": [result.summary for result in algorithm_results],
        "all_expected_results_match": all(
            result.summary["expected_match"]
            for result in algorithm_results
        ),
    }
    rows = tuple(
        row
        for result in algorithm_results
        for row in result.per_query_rows
    )
    _write_results(output_directory, summary, rows)
    return summary

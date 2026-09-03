from __future__ import annotations

import csv
import json
import math
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Protocol


CANDIDATE_MANIFEST_RELATIVE_PATH = Path(
    "data/cpe_candidate_universe/manifest.json"
)
TIE_TOLERANCE = 1e-12

EXPECTED_SCHEMA_VERSION = 1
EXPECTED_CANDIDATE_FILE = "candidate_families.csv"
EXPECTED_TOTAL_FAMILIES = 181_493
EXPECTED_SEARCHABLE_FAMILIES = 181_484
EXPECTED_CPE_SNAPSHOT = "20260819T035002Z"
EXPECTED_NVD_SNAPSHOT = "20260820T110357Z"
EXPECTED_EVALUATION_QUERY_COUNT = 158
EXPECTED_GT_DECISION_COUNTS = {
    "CPE_CONFIRMED": 10,
    "OFFICIAL_CPE_MAPPED": 101,
    "VERSION_NOT_IN_DICTIONARY": 45,
    "NVD_CONFIGURATION_ONLY": 2,
}
SUPPORTED_ALGORITHM_NAMES = (
    "Levenshtein",
    "Jaro-Winkler",
    "Character n-gram",
    "Token Jaccard",
    "TF-IDF + Cosine",
)
EXPECTED_CANDIDATE_SOURCES = (
    "ACTIVE_DICTIONARY",
    "NVD_CONFIGURATION_ONLY",
)

_CPE_UNQUOTED_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-._"
)
_CPE_ESCAPABLE_CHARACTERS = frozenset(
    "\\?!\"#$%&'()+,/:;<=>@[]^`{|}~-._*"
)
_REQUIRED_CANDIDATE_COLUMNS = frozenset(
    {
        "family_id",
        "part",
        "vendor",
        "product",
        "source",
        "searchable",
    }
)


class MatchingContractError(ValueError):
    """Raised when common matching input or evaluation is invalid."""


class CpeProductDecodeError(MatchingContractError):
    """Raised when a CPE formatted-string product cannot be decoded."""


class CandidateUniverseError(MatchingContractError):
    """Raised when the frozen candidate universe violates its manifest."""


class ScoreDirection(str, Enum):
    LOWER_IS_BETTER = "LOWER_IS_BETTER"
    HIGHER_IS_BETTER = "HIGHER_IS_BETTER"


class EvaluationOutcome(str, Enum):
    UNIQUE_CORRECT = "UNIQUE_CORRECT"
    CORRECT_BUT_AMBIGUOUS = "CORRECT_BUT_AMBIGUOUS"
    NOT_TOP_GROUP = "NOT_TOP_GROUP"


class FamilySimilarityScorer(Protocol):
    """Common scorer interface for product-family retrieval algorithms.

    Implementations must be deterministic and must not mutate or normalize
    either input. The evaluation engine supplies the stored SBOM name and the
    decoded logical CPE product value exactly as held by its input objects.
    """

    algorithm_id: str
    algorithm_name: str
    score_direction: ScoreDirection

    def score(self, query_text: str, candidate_text: str) -> float:
        """Return a full-precision score for the two input strings."""


@dataclass(frozen=True)
class CandidateUniverseManifest:
    schema_version: int
    candidate_file: str
    total_candidate_families: int
    searchable_candidate_families: int
    cpe_snapshot: str
    nvd_snapshot: str
    candidate_sources: tuple[str, ...]


@dataclass(frozen=True)
class CandidateFamily:
    family_id: str
    part: str
    vendor: str
    serialized_product: str
    decoded_product: str
    source: str
    searchable: bool


@dataclass(frozen=True)
class CandidateUniverseValidation:
    total_families: int
    searchable_families: int
    decode_successes: int
    decode_failures: int


@dataclass(frozen=True)
class CandidateUniverse:
    manifest: CandidateUniverseManifest
    families: tuple[CandidateFamily, ...]
    searchable_families: tuple[CandidateFamily, ...]
    validation: CandidateUniverseValidation


@dataclass(frozen=True)
class FamilyRetrievalQuery:
    component_id: int
    sbom_document_id: int
    query_text: str
    gt_family_id: str
    gt_part: str
    gt_vendor: str
    gt_product: str

    def __post_init__(self) -> None:
        if isinstance(self.component_id, bool) or not isinstance(
            self.component_id,
            int,
        ):
            raise MatchingContractError("component_id must be an integer.")
        if isinstance(self.sbom_document_id, bool) or not isinstance(
            self.sbom_document_id,
            int,
        ):
            raise MatchingContractError(
                "sbom_document_id must be an integer."
            )
        for field_name in (
            "query_text",
            "gt_family_id",
            "gt_part",
            "gt_vendor",
            "gt_product",
        ):
            if not isinstance(getattr(self, field_name), str):
                raise MatchingContractError(
                    f"{field_name} must be a string."
                )


@dataclass(frozen=True)
class QueryEvaluationResult:
    component_id: int
    sbom_document_id: int
    query_text: str
    gt_family_id: str
    gt_part: str
    gt_vendor: str
    gt_product: str
    algorithm_id: str
    target_score: float
    better_count: int
    tie_size: int
    best_rank: int
    worst_rank: int
    top_group_hit: bool
    outcome: EvaluationOutcome
    top1_success: bool
    recall_at_5_success: bool
    recall_at_10_success: bool
    reciprocal_rank: float


@dataclass(frozen=True)
class AggregateEvaluationResult:
    algorithm_id: str
    query_count: int
    top1_accuracy: float
    recall_at_5: float
    recall_at_10: float
    mrr: float
    unique_correct_count: int
    correct_but_ambiguous_count: int
    not_top_group_count: int
    top_group_hit_count: int
    queries_with_tie: int
    maximum_tie_size: int


def decode_cpe_product(serialized_product: str) -> str:
    """Decode one CPE 2.3 formatted-string product attribute.

    Backslash quoting is interpreted exactly once. A quoted backslash becomes
    one logical backslash; other quoted special characters become their one
    logical character. Invalid or dangling quoting is rejected rather than
    repaired. The input string itself is never changed.
    """

    if not isinstance(serialized_product, str):
        raise CpeProductDecodeError(
            "CPE product must be a formatted-string value."
        )
    if serialized_product == "":
        raise CpeProductDecodeError("CPE product must not be empty.")

    decoded: list[str] = []
    unquoted_wildcards: list[tuple[int, str]] = []
    logical_position = 0
    index = 0
    while index < len(serialized_product):
        character = serialized_product[index]
        if character == "\\":
            index += 1
            if index >= len(serialized_product):
                raise CpeProductDecodeError(
                    "CPE product ends with a dangling escape."
                )
            quoted = serialized_product[index]
            if quoted not in _CPE_ESCAPABLE_CHARACTERS:
                raise CpeProductDecodeError(
                    "CPE product contains an invalid escaped character "
                    f"{quoted!r} at index {index}."
                )
            decoded.append(quoted)
        elif character in _CPE_UNQUOTED_CHARACTERS:
            decoded.append(character)
        elif character in "*?":
            decoded.append(character)
            unquoted_wildcards.append((logical_position, character))
        else:
            raise CpeProductDecodeError(
                "CPE product contains an unescaped special character "
                f"{character!r} at index {index}."
            )
        logical_position += 1
        index += 1

    if unquoted_wildcards:
        first_non_wildcard = 0
        wildcard_positions = {
            position for position, _ in unquoted_wildcards
        }
        while first_non_wildcard in wildcard_positions:
            first_non_wildcard += 1
        last_non_wildcard = logical_position - 1
        while last_non_wildcard in wildcard_positions:
            last_non_wildcard -= 1
        if any(
            first_non_wildcard <= position <= last_non_wildcard
            for position, _ in unquoted_wildcards
        ):
            raise CpeProductDecodeError(
                "CPE product contains an embedded unquoted wildcard."
            )
        if any(
            wildcard == "*"
            and position not in {0, logical_position - 1}
            for position, wildcard in unquoted_wildcards
        ):
            raise CpeProductDecodeError(
                "CPE product contains an unquoted '*' away from an endpoint."
            )

    return "".join(decoded)


def _required_integer(data: dict[str, Any], field: str) -> int:
    value = data.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateUniverseError(
            f"Manifest field {field!r} must be a non-negative integer."
        )
    return value


def _required_string(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise CandidateUniverseError(
            f"Manifest field {field!r} must be a non-empty string."
        )
    return value


def _load_manifest(
    repository_root: Path,
    *,
    enforce_research_contract: bool,
) -> tuple[CandidateUniverseManifest, Path]:
    manifest_path = repository_root / CANDIDATE_MANIFEST_RELATIVE_PATH
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateUniverseError(
            "Candidate universe manifest could not be read."
        ) from error
    if not isinstance(data, dict):
        raise CandidateUniverseError(
            "Candidate universe manifest must contain an object."
        )

    sources = data.get("candidate_sources")
    if (
        not isinstance(sources, list)
        or not sources
        or any(not isinstance(source, str) or not source for source in sources)
    ):
        raise CandidateUniverseError(
            "Manifest candidate_sources must be a non-empty string list."
        )
    family_definition = data.get("family_definition")
    if family_definition != ["part", "vendor", "product"]:
        raise CandidateUniverseError(
            "Manifest family_definition must be part/vendor/product."
        )
    if data.get("search_condition") != "searchable == true":
        raise CandidateUniverseError(
            "Manifest search_condition must select searchable families."
        )

    manifest = CandidateUniverseManifest(
        schema_version=_required_integer(data, "schema_version"),
        candidate_file=_required_string(data, "candidate_file"),
        total_candidate_families=_required_integer(
            data,
            "total_candidate_families",
        ),
        searchable_candidate_families=_required_integer(
            data,
            "searchable_candidate_families",
        ),
        cpe_snapshot=_required_string(data, "cpe_snapshot"),
        nvd_snapshot=_required_string(data, "nvd_snapshot"),
        candidate_sources=tuple(sources),
    )
    candidate_relative_path = Path(manifest.candidate_file)
    if (
        candidate_relative_path.is_absolute()
        or candidate_relative_path.name != manifest.candidate_file
    ):
        raise CandidateUniverseError(
            "Manifest candidate_file must be a plain relative filename."
        )

    if enforce_research_contract:
        expected = {
            "schema_version": EXPECTED_SCHEMA_VERSION,
            "candidate_file": EXPECTED_CANDIDATE_FILE,
            "total_candidate_families": EXPECTED_TOTAL_FAMILIES,
            "searchable_candidate_families": (
                EXPECTED_SEARCHABLE_FAMILIES
            ),
            "cpe_snapshot": EXPECTED_CPE_SNAPSHOT,
            "nvd_snapshot": EXPECTED_NVD_SNAPSHOT,
            "candidate_sources": EXPECTED_CANDIDATE_SOURCES,
        }
        for field, expected_value in expected.items():
            if getattr(manifest, field) != expected_value:
                raise CandidateUniverseError(
                    f"Manifest field {field!r} does not match the frozen "
                    "RQ2 research contract."
                )

    candidate_path = manifest_path.parent / candidate_relative_path
    return manifest, candidate_path


def _parse_searchable(value: str, *, row_number: int) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise CandidateUniverseError(
        "Candidate searchable must be exactly 'True' or 'False'; "
        f"found {value!r} at CSV row {row_number}."
    )


def load_candidate_universe(
    repository_root: Path,
    *,
    enforce_research_contract: bool = True,
) -> CandidateUniverse:
    """Load and validate the immutable product-family candidate universe."""

    repository_root = Path(repository_root)
    manifest, candidate_path = _load_manifest(
        repository_root,
        enforce_research_contract=enforce_research_contract,
    )

    families: list[CandidateFamily] = []
    searchable_families: list[CandidateFamily] = []
    seen_family_ids: set[str] = set()
    seen_family_keys: set[tuple[str, str, str]] = set()
    allowed_sources = set(manifest.candidate_sources)
    try:
        with candidate_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            actual_columns = set(reader.fieldnames or ())
            missing_columns = _REQUIRED_CANDIDATE_COLUMNS - actual_columns
            if missing_columns:
                raise CandidateUniverseError(
                    "Candidate CSV is missing required columns: "
                    + ", ".join(sorted(missing_columns))
                )
            for row_number, row in enumerate(reader, start=2):
                family_id = row["family_id"]
                if not family_id:
                    raise CandidateUniverseError(
                        f"Candidate family_id is empty at CSV row {row_number}."
                    )
                if family_id in seen_family_ids:
                    raise CandidateUniverseError(
                        f"Duplicate family_id {family_id!r} at CSV row "
                        f"{row_number}."
                    )
                family_key = (row["part"], row["vendor"], row["product"])
                if family_key in seen_family_keys:
                    raise CandidateUniverseError(
                        "Duplicate part/vendor/product family at CSV row "
                        f"{row_number}."
                    )
                source = row["source"]
                if source not in allowed_sources:
                    raise CandidateUniverseError(
                        f"Unknown candidate source {source!r} at CSV row "
                        f"{row_number}."
                    )
                try:
                    decoded_product = decode_cpe_product(row["product"])
                except CpeProductDecodeError as error:
                    raise CandidateUniverseError(
                        "Candidate product decode failed at CSV row "
                        f"{row_number}: {error}"
                    ) from error
                candidate = CandidateFamily(
                    family_id=family_id,
                    part=row["part"],
                    vendor=row["vendor"],
                    serialized_product=row["product"],
                    decoded_product=decoded_product,
                    source=source,
                    searchable=_parse_searchable(
                        row["searchable"],
                        row_number=row_number,
                    ),
                )
                seen_family_ids.add(family_id)
                seen_family_keys.add(family_key)
                families.append(candidate)
                if candidate.searchable:
                    searchable_families.append(candidate)
    except (OSError, UnicodeError, csv.Error) as error:
        raise CandidateUniverseError(
            "Candidate universe CSV could not be parsed."
        ) from error

    if len(families) != manifest.total_candidate_families:
        raise CandidateUniverseError(
            "Candidate family count does not match its manifest: "
            f"expected {manifest.total_candidate_families}, "
            f"found {len(families)}."
        )
    if len(searchable_families) != manifest.searchable_candidate_families:
        raise CandidateUniverseError(
            "Searchable candidate count does not match its manifest: "
            f"expected {manifest.searchable_candidate_families}, "
            f"found {len(searchable_families)}."
        )

    validation = CandidateUniverseValidation(
        total_families=len(families),
        searchable_families=len(searchable_families),
        decode_successes=len(families),
        decode_failures=0,
    )
    return CandidateUniverse(
        manifest=manifest,
        families=tuple(families),
        searchable_families=tuple(searchable_families),
        validation=validation,
    )


def scores_tie(left: float, right: float) -> bool:
    """Return numerical equality under the absolute research tolerance."""

    return abs(left - right) <= TIE_TOLERANCE


def _valid_score(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MatchingContractError(
            "Scorer output must be a finite real number."
        )
    score = float(value)
    if not math.isfinite(score):
        raise MatchingContractError(
            "Scorer output must be a finite real number."
        )
    return score


def _score_is_better(
    score: float,
    target_score: float,
    direction: ScoreDirection,
) -> bool:
    if scores_tie(score, target_score):
        return False
    if direction is ScoreDirection.LOWER_IS_BETTER:
        return score < target_score
    if direction is ScoreDirection.HIGHER_IS_BETTER:
        return score > target_score
    raise MatchingContractError(f"Unsupported score direction: {direction!r}")


def evaluate_query(
    query: FamilyRetrievalQuery,
    candidates: Iterable[CandidateFamily],
    scorer: FamilySimilarityScorer,
) -> QueryEvaluationResult:
    """Evaluate one raw-name query against every supplied candidate family.

    The target label is used only to locate the target score after all
    candidate texts have been scored. It never changes the raw query, filters
    candidates, or contributes a feature. Scores for duplicate decoded
    products are computed once, while every family still contributes to
    better_count and tie_size.
    """

    algorithm_id = getattr(scorer, "algorithm_id", None)
    algorithm_name = getattr(scorer, "algorithm_name", None)
    direction = getattr(scorer, "score_direction", None)
    if not isinstance(algorithm_id, str) or not algorithm_id:
        raise MatchingContractError(
            "Scorer algorithm_id must be a non-empty string."
        )
    if not isinstance(algorithm_name, str) or not algorithm_name:
        raise MatchingContractError(
            "Scorer algorithm_name must be a non-empty string."
        )
    if not isinstance(direction, ScoreDirection):
        raise MatchingContractError(
            "Scorer score_direction must be a ScoreDirection."
        )

    candidate_tuple = tuple(candidates)
    if not candidate_tuple:
        raise MatchingContractError("Candidate set must not be empty.")
    if any(not candidate.searchable for candidate in candidate_tuple):
        raise MatchingContractError(
            "Evaluation candidates must all be searchable families."
        )
    family_ids = [candidate.family_id for candidate in candidate_tuple]
    if len(family_ids) != len(set(family_ids)):
        raise MatchingContractError(
            "Candidate family_id values must be unique."
        )
    target_candidates = [
        candidate
        for candidate in candidate_tuple
        if candidate.family_id == query.gt_family_id
    ]
    if len(target_candidates) != 1:
        raise MatchingContractError(
            "GT family must occur exactly once in the candidate set."
        )

    unique_products = {
        candidate.decoded_product for candidate in candidate_tuple
    }
    product_scores = {
        product: _valid_score(scorer.score(query.query_text, product))
        for product in sorted(unique_products)
    }
    target_score = product_scores[target_candidates[0].decoded_product]
    better_count = sum(
        _score_is_better(
            product_scores[candidate.decoded_product],
            target_score,
            direction,
        )
        for candidate in candidate_tuple
    )
    tie_size = sum(
        scores_tie(
            product_scores[candidate.decoded_product],
            target_score,
        )
        for candidate in candidate_tuple
    )
    best_rank = better_count + 1
    worst_rank = better_count + tie_size
    top_group_hit = best_rank == 1
    if top_group_hit and worst_rank == 1:
        outcome = EvaluationOutcome.UNIQUE_CORRECT
    elif top_group_hit:
        outcome = EvaluationOutcome.CORRECT_BUT_AMBIGUOUS
    else:
        outcome = EvaluationOutcome.NOT_TOP_GROUP

    return QueryEvaluationResult(
        component_id=query.component_id,
        sbom_document_id=query.sbom_document_id,
        query_text=query.query_text,
        gt_family_id=query.gt_family_id,
        gt_part=query.gt_part,
        gt_vendor=query.gt_vendor,
        gt_product=query.gt_product,
        algorithm_id=algorithm_id,
        target_score=target_score,
        better_count=better_count,
        tie_size=tie_size,
        best_rank=best_rank,
        worst_rank=worst_rank,
        top_group_hit=top_group_hit,
        outcome=outcome,
        top1_success=worst_rank == 1,
        recall_at_5_success=worst_rank <= 5,
        recall_at_10_success=worst_rank <= 10,
        reciprocal_rank=1.0 / worst_rank,
    )


def aggregate_results(
    results: Iterable[QueryEvaluationResult],
) -> AggregateEvaluationResult:
    """Aggregate worst-rank primary metrics and tie diagnostics."""

    result_tuple = tuple(results)
    if not result_tuple:
        raise MatchingContractError(
            "At least one query result is required for aggregation."
        )
    algorithm_ids = {result.algorithm_id for result in result_tuple}
    if len(algorithm_ids) != 1:
        raise MatchingContractError(
            "Aggregate results must use one algorithm_id."
        )
    query_keys = {
        (result.sbom_document_id, result.component_id)
        for result in result_tuple
    }
    if len(query_keys) != len(result_tuple):
        raise MatchingContractError(
            "Aggregate results must contain unique component queries."
        )

    query_count = len(result_tuple)
    outcomes = Counter(result.outcome for result in result_tuple)
    return AggregateEvaluationResult(
        algorithm_id=next(iter(algorithm_ids)),
        query_count=query_count,
        top1_accuracy=(
            sum(result.worst_rank == 1 for result in result_tuple)
            / query_count
        ),
        recall_at_5=(
            sum(result.worst_rank <= 5 for result in result_tuple)
            / query_count
        ),
        recall_at_10=(
            sum(result.worst_rank <= 10 for result in result_tuple)
            / query_count
        ),
        mrr=(
            math.fsum(1.0 / result.worst_rank for result in result_tuple)
            / query_count
        ),
        unique_correct_count=outcomes[EvaluationOutcome.UNIQUE_CORRECT],
        correct_but_ambiguous_count=outcomes[
            EvaluationOutcome.CORRECT_BUT_AMBIGUOUS
        ],
        not_top_group_count=outcomes[EvaluationOutcome.NOT_TOP_GROUP],
        top_group_hit_count=sum(
            result.best_rank == 1 for result in result_tuple
        ),
        queries_with_tie=sum(
            result.tie_size > 1 for result in result_tuple
        ),
        maximum_tie_size=max(result.tie_size for result in result_tuple),
    )

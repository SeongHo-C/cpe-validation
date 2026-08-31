from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from cpe_analysis.matching import MatchingContractError, ScoreDirection

try:
    from rapidfuzz import __version__ as RAPIDFUZZ_VERSION
    from rapidfuzz.distance import Levenshtein as RapidFuzzLevenshtein
except ImportError:  # pragma: no cover - exercised only in an invalid runtime
    RAPIDFUZZ_VERSION = "not-installed"
    RapidFuzzLevenshtein = None


class LevenshteinBackendUnavailableError(MatchingContractError):
    """Raised when the validated integer-distance backend is unavailable."""


def reference_levenshtein_distance(left: str, right: str) -> int:
    """Small pure-Python unit-cost reference used for backend validation."""

    previous = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1]
                    + (left_character != right_character),
                )
            )
        previous = current
    return previous[-1]


@dataclass
class LengthNormalizedLevenshteinScorer:
    """Unit-cost Levenshtein distance divided by maximum raw length."""

    algorithm_id: ClassVar[str] = "length_normalized_levenshtein"
    algorithm_name: ClassVar[str] = "Length-normalized Levenshtein"
    score_direction: ClassVar[ScoreDirection] = (
        ScoreDirection.LOWER_IS_BETTER
    )
    score_call_count: int = 0
    distance_computation_count: int = 0

    @property
    def backend_name(self) -> str:
        return f"RapidFuzz {RAPIDFUZZ_VERSION} Levenshtein.distance"

    def integer_distance(self, left: str, right: str) -> int:
        if not isinstance(left, str) or not isinstance(right, str):
            raise MatchingContractError(
                "Levenshtein inputs must both be strings."
            )
        if RapidFuzzLevenshtein is None:
            raise LevenshteinBackendUnavailableError(
                "RapidFuzz is required for the Levenshtein benchmark."
            )
        self.distance_computation_count += 1
        return int(
            RapidFuzzLevenshtein.distance(
                left,
                right,
                weights=(1, 1, 1),
                processor=None,
            )
        )

    def score(self, query_text: str, candidate_text: str) -> float:
        self.score_call_count += 1
        if not isinstance(query_text, str) or not isinstance(
            candidate_text,
            str,
        ):
            raise MatchingContractError(
                "Levenshtein inputs must both be strings."
            )
        denominator = max(len(query_text), len(candidate_text))
        if denominator == 0:
            raise MatchingContractError(
                "Length-normalized Levenshtein is undefined for two "
                "empty strings."
            )
        return self.integer_distance(query_text, candidate_text) / denominator


def validate_levenshtein_backend() -> tuple[dict[str, object], ...]:
    """Validate the benchmark backend against standard reference fixtures."""

    fixtures = (
        ("", "a", 1),
        ("a", "", 1),
        ("a", "a", 0),
        ("a", "b", 1),
        ("kitten", "sitting", 3),
        ("curl", "curl", 0),
        ("libcurl4", "curl", 4),
    )
    scorer = LengthNormalizedLevenshteinScorer()
    results: list[dict[str, object]] = []
    for left, right, expected in fixtures:
        reference = reference_levenshtein_distance(left, right)
        backend = scorer.integer_distance(left, right)
        if reference != expected or backend != expected:
            raise MatchingContractError(
                "Levenshtein backend failed its reference fixture."
            )
        results.append(
            {
                "left": left,
                "right": right,
                "expected_integer_distance": expected,
                "reference_integer_distance": reference,
                "backend_integer_distance": backend,
            }
        )
    return tuple(results)


@dataclass
class RepeatedQueryScoreCache:
    """Cache one raw query's exact product scores without changing semantics."""

    scorer: LengthNormalizedLevenshteinScorer
    algorithm_id: ClassVar[str] = "length_normalized_levenshtein"
    algorithm_name: ClassVar[str] = "Length-normalized Levenshtein"
    score_direction: ClassVar[ScoreDirection] = (
        ScoreDirection.LOWER_IS_BETTER
    )
    _query_text: str | None = None
    _scores: dict[str, float] | None = None

    def score(self, query_text: str, candidate_text: str) -> float:
        if query_text != self._query_text:
            self._query_text = query_text
            self._scores = {}
        if self._scores is None:
            self._scores = {}
        if candidate_text not in self._scores:
            self._scores[candidate_text] = self.scorer.score(
                query_text,
                candidate_text,
            )
        return self._scores[candidate_text]

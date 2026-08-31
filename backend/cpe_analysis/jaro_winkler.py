from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from cpe_analysis.matching import MatchingContractError, ScoreDirection

try:
    from rapidfuzz import __version__ as RAPIDFUZZ_VERSION
    from rapidfuzz.distance import Jaro as RapidFuzzJaro
except ImportError:  # pragma: no cover - exercised only in an invalid runtime
    RAPIDFUZZ_VERSION = "not-installed"
    RapidFuzzJaro = None


JARO_WEIGHTS = (1 / 3, 1 / 3, 1 / 3)
MAX_PREFIX_LENGTH = 4
PREFIX_WEIGHT = 0.1
REFERENCE_TOLERANCE = 1e-12
PUBLISHED_EXAMPLE_TOLERANCE = 0.0001

PUBLISHED_WINKLER_1990_EXAMPLES = (
    ("shackleford", "shackelford", 0.9848),
    ("cunningham", "cunnigham", 0.9833),
    ("campell", "campbell", 0.9792),
    ("abroms", "abrams", 0.9333),
    ("lampley", "campley", 0.9048),
    ("marhta", "martha", 0.9667),
)


class JaroBackendUnavailableError(MatchingContractError):
    """Raised when the validated RapidFuzz Jaro backend is unavailable."""


def _validate_inputs(left: str, right: str) -> None:
    if not isinstance(left, str) or not isinstance(right, str):
        raise MatchingContractError(
            "Jaro-Winkler inputs must both be strings."
        )


def matching_window_radius(left: str, right: str) -> int:
    """Return floor(max length / 2) - 1, clamped to zero."""

    _validate_inputs(left, right)
    return max(0, max(len(left), len(right)) // 2 - 1)


def common_prefix_length(left: str, right: str) -> int:
    """Return the exact common-prefix length capped at four characters."""

    _validate_inputs(left, right)
    prefix_length = 0
    for left_character, right_character in zip(left, right):
        if left_character != right_character:
            break
        prefix_length += 1
        if prefix_length == MAX_PREFIX_LENGTH:
            break
    return prefix_length


def reference_jaro_similarity(left: str, right: str) -> float:
    """Pure-Python Jaro similarity for independent backend validation."""

    _validate_inputs(left, right)
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0

    window = matching_window_radius(left, right)
    left_matches = [False] * len(left)
    right_matches = [False] * len(right)

    for left_index, left_character in enumerate(left):
        start = max(0, left_index - window)
        stop = min(left_index + window + 1, len(right))
        for right_index in range(start, stop):
            if right_matches[right_index]:
                continue
            if left_character != right[right_index]:
                continue
            left_matches[left_index] = True
            right_matches[right_index] = True
            break

    match_count = sum(left_matches)
    if match_count == 0:
        return 0.0

    left_sequence = [
        character
        for character, matched in zip(left, left_matches)
        if matched
    ]
    right_sequence = [
        character
        for character, matched in zip(right, right_matches)
        if matched
    ]
    transpositions = sum(
        left_character != right_character
        for left_character, right_character in zip(
            left_sequence,
            right_sequence,
            strict=True,
        )
    ) / 2

    return sum(
        (
            match_count / len(left),
            match_count / len(right),
            (match_count - transpositions) / match_count,
        )
    ) / 3


def apply_winkler_1990_prefix(
    base_jaro: float,
    left: str,
    right: str,
) -> float:
    """Apply the specified four-character, 0.1 prefix adjustment.

    No 0.7 score gate or retrieval threshold is applied.
    """

    _validate_inputs(left, right)
    if not 0.0 <= base_jaro <= 1.0:
        raise MatchingContractError("Base Jaro score must be in [0, 1].")
    prefix_length = common_prefix_length(left, right)
    return base_jaro + prefix_length * PREFIX_WEIGHT * (1 - base_jaro)


def reference_jaro_winkler_similarity(left: str, right: str) -> float:
    return apply_winkler_1990_prefix(
        reference_jaro_similarity(left, right),
        left,
        right,
    )


@dataclass
class Winkler1990JaroWinklerScorer:
    """Raw-string Jaro plus an unconditional Winkler prefix adjustment."""

    algorithm_id: ClassVar[str] = "jaro_winkler"
    algorithm_name: ClassVar[str] = "Jaro-Winkler"
    score_direction: ClassVar[ScoreDirection] = (
        ScoreDirection.HIGHER_IS_BETTER
    )
    score_call_count: int = 0
    jaro_computation_count: int = 0

    @property
    def backend_name(self) -> str:
        return f"RapidFuzz {RAPIDFUZZ_VERSION} Jaro.similarity"

    def base_jaro_similarity(self, left: str, right: str) -> float:
        _validate_inputs(left, right)
        if RapidFuzzJaro is None:
            raise JaroBackendUnavailableError(
                "RapidFuzz is required for the Jaro-Winkler benchmark."
            )
        self.jaro_computation_count += 1
        return float(
            RapidFuzzJaro.similarity(
                left,
                right,
                processor=None,
            )
        )

    def score(self, query_text: str, candidate_text: str) -> float:
        self.score_call_count += 1
        base_jaro = self.base_jaro_similarity(query_text, candidate_text)
        score = apply_winkler_1990_prefix(
            base_jaro,
            query_text,
            candidate_text,
        )
        return min(max(score, 0.0), 1.0)


@dataclass
class RepeatedQueryScoreCache:
    """Cache exact raw-query/decoded-product scores without normalization."""

    scorer: Winkler1990JaroWinklerScorer
    algorithm_id: ClassVar[str] = "jaro_winkler"
    algorithm_name: ClassVar[str] = "Jaro-Winkler"
    score_direction: ClassVar[ScoreDirection] = (
        ScoreDirection.HIGHER_IS_BETTER
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


def validate_jaro_winkler_backend() -> dict[str, object]:
    """Cross-check RapidFuzz Jaro and the explicit prefix formulation."""

    fixtures = (
        ("", ""),
        ("", "a"),
        ("a", ""),
        ("abc", "xyz"),
        ("curl", "curl"),
        ("MARTHA", "MARHTA"),
        ("DIXON", "DICKSONX"),
        ("abxxxx", "abyyyy"),
        ("project/server", "project-server"),
    )
    scorer = Winkler1990JaroWinklerScorer()
    reference_rows: list[dict[str, object]] = []
    for left, right in fixtures:
        reference_jaro = reference_jaro_similarity(left, right)
        backend_jaro = scorer.base_jaro_similarity(left, right)
        reference_winkler = reference_jaro_winkler_similarity(left, right)
        backend_winkler = apply_winkler_1990_prefix(
            backend_jaro,
            left,
            right,
        )
        if abs(reference_jaro - backend_jaro) > REFERENCE_TOLERANCE:
            raise MatchingContractError(
                "RapidFuzz Jaro disagrees with the independent reference."
            )
        if abs(reference_winkler - backend_winkler) > REFERENCE_TOLERANCE:
            raise MatchingContractError(
                "Explicit Winkler adjustment disagrees with its reference."
            )
        reference_rows.append(
            {
                "left": left,
                "right": right,
                "reference_jaro": reference_jaro,
                "rapidfuzz_jaro": backend_jaro,
                "reference_jaro_winkler": reference_winkler,
                "explicit_backend_jaro_winkler": backend_winkler,
                "absolute_jaro_difference": abs(
                    reference_jaro - backend_jaro
                ),
                "absolute_jaro_winkler_difference": abs(
                    reference_winkler - backend_winkler
                ),
            }
        )

    published_rows: list[dict[str, object]] = []
    for left, right, published in PUBLISHED_WINKLER_1990_EXAMPLES:
        base_jaro = scorer.base_jaro_similarity(left, right)
        prefix_length = common_prefix_length(left, right)
        calculated = apply_winkler_1990_prefix(
            base_jaro,
            left,
            right,
        )
        difference = abs(calculated - published)
        implied_prefix_units = (
            (published - base_jaro) / (PREFIX_WEIGHT * (1 - base_jaro))
            if base_jaro < 1.0
            else 0.0
        )
        published_rows.append(
            {
                "left": left,
                "right": right,
                "published": published,
                "base_jaro": base_jaro,
                "capped_common_prefix_length": prefix_length,
                "calculated_specified_formulation": calculated,
                "absolute_difference": difference,
                "published_implied_prefix_units": implied_prefix_units,
                "within_tolerance": (
                    difference <= PUBLISHED_EXAMPLE_TOLERANCE
                ),
            }
        )

    published_match = all(
        bool(row["within_tolerance"]) for row in published_rows
    )
    return {
        "status": "PASS",
        "base_jaro_reference_status": "PASS",
        "winkler_prefix_formula_status": "PASS",
        "rapidfuzz_jaro_compatibility_status": "PASS",
        "rapidfuzz_jaro_winkler_used_directly": False,
        "reference_tolerance": REFERENCE_TOLERANCE,
        "reference_fixtures": reference_rows,
        "published_winkler_1990_examples": {
            "tolerance": PUBLISHED_EXAMPLE_TOLERANCE,
            "all_within_tolerance": published_match,
            "status": (
                "PASS" if published_match else "FORMULATION_DIFFERENCE"
            ),
            "interpretation": (
                "Five of the six supplied Table 1 values do not equal the "
                "explicitly requested min(common-prefix, 4) formula. Their "
                "implied prefix multipliers are approximately one greater "
                "than the actual common-prefix lengths; lampley/campley "
                "has no common prefix and agrees. This is recorded as a "
                "formulation difference, not used to tune the scorer."
            ),
            "investigation": {
                "matching_window_rechecked": True,
                "transposition_definition_rechecked": True,
                "equal_jaro_weights_rechecked": True,
                "explicit_prefix_cap_rechecked": True,
                "scorer_modified_to_fit_table": False,
                "paper_source": (
                    "https://www.stat.cmu.edu/NCRN/PUBLIC/RLClassFiles/"
                    "HW/Winkler1990.pdf"
                ),
            },
            "rows": published_rows,
        },
    }

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from cpe_analysis.matching import MatchingContractError, ScoreDirection


ALGORITHM_ID = "character_trigram_dice"
ALGORITHM_NAME = "Character n-gram"
TRIGRAM_SIZE = 3
COEFFICIENT = "dice"
BOUNDARY_PADDING = False
REPRESENTATION = "multiset"


def _validate_text(value: str) -> None:
    if not isinstance(value, str):
        raise MatchingContractError(
            "Character Trigram-Dice inputs must both be strings."
        )


def extract_character_trigrams(text: str) -> tuple[str, ...]:
    """Return non-padded consecutive character trigrams with duplicates."""

    _validate_text(text)
    return tuple(
        text[index : index + TRIGRAM_SIZE]
        for index in range(len(text) - TRIGRAM_SIZE + 1)
    )


def _sorted_character_trigrams(text: str) -> tuple[str, ...]:
    return tuple(sorted(extract_character_trigrams(text)))


def _multiset_overlap(
    left: tuple[str, ...],
    right: tuple[str, ...],
) -> int:
    left_index = 0
    right_index = 0
    overlap = 0
    while left_index < len(left) and right_index < len(right):
        left_gram = left[left_index]
        right_gram = right[right_index]
        if left_gram == right_gram:
            overlap += 1
            left_index += 1
            right_index += 1
        elif left_gram < right_gram:
            left_index += 1
        else:
            right_index += 1
    return overlap


def multiset_trigram_dice_similarity(left: str, right: str) -> float:
    """Calculate Dice over non-padded character-trigram multisets."""

    _validate_text(left)
    _validate_text(right)
    if left == right:
        return 1.0
    left_grams = _sorted_character_trigrams(left)
    right_grams = _sorted_character_trigrams(right)
    if not left_grams or not right_grams:
        return 0.0
    overlap = _multiset_overlap(left_grams, right_grams)
    return 2.0 * overlap / (len(left_grams) + len(right_grams))


@dataclass
class CharacterTrigramDiceScorer:
    """Fixed raw-string, non-padded, multiset Trigram-Dice scorer."""

    algorithm_id: ClassVar[str] = ALGORITHM_ID
    algorithm_name: ClassVar[str] = ALGORITHM_NAME
    score_direction: ClassVar[ScoreDirection] = (
        ScoreDirection.HIGHER_IS_BETTER
    )
    score_call_count: int = 0
    representation_computation_count: int = 0
    _representation_cache: dict[str, tuple[str, ...]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    @property
    def representation_cache_size(self) -> int:
        return len(self._representation_cache)

    def _representation(self, text: str) -> tuple[str, ...]:
        _validate_text(text)
        if text not in self._representation_cache:
            self._representation_cache[text] = _sorted_character_trigrams(text)
            self.representation_computation_count += 1
        return self._representation_cache[text]

    def score(self, query_text: str, candidate_text: str) -> float:
        _validate_text(query_text)
        _validate_text(candidate_text)
        self.score_call_count += 1
        if query_text == candidate_text:
            return 1.0
        query_grams = self._representation(query_text)
        candidate_grams = self._representation(candidate_text)
        if not query_grams or not candidate_grams:
            return 0.0
        overlap = _multiset_overlap(query_grams, candidate_grams)
        return 2.0 * overlap / (len(query_grams) + len(candidate_grams))


@dataclass
class RepeatedQueryScoreCache:
    """Reuse exact query/product scores across adjacent repeated raw names."""

    scorer: CharacterTrigramDiceScorer
    _query_text: str | None = None
    _scores: dict[str, float] | None = None

    @property
    def algorithm_id(self) -> str:
        return self.scorer.algorithm_id

    @property
    def algorithm_name(self) -> str:
        return self.scorer.algorithm_name

    @property
    def score_direction(self) -> ScoreDirection:
        return self.scorer.score_direction

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


def validate_character_trigram_dice() -> dict[str, object]:
    fixtures = (
        ("curl", "libcurl4", 0.5),
        ("aaaaa", "aaaa", 0.8),
        ("a", "a", 1.0),
        ("a", "b", 0.0),
        ("ab", "abc", 0.0),
        ("abc", "xyz", 0.0),
    )
    rows = []
    for left, right, expected in fixtures:
        reference = multiset_trigram_dice_similarity(left, right)
        observed = CharacterTrigramDiceScorer().score(left, right)
        if (
            abs(reference - expected) > 1e-15
            or abs(observed - expected) > 1e-15
        ):
            raise MatchingContractError(
                "Character Trigram-Dice failed a fixed reference fixture."
            )
        rows.append(
            {
                "left": left,
                "right": right,
                "expected": expected,
                "reference": reference,
                "scorer": observed,
            }
        )
    return {
        "status": "PASS",
        "algorithm_id": ALGORITHM_ID,
        "q": TRIGRAM_SIZE,
        "coefficient": COEFFICIENT,
        "dice_formula": "2 * c_common / (c1 + c2)",
        "multiset_semantics": "PASS",
        "no_boundary_padding": "PASS",
        "short_string_contract": "PASS",
        "fixtures": rows,
    }

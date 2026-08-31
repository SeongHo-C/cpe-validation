from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import ClassVar, Iterable

from cpe_analysis.matching import MatchingContractError, ScoreDirection


ALGORITHM_ID = "ratcliff_obershelp"
ALGORITHM_NAME = "Ratcliff–Obershelp"
REFERENCE = "Ratcliff & Metzener 1988"
SCORE_FORMULA = "2M / (len(s1) + len(s2))"
EQUAL_ANCHOR_POLICY = "first_encountered"
REFERENCE_TOLERANCE = 1e-12


@dataclass(frozen=True, order=True)
class CommonMatch:
    left_start: int
    right_start: int
    size: int


def _validate_inputs(left: str, right: str) -> None:
    if not isinstance(left, str) or not isinstance(right, str):
        raise MatchingContractError(
            "Ratcliff–Obershelp inputs must both be strings."
        )


def longest_common_contiguous_match(left: str, right: str) -> CommonMatch:
    """Return the longest substring match, preferring earliest left/right.

    The dynamic program computes contiguous suffix lengths. Equal-size maxima
    are compared by their start positions, which implements the fixed scan
    policy: left string first, then right string, both left to right.
    """

    _validate_inputs(left, right)
    if not left or not right:
        return CommonMatch(0, 0, 0)

    previous = [0] * (len(right) + 1)
    best = CommonMatch(0, 0, 0)
    for left_index, left_character in enumerate(left, start=1):
        current = [0] * (len(right) + 1)
        for right_index, right_character in enumerate(right, start=1):
            if left_character != right_character:
                continue
            size = previous[right_index - 1] + 1
            current[right_index] = size
            candidate = CommonMatch(
                left_index - size,
                right_index - size,
                size,
            )
            if size > best.size or (
                size == best.size
                and size > 0
                and (
                    candidate.left_start,
                    candidate.right_start,
                )
                < (best.left_start, best.right_start)
            ):
                best = candidate
        previous = current
    return best


def reference_matched_character_count(left: str, right: str) -> int:
    """Canonical recursive longest-common-contiguous-substring reference."""

    _validate_inputs(left, right)
    match = longest_common_contiguous_match(left, right)
    if match.size == 0:
        return 0
    left_end = match.left_start + match.size
    right_end = match.right_start + match.size
    return (
        match.size
        + reference_matched_character_count(
            left[: match.left_start],
            right[: match.right_start],
        )
        + reference_matched_character_count(left[left_end:], right[right_end:])
    )


def _similarity_from_match_count(
    left: str,
    right: str,
    matched_characters: int,
) -> float:
    total_length = len(left) + len(right)
    if total_length == 0:
        return 1.0
    return 2.0 * matched_characters / total_length


def reference_ratcliff_obershelp_similarity(left: str, right: str) -> float:
    return _similarity_from_match_count(
        left,
        right,
        reference_matched_character_count(left, right),
    )


def sequence_matcher_matched_character_count(left: str, right: str) -> int:
    """Validated backend primitive; ``SequenceMatcher.ratio`` is not used."""

    _validate_inputs(left, right)
    matcher = SequenceMatcher(None, left, right, autojunk=False)
    return sum(match.size for match in matcher.get_matching_blocks())


@dataclass
class RatcliffObershelpScorer:
    """Exact raw-string Ratcliff–Obershelp scorer with a validated backend."""

    algorithm_id: ClassVar[str] = ALGORITHM_ID
    algorithm_name: ClassVar[str] = ALGORITHM_NAME
    score_direction: ClassVar[ScoreDirection] = (
        ScoreDirection.HIGHER_IS_BETTER
    )
    score_call_count: int = 0
    matched_block_computation_count: int = 0
    _matcher: SequenceMatcher[str] = field(
        default_factory=lambda: SequenceMatcher(
            None,
            "",
            "",
            autojunk=False,
        ),
        init=False,
        repr=False,
    )

    @property
    def backend_name(self) -> str:
        return (
            "validated difflib.SequenceMatcher.get_matching_blocks "
            "(autojunk=False; ratio not used)"
        )

    def score(self, query_text: str, candidate_text: str) -> float:
        _validate_inputs(query_text, candidate_text)
        self.score_call_count += 1
        if query_text == candidate_text:
            return 1.0
        if not query_text or not candidate_text:
            return 0.0
        self._matcher.set_seqs(query_text, candidate_text)
        matched = sum(
            match.size for match in self._matcher.get_matching_blocks()
        )
        self.matched_block_computation_count += 1
        return _similarity_from_match_count(
            query_text,
            candidate_text,
            matched,
        )


@dataclass
class RepeatedQueryScoreCache:
    """Reuse exact query/product scores across adjacent repeated raw names."""

    scorer: RatcliffObershelpScorer
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


def _fixture_rows() -> list[dict[str, object]]:
    fixtures = (
        ("curl", "curl", 1.0),
        ("abc", "XYZ", 0.0),
        ("libopenssl", "openssl", 14 / 17),
        ("abcXYZdef", "abc123def", 12 / 18),
        ("", "", 1.0),
        ("", "curl", 0.0),
        ("curl", "", 0.0),
        ("aba", "bab", 4 / 6),
    )
    rows: list[dict[str, object]] = []
    for left, right, expected in fixtures:
        reference = reference_ratcliff_obershelp_similarity(left, right)
        backend_matches = sequence_matcher_matched_character_count(left, right)
        backend = _similarity_from_match_count(left, right, backend_matches)
        scorer = RatcliffObershelpScorer().score(left, right)
        if any(
            abs(value - expected) > REFERENCE_TOLERANCE
            for value in (reference, backend, scorer)
        ):
            raise MatchingContractError(
                "Ratcliff–Obershelp failed a fixed reference fixture."
            )
        rows.append(
            {
                "left": left,
                "right": right,
                "expected": expected,
                "reference": reference,
                "backend": backend,
                "scorer": scorer,
                "matched_characters": backend_matches,
            }
        )
    return rows


def _exhaustive_backend_validation() -> dict[str, object]:
    strings = [""]
    for length in range(1, 7):
        strings.extend(
            "".join(characters)
            for characters in itertools.product("ab", repeat=length)
        )
    mismatch_count = 0
    for left in strings:
        for right in strings:
            if reference_matched_character_count(
                left,
                right,
            ) != sequence_matcher_matched_character_count(left, right):
                mismatch_count += 1
    if mismatch_count:
        raise MatchingContractError(
            "SequenceMatcher blocks disagree with the canonical reference."
        )
    return {
        "alphabet": "ab",
        "maximum_length": 6,
        "string_count": len(strings),
        "pair_count": len(strings) ** 2,
        "mismatch_count": mismatch_count,
        "status": "PASS",
    }


def actual_sample_backend_validation(
    query_names: Iterable[str],
    products: Iterable[str],
    *,
    product_sample_size: int = 128,
) -> dict[str, object]:
    unique_queries = tuple(sorted(set(query_names)))
    unique_products = tuple(sorted(set(products)))
    if not unique_queries or not unique_products:
        raise MatchingContractError(
            "Actual-sample validation requires non-empty inputs."
        )
    if len(unique_products) <= product_sample_size:
        sampled_products = unique_products
    else:
        indexes = {
            round(index * (len(unique_products) - 1) / (product_sample_size - 1))
            for index in range(product_sample_size)
        }
        sampled_products = tuple(unique_products[index] for index in sorted(indexes))
    mismatch_count = 0
    for query_text in unique_queries:
        for candidate_text in sampled_products:
            if reference_matched_character_count(
                query_text,
                candidate_text,
            ) != sequence_matcher_matched_character_count(
                query_text,
                candidate_text,
            ):
                mismatch_count += 1
    if mismatch_count:
        raise MatchingContractError(
            "Actual-sample backend validation found a mismatch."
        )
    return {
        "query_count": len(unique_queries),
        "sampled_product_count": len(sampled_products),
        "pair_count": len(unique_queries) * len(sampled_products),
        "mismatch_count": mismatch_count,
        "selection": "evenly spaced over sorted distinct decoded products",
        "status": "PASS",
    }


def validate_ratcliff_obershelp_backend() -> dict[str, object]:
    fixtures = _fixture_rows()
    equal_anchor = longest_common_contiguous_match("aba", "bab")
    expected_anchor = CommonMatch(0, 1, 2)
    if equal_anchor != expected_anchor:
        raise MatchingContractError(
            "Equal-length anchor selection violated the fixed traversal rule."
        )

    symmetry_pairs = (
        ("curl", "curl"),
        ("libopenssl", "openssl"),
        ("abcXYZdef", "abc123def"),
        ("tide", "diet"),
    )
    symmetry_rows = []
    asymmetric_pairs = 0
    for left, right in symmetry_pairs:
        forward = RatcliffObershelpScorer().score(left, right)
        reverse = RatcliffObershelpScorer().score(right, left)
        equal = abs(forward - reverse) <= REFERENCE_TOLERANCE
        asymmetric_pairs += not equal
        symmetry_rows.append(
            {
                "left": left,
                "right": right,
                "forward": forward,
                "reverse": reverse,
                "equal": equal,
            }
        )

    return {
        "status": "PASS",
        "reference": REFERENCE,
        "formula": SCORE_FORMULA,
        "contiguous_match": True,
        "recursive_left_right": True,
        "equal_anchor_policy": EQUAL_ANCHOR_POLICY,
        "sequence_matcher_used_directly": False,
        "sequence_matcher_ratio_used": False,
        "sequence_matcher_matching_blocks_used": True,
        "optimized_backend": (
            "difflib.SequenceMatcher.get_matching_blocks; autojunk=False"
        ),
        "optimized_backend_compatibility": "PASS",
        "reference_tolerance": REFERENCE_TOLERANCE,
        "reference_fixtures": fixtures,
        "equal_anchor_fixture": {
            "left": "aba",
            "right": "bab",
            "expected": {
                "left_start": expected_anchor.left_start,
                "right_start": expected_anchor.right_start,
                "size": expected_anchor.size,
            },
            "observed": {
                "left_start": equal_anchor.left_start,
                "right_start": equal_anchor.right_start,
                "size": equal_anchor.size,
            },
            "status": "PASS",
        },
        "exhaustive_small_corpus": _exhaustive_backend_validation(),
        "symmetry_diagnostic": {
            "status": (
                "ORDER_SENSITIVE_EQUAL_ANCHOR_OBSERVED"
                if asymmetric_pairs
                else "SYMMETRIC_ON_FIXTURES"
            ),
            "asymmetric_pair_count": asymmetric_pairs,
            "scorer_modified_to_force_symmetry": False,
            "fixtures": symmetry_rows,
        },
    }

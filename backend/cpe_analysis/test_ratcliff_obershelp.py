from __future__ import annotations

import random
from dataclasses import fields
from difflib import SequenceMatcher
from unittest.mock import patch

from django.test import SimpleTestCase

from cpe_analysis.matching import (
    CandidateFamily,
    EvaluationOutcome,
    FamilyRetrievalQuery,
    ScoreDirection,
    aggregate_results,
    evaluate_query,
)
from cpe_analysis.ratcliff_obershelp import (
    ALGORITHM_ID,
    ALGORITHM_NAME,
    CommonMatch,
    RatcliffObershelpScorer,
    RepeatedQueryScoreCache,
    actual_sample_backend_validation,
    longest_common_contiguous_match,
    reference_matched_character_count,
    reference_ratcliff_obershelp_similarity,
    sequence_matcher_matched_character_count,
    validate_ratcliff_obershelp_backend,
)


def family(
    family_id: str,
    decoded_product: str,
    *,
    serialized_product: str | None = None,
) -> CandidateFamily:
    return CandidateFamily(
        family_id=family_id,
        part="a",
        vendor=f"vendor-{family_id}",
        serialized_product=serialized_product or decoded_product,
        decoded_product=decoded_product,
        source="ACTIVE_DICTIONARY",
        searchable=True,
    )


def query(target_family_id: str, text: str) -> FamilyRetrievalQuery:
    return FamilyRetrievalQuery(
        component_id=1,
        sbom_document_id=24,
        query_text=text,
        gt_family_id=target_family_id,
        gt_part="a",
        gt_vendor="unused-vendor",
        gt_product="unused-product",
    )


class RatcliffObershelpScorerTests(SimpleTestCase):
    def test_longest_common_contiguous_substring(self) -> None:
        self.assertEqual(
            longest_common_contiguous_match("abcXYZdef", "abc123def"),
            CommonMatch(0, 0, 3),
        )
        self.assertEqual(
            longest_common_contiguous_match("prefix", "suffix"),
            CommonMatch(3, 3, 3),
        )

    def test_recursive_left_and_right_blocks(self) -> None:
        self.assertEqual(
            reference_matched_character_count(
                "abcXYZdef",
                "abc123def",
            ),
            6,
        )
        self.assertEqual(
            reference_ratcliff_obershelp_similarity(
                "abcXYZdef",
                "abc123def",
            ),
            2 / 3,
        )

    def test_formula_identity_no_match_and_substring(self) -> None:
        scorer = RatcliffObershelpScorer()

        self.assertEqual(scorer.score("curl", "curl"), 1.0)
        self.assertEqual(scorer.score("abc", "XYZ"), 0.0)
        self.assertEqual(
            scorer.score("libopenssl", "openssl"),
            14 / 17,
        )

    def test_equal_anchor_uses_first_left_then_first_right(self) -> None:
        self.assertEqual(
            longest_common_contiguous_match("aba", "bab"),
            CommonMatch(0, 1, 2),
        )
        self.assertEqual(
            RatcliffObershelpScorer().score("aba", "bab"),
            2 / 3,
        )

    def test_empty_string_contract(self) -> None:
        scorer = RatcliffObershelpScorer()

        self.assertEqual(scorer.score("", ""), 1.0)
        self.assertEqual(scorer.score("", "curl"), 0.0)
        self.assertEqual(scorer.score("curl", ""), 0.0)

    def test_score_range_and_declared_direction(self) -> None:
        scorer = RatcliffObershelpScorer()
        fixtures = (
            ("abc", "XYZ"),
            ("curl", "curl"),
            ("libopenssl", "openssl"),
            ("abcXYZdef", "abc123def"),
            ("tide", "diet"),
        )

        for left, right in fixtures:
            with self.subTest(left=left, right=right):
                score = scorer.score(left, right)
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 1.0)
        self.assertEqual(ALGORITHM_ID, "ratcliff_obershelp")
        self.assertEqual(ALGORITHM_NAME, "Ratcliff–Obershelp")
        self.assertEqual(
            RatcliffObershelpScorer.score_direction,
            ScoreDirection.HIGHER_IS_BETTER,
        )

    def test_no_semantic_preprocessing(self) -> None:
        scorer = RatcliffObershelpScorer()

        self.assertLess(scorer.score("Curl", "curl"), 1.0)
        self.assertLess(scorer.score("curl-client", "curl_client"), 1.0)
        self.assertLess(scorer.score("libcurl", "curl"), 1.0)
        self.assertLess(scorer.score(" curl ", "curl"), 1.0)

    def test_validated_backend_does_not_call_sequence_matcher_ratio(self) -> None:
        with patch.object(
            SequenceMatcher,
            "ratio",
            side_effect=AssertionError("ratio must not be used"),
        ):
            self.assertEqual(
                RatcliffObershelpScorer().score(
                    "abcXYZdef",
                    "abc123def",
                ),
                2 / 3,
            )

    def test_backend_matches_reference_and_validation_passes(self) -> None:
        self.assertEqual(
            sequence_matcher_matched_character_count("tide", "diet"),
            reference_matched_character_count("tide", "diet"),
        )
        validation = validate_ratcliff_obershelp_backend()

        self.assertEqual(validation["status"], "PASS")
        self.assertEqual(
            validation["optimized_backend_compatibility"],
            "PASS",
        )
        self.assertFalse(validation["sequence_matcher_used_directly"])
        self.assertFalse(validation["sequence_matcher_ratio_used"])
        self.assertEqual(
            validation["exhaustive_small_corpus"]["pair_count"],
            16_129,
        )

    def test_symmetry_diagnostic_preserves_order_sensitive_semantics(self) -> None:
        scorer = RatcliffObershelpScorer()

        self.assertEqual(scorer.score("tide", "diet"), 0.25)
        self.assertEqual(scorer.score("diet", "tide"), 0.5)
        self.assertEqual(
            validate_ratcliff_obershelp_backend()["symmetry_diagnostic"][
                "status"
            ],
            "ORDER_SENSITIVE_EQUAL_ANCHOR_OBSERVED",
        )

    def test_actual_sample_backend_validation(self) -> None:
        result = actual_sample_backend_validation(
            ("curl", "openssl"),
            ("curl", "libcurl", "openssl", "open_ssl"),
            product_sample_size=4,
        )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["pair_count"], 8)

    def test_repeated_query_cache_preserves_raw_inputs(self) -> None:
        base = RatcliffObershelpScorer()
        cached = RepeatedQueryScoreCache(base)

        cached.score("curl", "curl")
        cached.score("curl", "curl")
        self.assertEqual(base.score_call_count, 1)
        cached.score("curl", "libcurl")
        self.assertEqual(base.score_call_count, 2)
        cached.score("Curl", "curl")
        self.assertEqual(base.score_call_count, 3)


class RatcliffObershelpCommonContractTests(SimpleTestCase):
    def test_decoded_candidate_and_raw_query_are_used(self) -> None:
        result = evaluate_query(
            query("gt", "project/server"),
            (
                family(
                    "gt",
                    "project/server",
                    serialized_product=r"project\/server",
                ),
                family("other", "project-server"),
            ),
            RatcliffObershelpScorer(),
        )

        self.assertEqual(result.target_score, 1.0)
        self.assertEqual(result.outcome, EvaluationOutcome.UNIQUE_CORRECT)

    def test_tie_handling_and_worst_rank_metrics(self) -> None:
        results = (
            evaluate_query(
                query("gt", "curl"),
                (
                    family("gt", "curl"),
                    family("same", "curl"),
                    family("lower", "other"),
                ),
                RatcliffObershelpScorer(),
            ),
            evaluate_query(
                FamilyRetrievalQuery(
                    component_id=2,
                    sbom_document_id=24,
                    query_text="curl",
                    gt_family_id="gt",
                    gt_part="a",
                    gt_vendor="unused",
                    gt_product="unused",
                ),
                (family("gt", "curl"), family("other", "other")),
                RatcliffObershelpScorer(),
            ),
        )

        self.assertEqual(results[0].tie_size, 2)
        self.assertEqual(results[0].worst_rank, 2)
        self.assertEqual(
            results[0].outcome,
            EvaluationOutcome.CORRECT_BUT_AMBIGUOUS,
        )
        self.assertEqual(aggregate_results(results).top1_accuracy, 0.5)

    def test_candidate_order_independence(self) -> None:
        candidates = [
            family("better", "curl"),
            family("gt", "curx"),
            family("tie", "cury"),
            family("lower", "unrelated"),
        ]
        shuffled = candidates.copy()
        random.Random(20260901).shuffle(shuffled)
        results = [
            evaluate_query(
                query("gt", "curl"),
                order,
                RatcliffObershelpScorer(),
            )
            for order in (candidates, list(reversed(candidates)), shuffled)
        ]

        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

    def test_query_contract_has_no_version_feature(self) -> None:
        field_names = {field.name for field in fields(FamilyRetrievalQuery)}

        self.assertFalse(
            field_names
            & {
                "version",
                "sbom_version",
                "verified_software_version",
                "cpe_version",
                "cpe_update",
            }
        )

    def test_gt_metadata_does_not_affect_scores(self) -> None:
        candidates = (family("gt", "curl"), family("other", "curly"))
        original = query("gt", "curl")
        changed = FamilyRetrievalQuery(
            component_id=original.component_id,
            sbom_document_id=original.sbom_document_id,
            query_text=original.query_text,
            gt_family_id=original.gt_family_id,
            gt_part="o",
            gt_vendor="changed",
            gt_product="changed",
        )

        first = evaluate_query(
            original,
            candidates,
            RatcliffObershelpScorer(),
        )
        second = evaluate_query(
            changed,
            candidates,
            RatcliffObershelpScorer(),
        )

        self.assertEqual(first.target_score, second.target_score)
        self.assertEqual(first.worst_rank, second.worst_rank)

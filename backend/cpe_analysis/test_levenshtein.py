from __future__ import annotations

import random
from dataclasses import fields

from django.test import SimpleTestCase

from cpe_analysis.levenshtein import (
    LengthNormalizedLevenshteinScorer,
    RepeatedQueryScoreCache,
    reference_levenshtein_distance,
    validate_levenshtein_backend,
)
from cpe_analysis.matching import (
    CandidateFamily,
    EvaluationOutcome,
    FamilyRetrievalQuery,
    MatchingContractError,
    ScoreDirection,
    aggregate_results,
    evaluate_query,
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


def query(
    target_family_id: str,
    query_text: str,
    *,
    component_id: int = 1,
) -> FamilyRetrievalQuery:
    return FamilyRetrievalQuery(
        component_id=component_id,
        sbom_document_id=24,
        query_text=query_text,
        gt_family_id=target_family_id,
        gt_part="a",
        gt_vendor="target-vendor",
        gt_product="target-product",
    )


class LengthNormalizedLevenshteinScorerTests(SimpleTestCase):
    def test_backend_integer_distance_matches_reference(self) -> None:
        scorer = LengthNormalizedLevenshteinScorer()
        fixtures = (
            ("", "a", 1),
            ("a", "", 1),
            ("a", "a", 0),
            ("a", "b", 1),
            ("kitten", "sitting", 3),
            ("curl", "curl", 0),
            ("libcurl4", "curl", 4),
        )

        for left, right, expected in fixtures:
            with self.subTest(left=left, right=right):
                self.assertEqual(
                    reference_levenshtein_distance(left, right),
                    expected,
                )
                self.assertEqual(
                    scorer.integer_distance(left, right),
                    expected,
                )
        self.assertEqual(len(validate_levenshtein_backend()), len(fixtures))

    def test_length_normalization_uses_maximum_raw_length(self) -> None:
        scorer = LengthNormalizedLevenshteinScorer()

        self.assertEqual(scorer.score("same", "same"), 0)
        self.assertEqual(scorer.score("a", "b"), 1)
        self.assertEqual(scorer.score("", "a"), 1)
        self.assertEqual(scorer.score("a", ""), 1)
        self.assertEqual(scorer.score("ab", "a"), 1 / 2)
        self.assertEqual(scorer.score("a", "ab"), 1 / 2)
        self.assertEqual(scorer.score("kitten", "sitting"), 3 / 7)
        self.assertEqual(scorer.score("libcurl4", "curl"), 4 / 8)

    def test_two_empty_strings_are_a_contract_violation(self) -> None:
        with self.assertRaisesMessage(
            MatchingContractError,
            "undefined for two empty strings",
        ):
            LengthNormalizedLevenshteinScorer().score("", "")

    def test_metadata_declares_lower_is_better(self) -> None:
        scorer = LengthNormalizedLevenshteinScorer()

        self.assertEqual(
            scorer.algorithm_id,
            "length_normalized_levenshtein",
        )
        self.assertEqual(
            scorer.score_direction,
            ScoreDirection.LOWER_IS_BETTER,
        )

    def test_raw_query_is_not_normalized(self) -> None:
        scorer = LengthNormalizedLevenshteinScorer()

        self.assertEqual(scorer.score(" Curl ", " Curl "), 0)
        self.assertGreater(scorer.score(" Curl ", "curl"), 0)

    def test_query_schema_has_no_version_feature(self) -> None:
        names = {field.name for field in fields(FamilyRetrievalQuery)}

        self.assertFalse(
            names
            & {
                "version",
                "sbom_version",
                "verified_software_version",
                "cpe_version",
                "cpe_update",
            }
        )

    def test_repeated_raw_query_cache_only_reuses_exact_input(self) -> None:
        base = LengthNormalizedLevenshteinScorer()
        cached = RepeatedQueryScoreCache(base)

        self.assertEqual(cached.score("curl", "curl"), 0)
        self.assertEqual(cached.score("curl", "curl"), 0)
        self.assertEqual(base.distance_computation_count, 1)
        cached.score("curl", "curly")
        self.assertEqual(base.distance_computation_count, 2)
        cached.score("Curl", "curl")
        self.assertEqual(base.distance_computation_count, 3)


class LevenshteinCommonContractIntegrationTests(SimpleTestCase):
    def test_unique_correct_and_decoded_candidate_usage(self) -> None:
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
            LengthNormalizedLevenshteinScorer(),
        )

        self.assertEqual(result.target_score, 0)
        self.assertEqual(result.best_rank, 1)
        self.assertEqual(result.worst_rank, 1)
        self.assertEqual(result.outcome, EvaluationOutcome.UNIQUE_CORRECT)

    def test_top_tie_preserves_family_multiplicity(self) -> None:
        result = evaluate_query(
            query("gt", "curl"),
            (
                family("gt", "curl"),
                family("same-product-family", "curl"),
                family("other", "curly"),
            ),
            LengthNormalizedLevenshteinScorer(),
        )

        self.assertEqual(result.better_count, 0)
        self.assertEqual(result.tie_size, 2)
        self.assertEqual(result.best_rank, 1)
        self.assertEqual(result.worst_rank, 2)
        self.assertTrue(result.top_group_hit)
        self.assertEqual(
            result.outcome,
            EvaluationOutcome.CORRECT_BUT_AMBIGUOUS,
        )
        self.assertFalse(result.top1_success)

    def test_not_top_group_and_worst_rank_metrics(self) -> None:
        results = (
            evaluate_query(
                query("gt", "curl", component_id=1),
                (
                    family("better", "curl"),
                    family("gt", "curx"),
                    family("tie", "cury"),
                ),
                LengthNormalizedLevenshteinScorer(),
            ),
            evaluate_query(
                query("gt", "curl", component_id=2),
                (family("gt", "curl"), family("other", "curly")),
                LengthNormalizedLevenshteinScorer(),
            ),
        )

        self.assertEqual(results[0].best_rank, 2)
        self.assertEqual(results[0].worst_rank, 3)
        self.assertEqual(results[0].outcome, EvaluationOutcome.NOT_TOP_GROUP)
        aggregate = aggregate_results(results)
        self.assertEqual(aggregate.top1_accuracy, 1 / 2)
        self.assertEqual(aggregate.recall_at_5, 1)
        self.assertEqual(aggregate.recall_at_10, 1)
        self.assertEqual(aggregate.mrr, (1 / 3 + 1) / 2)

    def test_order_independence_with_real_scorer(self) -> None:
        candidates = [
            family("better", "curl"),
            family("gt", "curx"),
            family("tie", "cury"),
            family("lower", "unrelated"),
        ]
        shuffled = candidates.copy()
        random.Random(20260831).shuffle(shuffled)
        orders = (candidates, list(reversed(candidates)), shuffled)

        results = [
            evaluate_query(
                query("gt", "curl"),
                order,
                LengthNormalizedLevenshteinScorer(),
            )
            for order in orders
        ]

        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

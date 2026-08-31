from __future__ import annotations

import random
from dataclasses import fields

from django.test import SimpleTestCase

from cpe_analysis.jaro_winkler import (
    JARO_WEIGHTS,
    MAX_PREFIX_LENGTH,
    PREFIX_WEIGHT,
    RepeatedQueryScoreCache,
    Winkler1990JaroWinklerScorer,
    apply_winkler_1990_prefix,
    common_prefix_length,
    matching_window_radius,
    reference_jaro_similarity,
    reference_jaro_winkler_similarity,
    validate_jaro_winkler_backend,
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


class Winkler1990JaroWinklerScorerTests(SimpleTestCase):
    def test_reference_jaro_matches_rapidfuzz_backend(self) -> None:
        validation = validate_jaro_winkler_backend()

        self.assertEqual(validation["base_jaro_reference_status"], "PASS")
        self.assertEqual(
            validation["rapidfuzz_jaro_compatibility_status"],
            "PASS",
        )
        for row in validation["reference_fixtures"]:
            self.assertLessEqual(row["absolute_jaro_difference"], 1e-12)
            self.assertLessEqual(
                row["absolute_jaro_winkler_difference"],
                1e-12,
            )

    def test_equal_jaro_weights_window_and_transposition(self) -> None:
        self.assertEqual(JARO_WEIGHTS, (1 / 3, 1 / 3, 1 / 3))
        self.assertEqual(matching_window_radius("a", "a"), 0)
        self.assertEqual(matching_window_radius("abcde", "abc"), 1)
        self.assertAlmostEqual(
            reference_jaro_similarity("MARTHA", "MARHTA"),
            0.9444444444444445,
        )

    def test_prefix_parameters_and_maximum_length(self) -> None:
        self.assertEqual(MAX_PREFIX_LENGTH, 4)
        self.assertEqual(PREFIX_WEIGHT, 0.1)
        self.assertEqual(common_prefix_length("abcdeX", "abcdeY"), 4)
        base = reference_jaro_similarity("abcdeX", "abcdeY")
        self.assertEqual(
            reference_jaro_winkler_similarity("abcdeX", "abcdeY"),
            base + 4 * 0.1 * (1 - base),
        )

    def test_no_point_seven_prefix_gate(self) -> None:
        left = "abxxxx"
        right = "abyyyy"
        base = reference_jaro_similarity(left, right)

        self.assertLess(base, 0.7)
        self.assertGreater(
            Winkler1990JaroWinklerScorer().score(left, right),
            base,
        )

    def test_prefix_effect_for_equal_base_jaro(self) -> None:
        prefix_pair = ("abxxxx", "abyyyy")
        no_prefix_pair = ("xxabxx", "yyabyy")
        prefix_base = reference_jaro_similarity(*prefix_pair)
        no_prefix_base = reference_jaro_similarity(*no_prefix_pair)

        self.assertEqual(prefix_base, no_prefix_base)
        self.assertGreater(
            reference_jaro_winkler_similarity(*prefix_pair),
            reference_jaro_winkler_similarity(*no_prefix_pair),
        )

    def test_empty_identical_no_match_symmetry_and_range(self) -> None:
        scorer = Winkler1990JaroWinklerScorer()
        self.assertEqual(scorer.score("", ""), 1.0)
        self.assertEqual(scorer.score("", "curl"), 0.0)
        self.assertEqual(scorer.score("curl", ""), 0.0)
        self.assertEqual(scorer.score("curl", "curl"), 1.0)
        self.assertEqual(scorer.score("abc", "xyz"), 0.0)
        fixtures = (
            ("MARTHA", "MARHTA"),
            ("DIXON", "DICKSONX"),
            ("project/server", "project-server"),
            ("a", "longer"),
        )
        for left, right in fixtures:
            with self.subTest(left=left, right=right):
                forward = scorer.score(left, right)
                reverse = scorer.score(right, left)
                self.assertAlmostEqual(forward, reverse, places=15)
                self.assertGreaterEqual(forward, 0.0)
                self.assertLessEqual(forward, 1.0)

    def test_published_examples_are_checked_without_changing_formula(self) -> None:
        published = validate_jaro_winkler_backend()[
            "published_winkler_1990_examples"
        ]

        self.assertEqual(published["status"], "FORMULATION_DIFFERENCE")
        self.assertFalse(published["all_within_tolerance"])
        self.assertEqual(len(published["rows"]), 6)
        lampley = next(
            row for row in published["rows"] if row["left"] == "lampley"
        )
        self.assertTrue(lampley["within_tolerance"])

    def test_metadata_and_input_validation(self) -> None:
        scorer = Winkler1990JaroWinklerScorer()
        self.assertEqual(scorer.algorithm_id, "jaro_winkler")
        self.assertEqual(
            scorer.score_direction,
            ScoreDirection.HIGHER_IS_BETTER,
        )
        with self.assertRaisesMessage(
            MatchingContractError,
            "must both be strings",
        ):
            scorer.score("curl", None)  # type: ignore[arg-type]

    def test_no_preprocessing(self) -> None:
        scorer = Winkler1990JaroWinklerScorer()

        self.assertEqual(scorer.score(" Curl ", " Curl "), 1.0)
        self.assertLess(scorer.score(" Curl ", "curl"), 1.0)
        self.assertLess(scorer.score("libcurl", "curl"), 1.0)

    def test_repeated_query_cache_only_reuses_exact_inputs(self) -> None:
        base = Winkler1990JaroWinklerScorer()
        cached = RepeatedQueryScoreCache(base)

        cached.score("curl", "curl")
        cached.score("curl", "curl")
        self.assertEqual(base.jaro_computation_count, 1)
        cached.score("curl", "curly")
        self.assertEqual(base.jaro_computation_count, 2)
        cached.score("Curl", "curl")
        self.assertEqual(base.jaro_computation_count, 3)


class JaroWinklerCommonContractIntegrationTests(SimpleTestCase):
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
            Winkler1990JaroWinklerScorer(),
        )

        self.assertEqual(result.target_score, 1.0)
        self.assertEqual(result.worst_rank, 1)
        self.assertEqual(result.outcome, EvaluationOutcome.UNIQUE_CORRECT)

    def test_tie_handling_and_worst_rank_metrics(self) -> None:
        results = (
            evaluate_query(
                query("gt", "curl", component_id=1),
                (
                    family("gt", "curl"),
                    family("same", "curl"),
                    family("lower", "curly"),
                ),
                Winkler1990JaroWinklerScorer(),
            ),
            evaluate_query(
                query("gt", "curl", component_id=2),
                (family("gt", "curl"), family("other", "curly")),
                Winkler1990JaroWinklerScorer(),
            ),
        )

        self.assertEqual(results[0].tie_size, 2)
        self.assertEqual(results[0].worst_rank, 2)
        self.assertEqual(
            results[0].outcome,
            EvaluationOutcome.CORRECT_BUT_AMBIGUOUS,
        )
        aggregate = aggregate_results(results)
        self.assertEqual(aggregate.top1_accuracy, 1 / 2)
        self.assertEqual(aggregate.recall_at_5, 1)

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
                Winkler1990JaroWinklerScorer(),
            )
            for order in orders
        ]

        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

    def test_query_contract_has_no_version_feature(self) -> None:
        field_names = {item.name for item in fields(FamilyRetrievalQuery)}

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

    def test_gt_metadata_does_not_affect_score_calls(self) -> None:
        candidates = (family("gt", "curl"), family("other", "curly"))
        original = query("gt", "curl")
        changed = FamilyRetrievalQuery(
            component_id=original.component_id,
            sbom_document_id=original.sbom_document_id,
            query_text=original.query_text,
            gt_family_id=original.gt_family_id,
            gt_part="o",
            gt_vendor="unused-vendor",
            gt_product="unused-product",
        )
        scorers = (
            Winkler1990JaroWinklerScorer(),
            Winkler1990JaroWinklerScorer(),
        )

        results = (
            evaluate_query(original, candidates, scorers[0]),
            evaluate_query(changed, candidates, scorers[1]),
        )

        self.assertEqual(
            results[0].target_score,
            results[1].target_score,
        )
        self.assertEqual(
            scorers[0].jaro_computation_count,
            scorers[1].jaro_computation_count,
        )

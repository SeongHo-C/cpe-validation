from __future__ import annotations

import random
from collections import Counter
from dataclasses import fields

from django.test import SimpleTestCase

from cpe_analysis.character_ngram import (
    ALGORITHM_ID,
    BOUNDARY_PADDING,
    COEFFICIENT,
    REPRESENTATION,
    TRIGRAM_SIZE,
    CharacterTrigramDiceScorer,
    RepeatedQueryScoreCache,
    extract_character_trigrams,
    multiset_trigram_dice_similarity,
    validate_character_trigram_dice,
)
from cpe_analysis.matching import (
    CandidateFamily,
    EvaluationOutcome,
    FamilyRetrievalQuery,
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


class CharacterTrigramDiceScorerTests(SimpleTestCase):
    def test_trigram_extraction_is_non_padded(self) -> None:
        self.assertEqual(
            extract_character_trigrams("curl"),
            ("cur", "url"),
        )
        self.assertFalse(BOUNDARY_PADDING)
        self.assertNotIn("##c", extract_character_trigrams("curl"))

    def test_multiset_duplicate_preservation(self) -> None:
        grams = extract_character_trigrams("aaaaa")

        self.assertEqual(grams, ("aaa", "aaa", "aaa"))
        self.assertEqual(Counter(grams), Counter({"aaa": 3}))
        self.assertEqual(
            multiset_trigram_dice_similarity("aaaaa", "aaaa"),
            0.8,
        )

    def test_fixed_trigram_dice_fixture(self) -> None:
        self.assertEqual(
            extract_character_trigrams("libcurl4"),
            ("lib", "ibc", "bcu", "cur", "url", "rl4"),
        )
        self.assertEqual(
            multiset_trigram_dice_similarity("curl", "libcurl4"),
            0.5,
        )

    def test_short_string_identity_and_non_identity(self) -> None:
        scorer = CharacterTrigramDiceScorer()

        self.assertEqual(scorer.score("", ""), 1.0)
        self.assertEqual(scorer.score("", "a"), 0.0)
        self.assertEqual(scorer.score("a", "a"), 1.0)
        self.assertEqual(scorer.score("a", "b"), 0.0)
        self.assertEqual(scorer.score("ab", "abc"), 0.0)

    def test_symmetry_no_overlap_and_score_range(self) -> None:
        scorer = CharacterTrigramDiceScorer()
        fixtures = (("abc", "xyz"), ("curl", "libcurl4"), ("aaaaa", "aaaa"))

        self.assertEqual(scorer.score("abc", "xyz"), 0.0)
        for left, right in fixtures:
            with self.subTest(left=left, right=right):
                forward = scorer.score(left, right)
                reverse = scorer.score(right, left)
                self.assertEqual(forward, reverse)
                self.assertGreaterEqual(forward, 0.0)
                self.assertLessEqual(forward, 1.0)

    def test_fixed_metadata_has_no_runtime_q_or_coefficient(self) -> None:
        scorer_fields = {field.name for field in fields(CharacterTrigramDiceScorer)}

        self.assertEqual(ALGORITHM_ID, "character_trigram_dice")
        self.assertEqual(TRIGRAM_SIZE, 3)
        self.assertEqual(COEFFICIENT, "dice")
        self.assertEqual(REPRESENTATION, "multiset")
        self.assertFalse(scorer_fields & {"q", "n", "coefficient"})
        self.assertEqual(
            CharacterTrigramDiceScorer.score_direction,
            ScoreDirection.HIGHER_IS_BETTER,
        )

    def test_no_preprocessing(self) -> None:
        scorer = CharacterTrigramDiceScorer()

        self.assertEqual(scorer.score(" Curl ", " Curl "), 1.0)
        self.assertLess(scorer.score(" Curl ", "curl"), 1.0)
        self.assertLess(scorer.score("libcurl", "curl"), 1.0)

    def test_reference_validation_passes(self) -> None:
        validation = validate_character_trigram_dice()

        self.assertEqual(validation["status"], "PASS")
        self.assertEqual(validation["q"], 3)
        self.assertEqual(validation["coefficient"], "dice")

    def test_repeated_query_cache_preserves_exact_raw_inputs(self) -> None:
        base = CharacterTrigramDiceScorer()
        cached = RepeatedQueryScoreCache(base)

        cached.score("curl", "curl")
        cached.score("curl", "curl")
        self.assertEqual(base.score_call_count, 1)
        cached.score("curl", "curly")
        self.assertEqual(base.score_call_count, 2)
        cached.score("Curl", "curl")
        self.assertEqual(base.score_call_count, 3)


class CharacterTrigramDiceCommonContractTests(SimpleTestCase):
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
            CharacterTrigramDiceScorer(),
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
                CharacterTrigramDiceScorer(),
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
                CharacterTrigramDiceScorer(),
            ),
        )

        self.assertEqual(results[0].tie_size, 2)
        self.assertEqual(results[0].worst_rank, 2)
        self.assertEqual(
            results[0].outcome,
            EvaluationOutcome.CORRECT_BUT_AMBIGUOUS,
        )
        self.assertEqual(aggregate_results(results).top1_accuracy, 0.5)

    def test_order_independence(self) -> None:
        candidates = [
            family("better", "curl"),
            family("gt", "curx"),
            family("tie", "cury"),
            family("lower", "unrelated"),
        ]
        shuffled = candidates.copy()
        random.Random(20260831).shuffle(shuffled)
        results = [
            evaluate_query(
                query("gt", "curl"),
                order,
                CharacterTrigramDiceScorer(),
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
            CharacterTrigramDiceScorer(),
        )
        second = evaluate_query(
            changed,
            candidates,
            CharacterTrigramDiceScorer(),
        )

        self.assertEqual(first.target_score, second.target_score)
        self.assertEqual(first.worst_rank, second.worst_rank)

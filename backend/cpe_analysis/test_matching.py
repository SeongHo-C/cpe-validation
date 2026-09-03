from __future__ import annotations

import csv
import json
import random
from dataclasses import dataclass, field, fields
from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings
from django.test import SimpleTestCase

from cpe_analysis.matching import (
    AggregateEvaluationResult,
    CandidateFamily,
    CandidateUniverseError,
    CpeProductDecodeError,
    EvaluationOutcome,
    FamilyRetrievalQuery,
    QueryEvaluationResult,
    ScoreDirection,
    aggregate_results,
    decode_cpe_product,
    evaluate_query,
    load_candidate_universe,
    scores_tie,
)


@dataclass
class MappingScorer:
    scores: dict[str, float]
    score_direction: ScoreDirection
    algorithm_id: str = "test-scorer"
    algorithm_name: str = "Test Scorer"
    calls: list[tuple[str, str]] = field(default_factory=list)

    def score(self, query_text: str, candidate_text: str) -> float:
        self.calls.append((query_text, candidate_text))
        return self.scores[candidate_text]


def candidate(
    family_id: str,
    product: str,
    *,
    source: str = "ACTIVE_DICTIONARY",
    searchable: bool = True,
) -> CandidateFamily:
    return CandidateFamily(
        family_id=family_id,
        part="a",
        vendor=f"vendor-{family_id}",
        serialized_product=product,
        decoded_product=product,
        source=source,
        searchable=searchable,
    )


def query(
    target_family_id: str = "gt",
    *,
    component_id: int = 1,
    query_text: str = "Raw SBOM_Name",
) -> FamilyRetrievalQuery:
    return FamilyRetrievalQuery(
        component_id=component_id,
        sbom_document_id=24,
        query_text=query_text,
        gt_family_id=target_family_id,
        gt_part="a",
        gt_vendor="ground-truth-vendor",
        gt_product="ground_truth_product",
    )


class CpeProductDecoderTests(SimpleTestCase):
    def test_decodes_required_formatted_string_cases_once(self) -> None:
        cases = {
            "ordinary_product": "ordinary_product",
            r"project\/product": "project/product",
            r"product\(server\)": "product(server)",
            r"c\+\+": "c++",
            r"path\\name": "path\\name",
            r"a\/b\+\(c\)\\d": "a/b+(c)\\d",
        }

        for serialized, expected in cases.items():
            with self.subTest(serialized=serialized):
                self.assertEqual(
                    decode_cpe_product(serialized),
                    expected,
                )

    def test_dangling_or_invalid_escape_is_not_repaired(self) -> None:
        with self.assertRaises(CpeProductDecodeError):
            decode_cpe_product("product" + "\\")
        with self.assertRaises(CpeProductDecodeError):
            decode_cpe_product(r"product\q")
        with self.assertRaises(CpeProductDecodeError):
            decode_cpe_product("product/name")


class TieAwareQueryEvaluationTests(SimpleTestCase):
    def test_score_direction_is_respected(self) -> None:
        candidates = (
            candidate("a", "A"),
            candidate("gt", "GT"),
            candidate("c", "C"),
        )
        cases = (
            (
                ScoreDirection.LOWER_IS_BETTER,
                {"A": 0.1, "GT": 0.2, "C": 0.3},
            ),
            (
                ScoreDirection.HIGHER_IS_BETTER,
                {"A": 0.9, "GT": 0.8, "C": 0.7},
            ),
        )

        for direction, scores in cases:
            with self.subTest(direction=direction):
                result = evaluate_query(
                    query(),
                    candidates,
                    MappingScorer(scores, direction),
                )
                self.assertEqual(result.better_count, 1)
                self.assertEqual(result.best_rank, 2)
                self.assertEqual(result.worst_rank, 2)

    def test_unique_correct(self) -> None:
        result = evaluate_query(
            query(),
            (candidate("gt", "GT"), candidate("other", "Other")),
            MappingScorer(
                {"GT": 1.0, "Other": 0.5},
                ScoreDirection.HIGHER_IS_BETTER,
            ),
        )

        self.assertEqual(result.better_count, 0)
        self.assertEqual(result.tie_size, 1)
        self.assertEqual(result.best_rank, 1)
        self.assertEqual(result.worst_rank, 1)
        self.assertTrue(result.top_group_hit)
        self.assertEqual(result.outcome, EvaluationOutcome.UNIQUE_CORRECT)
        self.assertTrue(result.top1_success)

    def test_two_way_top_tie_is_ambiguous_and_not_primary_top1(self) -> None:
        scorer = MappingScorer(
            {"Same": 1.0, "Lower": 0.5},
            ScoreDirection.HIGHER_IS_BETTER,
        )
        result = evaluate_query(
            query(),
            (
                candidate("gt", "Same"),
                candidate("same-family", "Same"),
                candidate("lower", "Lower"),
            ),
            scorer,
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
        self.assertTrue(result.recall_at_5_success)
        self.assertEqual(
            scorer.calls.count(("Raw SBOM_Name", "Same")),
            1,
        )

    def test_three_way_top_tie_uses_worst_rank_for_rr(self) -> None:
        result = evaluate_query(
            query(),
            (
                candidate("gt", "GT"),
                candidate("tie-a", "A"),
                candidate("tie-b", "B"),
                candidate("lower", "Lower"),
            ),
            MappingScorer(
                {"GT": 1.0, "A": 1.0, "B": 1.0, "Lower": 0.0},
                ScoreDirection.HIGHER_IS_BETTER,
            ),
        )

        self.assertEqual(result.better_count, 0)
        self.assertEqual(result.tie_size, 3)
        self.assertEqual(result.best_rank, 1)
        self.assertEqual(result.worst_rank, 3)
        self.assertEqual(result.reciprocal_rank, 1 / 3)
        self.assertEqual(
            result.outcome,
            EvaluationOutcome.CORRECT_BUT_AMBIGUOUS,
        )

    def test_non_top_tie_preserves_best_and_worst_rank(self) -> None:
        result = evaluate_query(
            query(),
            (
                candidate("better", "Better"),
                candidate("gt", "GT"),
                candidate("tie-a", "Tie A"),
                candidate("tie-b", "Tie B"),
            ),
            MappingScorer(
                {
                    "Better": 1.0,
                    "GT": 0.5,
                    "Tie A": 0.5,
                    "Tie B": 0.5,
                },
                ScoreDirection.HIGHER_IS_BETTER,
            ),
        )

        self.assertEqual(result.better_count, 1)
        self.assertEqual(result.tie_size, 3)
        self.assertEqual(result.best_rank, 2)
        self.assertEqual(result.worst_rank, 4)
        self.assertFalse(result.top_group_hit)
        self.assertEqual(result.outcome, EvaluationOutcome.NOT_TOP_GROUP)

    def test_absolute_tolerance_for_both_score_directions(self) -> None:
        self.assertTrue(scores_tie(0.5, 0.5000000000005))
        self.assertFalse(scores_tie(0.5, 0.500000000002))

        cases = (
            (
                ScoreDirection.HIGHER_IS_BETTER,
                {"GT": 0.5, "Near": 0.5000000000005, "Far": 0.500000000002},
            ),
            (
                ScoreDirection.LOWER_IS_BETTER,
                {"GT": 0.5, "Near": 0.4999999999995, "Far": 0.499999999998},
            ),
        )
        candidates = (
            candidate("gt", "GT"),
            candidate("near", "Near"),
            candidate("far", "Far"),
        )
        for direction, scores in cases:
            with self.subTest(direction=direction):
                result = evaluate_query(
                    query(),
                    candidates,
                    MappingScorer(scores, direction),
                )
                self.assertEqual(result.better_count, 1)
                self.assertEqual(result.tie_size, 2)
                self.assertEqual(result.best_rank, 2)
                self.assertEqual(result.worst_rank, 3)

    def test_candidate_order_does_not_change_logical_result(self) -> None:
        candidates = [
            candidate("better", "Better"),
            candidate("gt", "GT"),
            candidate("tie", "Tie"),
            candidate("lower", "Lower"),
        ]
        scores = {"Better": 0.9, "GT": 0.8, "Tie": 0.8, "Lower": 0.1}
        shuffled = candidates.copy()
        random.Random(20260831).shuffle(shuffled)
        orders = (candidates, list(reversed(candidates)), shuffled)

        results = [
            evaluate_query(
                query(),
                order,
                MappingScorer(scores, ScoreDirection.HIGHER_IS_BETTER),
            )
            for order in orders
        ]

        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

    def test_raw_query_is_passed_without_normalization(self) -> None:
        raw_query = "  LibExample_Package  "
        scorer = MappingScorer(
            {"decoded/product": 1.0},
            ScoreDirection.HIGHER_IS_BETTER,
        )

        result = evaluate_query(
            query(query_text=raw_query),
            (candidate("gt", "decoded/product"),),
            scorer,
        )

        self.assertEqual(result.query_text, raw_query)
        self.assertEqual(scorer.calls, [(raw_query, "decoded/product")])

    def test_non_searchable_candidate_is_rejected(self) -> None:
        with self.assertRaisesMessage(
            ValueError,
            "Evaluation candidates must all be searchable families.",
        ):
            evaluate_query(
                query(),
                (
                    candidate("gt", "GT"),
                    candidate("other", "Other", searchable=False),
                ),
                MappingScorer(
                    {"GT": 1.0, "Other": 0.0},
                    ScoreDirection.HIGHER_IS_BETTER,
                ),
            )

    def test_gt_metadata_and_candidate_source_do_not_affect_scoring(self) -> None:
        candidates = (
            candidate("gt", "GT", source="NVD_CONFIGURATION_ONLY"),
            candidate("other", "Other", source="ACTIVE_DICTIONARY"),
        )
        score_map = {"GT": 0.8, "Other": 0.7}
        original_query = query()
        changed_gt_metadata = FamilyRetrievalQuery(
            component_id=original_query.component_id,
            sbom_document_id=original_query.sbom_document_id,
            query_text=original_query.query_text,
            gt_family_id=original_query.gt_family_id,
            gt_part="o",
            gt_vendor="unused-vendor",
            gt_product="unused-product",
        )
        scorers = (
            MappingScorer(score_map, ScoreDirection.HIGHER_IS_BETTER),
            MappingScorer(score_map, ScoreDirection.HIGHER_IS_BETTER),
        )

        results = (
            evaluate_query(original_query, candidates, scorers[0]),
            evaluate_query(changed_gt_metadata, candidates, scorers[1]),
        )

        self.assertEqual(scorers[0].calls, scorers[1].calls)
        self.assertEqual(results[0].target_score, results[1].target_score)
        self.assertEqual(results[0].worst_rank, results[1].worst_rank)

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


class AggregateEvaluationTests(SimpleTestCase):
    def result(self, component_id: int, worst_rank: int) -> QueryEvaluationResult:
        best_rank = worst_rank
        outcome = (
            EvaluationOutcome.UNIQUE_CORRECT
            if worst_rank == 1
            else EvaluationOutcome.NOT_TOP_GROUP
        )
        return QueryEvaluationResult(
            component_id=component_id,
            sbom_document_id=24,
            query_text=f"query-{component_id}",
            gt_family_id=f"gt-{component_id}",
            gt_part="a",
            gt_vendor="vendor",
            gt_product="product",
            algorithm_id="test-scorer",
            target_score=1.0,
            better_count=best_rank - 1,
            tie_size=1,
            best_rank=best_rank,
            worst_rank=worst_rank,
            top_group_hit=best_rank == 1,
            outcome=outcome,
            top1_success=worst_rank == 1,
            recall_at_5_success=worst_rank <= 5,
            recall_at_10_success=worst_rank <= 10,
            reciprocal_rank=1 / worst_rank,
        )

    def test_worst_rank_primary_metrics(self) -> None:
        aggregate = aggregate_results(
            self.result(index, rank)
            for index, rank in enumerate((1, 2, 5, 11), start=1)
        )

        self.assertIsInstance(aggregate, AggregateEvaluationResult)
        self.assertEqual(aggregate.query_count, 4)
        self.assertEqual(aggregate.top1_accuracy, 1 / 4)
        self.assertEqual(aggregate.recall_at_5, 3 / 4)
        self.assertEqual(aggregate.recall_at_10, 3 / 4)
        self.assertAlmostEqual(
            aggregate.mrr,
            (1 + 1 / 2 + 1 / 5 + 1 / 11) / 4,
        )
        self.assertEqual(aggregate.unique_correct_count, 1)
        self.assertEqual(aggregate.not_top_group_count, 3)
        self.assertEqual(aggregate.queries_with_tie, 0)
        self.assertEqual(aggregate.maximum_tie_size, 1)


class CandidateUniverseLoaderTests(SimpleTestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.universe_directory = (
            self.root / "data/cpe_candidate_universe"
        )
        self.universe_directory.mkdir(parents=True)

    def write_universe(self) -> None:
        candidate_path = self.universe_directory / "candidate_families.csv"
        with candidate_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "family_id",
                    "part",
                    "vendor",
                    "product",
                    "source",
                    "searchable",
                ],
            )
            writer.writeheader()
            writer.writerows(
                [
                    {
                        "family_id": "one",
                        "part": "a",
                        "vendor": "example",
                        "product": r"product\/server",
                        "source": "ACTIVE_DICTIONARY",
                        "searchable": "True",
                    },
                    {
                        "family_id": "two",
                        "part": "a",
                        "vendor": "example",
                        "product": "*",
                        "source": "NVD_CONFIGURATION_ONLY",
                        "searchable": "False",
                    },
                ]
            )
        manifest = {
            "schema_version": 1,
            "family_definition": ["part", "vendor", "product"],
            "candidate_file": "candidate_families.csv",
            "search_condition": "searchable == true",
            "candidate_sources": [
                "ACTIVE_DICTIONARY",
                "NVD_CONFIGURATION_ONLY",
            ],
            "cpe_snapshot": "test-cpe",
            "nvd_snapshot": "test-nvd",
            "total_candidate_families": 2,
            "searchable_candidate_families": 1,
        }
        (self.universe_directory / "manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

    def test_loader_validates_counts_and_decodes_product(self) -> None:
        self.write_universe()

        universe = load_candidate_universe(
            self.root,
            enforce_research_contract=False,
        )

        self.assertEqual(universe.validation.total_families, 2)
        self.assertEqual(universe.validation.searchable_families, 1)
        self.assertEqual(universe.validation.decode_successes, 2)
        self.assertEqual(universe.validation.decode_failures, 0)
        self.assertEqual(len(universe.searchable_families), 1)
        self.assertEqual(
            universe.searchable_families[0].serialized_product,
            r"product\/server",
        )
        self.assertEqual(
            universe.searchable_families[0].decoded_product,
            "product/server",
        )


class FrozenCandidateUniverseValidationTests(SimpleTestCase):
    def test_all_frozen_candidate_products_decode(self) -> None:
        universe = load_candidate_universe(settings.REPOSITORY_ROOT)

        self.assertEqual(universe.validation.total_families, 181_493)
        self.assertEqual(universe.validation.searchable_families, 181_484)
        self.assertEqual(universe.validation.decode_successes, 181_493)
        self.assertEqual(universe.validation.decode_failures, 0)

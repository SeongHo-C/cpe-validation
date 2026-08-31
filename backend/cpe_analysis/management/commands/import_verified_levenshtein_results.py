from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from cpe_analysis.result_importer import (
    BenchmarkResultImportError,
    VERIFIED_LEVENSHTEIN_IDENTITY,
    import_benchmark_results,
)


DEFAULT_ARTIFACT_DIRECTORY = Path(
    "/tmp/cpe-family-levenshtein-evaluation"
)


class Command(BaseCommand):
    help = (
        "Validate and atomically persist the verified Length-normalized "
        "Levenshtein family-retrieval result."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--artifact-directory",
            type=Path,
            default=DEFAULT_ARTIFACT_DIRECTORY,
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Validate all inputs without inserting database rows.",
        )

    def handle(self, *args, **options) -> None:
        artifact_directory = options["artifact_directory"].resolve()
        try:
            result = import_benchmark_results(
                artifact_directory,
                expected_identity=VERIFIED_LEVENSHTEIN_IDENTITY,
                dry_run=options["dry_run"],
            )
        except BenchmarkResultImportError as error:
            raise CommandError(str(error)) from error

        metrics = result.metrics
        payload = {
            "algorithm_id": VERIFIED_LEVENSHTEIN_IDENTITY.algorithm_id,
            "artifact_directory": str(artifact_directory),
            "atomic_import": not result.dry_run,
            "candidate_family_count": (
                VERIFIED_LEVENSHTEIN_IDENTITY.candidate_family_count
            ),
            "component_coverage": result.component_coverage,
            "dry_run": result.dry_run,
            "inserted_query_results": result.inserted_query_results,
            "metrics": {
                "ambiguous_count": metrics.ambiguous_count,
                "mrr": metrics.mrr,
                "not_top_group_count": metrics.not_top_group_count,
                "query_count": metrics.query_count,
                "recall_at_10": metrics.recall_at_10,
                "recall_at_10_count": metrics.recall_at_10_count,
                "recall_at_5": metrics.recall_at_5,
                "recall_at_5_count": metrics.recall_at_5_count,
                "top1_accuracy": metrics.top1_accuracy,
                "top1_count": metrics.top1_count,
                "top_group_hit_count": metrics.top_group_hit_count,
                "unique_correct_count": metrics.unique_correct_count,
            },
            "run_id": result.run_id,
        }
        self.stdout.write(json.dumps(payload, sort_keys=True))

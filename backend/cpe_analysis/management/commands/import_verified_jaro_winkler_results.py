from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from cpe_analysis.result_importer import (
    BenchmarkResultImportError,
    ExistingAnalysisRunError,
    VERIFIED_JARO_WINKLER_IDENTITY,
    import_benchmark_results,
)


DEFAULT_ARTIFACT_DIRECTORY = Path(
    "/tmp/cpe-family-jaro-winkler-evaluation"
)
JARO_WINKLER_PARAMETERS = {
    "max_prefix_length": 4,
    "prefix_weight": 0.1,
    "prefix_gate": None,
}


class Command(BaseCommand):
    help = (
        "Validate and atomically persist the verified Jaro-Winkler "
        "family-retrieval result."
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
        required_source_files = (
            "per_query_results.csv",
            "aggregate_metrics.json",
        )
        if any(
            not (artifact_directory / name).is_file()
            for name in required_source_files
        ):
            raise CommandError("VERIFIED_JARO_WINKLER_ARTIFACT_MISSING")

        try:
            result = import_benchmark_results(
                artifact_directory,
                expected_identity=VERIFIED_JARO_WINKLER_IDENTITY,
                run_parameters=JARO_WINKLER_PARAMETERS,
                dry_run=options["dry_run"],
            )
        except ExistingAnalysisRunError as error:
            raise CommandError(
                f"DUPLICATE_JARO_WINKLER_IMPORT_BLOCKED: {error}"
            ) from error
        except BenchmarkResultImportError as error:
            raise CommandError(str(error)) from error

        metrics = result.metrics
        payload = {
            "algorithm_id": VERIFIED_JARO_WINKLER_IDENTITY.algorithm_id,
            "artifact_directory": str(artifact_directory),
            "atomic_import": not result.dry_run,
            "candidate_family_count": (
                VERIFIED_JARO_WINKLER_IDENTITY.candidate_family_count
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
            "parameters": JARO_WINKLER_PARAMETERS,
            "run_id": result.run_id,
        }
        self.stdout.write(json.dumps(payload, sort_keys=True))

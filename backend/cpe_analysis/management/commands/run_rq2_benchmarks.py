from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from cpe_analysis.rq2_runner import (
    CANDIDATE_UNIVERSE_RELATIVE_PATH,
    GROUND_TRUTH_RELATIVE_PATH,
    RQ2RunnerError,
    run_rq2_benchmarks,
)


class Command(BaseCommand):
    help = "Run all four final RQ2 candidate-family retrieval benchmarks."

    def add_arguments(self, parser) -> None:
        repository_root = Path(settings.REPOSITORY_ROOT)
        parser.add_argument(
            "--ground-truth",
            type=Path,
            default=repository_root / GROUND_TRUTH_RELATIVE_PATH,
        )
        parser.add_argument(
            "--candidate-universe",
            type=Path,
            default=repository_root / CANDIDATE_UNIVERSE_RELATIVE_PATH,
        )
        parser.add_argument(
            "--output-directory",
            type=Path,
            required=True,
            help="New directory for summary.json and per_query_results.csv.",
        )

    def handle(self, *args, **options) -> None:
        try:
            summary = run_rq2_benchmarks(
                ground_truth_csv=options["ground_truth"],
                candidate_csv=options["candidate_universe"],
                output_directory=options["output_directory"],
                progress=self.stdout.write,
            )
        except RQ2RunnerError as error:
            raise CommandError(str(error)) from error
        self.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2))

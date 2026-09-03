from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ObjectDoesNotExist

from cpe_analysis.rq3_runner import (
    GROUND_TRUTH_RELATIVE_PATH,
    NVD_SNAPSHOT_ID,
    RQ3RunnerError,
    run_rq3_matching,
)


class Command(BaseCommand):
    help = "Run the fixed-snapshot RQ3 Original-vs-Ground-Truth CVE matching."

    def add_arguments(self, parser) -> None:
        repository_root = Path(settings.REPOSITORY_ROOT)
        parser.add_argument(
            "--ground-truth",
            type=Path,
            default=repository_root / GROUND_TRUTH_RELATIVE_PATH,
        )
        parser.add_argument(
            "--nvd-snapshot",
            default=NVD_SNAPSHOT_ID,
        )
        parser.add_argument(
            "--output-directory",
            type=Path,
            required=True,
            help="New or empty directory for summary.json and result CSV files.",
        )
        parser.add_argument(
            "--analyze-added-causes",
            action="store_true",
            help=(
                "Replay GT MATCH witnesses and also write the minimal ADDED "
                "cause results."
            ),
        )

    def handle(self, *args, **options) -> None:
        try:
            summary = run_rq3_matching(
                ground_truth_csv=options["ground_truth"],
                output_directory=options["output_directory"],
                nvd_snapshot_id=options["nvd_snapshot"],
                analyze_added_causes=options["analyze_added_causes"],
                progress=self.stdout.write,
            )
        except (RQ3RunnerError, ObjectDoesNotExist) as error:
            raise CommandError(str(error)) from error
        self.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2))

from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from cpe_analysis.candidate_universe_generator import (
    DEFAULT_CPE_SNAPSHOT,
    DEFAULT_NVD_SNAPSHOT,
    CandidateUniverseGenerationError,
    generate_candidate_universe,
)


class Command(BaseCommand):
    help = (
        "Generate the CPE product-family candidate universe from fixed "
        "CPE Dictionary and NVD snapshots."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output-directory",
            type=Path,
            required=True,
            help=(
                "New output directory for candidate_families.csv and "
                "manifest.json. Existing outputs are never overwritten."
            ),
        )
        parser.add_argument(
            "--cpe-snapshot",
            default=DEFAULT_CPE_SNAPSHOT,
        )
        parser.add_argument(
            "--nvd-snapshot",
            default=DEFAULT_NVD_SNAPSHOT,
        )

    def handle(self, *args, **options) -> None:
        try:
            result = generate_candidate_universe(
                options["output_directory"],
                cpe_snapshot=options["cpe_snapshot"],
                nvd_snapshot=options["nvd_snapshot"],
            )
        except CandidateUniverseGenerationError as error:
            raise CommandError(str(error)) from error
        self.stdout.write(
            json.dumps(result.to_dict(), indent=2, sort_keys=True)
        )

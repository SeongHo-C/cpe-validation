from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError, CommandParser

from sboms.unitronics_ground_truth_human_validation import (
    UnitronicsHumanValidationError,
    load_wpa_candidate,
    refresh_wpa_supplicant_card,
)


class Command(BaseCommand):
    help = (
        "Refresh the approved wpa_supplicant card in the static Unitronics "
        "Ground Truth human-validation HTML without changing other cards."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--candidate-dir", type=Path, required=True)
        parser.add_argument("--source-html", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)

    def handle(self, *args, **options) -> None:
        candidate_directory: Path = options["candidate_dir"]
        source_html: Path = options["source_html"]
        output: Path = options["output"]
        if output.exists():
            raise CommandError(f"Refusing to modify existing HTML: {output}")
        try:
            row, manifest = load_wpa_candidate(candidate_directory)
            rendered = refresh_wpa_supplicant_card(
                source_html.read_text(encoding="utf-8"),
                row,
                manifest,
            )
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        except (OSError, ValueError, UnitronicsHumanValidationError) as error:
            raise CommandError(str(error)) from error
        self.stdout.write(self.style.SUCCESS(f"Wrote refreshed HTML: {output}"))

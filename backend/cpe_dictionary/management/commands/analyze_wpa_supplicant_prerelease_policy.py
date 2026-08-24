from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, transaction

from cpe_dictionary.snapshot_selection import select_cpe_dictionary_snapshot
from cpe_dictionary.wpa_supplicant_prerelease_policy import (
    SNAPSHOT_ID,
    WpaPrereleasePolicyError,
    build_wpa_prerelease_policy,
    default_output_directory,
    finalize_validation,
    write_wpa_prerelease_policy,
)
from sboms.models import ComponentCpeGroundTruth


class Command(BaseCommand):
    help = (
        "Analyze wpa_supplicant prerelease CPE modeling in the fixed "
        "Dictionary snapshot using a read-only transaction."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--output-dir", type=Path)

    @staticmethod
    def _set_read_only() -> None:
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")

    def handle(self, *args, **options) -> None:
        output_directory = options["output_dir"] or default_output_directory()
        if not output_directory.is_absolute():
            from django.conf import settings

            output_directory = settings.REPOSITORY_ROOT / output_directory
        if output_directory.exists():
            raise CommandError(
                f"Refusing to modify existing policy directory: {output_directory}"
            )
        try:
            with transaction.atomic():
                self._set_read_only()
                ground_truth_count_before = ComponentCpeGroundTruth.objects.count()
                analysis = build_wpa_prerelease_policy(
                    select_cpe_dictionary_snapshot(SNAPSHOT_ID),
                    ground_truth_count_before=ground_truth_count_before,
                )
            with transaction.atomic():
                self._set_read_only()
                ground_truth_count_after = ComponentCpeGroundTruth.objects.count()
            finalize_validation(
                analysis,
                ground_truth_count_after=ground_truth_count_after,
            )
            paths = write_wpa_prerelease_policy(analysis, output_directory)
        except (OSError, ValueError, WpaPrereleasePolicyError) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(
            self.style.SUCCESS(
                f"Wrote {len(paths)} read-only prerelease policy artifacts"
            )
        )
        for path in paths:
            self.stdout.write(str(path))

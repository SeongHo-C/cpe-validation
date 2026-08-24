from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, transaction

from cpe_dictionary.snapshot_selection import select_cpe_dictionary_snapshot
from nvd_cve.snapshot_selection import select_nvd_cve_snapshot
from sboms.models import ComponentCpeGroundTruth
from sboms.unitronics_ground_truth_cpe_audit import (
    CPE_SNAPSHOT_ID,
    NVD_SNAPSHOT_ID,
    UnitronicsCpeAuditError,
    build_unitronics_cpe_audit,
    default_output_directory,
    finalize_validation,
    write_unitronics_cpe_audit,
)


class Command(BaseCommand):
    help = (
        "Independently audit exactly 48 existing Unitronics CPE-bearing "
        "candidates in a read-only transaction."
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
                f"Refusing to modify existing audit directory: {output_directory}"
            )
        try:
            with transaction.atomic():
                self._set_read_only()
                analysis = build_unitronics_cpe_audit(
                    cpe_snapshot=select_cpe_dictionary_snapshot(CPE_SNAPSHOT_ID),
                    nvd_snapshot=select_nvd_cve_snapshot(NVD_SNAPSHOT_ID),
                )
            with transaction.atomic():
                self._set_read_only()
                ground_truth_count_after = ComponentCpeGroundTruth.objects.count()
            finalize_validation(
                analysis,
                ground_truth_count_after=ground_truth_count_after,
            )
            paths = write_unitronics_cpe_audit(analysis, output_directory)
        except (OSError, ValueError, UnitronicsCpeAuditError) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(
            self.style.SUCCESS(
                f"Wrote {len(paths)} independent read-only CPE audit artifacts"
            )
        )
        for path in paths:
            self.stdout.write(str(path))

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, transaction

from sboms.unitronics_duplicate_cpe_audit import (
    OUTPUT_RELATIVE,
    UnitronicsDuplicateCpeAuditError,
    build_duplicate_cpe_audit,
    finalize_read_only_validation,
    write_duplicate_cpe_audit,
)


class Command(BaseCommand):
    help = (
        "Read-only audit of exact and semantic duplicate CPE mappings across "
        "the fixed 48 CPE-bearing Unitronics Ground Truth records."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--output-dir", type=Path)

    @staticmethod
    def _set_read_only() -> None:
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")

    def handle(self, *args, **options) -> None:
        output_directory = options["output_dir"] or (
            settings.REPOSITORY_ROOT / OUTPUT_RELATIVE
        )
        if not output_directory.is_absolute():
            output_directory = settings.REPOSITORY_ROOT / output_directory
        if output_directory.exists():
            raise CommandError(
                f"Refusing to overwrite existing audit directory: "
                f"{output_directory}"
            )
        try:
            with transaction.atomic():
                self._set_read_only()
                analysis = build_duplicate_cpe_audit()
            with transaction.atomic():
                self._set_read_only()
                finalize_read_only_validation(analysis)
            paths = write_duplicate_cpe_audit(analysis, output_directory)
        except (OSError, ValueError, UnitronicsDuplicateCpeAuditError) as error:
            raise CommandError(str(error)) from error

        grouping = analysis["summary"]["grouping"]
        recommendations = analysis["summary"][
            "component_recommendation_counts"
        ]
        self.stdout.write(self.style.SUCCESS("READ-ONLY DUPLICATE CPE AUDIT PASS"))
        self.stdout.write(
            f"CPE-bearing=48; distinct={grouping['distinct_canonical_gt_cpes']}; "
            f"duplicate_groups={grouping['duplicated_gt_cpe_groups']}; "
            f"duplicate_components={grouping['components_in_duplicate_groups']}; "
            f"remove_recommendations="
            f"{recommendations['REMOVE_DUPLICATED_GT_CPE']}"
        )
        for path in paths:
            self.stdout.write(str(path))

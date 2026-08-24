from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, transaction

from sboms.unitronics_ground_truth_db_application import (
    EXPECTED_DECISION_COUNTS,
    UnitronicsGroundTruthApplicationError,
    apply_application_plan,
    database_preflight,
    default_application_report_path,
    load_application_plan,
    write_application_report,
)


class Command(BaseCommand):
    help = (
        "Validate and safely apply the fixed 582-row Unitronics Ground Truth "
        "candidate artifact. The default mode is read-only dry-run."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Create all 582 Ground Truth records in one transaction.",
        )
        parser.add_argument(
            "--report-path",
            type=Path,
            help="Application report path; used only with --apply.",
        )

    @staticmethod
    def _set_read_only() -> None:
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")

    def handle(self, *args, **options) -> None:
        apply_changes = options["apply"]
        report_path = options["report_path"] or default_application_report_path()
        if not report_path.is_absolute():
            report_path = settings.REPOSITORY_ROOT / report_path
        if not apply_changes and options["report_path"] is not None:
            raise CommandError("--report-path requires --apply")
        if apply_changes and report_path.exists():
            raise CommandError(
                f"Refusing to overwrite existing application report: {report_path}"
            )
        try:
            plan = load_application_plan()
            with transaction.atomic():
                self._set_read_only()
                preflight = database_preflight(plan)
        except UnitronicsGroundTruthApplicationError as error:
            raise CommandError(str(error)) from error

        self.stdout.write(self.style.SUCCESS("PREFLIGHT PASS"))
        self.stdout.write(
            f"Components={preflight.component_count}; "
            f"candidate_rows={len(plan.rows)}; "
            f"Ground Truth before={preflight.ground_truth_count_before}; "
            f"GT CPE present={plan.cpe_present_count}; "
            f"GT CPE null={len(plan.rows) - plan.cpe_present_count}"
        )
        for decision, count in plan.decision_counts.items():
            self.stdout.write(f"{decision}={count}")
        if plan.decision_counts != EXPECTED_DECISION_COUNTS:
            raise CommandError("Unexpected candidate decision counts")
        if not apply_changes:
            self.stdout.write(
                self.style.SUCCESS("DRY RUN PASS; no database writes performed")
            )
            return

        try:
            locked_preflight, result = apply_application_plan(plan)
            report = write_application_report(
                plan,
                locked_preflight,
                result,
                report_path,
            )
        except UnitronicsGroundTruthApplicationError as error:
            raise CommandError(str(error)) from error
        self.stdout.write(self.style.SUCCESS("APPLICATION SUCCESS"))
        self.stdout.write(
            f"Ground Truth records={result.record_count}; "
            f"GT CPE present={result.cpe_present_count}; "
            f"GT CPE null={result.cpe_null_count}; "
            f"candidate mismatches="
            f"{result.candidate_cpe_mismatch_count + result.candidate_decision_mismatch_count}"
        )
        self.stdout.write(str(report))

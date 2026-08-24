from __future__ import annotations

from pathlib import Path

from django.conf import settings
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
    finalize_validation as finalize_cpe_audit_validation,
    write_unitronics_cpe_audit,
)
from sboms.unitronics_representative_finalization import (
    UnitronicsRepresentativeFinalizationError,
    _sha256,
    apply_representative_finalization,
    database_preflight,
    default_output_directory,
    load_finalization_plan,
    write_finalization_artifacts,
)


class Command(BaseCommand):
    help = (
        "Preflight and transactionally apply the eight approved Unitronics "
        "representative-component Ground Truth removals."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Update exactly the eight approved Ground Truth records.",
        )
        parser.add_argument("--output-dir", type=Path)
        parser.add_argument(
            "--cpe-audit-output-dir",
            type=Path,
            help=(
                "New directory for the post-application 40-row independent "
                "CPE audit; required with --apply."
            ),
        )

    @staticmethod
    def _set_read_only() -> None:
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")

    @staticmethod
    def _absolute(path: Path) -> Path:
        return path if path.is_absolute() else settings.REPOSITORY_ROOT / path

    def _build_cpe_audit(self):
        with transaction.atomic():
            self._set_read_only()
            analysis = build_unitronics_cpe_audit(
                cpe_snapshot=select_cpe_dictionary_snapshot(CPE_SNAPSHOT_ID),
                nvd_snapshot=select_nvd_cve_snapshot(NVD_SNAPSHOT_ID),
            )
            ground_truth_count = ComponentCpeGroundTruth.objects.count()
        finalize_cpe_audit_validation(
            analysis,
            ground_truth_count_after=ground_truth_count,
        )
        return analysis

    def handle(self, *args, **options) -> None:
        apply_changes = options["apply"]
        output_directory = self._absolute(
            options["output_dir"] or default_output_directory()
        )
        cpe_audit_option = options["cpe_audit_output_dir"]
        if not apply_changes and (
            options["output_dir"] is not None
            or cpe_audit_option is not None
        ):
            raise CommandError(
                "--output-dir and --cpe-audit-output-dir require --apply"
            )
        if apply_changes and cpe_audit_option is None:
            raise CommandError("--cpe-audit-output-dir is required with --apply")
        cpe_audit_directory = (
            self._absolute(cpe_audit_option)
            if cpe_audit_option is not None
            else None
        )
        if output_directory.exists():
            raise CommandError(
                f"Refusing to overwrite finalization output: {output_directory}"
            )
        if cpe_audit_directory is not None and cpe_audit_directory.exists():
            raise CommandError(
                f"Refusing to overwrite CPE audit output: {cpe_audit_directory}"
            )

        try:
            plan = load_finalization_plan()
            with transaction.atomic():
                self._set_read_only()
                preflight = database_preflight(plan)
            preflight_audit = self._build_cpe_audit()
        except (
            OSError,
            ValueError,
            UnitronicsCpeAuditError,
            UnitronicsRepresentativeFinalizationError,
        ) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(self.style.SUCCESS("PREFLIGHT PASS"))
        self.stdout.write(
            "Ground Truth=582; CPE present/null="
            f"{preflight.cpe_present_count}/{preflight.cpe_null_count}; "
            "candidate diff=8; staged CPE audit="
            f"{preflight_audit.summary['final_audit_status']['counts']}"
        )
        if not apply_changes:
            self.stdout.write(
                self.style.SUCCESS("DRY RUN PASS; no database writes performed")
            )
            return

        assert cpe_audit_directory is not None
        try:
            result = apply_representative_finalization(plan)
            final_cpe_audit = self._build_cpe_audit()
            cpe_paths = write_unitronics_cpe_audit(
                final_cpe_audit,
                cpe_audit_directory,
            )
            cpe_hashes = {
                path.name: _sha256(path) for path in cpe_paths
            }
            final_paths = write_finalization_artifacts(
                result,
                cpe_audit_summary=final_cpe_audit.summary,
                cpe_audit_hashes=cpe_hashes,
                output_directory=output_directory,
            )
        except (
            OSError,
            ValueError,
            UnitronicsCpeAuditError,
            UnitronicsRepresentativeFinalizationError,
        ) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(self.style.SUCCESS("APPLICATION SUCCESS"))
        self.stdout.write(
            "Ground Truth=582; CPE present/null="
            f"{result.after_cpe_present_count}/"
            f"{result.after_cpe_null_count}; distinct="
            f"{result.final_distinct_canonical_gt_cpes}; duplicate_groups="
            f"{result.final_duplicate_canonical_gt_cpe_groups}"
        )
        for path in [*cpe_paths, *final_paths]:
            self.stdout.write(str(path))

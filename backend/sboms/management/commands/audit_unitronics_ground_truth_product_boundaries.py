from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, transaction

from cpe_dictionary.models import CpeDictionarySnapshot
from nvd_cve.models import NvdCveSnapshot
from sboms.unitronics_ground_truth_product_boundary_full_audit import (
    CPE_SNAPSHOT_ID,
    NVD_SNAPSHOT_ID,
    UnitronicsProductBoundaryAuditError,
    build_product_boundary_full_audit,
    default_output_directory,
    write_product_boundary_full_audit,
)


class Command(BaseCommand):
    help = (
        "Read-only fixed-snapshot product-boundary audit of all 40 "
        "CPE-bearing Unitronics Ground Truth records."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--output-dir", type=Path)
        parser.add_argument(
            "--finalized",
            action="store_true",
            help=(
                "Audit the approved final 39-row CPE-bearing state after the "
                "wireguard-tools removal."
            ),
        )

    @staticmethod
    def _set_read_only() -> None:
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION READ ONLY")

    def handle(self, *args, **options) -> None:
        output_directory = options["output_dir"] or default_output_directory()
        if not output_directory.is_absolute():
            output_directory = settings.REPOSITORY_ROOT / output_directory
        if output_directory.exists():
            raise CommandError(
                "Refusing to overwrite existing audit directory: "
                f"{output_directory}"
            )
        try:
            with transaction.atomic():
                self._set_read_only()
                cpe_snapshot = CpeDictionarySnapshot.objects.get(
                    snapshot_id=CPE_SNAPSHOT_ID
                )
                nvd_snapshot = NvdCveSnapshot.objects.get(
                    snapshot_id=NVD_SNAPSHOT_ID
                )
                analysis = build_product_boundary_full_audit(
                    cpe_snapshot=cpe_snapshot,
                    nvd_snapshot=nvd_snapshot,
                    finalized=options["finalized"],
                )
            paths = write_product_boundary_full_audit(
                analysis,
                output_directory,
            )
        except (
            CpeDictionarySnapshot.DoesNotExist,
            NvdCveSnapshot.DoesNotExist,
            OSError,
            ValueError,
            UnitronicsProductBoundaryAuditError,
        ) as error:
            raise CommandError(str(error)) from error

        statuses = analysis.summary["audit_status"]
        self.stdout.write(
            self.style.SUCCESS(
                "READ-ONLY UNITRONICS PRODUCT-BOUNDARY FULL AUDIT PASS"
            )
        )
        self.stdout.write(
            f"KEEP={statuses['KEEP']}; "
            f"CHANGE_CPE={statuses['CHANGE_CPE']}; "
            f"REMOVE_CPE={statuses['REMOVE_CPE']}; "
            f"REVIEW_REQUIRED={statuses['REVIEW_REQUIRED']}; "
            "wireguard="
            + (
                "REMOVED_FROM_CPE_BEARING_SCOPE"
                if options["finalized"]
                else "REMOVE_CPE"
            )
        )
        for path in paths:
            self.stdout.write(str(path))

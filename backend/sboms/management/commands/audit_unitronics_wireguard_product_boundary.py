from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, transaction

from cpe_dictionary.models import CpeDictionarySnapshot
from nvd_cve.models import NvdCveSnapshot
from sboms.unitronics_wireguard_product_boundary_audit import (
    CPE_SNAPSHOT_ID,
    NVD_SNAPSHOT_ID,
    UnitronicsWireguardAuditError,
    build_wireguard_product_boundary_audit,
    default_output_directory,
    write_wireguard_product_boundary_audit,
)


class Command(BaseCommand):
    help = (
        "Read-only fixed-snapshot product-boundary audit for the Unitronics "
        "wireguard-tools Ground Truth mapping."
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
            output_directory = settings.REPOSITORY_ROOT / output_directory
        if output_directory.exists():
            raise CommandError(
                f"Refusing to overwrite existing audit directory: "
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
                analysis = build_wireguard_product_boundary_audit(
                    cpe_snapshot=cpe_snapshot,
                    nvd_snapshot=nvd_snapshot,
                )
            paths = write_wireguard_product_boundary_audit(
                analysis,
                output_directory,
            )
        except (
            CpeDictionarySnapshot.DoesNotExist,
            NvdCveSnapshot.DoesNotExist,
            OSError,
            ValueError,
            UnitronicsWireguardAuditError,
        ) as error:
            raise CommandError(str(error)) from error

        summary = analysis.summary
        self.stdout.write(
            self.style.SUCCESS(
                "READ-ONLY WIREGUARD PRODUCT-BOUNDARY AUDIT PASS"
            )
        )
        self.stdout.write(
            "classification="
            f"{summary['judgment']['classification']}; "
            f"audit_status={summary['comparison']['audit_status']}; "
            "dictionary_family="
            f"{summary['cpe_dictionary']['vendor_family_record_count']}; "
            "nvd_occurrences="
            f"{summary['nvd_configuration']['wireguard_family_occurrence_count']}; "
            "direct_tools_cpe="
            f"{summary['cpe_dictionary']['direct_wireguard_tools_product_found']}; "
            "direct_tools_nvd="
            f"{summary['nvd_configuration']['direct_wireguard_tools_expression_count']}"
        )
        for path in paths:
            self.stdout.write(str(path))

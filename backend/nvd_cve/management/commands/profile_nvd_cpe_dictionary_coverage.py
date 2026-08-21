from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from cpe_dictionary.snapshot_selection import (
    CpeDictionarySnapshotSelectionError,
)
from nvd_cve.cpe_dictionary_coverage import (
    NvdCpeDictionaryCoverageError,
    analyze_nvd_cpe_dictionary_coverage,
    write_coverage_analysis,
)
from nvd_cve.snapshot_selection import NvdCveSnapshotSelectionError


class Command(BaseCommand):
    help = (
        "Profile raw exact-string and part/vendor/product tuple coverage "
        "between the active COMPLETE NVD CVE and CPE Dictionary snapshots."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output-root",
            type=Path,
            default=settings.REPOSITORY_ROOT
            / "analysis"
            / "results"
            / "nvd-cpe-dictionary-coverage",
            help=(
                "Root for <NVD snapshot>__<CPE snapshot>/ coverage outputs."
            ),
        )

    def handle(self, *args, **options) -> None:
        del args
        output_root = options["output_root"].resolve()
        self.stdout.write(
            "Starting read-only NVD criteria × CPE Dictionary coverage "
            "analysis..."
        )
        try:
            analysis = analyze_nvd_cpe_dictionary_coverage(
                configured_nvd_snapshot_id=settings.NVD_CVE_SNAPSHOT_ID,
                configured_cpe_snapshot_id=(
                    settings.CPE_DICTIONARY_SNAPSHOT_ID
                ),
                staging_directory=output_root,
            )
            dataset = analysis.summary["dataset"]
            directory_name = (
                f"{dataset['nvd_snapshot_id']}__"
                f"{dataset['cpe_dictionary_snapshot_id']}"
            )
            paths = write_coverage_analysis(
                analysis,
                output_root / directory_name,
            )
        except (
            CpeDictionarySnapshotSelectionError,
            NvdCveSnapshotSelectionError,
            NvdCpeDictionaryCoverageError,
        ) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(
            self.style.SUCCESS(
                "Coverage analysis complete; database state unchanged."
            )
        )
        for filename, path in paths.items():
            self.stdout.write(f"{filename}: {path}")

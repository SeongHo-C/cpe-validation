from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from nvd_cve.cpe_match_analysis import (
    NvdCpeMatchAnalysisError,
    analyze_nvd_cpe_matches,
    write_analysis,
)
from nvd_cve.snapshot_selection import NvdCveSnapshotSelectionError


class Command(BaseCommand):
    help = (
        "Profile all cpeMatch occurrences in the active COMPLETE NVD CVE "
        "snapshot using PostgreSQL READ ONLY transactions."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output-root",
            type=Path,
            default=settings.REPOSITORY_ROOT
            / "analysis"
            / "results"
            / "nvd-cpe-match-profile",
            help=(
                "Root directory for <snapshot-id>/summary.json and "
                "report.md."
            ),
        )

    def handle(self, *args, **options) -> None:
        del args
        configured_snapshot_id = settings.NVD_CVE_SNAPSHOT_ID
        self.stdout.write(
            "Starting read-only NVD cpeMatch analysis for the configured "
            "active COMPLETE snapshot..."
        )
        try:
            analysis = analyze_nvd_cpe_matches(configured_snapshot_id)
        except (NvdCveSnapshotSelectionError, NvdCpeMatchAnalysisError) as error:
            raise CommandError(str(error)) from error

        snapshot_id = analysis.summary["dataset"]["snapshot_id"]
        output_directory = options["output_root"].resolve() / snapshot_id
        paths = write_analysis(analysis, output_directory)
        self.stdout.write(
            self.style.SUCCESS(
                "Read-only analysis complete; database state unchanged."
            )
        )
        for filename, path in paths.items():
            self.stdout.write(f"{filename}: {path}")

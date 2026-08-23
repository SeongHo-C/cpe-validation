import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import (
    BaseCommand,
    CommandError,
    CommandParser,
)

from sboms.unitronics_source_package_analysis import (
    EXPECTED_SBOM_ID,
    UnitronicsSourceAnalysisError,
    build_unitronics_source_analysis,
    default_first_analysis_directory,
    default_output_directory,
    write_unitronics_source_analysis,
)


class Command(BaseCommand):
    help = (
        "Build the read-only second-pass Unitronics Source/installed-package "
        "analysis from exact firmware control, list, and status evidence."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--sbom-id", type=int, default=EXPECTED_SBOM_ID)
        parser.add_argument(
            "--firmware-binary",
            type=Path,
            required=True,
            help="Exact UCRB8_R_52.07.13.7_WEBUI.bin path.",
        )
        parser.add_argument(
            "--firmware-rootfs",
            type=Path,
            required=True,
            help="Read-only rootfs extracted from the exact firmware.",
        )
        parser.add_argument(
            "--first-analysis-dir",
            type=Path,
            help="Directory containing the first-pass components.csv.",
        )
        parser.add_argument("--output-dir", type=Path)
        parser.add_argument(
            "--overwrite",
            action="store_true",
            help="Replace only the six known second-pass output files.",
        )

    @staticmethod
    def _repository_path(value: Path | None, default: Path) -> Path:
        if value is None:
            return default
        return value if value.is_absolute() else settings.REPOSITORY_ROOT / value

    def handle(self, *args, **options) -> None:
        first_analysis_directory = self._repository_path(
            options["first_analysis_dir"], default_first_analysis_directory()
        )
        output_directory = self._repository_path(
            options["output_dir"], default_output_directory()
        )
        try:
            analysis = build_unitronics_source_analysis(
                sbom_id=options["sbom_id"],
                firmware_binary_path=options["firmware_binary"].resolve(),
                firmware_rootfs=options["firmware_rootfs"].resolve(),
                first_analysis_directory=first_analysis_directory.resolve(),
            )
            output_paths = write_unitronics_source_analysis(
                analysis,
                output_directory,
                overwrite=options["overwrite"],
            )
        except (OSError, ValueError, UnitronicsSourceAnalysisError) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(
            json.dumps(
                analysis.summary["validation"],
                ensure_ascii=False,
                indent=2,
            )
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Wrote {len(output_paths)} second-pass analysis files"
            )
        )
        for path in output_paths:
            self.stdout.write(str(path))

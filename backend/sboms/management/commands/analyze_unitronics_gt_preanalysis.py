import json
from pathlib import Path

from django.core.management.base import (
    BaseCommand,
    CommandError,
    CommandParser,
)

from sboms.unitronics_gt_preanalysis import (
    EXPECTED_SBOM_ID,
    UnitronicsPreanalysisError,
    build_unitronics_preanalysis,
    default_output_directory,
    write_unitronics_preanalysis,
)


class Command(BaseCommand):
    help = (
        "Build read-only Unitronics UCR-ST-B8 Ground Truth rule-design "
        "pre-analysis from CycloneDX and exact firmware evidence."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--sbom-id", type=int, default=EXPECTED_SBOM_ID
        )
        parser.add_argument(
            "--official-zip",
            type=Path,
            required=True,
            help="Pinned official Unitronics UCR-RUT OS-7 ZIP path.",
        )
        parser.add_argument(
            "--firmware-binary",
            type=Path,
            required=True,
            help="Extracted UCRB8_R_52.07.13.7_WEBUI.bin path.",
        )
        parser.add_argument(
            "--firmware-rootfs",
            type=Path,
            required=True,
            help="Read-only rootfs extracted from the exact firmware.",
        )
        parser.add_argument("--output-dir", type=Path)
        parser.add_argument(
            "--overwrite",
            action="store_true",
            help="Replace only the five known analysis output files.",
        )

    def handle(self, *args, **options) -> None:
        output_directory = options["output_dir"]
        if output_directory is None:
            output_directory = default_output_directory()
        elif not output_directory.is_absolute():
            from django.conf import settings

            output_directory = (
                settings.REPOSITORY_ROOT / output_directory
            )
        try:
            analysis = build_unitronics_preanalysis(
                sbom_id=options["sbom_id"],
                official_zip_path=options["official_zip"].resolve(),
                firmware_binary_path=options[
                    "firmware_binary"
                ].resolve(),
                firmware_rootfs=options["firmware_rootfs"].resolve(),
            )
            output_paths = write_unitronics_preanalysis(
                analysis,
                output_directory,
                overwrite=options["overwrite"],
            )
        except (
            OSError,
            ValueError,
            UnitronicsPreanalysisError,
        ) as error:
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
                f"Wrote {len(output_paths)} pre-analysis files"
            )
        )
        for path in output_paths:
            self.stdout.write(str(path))

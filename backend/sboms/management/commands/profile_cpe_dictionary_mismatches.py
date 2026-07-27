import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import (
    BaseCommand,
    CommandError,
    CommandParser,
)

from sboms.cpe_mismatch_profiling import (
    CPEMismatchProfilingError,
    build_cpe_mismatch_profile_analysis,
    write_cpe_mismatch_profile_analysis,
)
from sboms.exact_matching import (
    CpeDictionarySnapshotSelectionError,
    select_cpe_dictionary_snapshot,
)


class Command(BaseCommand):
    help = (
        "Profile structured-field evidence for unique raw CPE "
        "Dictionary mismatches without database writes."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--snapshot-id",
            help=(
                "COMPLETE Dictionary snapshot ID; required when "
                "multiple COMPLETE snapshots exist."
            ),
        )
        parser.add_argument(
            "--output-dir",
            type=Path,
            help=(
                "output directory; defaults to analysis/results/"
                "cpe-dictionary-mismatch/<snapshot-id>"
            ),
        )
        parser.add_argument(
            "--overwrite",
            action="store_true",
            help="replace the three known output files if they exist",
        )

    @staticmethod
    def resolve_output_directory(
        output_directory: Path | None,
        snapshot_id: str,
    ) -> Path:
        if output_directory is None:
            return (
                settings.REPOSITORY_ROOT
                / "analysis"
                / "results"
                / "cpe-dictionary-mismatch"
                / snapshot_id
            )
        if output_directory.is_absolute():
            return output_directory
        return settings.REPOSITORY_ROOT / output_directory

    def handle(self, *args, **options) -> None:
        try:
            snapshot = select_cpe_dictionary_snapshot(
                options["snapshot_id"]
            )
            analysis = build_cpe_mismatch_profile_analysis(
                snapshot
            )
            output_directory = self.resolve_output_directory(
                options["output_dir"],
                snapshot.snapshot_id,
            )
            output_paths = write_cpe_mismatch_profile_analysis(
                analysis,
                output_directory,
                overwrite=options["overwrite"],
            )
        except (
            CpeDictionarySnapshotSelectionError,
            CPEMismatchProfilingError,
        ) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(
            json.dumps(
                analysis.summary,
                ensure_ascii=False,
                indent=2,
            )
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Wrote {len(output_paths)} mismatch profile files"
            )
        )
        for output_path in output_paths:
            self.stdout.write(str(output_path))

import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from sboms.cpe_profiling import (
    build_cpe_profile,
    write_cpe_profile,
)


class Command(BaseCommand):
    help = "Profile Component.cpe values without modifying database records"

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output-dir",
            type=Path,
            default=Path("analysis/results/cpe-profile"),
            help=(
                "output directory; relative paths use the repository root"
            ),
        )
        parser.add_argument(
            "--stdout-only",
            action="store_true",
            help="print summary JSON without creating output files",
        )

    @staticmethod
    def resolve_output_directory(
        output_directory: Path,
        repository_root: Path,
    ) -> Path:
        if output_directory.is_absolute():
            return output_directory
        return repository_root / output_directory

    def handle(self, *args, **options) -> None:
        profile = build_cpe_profile()
        self.stdout.write(
            json.dumps(
                profile.summary,
                ensure_ascii=False,
                indent=2,
            )
        )
        if options["stdout_only"]:
            return

        repository_root = Path(settings.BASE_DIR).parent
        output_directory = self.resolve_output_directory(
            options["output_dir"],
            repository_root,
        )
        output_paths = write_cpe_profile(
            profile,
            output_directory,
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Wrote {len(output_paths)} profile files"
            )
        )
        for output_path in output_paths:
            self.stdout.write(str(output_path))

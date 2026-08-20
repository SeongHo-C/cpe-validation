from pathlib import Path

from django.conf import settings
from django.core.management.base import (
    BaseCommand,
    CommandError,
    CommandParser,
)

from nvd_cve.snapshot import (
    NVD_CVE_BASE_URL,
    SnapshotError,
    acquire_snapshot,
    file_sha256,
)


DEFAULT_OUTPUT_ROOT = Path("data/nvd-cve")


class Command(BaseCommand):
    help = (
        "Download and verify an immutable NVD CVE JSON 2.0 yearly "
        "feed snapshot."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--output-root",
            default=str(DEFAULT_OUTPUT_ROOT),
            help=(
                "Snapshot root. Relative paths are resolved from the "
                "repository root."
            ),
        )
        parser.add_argument(
            "--base-url",
            default=NVD_CVE_BASE_URL,
            help="NVD CVE JSON 2.0 yearly feed base URL.",
        )

    def _resolve_output_root(self, raw_path: str) -> Path:
        output_root = Path(raw_path)
        if not output_root.is_absolute():
            output_root = settings.REPOSITORY_ROOT / output_root
        return output_root

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.relative_to(settings.REPOSITORY_ROOT))
        except ValueError:
            return str(path)

    def handle(self, *args, **options) -> None:
        try:
            result = acquire_snapshot(
                self._resolve_output_root(options["output_root"]),
                base_url=options["base_url"],
                reporter=self.stdout.write,
            )
        except SnapshotError as error:
            raise CommandError(str(error)) from error

        message = (
            "NVD CVE snapshot already verified"
            if result.already_verified
            else "NVD CVE snapshot verified"
        )
        self.stdout.write(self.style.SUCCESS(message))
        self.stdout.write(f"Snapshot ID: {result.snapshot_id}")
        self.stdout.write(f"Feed count: {result.manifest['feed_count']}")
        self.stdout.write(
            f"Total CVE count: {result.manifest['total_parsed_count']}"
        )
        self.stdout.write(
            "Duplicate CVE count: "
            f"{result.manifest['duplicate_cve_count']}"
        )
        content = result.manifest["content"]
        if not isinstance(content, dict):
            raise CommandError("VERIFIED manifest content is invalid")
        self.stdout.write(
            "Aggregate content SHA-256: "
            f"{content['aggregate_sha256']}"
        )
        manifest_path = result.snapshot_path / "manifest.json"
        self.stdout.write(
            f"Manifest path: {self._display_path(manifest_path)}"
        )
        self.stdout.write(
            f"Manifest SHA-256: {file_sha256(manifest_path)}"
        )
        self.stdout.write("VERIFIED: YES")

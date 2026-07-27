from pathlib import Path

from django.conf import settings
from django.core.management.base import (
    BaseCommand,
    CommandError,
    CommandParser,
)

from cpe_dictionary.snapshot import (
    NVD_CPE_FEED_URL,
    NVD_CPE_META_URL,
    NVD_CPE_SCHEMA_URL,
    SnapshotError,
    SnapshotPlan,
    SnapshotResult,
    acquire_snapshot,
)


DEFAULT_OUTPUT_ROOT = Path(
    "data/cpe-dictionary/snapshots"
)


class Command(BaseCommand):
    help = (
        "Download and verify an immutable NVD CPE Dictionary 2.0 "
        "snapshot."
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
            "--dry-run",
            action="store_true",
            help="Download META and report the planned snapshot only.",
        )
        parser.add_argument(
            "--meta-url",
            default=NVD_CPE_META_URL,
        )
        parser.add_argument(
            "--feed-url",
            default=NVD_CPE_FEED_URL,
        )
        parser.add_argument(
            "--schema-url",
            default=NVD_CPE_SCHEMA_URL,
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
        output_root = self._resolve_output_root(
            options["output_root"]
        )
        try:
            outcome = acquire_snapshot(
                output_root,
                meta_url=options["meta_url"],
                feed_url=options["feed_url"],
                schema_url=options["schema_url"],
                dry_run=options["dry_run"],
                reporter=self.stdout.write,
            )
        except SnapshotError as error:
            raise CommandError(str(error)) from error

        if isinstance(outcome, SnapshotPlan):
            self.stdout.write(
                self.style.SUCCESS(
                    "CPE Dictionary snapshot dry-run completed"
                )
            )
            self.stdout.write(
                f"Snapshot ID: {outcome.snapshot_id}"
            )
            self.stdout.write(
                "Feed last modified: "
                f"{outcome.metadata.last_modified.isoformat()}"
            )
            self.stdout.write(
                f"Expected archive size: {outcome.metadata.gz_size}"
            )
            self.stdout.write(
                f"Expected content size: {outcome.metadata.size}"
            )
            self.stdout.write(
                "Snapshot path: "
                f"{self._display_path(outcome.snapshot_path)}"
            )
            return

        if not isinstance(outcome, SnapshotResult):
            raise CommandError("Unexpected snapshot result")
        archive = outcome.manifest["archive"]
        content = outcome.manifest["content"]
        if not isinstance(archive, dict) or not isinstance(
            content,
            dict,
        ):
            raise CommandError("Verified manifest is incomplete")

        message = (
            "Snapshot already verified"
            if outcome.already_verified
            else "CPE Dictionary snapshot verified"
        )
        self.stdout.write(self.style.SUCCESS(message))
        self.stdout.write(f"Snapshot ID: {outcome.snapshot_id}")
        self.stdout.write(
            "Feed last modified: "
            f"{outcome.manifest['feed_last_modified']}"
        )
        self.stdout.write(
            f"Archive size: {archive['size']}"
        )
        self.stdout.write(
            f"Archive SHA-256: {archive['sha256']}"
        )
        self.stdout.write(
            f"JSON member count: {content['member_count']}"
        )
        self.stdout.write(
            f"Aggregate content size: {content['aggregate_size']}"
        )
        self.stdout.write(
            "Aggregate content SHA-256: "
            f"{content['aggregate_sha256']}"
        )
        self.stdout.write(
            "Snapshot path: "
            f"{self._display_path(outcome.snapshot_path)}"
        )

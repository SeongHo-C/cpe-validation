from pathlib import Path

from django.conf import settings
from django.core.management.base import (
    BaseCommand,
    CommandError,
    CommandParser,
)

from nvd_cve.importer import (
    DEFAULT_BATCH_SIZE,
    MAX_BATCH_SIZE,
    MIN_BATCH_SIZE,
    NvdCveImportError,
    import_nvd_cve_snapshot,
)


DEFAULT_INPUT_ROOT = Path("data/nvd-cve")


class Command(BaseCommand):
    help = "Import a VERIFIED NVD CVE snapshot into PostgreSQL."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--snapshot-id",
            required=True,
            help="VERIFIED snapshot ID in YYYYMMDDTHHMMSSZ format.",
        )
        parser.add_argument(
            "--input-root",
            default=str(DEFAULT_INPUT_ROOT),
            help=(
                "Snapshot root. Relative paths are resolved from the "
                "repository root."
            ),
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=DEFAULT_BATCH_SIZE,
            help=(
                f"bulk_create batch size ({MIN_BATCH_SIZE}-"
                f"{MAX_BATCH_SIZE})."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=(
                "Parse and validate the entire snapshot without "
                "database writes."
            ),
        )

    def _resolve_input_root(self, raw_path: str) -> Path:
        input_root = Path(raw_path)
        if not input_root.is_absolute():
            input_root = settings.REPOSITORY_ROOT / input_root
        return input_root

    def handle(self, *args, **options) -> None:
        try:
            result = import_nvd_cve_snapshot(
                self._resolve_input_root(options["input_root"]),
                options["snapshot_id"],
                batch_size=options["batch_size"],
                dry_run=options["dry_run"],
                reporter=self.stdout.write,
            )
        except NvdCveImportError as error:
            raise CommandError(str(error)) from error

        if result.already_imported:
            message = "NVD CVE snapshot already imported"
        elif result.dry_run:
            message = "NVD CVE snapshot dry-run completed"
        else:
            message = "NVD CVE snapshot import completed"
        self.stdout.write(self.style.SUCCESS(message))
        self.stdout.write(f"Snapshot ID: {result.snapshot_id}")
        self.stdout.write(f"Feed count: {result.feed_count}")
        self.stdout.write(
            f"Expected CVE count: {result.expected_record_count}"
        )
        self.stdout.write(f"Parsed CVE count: {result.record_count}")
        self.stdout.write(
            f"Configuration count: {result.configuration_count}"
        )
        self.stdout.write(f"CPE match count: {result.cpe_match_count}")
        self.stdout.write(
            "Vulnerable=true CPE match count: "
            f"{result.vulnerable_true_count}"
        )
        self.stdout.write(
            "Vulnerable=false CPE match count: "
            f"{result.vulnerable_false_count}"
        )
        self.stdout.write(
            f"Duplicate CVE count: {result.duplicate_cve_count}"
        )
        self.stdout.write("Validation result: PASS")
        if result.dry_run:
            self.stdout.write("DB writes: 0")

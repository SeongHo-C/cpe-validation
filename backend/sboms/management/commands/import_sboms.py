from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from sboms.importers import ImporterError, ImportResult, import_sboms


class Command(BaseCommand):
    help = "Import digest-matched Syft CycloneDX JSON SBOM files"

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--sbom-dir",
            type=Path,
            help="SBOM directory; relative paths use the repository root",
        )
        parser.add_argument(
            "--digest-file",
            type=Path,
            help="digest JSON; relative paths use the repository root",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="validate and calculate results, then roll back DB changes",
        )

    @staticmethod
    def resolve_path(path: Path, repository_root: Path) -> Path:
        if path.is_absolute():
            return path
        return repository_root / path

    def handle(self, *args, **options) -> None:
        backend_root = Path(settings.BASE_DIR)
        repository_root = backend_root.parent
        sbom_directory = self.resolve_path(
            options["sbom_dir"]
            or Path("pilot/results/sboms"),
            repository_root,
        )
        digest_file = self.resolve_path(
            options["digest_file"]
            or Path("pilot/results/image-digests.json"),
            repository_root,
        )
        try:
            result = import_sboms(
                sbom_directory=sbom_directory,
                digest_file=digest_file,
                repository_root=repository_root,
                dry_run=options["dry_run"],
            )
        except ImporterError as error:
            raise CommandError(str(error)) from error

        self.print_result(result)
        if options["dry_run"]:
            self.stdout.write(self.style.SUCCESS("Dry run completed"))
            self.stdout.write("No database changes were committed")
        else:
            self.stdout.write(self.style.SUCCESS("Import completed"))

    def print_result(self, result: ImportResult) -> None:
        self.stdout.write(
            f"Importing {result.files_processed} CycloneDX SBOM files..."
        )
        for index, file_result in enumerate(result.files, start=1):
            self.stdout.write(
                f"\n[{index}/{result.files_processed}] "
                f"{file_result.filename}"
            )
            self.stdout.write(f"  Image: {file_result.image}")
            self.stdout.write(
                f"  Manifest: {file_result.manifest_digest}"
            )
            self.stdout.write(
                f"  SBOM: {file_result.sbom_status}"
            )
            self.stdout.write(
                f"  Components: {file_result.component_count}"
            )
            self.stdout.write(
                "  Components with primary CPE: "
                f"{file_result.components_with_primary_cpe}"
            )
            self.stdout.write(
                "  Components without primary CPE: "
                f"{file_result.components_without_primary_cpe}"
            )

        self.stdout.write("\nImport summary")
        self.stdout.write(
            f"  Files processed: {result.files_processed}"
        )
        self.stdout.write(
            f"  Docker images created: {result.images_created}"
        )
        self.stdout.write(
            f"  Docker images existing: {result.images_existing}"
        )
        self.stdout.write(
            f"  SBOM documents created: {result.sboms_created}"
        )
        self.stdout.write(
            f"  SBOM documents skipped: {result.sboms_skipped}"
        )
        self.stdout.write(
            f"  Components created: {result.components_created}"
        )
        self.stdout.write(
            "  Components with primary CPE: "
            f"{result.components_with_primary_cpe}"
        )
        self.stdout.write(
            "  Components without primary CPE: "
            f"{result.components_without_primary_cpe}"
        )

from django.core.management.base import BaseCommand, CommandError

from sboms.models import SBOMDocument, SourceArtifact
from sboms.source_extraction import (
    SourceArtifactExtractionError,
    extract_source_artifact,
)


class Command(BaseCommand):
    help = "Safely extract the SourceArtifact linked to one SBOMDocument"

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--sbom-id",
            type=int,
            required=True,
            help="SBOMDocument primary key",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="replace only this SourceArtifact's existing extraction",
        )

    def handle(self, *args, **options) -> None:
        sbom_id = options["sbom_id"]
        try:
            document = SBOMDocument.objects.get(pk=sbom_id)
        except SBOMDocument.DoesNotExist as error:
            raise CommandError(
                f"SBOMDocument {sbom_id} does not exist."
            ) from error

        try:
            source_artifact = document.source_artifact
        except SourceArtifact.DoesNotExist as error:
            raise CommandError(
                f"SBOMDocument {sbom_id} has no SourceArtifact."
            ) from error

        try:
            result = extract_source_artifact(
                source_artifact,
                force=options["force"],
            )
        except SourceArtifactExtractionError as error:
            raise CommandError(str(error)) from error

        self.stdout.write(f"SBOMDocument: {document.pk}")
        self.stdout.write(f"SourceArtifact: {source_artifact.pk}")
        self.stdout.write(
            f"Archive: {source_artifact.source_archive.name}"
        )
        self.stdout.write(f"Verified SHA-256: {result.file_sha256}")
        if result.skipped:
            self.stdout.write(
                self.style.SUCCESS(
                    "Already extracted; no files were changed."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "Extraction completed: "
                    f"{result.file_count} files, "
                    f"{result.directory_count} directories"
                )
            )
        self.stdout.write(
            f"Extraction directory: {result.extraction_directory}"
        )

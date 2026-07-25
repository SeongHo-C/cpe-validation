from django.db import IntegrityError, transaction
from django.test import TestCase

from .models import Component, DockerImage, SBOMDocument


class SbomModelTests(TestCase):
    def setUp(self) -> None:
        self.docker_image = DockerImage.objects.create(
            repository="docker.io/library/example",
            tag="1.0",
            manifest_digest="sha256:" + ("a" * 64),
            pinned_reference=(
                "docker.io/library/example@sha256:" + ("a" * 64)
            ),
        )
        self.sbom_document = SBOMDocument.objects.create(
            docker_image=self.docker_image,
            source_path="pilot/results/sboms/example-1.0.cdx.json",
            file_sha256="b" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )

    def create_component(
        self,
        sbom_document: SBOMDocument | None = None,
        bom_ref: str = "pkg:generic/example@1.0",
    ) -> Component:
        return Component.objects.create(
            sbom_document=sbom_document or self.sbom_document,
            bom_ref=bom_ref,
            component_type="library",
            name="example",
            version="1.0",
        )

    def test_docker_image_string(self) -> None:
        self.assertEqual(
            str(self.docker_image),
            "docker.io/library/example:1.0 (linux/amd64)",
        )

    def test_sbom_document_relates_to_docker_image(self) -> None:
        self.assertEqual(
            self.sbom_document.docker_image,
            self.docker_image,
        )
        self.assertEqual(
            list(self.docker_image.sbom_documents.all()),
            [self.sbom_document],
        )

    def test_component_relates_to_sbom_document(self) -> None:
        component = self.create_component()

        self.assertEqual(
            component.sbom_document,
            self.sbom_document,
        )
        self.assertEqual(
            list(self.sbom_document.components.all()),
            [component],
        )

    def test_duplicate_bom_ref_in_same_sbom_is_rejected(self) -> None:
        self.create_component()

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                self.create_component()

    def test_same_bom_ref_in_different_sboms_is_allowed(self) -> None:
        second_document = SBOMDocument.objects.create(
            docker_image=self.docker_image,
            source_path="pilot/results/sboms/example-1.0-second.cdx.json",
            file_sha256="c" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )

        first_component = self.create_component()
        second_component = self.create_component(
            sbom_document=second_document,
        )

        self.assertEqual(first_component.bom_ref, second_component.bom_ref)
        self.assertNotEqual(
            first_component.sbom_document,
            second_component.sbom_document,
        )

    def test_properties_default_to_empty_list(self) -> None:
        component = self.create_component()

        self.assertEqual(component.properties, [])

from datetime import timedelta

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from sboms.models import Component, DockerImage, SBOMDocument


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
        self.assertEqual(self.sbom_document.manufacturer, "")
        self.assertEqual(self.sbom_document.product_name, "")
        self.assertEqual(self.sbom_document.product_version, "")
        self.assertEqual(self.sbom_document.original_filename, "")

    def test_sbom_document_can_be_created_without_docker_image(
        self,
    ) -> None:
        document = SBOMDocument.objects.create(
            manufacturer="NETGEAR",
            product_name="R7000",
            product_version="1.0.11.136",
            original_filename="r7000.cdx.json",
            source_path="uploads/sboms/r7000.cdx.json",
            file_sha256="d" * 64,
            spec_version="1.6",
            generator_name="EMBA",
            generator_version="1.4.3",
        )

        self.assertIsNone(document.docker_image)
        self.assertEqual(document.manufacturer, "NETGEAR")
        self.assertEqual(document.product_name, "R7000")
        self.assertEqual(document.product_version, "1.0.11.136")
        self.assertEqual(document.original_filename, "r7000.cdx.json")

    def test_same_product_information_with_different_hash_is_allowed(
        self,
    ) -> None:
        values = {
            "manufacturer": "NETGEAR",
            "product_name": "R7000",
            "product_version": "1.0.11.136",
            "original_filename": "r7000.cdx.json",
            "source_path": "uploads/sboms/r7000.cdx.json",
            "spec_version": "1.6",
            "generator_name": "EMBA",
            "generator_version": "1.4.3",
        }

        first = SBOMDocument.objects.create(
            file_sha256="d" * 64,
            **values,
        )
        second = SBOMDocument.objects.create(
            file_sha256="e" * 64,
            **values,
        )

        self.assertNotEqual(first.pk, second.pk)

    def test_duplicate_file_hash_is_rejected_for_different_products(
        self,
    ) -> None:
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                SBOMDocument.objects.create(
                    manufacturer="Different vendor",
                    product_name="Different product",
                    source_path="uploads/sboms/different.cdx.json",
                    file_sha256=self.sbom_document.file_sha256,
                    spec_version="1.6",
                    generator_name="EMBA",
                    generator_version="1.4.3",
                )

    def test_sbom_document_string_uses_product_identity(self) -> None:
        document = SBOMDocument.objects.create(
            manufacturer="NETGEAR",
            product_name="R7000",
            product_version="1.0.11.136",
            original_filename="r7000.cdx.json",
            source_path="uploads/sboms/r7000.cdx.json",
            file_sha256="d" * 64,
            spec_version="1.6",
            generator_name="EMBA",
            generator_version="1.4.3",
        )

        rendered = str(document)
        self.assertIn("NETGEAR", rendered)
        self.assertIn("R7000", rendered)
        self.assertIn("1.0.11.136", rendered)

    def test_sbom_document_string_keeps_docker_identity(self) -> None:
        rendered = str(self.sbom_document)

        self.assertIn("docker.io/library/example:1.0", rendered)
        self.assertIn("syft 1.49.0", rendered)

    def test_sbom_document_string_uses_original_filename(self) -> None:
        document = SBOMDocument.objects.create(
            original_filename="firmware.cdx.json",
            source_path="uploads/sboms/firmware.cdx.json",
            file_sha256="d" * 64,
            spec_version="1.6",
            generator_name="EMBA",
            generator_version="1.4.3",
        )

        self.assertIn("firmware.cdx.json", str(document))

    def test_sbom_document_string_has_stable_fallback(self) -> None:
        document = SBOMDocument.objects.create(
            source_path="uploads/sboms/unknown.cdx.json",
            file_sha256="d" * 64,
            spec_version="1.6",
            generator_name="EMBA",
            generator_version="1.4.3",
        )

        self.assertIn("d" * 12, str(document))

    def test_sbom_documents_order_newest_import_first(self) -> None:
        newer = SBOMDocument.objects.create(
            source_path="uploads/sboms/newer.cdx.json",
            file_sha256="d" * 64,
            spec_version="1.6",
            generator_name="EMBA",
            generator_version="1.4.3",
        )
        now = timezone.now()
        SBOMDocument.objects.filter(pk=self.sbom_document.pk).update(
            imported_at=now - timedelta(days=1)
        )
        SBOMDocument.objects.filter(pk=newer.pk).update(imported_at=now)

        self.assertEqual(
            list(SBOMDocument.objects.values_list("pk", flat=True)),
            [newer.pk, self.sbom_document.pk],
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

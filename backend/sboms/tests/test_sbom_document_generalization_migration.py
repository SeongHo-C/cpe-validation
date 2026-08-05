from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from django.db import IntegrityError, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


MIGRATE_FROM = [("sboms", "0005_resolution_outcome_correction_types")]
MIGRATE_TO = [("sboms", "0006_generalize_sbom_document")]


class SBOMDocumentGeneralizationMigrationTests(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_FROM)
        self.old_apps = executor.loader.project_state(MIGRATE_FROM).apps

    def tearDown(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_TO)
        super().tearDown()

    def create_legacy_data(self) -> dict[str, int]:
        DockerImage = self.old_apps.get_model("sboms", "DockerImage")
        SBOMDocument = self.old_apps.get_model(
            "sboms",
            "SBOMDocument",
        )
        Component = self.old_apps.get_model("sboms", "Component")
        CorrectionType = self.old_apps.get_model(
            "sboms",
            "GroundTruthCorrectionType",
        )
        Snapshot = self.old_apps.get_model(
            "cpe_dictionary",
            "CpeDictionarySnapshot",
        )
        CpeName = self.old_apps.get_model("cpe_dictionary", "CpeName")

        image = DockerImage.objects.create(
            repository="docker.io/library/migration-test",
            tag="1.0",
            manifest_digest="sha256:" + ("a" * 64),
            pinned_reference=(
                "docker.io/library/migration-test@sha256:"
                + ("a" * 64)
            ),
        )
        document = SBOMDocument.objects.create(
            docker_image=image,
            source_path=(
                "pilot/results/sboms/migration-test-1.0.cdx.json"
            ),
            file_sha256="b" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )
        component = Component.objects.create(
            sbom_document=document,
            bom_ref="pkg:generic/migration-test@1.0",
            component_type="library",
            name="migration-test",
            version="1.0",
        )
        correction_type = CorrectionType.objects.create(
            code="migration_test_correction",
            name="Migration test correction",
            description="Preserved across the compatibility migration.",
        )
        snapshot = Snapshot.objects.create(
            snapshot_id="20260805T010000Z",
            status="COMPLETE",
            feed_last_modified=datetime(
                2026,
                8,
                5,
                tzinfo=timezone.utc,
            ),
            manifest_sha256="1" * 64,
            archive_sha256="2" * 64,
            content_sha256="3" * 64,
            member_count=1,
            expected_record_count=1,
            record_count=1,
            active_count=1,
            deprecated_count=0,
            completed_at=datetime(
                2026,
                8,
                5,
                tzinfo=timezone.utc,
            ),
        )
        cpe_name = CpeName.objects.create(
            snapshot=snapshot,
            cpe_name_id=UUID(
                "11111111-1111-4111-8111-111111111111"
            ),
            cpe_name=(
                "cpe:2.3:a:example:migration:1.0:*:*:*:*:*:*:*"
            ),
            deprecated=False,
            created_at_nvd=datetime(
                2020,
                1,
                1,
                tzinfo=timezone.utc,
            ),
            last_modified_at_nvd=datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
            part="a",
            vendor="example",
            product="migration",
            version="1.0",
            update="*",
            edition="*",
            language="*",
            sw_edition="*",
            target_sw="*",
            target_hw="*",
            other="*",
        )
        return {
            "image": image.pk,
            "document": document.pk,
            "component": component.pk,
            "correction_type": correction_type.pk,
            "snapshot": snapshot.pk,
            "cpe_name": cpe_name.pk,
        }

    @staticmethod
    def migrate_to_target():
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_TO)
        return executor.loader.project_state(MIGRATE_TO).apps

    def test_forward_preserves_legacy_data_and_allows_document_without_image(
        self,
    ) -> None:
        identifiers = self.create_legacy_data()

        new_apps = self.migrate_to_target()
        DockerImage = new_apps.get_model("sboms", "DockerImage")
        SBOMDocument = new_apps.get_model("sboms", "SBOMDocument")
        Component = new_apps.get_model("sboms", "Component")
        CorrectionType = new_apps.get_model(
            "sboms",
            "GroundTruthCorrectionType",
        )
        Snapshot = new_apps.get_model(
            "cpe_dictionary",
            "CpeDictionarySnapshot",
        )
        CpeName = new_apps.get_model("cpe_dictionary", "CpeName")

        document = SBOMDocument.objects.get(pk=identifiers["document"])
        self.assertTrue(
            DockerImage.objects.filter(pk=identifiers["image"]).exists()
        )
        self.assertEqual(document.docker_image_id, identifiers["image"])
        self.assertEqual(document.manufacturer, "")
        self.assertEqual(document.product_name, "")
        self.assertEqual(document.product_version, "")
        self.assertEqual(document.original_filename, "")
        self.assertTrue(
            Component.objects.filter(
                pk=identifiers["component"],
                sbom_document_id=identifiers["document"],
            ).exists()
        )

        uploaded_document = SBOMDocument.objects.create(
            docker_image=None,
            manufacturer="NETGEAR",
            product_name="R7000",
            product_version="1.0.11.136",
            original_filename="r7000.cdx.json",
            source_path="uploads/sboms/r7000.cdx.json",
            file_sha256="c" * 64,
            spec_version="1.6",
            generator_name="EMBA",
            generator_version="1.4.3",
        )
        self.assertIsNone(uploaded_document.docker_image_id)
        self.assertTrue(
            CorrectionType.objects.filter(
                pk=identifiers["correction_type"]
            ).exists()
        )
        self.assertTrue(
            Snapshot.objects.filter(pk=identifiers["snapshot"]).exists()
        )
        self.assertTrue(
            CpeName.objects.filter(pk=identifiers["cpe_name"]).exists()
        )

    def test_reverse_succeeds_for_docker_backed_documents(self) -> None:
        identifiers = self.create_legacy_data()
        self.migrate_to_target()

        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_FROM)
        old_apps = executor.loader.project_state(MIGRATE_FROM).apps
        DockerImage = old_apps.get_model("sboms", "DockerImage")
        SBOMDocument = old_apps.get_model("sboms", "SBOMDocument")
        Component = old_apps.get_model("sboms", "Component")

        document = SBOMDocument.objects.get(pk=identifiers["document"])
        self.assertEqual(document.docker_image_id, identifiers["image"])
        self.assertTrue(
            DockerImage.objects.filter(pk=identifiers["image"]).exists()
        )
        self.assertTrue(
            Component.objects.filter(pk=identifiers["component"]).exists()
        )
        field_names = {
            field.name for field in SBOMDocument._meta.get_fields()
        }
        self.assertNotIn("manufacturer", field_names)
        self.assertNotIn("product_name", field_names)
        self.assertNotIn("product_version", field_names)
        self.assertNotIn("original_filename", field_names)
        self.assertFalse(
            SBOMDocument._meta.get_field("docker_image").null
        )

    def test_reverse_refuses_document_without_docker_image(self) -> None:
        new_apps = self.migrate_to_target()
        SBOMDocument = new_apps.get_model("sboms", "SBOMDocument")
        document = SBOMDocument.objects.create(
            docker_image=None,
            manufacturer="NETGEAR",
            product_name="R7000",
            product_version="1.0.11.136",
            original_filename="r7000.cdx.json",
            source_path="uploads/sboms/r7000.cdx.json",
            file_sha256="c" * 64,
            spec_version="1.6",
            generator_name="EMBA",
            generator_version="1.4.3",
        )

        with self.assertRaises(IntegrityError):
            MigrationExecutor(connection).migrate(MIGRATE_FROM)

        self.assertTrue(
            SBOMDocument.objects.filter(pk=document.pk).exists()
        )

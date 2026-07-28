from datetime import datetime, timezone
from uuid import UUID

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class GroundTruthManualCpeMigrationTests(TransactionTestCase):
    migrate_from = (
        "sboms",
        "0002_componentcpegroundtruth",
    )
    migrate_to = (
        "sboms",
        "0003_componentcpegroundtruth_manual_cpe",
    )

    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_from])
        old_apps = executor.loader.project_state(
            [self.migrate_from]
        ).apps

        DockerImage = old_apps.get_model("sboms", "DockerImage")
        SBOMDocument = old_apps.get_model(
            "sboms",
            "SBOMDocument",
        )
        Component = old_apps.get_model("sboms", "Component")
        GroundTruth = old_apps.get_model(
            "sboms",
            "ComponentCpeGroundTruth",
        )
        Snapshot = old_apps.get_model(
            "cpe_dictionary",
            "CpeDictionarySnapshot",
        )
        CpeName = old_apps.get_model(
            "cpe_dictionary",
            "CpeName",
        )

        snapshot = Snapshot.objects.create(
            snapshot_id="20260725T035002Z",
            status="COMPLETE",
            feed_last_modified=datetime(
                2026,
                7,
                25,
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
                7,
                27,
                tzinfo=timezone.utc,
            ),
        )
        cpe = CpeName.objects.create(
            snapshot=snapshot,
            cpe_name_id=UUID(int=900),
            cpe_name=(
                "cpe:2.3:a:example:legacy:1.0:*:*:*:*:*:*:*"
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
            product="legacy",
            version="1.0",
            update="*",
            edition="*",
            language="*",
            sw_edition="*",
            target_sw="*",
            target_hw="*",
            other="*",
        )
        image = DockerImage.objects.create(
            repository="docker.io/library/legacy",
            tag="1.0",
            manifest_digest="sha256:" + ("a" * 64),
            pinned_reference=(
                "docker.io/library/legacy@sha256:" + ("a" * 64)
            ),
        )
        document = SBOMDocument.objects.create(
            docker_image=image,
            source_path="pilot/results/sboms/legacy-1.0.cdx.json",
            file_sha256="b" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )
        component = Component.objects.create(
            sbom_document=document,
            bom_ref="legacy",
            component_type="library",
            name="legacy",
            cpe=cpe.cpe_name,
        )
        record = GroundTruth.objects.create(
            component=component,
            snapshot=snapshot,
            ground_truth_cpe=cpe,
            decision_type="Legacy review",
            note="Preserve this record",
        )
        self.record_id = record.id
        self.component_id = component.id
        self.cpe_id = cpe.id

        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_to])
        self.apps = executor.loader.project_state(
            [self.migrate_to]
        ).apps

    def test_existing_dictionary_ground_truth_is_preserved(
        self,
    ) -> None:
        GroundTruth = self.apps.get_model(
            "sboms",
            "ComponentCpeGroundTruth",
        )

        record = GroundTruth.objects.get(pk=self.record_id)

        self.assertEqual(record.component_id, self.component_id)
        self.assertEqual(record.ground_truth_cpe_id, self.cpe_id)
        self.assertEqual(record.decision_type, "Legacy review")
        self.assertEqual(record.note, "Preserve this record")
        self.assertEqual(record.manual_ground_truth_cpe, "")

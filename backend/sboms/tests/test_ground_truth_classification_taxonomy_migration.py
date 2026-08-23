from __future__ import annotations

from datetime import datetime, timezone

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


MIGRATE_FROM = [("sboms", "0010_sourceartifact")]
MIGRATE_TO = [
    ("sboms", "0011_ground_truth_classification_taxonomy")
]


class GroundTruthClassificationTaxonomyMigrationTests(
    TransactionTestCase
):
    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_FROM)
        self.old_apps = executor.loader.project_state(MIGRATE_FROM).apps

    def tearDown(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_TO)
        super().tearDown()

    def test_preserves_records_and_relations_while_seeding_fields(
        self,
    ) -> None:
        Document = self.old_apps.get_model("sboms", "SBOMDocument")
        Component = self.old_apps.get_model("sboms", "Component")
        GroundTruth = self.old_apps.get_model(
            "sboms",
            "ComponentCpeGroundTruth",
        )
        DiscrepancyType = self.old_apps.get_model(
            "sboms",
            "GroundTruthDiscrepancyType",
        )
        Snapshot = self.old_apps.get_model(
            "cpe_dictionary",
            "CpeDictionarySnapshot",
        )

        document = Document.objects.create(
            source_path="migration/classification-taxonomy.cdx.json",
            file_sha256="a" * 64,
            spec_version="1.6",
            generator_name="migration-test",
            generator_version="1.0",
        )
        component = Component.objects.create(
            sbom_document=document,
            bom_ref="classification-taxonomy-preservation",
            component_type="library",
            name="example",
            version="1.0",
            cpe="cpe:2.3:a:example:source:1.0:*:*:*:*:*:*:*",
        )
        snapshot = Snapshot.objects.create(
            snapshot_id="20260823T000001Z",
            status="COMPLETE",
            feed_last_modified=datetime(
                2026,
                8,
                23,
                tzinfo=timezone.utc,
            ),
            manifest_sha256="1" * 64,
            archive_sha256="2" * 64,
            content_sha256="3" * 64,
            member_count=0,
            expected_record_count=0,
            record_count=0,
            active_count=0,
            deprecated_count=0,
            completed_at=datetime(
                2026,
                8,
                23,
                tzinfo=timezone.utc,
            ),
        )
        vendor = DiscrepancyType.objects.get(code="VENDOR_MISMATCH")
        legacy_reason = DiscrepancyType.objects.get(
            code="DISTRIBUTION_PACKAGE_VERSION_NORMALIZED"
        )
        vendor_id = vendor.pk
        legacy_reason_id = legacy_reason.pk
        record = GroundTruth.objects.create(
            component=component,
            snapshot=snapshot,
            manual_ground_truth_cpe=(
                "cpe:2.3:a:canonical:product:1.0:*:*:*:*:*:*:*"
            ),
            resolution_outcome="MANUAL_FROM_OFFICIAL_FAMILY",
            decision="OFFICIAL_CPE_MAPPED",
            note="Preserve reviewed evidence.",
        )
        record.discrepancy_types.add(vendor, legacy_reason)
        record_id = record.pk

        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_TO)
        apps = executor.loader.project_state(MIGRATE_TO).apps
        MigratedGroundTruth = apps.get_model(
            "sboms",
            "ComponentCpeGroundTruth",
        )
        MigratedDiscrepancyType = apps.get_model(
            "sboms",
            "GroundTruthDiscrepancyType",
        )

        migrated = MigratedGroundTruth.objects.get(pk=record_id)
        self.assertEqual(migrated.decision, "OFFICIAL_CPE_MAPPED")
        self.assertEqual(migrated.note, "Preserve reviewed evidence.")
        self.assertEqual(
            set(
                migrated.discrepancy_types.values_list(
                    "code",
                    flat=True,
                )
            ),
            {"VENDOR", "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED"},
        )
        self.assertEqual(
            MigratedDiscrepancyType.objects.get(code="VENDOR").pk,
            vendor_id,
        )
        preserved_legacy = MigratedDiscrepancyType.objects.get(
            code="DISTRIBUTION_PACKAGE_VERSION_NORMALIZED"
        )
        self.assertEqual(preserved_legacy.pk, legacy_reason_id)
        self.assertFalse(preserved_legacy.is_active)
        self.assertEqual(
            list(
                MigratedDiscrepancyType.objects.filter(
                    is_active=True,
                ).values_list("code", flat=True)
            ),
            [
                "PART",
                "VENDOR",
                "PRODUCT",
                "VERSION",
                "UPDATE",
                "EDITION",
                "LANGUAGE",
                "SW_EDITION",
                "TARGET_SW",
                "TARGET_HW",
                "OTHER",
            ],
        )

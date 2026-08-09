from __future__ import annotations

from datetime import datetime, timezone

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


MIGRATE_FROM = [
    ("sboms", "0008_ground_truth_decision_discrepancies")
]
MIGRATE_TO = [
    ("sboms", "0009_version_mismatch_discrepancy_ordering")
]


class GroundTruthVersionMismatchMigrationTests(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_FROM)
        self.old_apps = executor.loader.project_state(MIGRATE_FROM).apps

    def tearDown(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_TO)
        super().tearDown()

    def test_adds_lookup_and_order_without_changing_ground_truth(
        self,
    ) -> None:
        Document = self.old_apps.get_model("sboms", "SBOMDocument")
        Component = self.old_apps.get_model("sboms", "Component")
        GroundTruth = self.old_apps.get_model(
            "sboms",
            "ComponentCpeGroundTruth",
        )
        CorrectionType = self.old_apps.get_model(
            "sboms",
            "GroundTruthCorrectionType",
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
            source_path="migration/version-mismatch.cdx.json",
            file_sha256="a" * 64,
            spec_version="1.6",
            generator_name="migration-test",
            generator_version="1.0",
        )
        component = Component.objects.create(
            sbom_document=document,
            bom_ref="version-mismatch-preservation",
            component_type="library",
            name="busybox",
            version="1.34.1-122.19",
            cpe=(
                "cpe:2.3:a:openwrt:busybox:"
                "1.34.1-122.19:*:*:*:*:*:*:*"
            ),
        )
        snapshot = Snapshot.objects.create(
            snapshot_id="20260809T000001Z",
            status="COMPLETE",
            feed_last_modified=datetime(
                2026, 8, 9, tzinfo=timezone.utc
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
                2026, 8, 9, tzinfo=timezone.utc
            ),
        )
        correction = CorrectionType.objects.update_or_create(
            code="distribution_package_version_normalized",
            defaults={
                "name": "Distribution package version normalized",
                "description": "Legacy relation must remain.",
                "is_active": True,
            },
        )[0]
        existing_discrepancies = {}
        for code, name in (
            ("PART_MISMATCH", "Part mismatch"),
            ("PRODUCT_MISMATCH", "Product mismatch"),
            ("VENDOR_MISMATCH", "Vendor mismatch"),
            (
                "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
                "Distribution package version normalized",
            ),
            (
                "VERSION_NOT_IN_DICTIONARY",
                "Version not in Dictionary",
            ),
        ):
            existing_discrepancies[code] = (
                DiscrepancyType.objects.update_or_create(
                    code=code,
                    defaults={
                        "name": name,
                        "description": f"Preserve {code}.",
                        "is_active": True,
                    },
                )[0]
            )
        distribution = existing_discrepancies[
            "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED"
        ]
        record = GroundTruth.objects.create(
            component=component,
            snapshot=snapshot,
            manual_ground_truth_cpe=(
                "cpe:2.3:a:busybox:busybox:"
                "1.34.1:*:*:*:*:*:*:*"
            ),
            resolution_outcome="MANUAL_FROM_OFFICIAL_FAMILY",
            decision="OFFICIAL_CPE_MAPPED",
            note="Preserve authoritative evidence.",
        )
        record.correction_types.add(correction)
        record.discrepancy_types.add(distribution)
        record_id = record.pk
        preserved = {
            "component_id": record.component_id,
            "snapshot_id": record.snapshot_id,
            "ground_truth_cpe_id": record.ground_truth_cpe_id,
            "manual_ground_truth_cpe": record.manual_ground_truth_cpe,
            "resolution_outcome": record.resolution_outcome,
            "decision": record.decision,
            "note": record.note,
            "correction_ids": list(
                record.correction_types.values_list("id", flat=True)
            ),
            "discrepancy_codes": list(
                record.discrepancy_types.values_list("code", flat=True)
            ),
        }

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
        actual = {
            "component_id": migrated.component_id,
            "snapshot_id": migrated.snapshot_id,
            "ground_truth_cpe_id": migrated.ground_truth_cpe_id,
            "manual_ground_truth_cpe": (
                migrated.manual_ground_truth_cpe
            ),
            "resolution_outcome": migrated.resolution_outcome,
            "decision": migrated.decision,
            "note": migrated.note,
            "correction_ids": list(
                migrated.correction_types.values_list("id", flat=True)
            ),
            "discrepancy_codes": list(
                migrated.discrepancy_types.values_list("code", flat=True)
            ),
        }
        self.assertEqual(MigratedGroundTruth.objects.count(), 1)
        self.assertEqual(actual, preserved)
        self.assertEqual(
            list(
                MigratedDiscrepancyType.objects.values_list(
                    "code", flat=True
                )
            ),
            [
                "PART_MISMATCH",
                "PRODUCT_MISMATCH",
                "VENDOR_MISMATCH",
                "VERSION_MISMATCH",
                "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
                "VERSION_NOT_IN_DICTIONARY",
            ],
        )
        version_mismatch = MigratedDiscrepancyType.objects.get(
            code="VERSION_MISMATCH"
        )
        self.assertEqual(version_mismatch.display_order, 40)
        self.assertFalse(
            migrated.discrepancy_types.filter(
                code="VERSION_MISMATCH"
            ).exists()
        )

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


MIGRATE_FROM = [("sboms", "0007_sbomdocument_uploaded_file")]
MIGRATE_TO = [
    ("sboms", "0008_ground_truth_decision_discrepancies")
]
MIGRATE_LATEST = [
    ("sboms", "0009_version_mismatch_discrepancy_ordering")
]


class GroundTruthDecisionDiscrepancyMigrationTests(
    TransactionTestCase
):
    def setUp(self) -> None:
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_FROM)
        self.old_apps = executor.loader.project_state(MIGRATE_FROM).apps

    def tearDown(self) -> None:
        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_LATEST)
        super().tearDown()

    def _create_legacy_records(self) -> dict[str, int]:
        DockerImage = self.old_apps.get_model("sboms", "DockerImage")
        SBOMDocument = self.old_apps.get_model(
            "sboms",
            "SBOMDocument",
        )
        Component = self.old_apps.get_model("sboms", "Component")
        GroundTruth = self.old_apps.get_model(
            "sboms",
            "ComponentCpeGroundTruth",
        )
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
            repository="docker.io/library/taxonomy-migration",
            tag="1.0",
            manifest_digest="sha256:" + ("8" * 64),
            pinned_reference=(
                "docker.io/library/taxonomy-migration@sha256:"
                + ("8" * 64)
            ),
        )
        document = SBOMDocument.objects.create(
            docker_image=image,
            source_path="migration/taxonomy.cdx.json",
            file_sha256="9" * 64,
            spec_version="1.6",
            generator_name="migration-test",
            generator_version="1.0",
        )
        snapshot = Snapshot.objects.create(
            snapshot_id="20260809T000000Z",
            status="COMPLETE",
            feed_last_modified=datetime(
                2026,
                8,
                9,
                tzinfo=timezone.utc,
            ),
            manifest_sha256="1" * 64,
            archive_sha256="2" * 64,
            content_sha256="3" * 64,
            member_count=2,
            expected_record_count=2,
            record_count=2,
            active_count=2,
            deprecated_count=0,
            completed_at=datetime(
                2026,
                8,
                9,
                tzinfo=timezone.utc,
            ),
        )

        original_value = (
            "cpe:2.3:a:example:original:1.0:*:*:*:*:*:*:*"
        )
        mapped_value = (
            "cpe:2.3:a:canonical:product:1.0:*:*:*:*:*:*:*"
        )
        original_cpe = CpeName.objects.create(
            snapshot=snapshot,
            cpe_name_id=UUID("11111111-1111-4111-8111-111111111111"),
            cpe_name=original_value,
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
            product="original",
            version="1.0",
            update="*",
            edition="*",
            language="*",
            sw_edition="*",
            target_sw="*",
            target_hw="*",
            other="*",
        )
        mapped_cpe = CpeName.objects.create(
            snapshot=snapshot,
            cpe_name_id=UUID("22222222-2222-4222-8222-222222222222"),
            cpe_name=mapped_value,
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
            vendor="canonical",
            product="product",
            version="1.0",
            update="*",
            edition="*",
            language="*",
            sw_edition="*",
            target_sw="*",
            target_hw="*",
            other="*",
        )

        corrections = {}
        for code, name in (
            (
                "mapped_to_official_product_cpe",
                "Mapped to official product CPE",
            ),
            (
                "distribution_package_version_normalized",
                "Distribution package version normalized",
            ),
            (
                "version_not_in_dictionary",
                "Version not in Dictionary",
            ),
            ("cpe_confirmed", "CPE_CONFIRMED"),
        ):
            corrections[code] = CorrectionType.objects.update_or_create(
                code=code,
                defaults={"name": name, "is_active": True},
            )[0]

        records = {}
        cases = (
            (
                "mapped_without_reason",
                "CORRECTED_TO_DICTIONARY",
                mapped_cpe,
                corrections["mapped_to_official_product_cpe"],
            ),
            (
                "distribution",
                "CORRECTED_TO_DICTIONARY",
                mapped_cpe,
                corrections[
                    "distribution_package_version_normalized"
                ],
            ),
            (
                "version_missing",
                "DIRECT_OFFICIAL_NOT_CONFIRMED",
                None,
                corrections["version_not_in_dictionary"],
            ),
            (
                "confirmed",
                "ORIGINAL_OFFICIAL_CONFIRMED",
                original_cpe,
                corrections["cpe_confirmed"],
            ),
        )
        for index, (name, outcome, cpe, correction) in enumerate(cases):
            component = Component.objects.create(
                sbom_document=document,
                bom_ref=f"migration-{index}",
                component_type="library",
                name=name,
                version="1.0",
                cpe=original_value,
            )
            record = GroundTruth.objects.create(
                component=component,
                snapshot=snapshot,
                ground_truth_cpe=cpe,
                resolution_outcome=outcome,
                note=f"Preserve {name}",
            )
            record.correction_types.add(correction)
            records[name] = record.pk
        return records

    def test_forward_preserves_records_and_maps_only_explicit_meaning(
        self,
    ) -> None:
        identifiers = self._create_legacy_records()

        executor = MigrationExecutor(connection)
        executor.migrate(MIGRATE_TO)
        apps = executor.loader.project_state(MIGRATE_TO).apps
        GroundTruth = apps.get_model(
            "sboms",
            "ComponentCpeGroundTruth",
        )
        DiscrepancyType = apps.get_model(
            "sboms",
            "GroundTruthDiscrepancyType",
        )

        self.assertEqual(GroundTruth.objects.count(), 4)
        self.assertEqual(
            set(DiscrepancyType.objects.values_list("code", flat=True)),
            {
                "VENDOR_MISMATCH",
                "PRODUCT_MISMATCH",
                "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
                "VERSION_NOT_IN_DICTIONARY",
                "PART_MISMATCH",
            },
        )

        expected = {
            "mapped_without_reason": ("OFFICIAL_CPE_MAPPED", set()),
            "distribution": (
                "OFFICIAL_CPE_MAPPED",
                {"DISTRIBUTION_PACKAGE_VERSION_NORMALIZED"},
            ),
            "version_missing": (
                "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
                {"VERSION_NOT_IN_DICTIONARY"},
            ),
            "confirmed": ("CPE_CONFIRMED", set()),
        }
        for name, (decision, discrepancy_codes) in expected.items():
            record = GroundTruth.objects.get(pk=identifiers[name])
            self.assertEqual(record.decision, decision)
            self.assertEqual(
                set(
                    record.discrepancy_types.values_list(
                        "code",
                        flat=True,
                    )
                ),
                discrepancy_codes,
            )
            self.assertEqual(record.note, f"Preserve {name}")
            self.assertEqual(record.correction_types.count(), 1)

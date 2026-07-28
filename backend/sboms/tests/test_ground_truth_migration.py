import re
from datetime import datetime, timezone
from uuid import UUID

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class GroundTruthDecisionTypeMigrationTests(TransactionTestCase):
    migrate_from = (
        "sboms",
        "0003_componentcpegroundtruth_manual_cpe",
    )
    migrate_to = (
        "sboms",
        "0004_groundtruthdecisiontype",
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
            decision_type="기존 시험 유형",
            note="Delete this calibration record",
        )
        second_component = Component.objects.create(
            sbom_document=document,
            bom_ref="legacy-second",
            component_type="library",
            name="legacy second",
            cpe=cpe.cpe_name,
        )
        second_record = GroundTruth.objects.create(
            component=second_component,
            snapshot=snapshot,
            ground_truth_cpe=cpe,
            decision_type="Legacy review",
            note="Delete this legacy record",
        )
        self.record_id = record.id
        self.second_record_id = second_record.id
        self.component_id = component.id
        self.second_component_id = second_component.id
        self.cpe_id = cpe.id
        self.original_component_cpe = component.cpe

        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_to])
        self.apps = executor.loader.project_state(
            [self.migrate_to]
        ).apps

    def test_existing_ground_truth_and_legacy_values_are_removed(
        self,
    ) -> None:
        GroundTruth = self.apps.get_model(
            "sboms",
            "ComponentCpeGroundTruth",
        )
        DecisionType = self.apps.get_model(
            "sboms",
            "GroundTruthDecisionType",
        )

        self.assertEqual(GroundTruth.objects.count(), 0)
        self.assertFalse(
            DecisionType.objects.filter(
                name__in=("기존 시험 유형", "Legacy review")
            ).exists()
        )

    def test_protected_source_data_is_unchanged(self) -> None:
        Component = self.apps.get_model("sboms", "Component")
        CpeName = self.apps.get_model(
            "cpe_dictionary",
            "CpeName",
        )

        self.assertEqual(Component.objects.count(), 2)
        self.assertEqual(CpeName.objects.count(), 1)
        self.assertEqual(
            Component.objects.get(pk=self.component_id).cpe,
            self.original_component_cpe,
        )
        self.assertEqual(
            Component.objects.get(pk=self.second_component_id).cpe,
            self.original_component_cpe,
        )

    def test_exact_english_taxonomy_is_created(self) -> None:
        DecisionType = self.apps.get_model(
            "sboms",
            "GroundTruthDecisionType",
        )
        expected = {
            "Official CPE confirmed": (
                "The exact active CPE Name is present in the "
                "selected CPE Dictionary snapshot."
            ),
            (
                "Official CPE family confirmed; version not in "
                "Dictionary"
            ): (
                "The canonical part, vendor, and product are "
                "confirmed, but the exact component version is "
                "absent from the selected CPE Dictionary snapshot."
            ),
            "Distribution package revision normalized": (
                "A distribution-specific package revision was "
                "removed while preserving the confirmed upstream "
                "product version."
            ),
            "Deprecated CPE redirected to active CPE": (
                "A deprecated CPE or alias was resolved to its "
                "active canonical CPE."
            ),
            "Mapped to parent product CPE": (
                "The component is a subpackage or derived package "
                "represented by the parent product's CPE."
            ),
            "No independent CPE": (
                "The component is a subpackage, data package, "
                "compatibility package, or internal unit without "
                "an independent CPE identity."
            ),
            "Direct official CPE not confirmed": (
                "No directly corresponding official CPE family "
                "could be confirmed from the available evidence."
            ),
        }
        actual_rows = list(
            DecisionType.objects.order_by("id").values_list(
                "name",
                "description",
            )
        )
        actual = dict(actual_rows)

        self.assertEqual(actual, expected)
        self.assertEqual(actual_rows, list(expected.items()))
        self.assertEqual(DecisionType.objects.count(), 7)
        self.assertFalse(
            any(
                re.search(
                    (
                        "[\u1100-\u11ff\u3130-\u318f"
                        "\ua960-\ua97f\uac00-\ud7ff"
                        "\uffa0-\uffdc]"
                    ),
                    f"{name}{description}",
                )
                for name, description in actual.items()
            )
        )
        self.assertTrue(
            all(
                DecisionType.objects.values_list(
                    "is_active",
                    flat=True,
                )
            )
        )

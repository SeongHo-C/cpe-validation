from datetime import datetime, timezone
from importlib import import_module
from types import SimpleNamespace

from django.apps import apps
from django.db import connection, migrations
from django.test import TestCase

from cpe_dictionary.models import CpeDictionarySnapshot
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    DockerImage,
    GroundTruthCorrectionType,
    GroundTruthDecision,
    SBOMDocument,
)


migration = import_module(
    "sboms.migrations.0005_resolution_outcome_correction_types"
)


def create_snapshot() -> CpeDictionarySnapshot:
    return CpeDictionarySnapshot.objects.create(
        snapshot_id="20260725T035002Z",
        status=CpeDictionarySnapshot.Status.COMPLETE,
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


def create_component() -> Component:
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
    return Component.objects.create(
        sbom_document=document,
        bom_ref="pkg:generic/migration-test@1.0",
        component_type="library",
        name="migration-test",
        version="1.0",
        cpe=(
            "cpe:2.3:a:example:migration-test:"
            "1.0:*:*:*:*:*:*:*"
        ),
    )


class GroundTruthTaxonomyResetMigrationTests(TestCase):
    def test_reset_removes_only_ground_truth_annotations(
        self,
    ) -> None:
        snapshot = create_snapshot()
        component = create_component()
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=component,
            snapshot=snapshot,
            decision=GroundTruthDecision.OFFICIAL_CPE_MAPPED,
            manual_ground_truth_cpe=(
                "cpe:2.3:a:example:migration-test:"
                "2.0:*:*:*:*:*:*:*"
            ),
            note="Pilot annotation to reset",
        )
        ground_truth.correction_types.add(
            GroundTruthCorrectionType.objects.get(
                code="vendor_corrected"
            )
        )
        preserved = {
            "images": DockerImage.objects.count(),
            "documents": SBOMDocument.objects.count(),
            "components": Component.objects.count(),
            "snapshots": CpeDictionarySnapshot.objects.count(),
        }

        migration.reset_legacy_ground_truth_and_seed_corrections(
            apps,
            SimpleNamespace(connection=connection),
        )

        self.assertEqual(
            ComponentCpeGroundTruth.objects.count(),
            0,
        )
        self.assertEqual(
            {
                "images": DockerImage.objects.count(),
                "documents": SBOMDocument.objects.count(),
                "components": Component.objects.count(),
                "snapshots": CpeDictionarySnapshot.objects.count(),
            },
            preserved,
        )

    def test_seeds_exact_correction_type_taxonomy(self) -> None:
        migration.reset_legacy_ground_truth_and_seed_corrections(
            apps,
            SimpleNamespace(connection=connection),
        )

        self.assertEqual(
            set(
                GroundTruthCorrectionType.objects.values_list(
                    "code",
                    flat=True,
                )
            ),
            {
                "vendor_corrected",
                "product_corrected",
                "distribution_package_version_normalized",
                "mapped_to_parent_product",
                "deprecated_cpe_redirected",
            },
        )
        self.assertFalse(
            GroundTruthCorrectionType.objects.filter(
                is_active=False
            ).exists()
        )

    def test_data_reset_operation_is_explicitly_irreversible(
        self,
    ) -> None:
        reset_operation = next(
            operation
            for operation in migration.Migration.operations
            if isinstance(operation, migrations.RunPython)
        )

        self.assertFalse(reset_operation.reversible)
        self.assertIsNone(reset_operation.reverse_code)

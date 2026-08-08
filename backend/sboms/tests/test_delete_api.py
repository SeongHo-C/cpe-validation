from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from uuid import UUID

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import DatabaseError
from django.db.models.signals import post_delete
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from sboms.deletions import delete_sbom_document
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    GroundTruthCorrectionType,
    SBOMDocument,
)


class SBOMDocumentDeleteAPITests(APITestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.media_root = Path(self.temporary_directory.name)
        self.media_settings = override_settings(
            MEDIA_ROOT=self.media_root,
            CPE_DICTIONARY_SNAPSHOT_ID=None,
        )
        self.media_settings.enable()

    def tearDown(self) -> None:
        self.media_settings.disable()
        self.temporary_directory.cleanup()

    @staticmethod
    def build_document(serial_number: str) -> dict[str, object]:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "tools": [
                    {
                        "vendor": "EMBA",
                        "name": "EMBA",
                        "version": "1.0",
                    }
                ]
            },
            "components": [
                {
                    "bom-ref": f"{serial_number}-openssl",
                    "type": "library",
                    "name": "openssl",
                    "version": "3.0.0",
                    "cpe": (
                        "cpe:2.3:a:openssl:openssl:3.0.0:"
                        "*:*:*:*:*:*:*"
                    ),
                },
                {
                    "bom-ref": f"{serial_number}-busybox",
                    "type": "application",
                    "name": "busybox",
                    "version": "1.36.0",
                },
            ],
        }

    def upload_document(
        self,
        serial_number: str,
        *,
        product_name: str,
    ) -> SBOMDocument:
        content = json.dumps(
            self.build_document(serial_number),
            separators=(",", ":"),
        ).encode("utf-8")
        response = self.client.post(
            reverse("sboms_api:sbom-upload"),
            {
                "file": SimpleUploadedFile(
                    f"{product_name}.cdx.json",
                    content,
                    content_type="application/json",
                ),
                "manufacturer": "Example Devices",
                "product_name": product_name,
                "product_version": "1.0",
            },
            format="multipart",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return SBOMDocument.objects.get(pk=response.json()["id"])

    @staticmethod
    def delete_url(document_id: int) -> str:
        return reverse("sboms_api:sbom-detail", args=[document_id])

    @staticmethod
    def create_snapshot() -> CpeDictionarySnapshot:
        return CpeDictionarySnapshot.objects.create(
            snapshot_id="delete-test-snapshot",
            status=CpeDictionarySnapshot.Status.COMPLETE,
            feed_last_modified=datetime(
                2026,
                8,
                8,
                tzinfo=timezone.utc,
            ),
            manifest_sha256="a" * 64,
            archive_sha256="b" * 64,
            content_sha256="c" * 64,
            member_count=1,
            expected_record_count=1,
            record_count=1,
            active_count=1,
            deprecated_count=0,
            completed_at=datetime(
                2026,
                8,
                8,
                tzinfo=timezone.utc,
            ),
        )

    @staticmethod
    def create_cpe(snapshot: CpeDictionarySnapshot) -> CpeName:
        return CpeName.objects.create(
            snapshot=snapshot,
            cpe_name_id=UUID("11111111-1111-4111-8111-111111111111"),
            cpe_name=(
                "cpe:2.3:a:example:router:1.0:*:*:*:*:*:*:*"
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
            product="router",
            version="1.0",
            update="*",
            edition="*",
            language="*",
            sw_edition="*",
            target_sw="*",
            target_hw="*",
            other="*",
        )

    def test_delete_removes_document_components_and_uploaded_file(
        self,
    ) -> None:
        document = self.upload_document(
            "urn:uuid:delete-success",
            product_name="delete-success",
        )
        document_id = document.id
        uploaded_path = Path(document.uploaded_file.path)
        component_ids = list(
            document.components.values_list("id", flat=True)
        )
        self.assertEqual(len(component_ids), 2)
        self.assertTrue(uploaded_path.exists())

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.delete(self.delete_url(document_id))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(
            SBOMDocument.objects.filter(pk=document_id).exists()
        )
        self.assertFalse(
            Component.objects.filter(pk__in=component_ids).exists()
        )
        self.assertFalse(uploaded_path.exists())

    def test_delete_preserves_other_sbom_components_and_file(self) -> None:
        first = self.upload_document(
            "urn:uuid:first-delete",
            product_name="first-delete",
        )
        second = self.upload_document(
            "urn:uuid:second-preserved",
            product_name="second-preserved",
        )
        first_id = first.id
        first_component_ids = list(
            first.components.values_list("id", flat=True)
        )
        second_component_ids = list(
            second.components.values_list("id", flat=True)
        )
        second_path = Path(second.uploaded_file.path)

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.delete(self.delete_url(first_id))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(SBOMDocument.objects.filter(pk=first_id).exists())
        self.assertFalse(
            Component.objects.filter(pk__in=first_component_ids).exists()
        )
        self.assertTrue(
            SBOMDocument.objects.filter(pk=second.id).exists()
        )
        self.assertEqual(
            Component.objects.filter(pk__in=second_component_ids).count(),
            2,
        )
        self.assertTrue(second_path.exists())

    def test_delete_preserves_global_reference_data(self) -> None:
        document = self.upload_document(
            "urn:uuid:reference-preservation",
            product_name="reference-preservation",
        )
        snapshot = self.create_snapshot()
        cpe_name = self.create_cpe(snapshot)
        correction_type = GroundTruthCorrectionType.objects.create(
            code="vendor_typo",
            name="Vendor Typo",
        )

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.delete(self.delete_url(document.id))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertTrue(
            CpeDictionarySnapshot.objects.filter(pk=snapshot.pk).exists()
        )
        self.assertTrue(CpeName.objects.filter(pk=cpe_name.pk).exists())
        self.assertTrue(
            GroundTruthCorrectionType.objects.filter(
                pk=correction_type.pk
            ).exists()
        )

    def test_protected_review_data_returns_conflict_and_preserves_all(
        self,
    ) -> None:
        document = self.upload_document(
            "urn:uuid:protected-review",
            product_name="protected-review",
        )
        component = document.components.first()
        assert component is not None
        snapshot = self.create_snapshot()
        correction_type = GroundTruthCorrectionType.objects.create(
            code="product_typo",
            name="Product Typo",
        )
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=component,
            snapshot=snapshot,
            manual_ground_truth_cpe=(
                "cpe:2.3:a:example:reviewed:1.0:*:*:*:*:*:*:*"
            ),
        )
        ground_truth.correction_types.add(correction_type)
        uploaded_path = Path(document.uploaded_file.path)

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.delete(self.delete_url(document.id))

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(
            response.json(),
            {
                "code": "sbom_delete_conflict",
                "detail": (
                    "This SBOM cannot be deleted while its components "
                    "have protected review data."
                ),
            },
        )
        self.assertEqual(callbacks, [])
        self.assertTrue(
            SBOMDocument.objects.filter(pk=document.id).exists()
        )
        self.assertEqual(document.components.count(), 2)
        self.assertTrue(
            ComponentCpeGroundTruth.objects.filter(
                pk=ground_truth.pk
            ).exists()
        )
        self.assertTrue(
            GroundTruthCorrectionType.objects.filter(
                pk=correction_type.pk
            ).exists()
        )
        self.assertTrue(
            CpeDictionarySnapshot.objects.filter(pk=snapshot.pk).exists()
        )
        self.assertTrue(uploaded_path.exists())

    def test_delete_missing_document_returns_not_found(self) -> None:
        response = self.client.delete(self.delete_url(999999))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_database_delete_failure_preserves_row_and_file(self) -> None:
        document = self.upload_document(
            "urn:uuid:database-failure",
            product_name="database-failure",
        )
        uploaded_path = Path(document.uploaded_file.path)

        def fail_after_component_delete(**kwargs) -> None:
            del kwargs
            raise DatabaseError("simulated delete failure")

        dispatch_uid = "test_sbom_delete_transaction_rollback"
        post_delete.connect(
            fail_after_component_delete,
            sender=Component,
            weak=False,
            dispatch_uid=dispatch_uid,
        )
        try:
            with self.captureOnCommitCallbacks(execute=True) as callbacks:
                with self.assertRaises(DatabaseError):
                    delete_sbom_document(document)
        finally:
            post_delete.disconnect(
                sender=Component,
                dispatch_uid=dispatch_uid,
            )

        self.assertEqual(callbacks, [])
        self.assertTrue(
            SBOMDocument.objects.filter(pk=document.id).exists()
        )
        self.assertEqual(document.components.count(), 2)
        self.assertTrue(uploaded_path.exists())

    def test_file_cleanup_failure_is_logged_after_successful_delete(
        self,
    ) -> None:
        document = self.upload_document(
            "urn:uuid:file-cleanup-failure",
            product_name="file-cleanup-failure",
        )
        document_id = document.id
        uploaded_path = Path(document.uploaded_file.path)

        with mock.patch.object(
            document.uploaded_file.storage,
            "delete",
            side_effect=OSError("simulated storage failure"),
        ):
            with self.assertLogs("sboms.deletions", level="ERROR"):
                with self.captureOnCommitCallbacks(execute=True):
                    response = self.client.delete(
                        self.delete_url(document_id)
                    )

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(
            SBOMDocument.objects.filter(pk=document_id).exists()
        )
        self.assertTrue(uploaded_path.exists())

    def test_shared_storage_name_is_preserved(self) -> None:
        first = self.upload_document(
            "urn:uuid:shared-storage-first",
            product_name="shared-storage-first",
        )
        second = self.upload_document(
            "urn:uuid:shared-storage-second",
            product_name="shared-storage-second",
        )
        shared_name = first.uploaded_file.name
        shared_path = Path(first.uploaded_file.path)
        second.uploaded_file.name = shared_name
        second.save(update_fields=["uploaded_file"])

        with self.assertLogs("sboms.deletions", level="WARNING"):
            with self.captureOnCommitCallbacks(execute=True):
                response = self.client.delete(self.delete_url(first.id))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertTrue(
            SBOMDocument.objects.filter(pk=second.id).exists()
        )
        self.assertEqual(
            SBOMDocument.objects.get(pk=second.id).uploaded_file.name,
            shared_name,
        )
        self.assertTrue(shared_path.exists())
        self.assertEqual(
            hashlib.sha256(shared_path.read_bytes()).hexdigest(),
            first.file_sha256,
        )

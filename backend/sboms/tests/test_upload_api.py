from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import IntegrityError
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from cpe_dictionary.models import CpeDictionarySnapshot
from sboms.models import Component, DockerImage, SBOMDocument


class SBOMDocumentUploadAPITests(APITestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.media_root = Path(self.temporary_directory.name)
        self.media_settings = override_settings(
            MEDIA_ROOT=self.media_root,
            CPE_DICTIONARY_SNAPSHOT_ID=None,
        )
        self.media_settings.enable()
        self.upload_url = reverse("sboms_api:sbom-upload")

    def tearDown(self) -> None:
        self.media_settings.disable()
        self.temporary_directory.cleanup()

    @staticmethod
    def build_document(
        *,
        serial_number: str = "urn:uuid:emba-fixture",
        include_components: bool = True,
    ) -> dict[str, object]:
        document: dict[str, object] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": "2026-08-05T01:02:03+00:00",
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "EMBA",
                            "version": "2.0.1",
                        }
                    ]
                },
            },
        }
        if include_components:
            document["components"] = [
                {
                    "bom-ref": "pkg:generic/openssl@3.0.0",
                    "type": "library",
                    "group": "openssl",
                    "name": "openssl",
                    "version": "3.0.0",
                    "publisher": "OpenSSL Software Foundation",
                    "purl": "pkg:generic/openssl@3.0.0",
                    "cpe": (
                        "cpe:2.3:a:openssl:openssl:3.0.0:"
                        "*:*:*:*:*:*:*"
                    ),
                    "properties": [
                        {
                            "name": "emba:source",
                            "value": "firmware",
                        }
                    ],
                    "licenses": [
                        {"license": {"id": "Apache-2.0"}}
                    ],
                }
            ]
        return document

    @staticmethod
    def encode_document(document: object) -> bytes:
        return json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def post_bytes(
        self,
        content: bytes,
        *,
        filename: str = "emba-sbom.json",
        **metadata: str,
    ):
        values: dict[str, object] = {
            "file": SimpleUploadedFile(
                filename,
                content,
                content_type="application/json",
            ),
            **metadata,
        }
        return self.client.post(
            self.upload_url,
            values,
            format="multipart",
        )

    def post_document(
        self,
        document: object,
        *,
        filename: str = "emba-sbom.json",
        **metadata: str,
    ):
        return self.post_bytes(
            self.encode_document(document),
            filename=filename,
            **metadata,
        )

    def stored_files(self) -> list[Path]:
        return sorted(
            path for path in self.media_root.rglob("*") if path.is_file()
        )

    @staticmethod
    def create_snapshot() -> CpeDictionarySnapshot:
        return CpeDictionarySnapshot.objects.create(
            snapshot_id="upload-test-snapshot",
            status=CpeDictionarySnapshot.Status.COMPLETE,
            feed_last_modified=datetime(
                2026,
                8,
                5,
                tzinfo=timezone.utc,
            ),
            manifest_sha256="a" * 64,
            archive_sha256="b" * 64,
            content_sha256="c" * 64,
            member_count=1,
            expected_record_count=0,
            record_count=0,
            active_count=0,
            deprecated_count=0,
            completed_at=datetime(
                2026,
                8,
                5,
                tzinfo=timezone.utc,
            ),
        )

    def test_docker_document_remains_valid_without_uploaded_file(
        self,
    ) -> None:
        image = DockerImage.objects.create(
            repository="docker.io/library/example",
            tag="1.0",
            manifest_digest="sha256:" + ("a" * 64),
            pinned_reference=(
                "docker.io/library/example@sha256:" + ("a" * 64)
            ),
        )

        document = SBOMDocument.objects.create(
            docker_image=image,
            source_path="pilot/results/sboms/example.cdx.json",
            file_sha256="b" * 64,
            spec_version="1.7",
            generator_name="syft",
            generator_version="1.49.0",
        )

        self.assertEqual(document.uploaded_file.name, "")
        self.assertEqual(self.stored_files(), [])

    def test_upload_stores_document_components_and_original_bytes(
        self,
    ) -> None:
        self.create_snapshot()
        raw_bytes = self.encode_document(self.build_document())

        response = self.post_bytes(
            raw_bytes,
            filename="router-firmware.cdx.json",
            manufacturer="Example Devices",
            product_name="Router 1000",
            product_version="1.2.3",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        body = response.json()
        self.assertEqual(
            set(body),
            {
                "id",
                "manufacturer",
                "product_name",
                "product_version",
                "original_filename",
                "format",
                "spec_version",
                "generator_name",
                "generator_version",
                "component_count",
                "uploaded_at",
                "file_sha256",
                "serial_number",
                "document_version",
                "generated_at",
            },
        )
        digest = hashlib.sha256(raw_bytes).hexdigest()
        self.assertEqual(body["file_sha256"], digest)
        self.assertEqual(body["format"], "CYCLONEDX_JSON")
        self.assertEqual(body["spec_version"], "1.6")
        self.assertEqual(body["generator_name"], "EMBA")
        self.assertEqual(body["generator_version"], "2.0.1")
        self.assertEqual(body["component_count"], 1)

        document = SBOMDocument.objects.get()
        self.assertIsNone(document.docker_image)
        self.assertEqual(document.manufacturer, "Example Devices")
        self.assertEqual(document.product_name, "Router 1000")
        self.assertEqual(document.product_version, "1.2.3")
        self.assertEqual(
            document.original_filename,
            "router-firmware.cdx.json",
        )
        self.assertEqual(document.source_path, "")
        self.assertEqual(document.source_type, "upload")
        self.assertEqual(document.scope, "document")
        expected_name = f"uploaded-sboms/{digest}.json"
        self.assertEqual(document.uploaded_file.name, expected_name)
        self.assertFalse(
            (self.media_root / "uploaded-sboms" / digest[:2]).exists()
        )
        with document.uploaded_file.open("rb") as stored_file:
            self.assertEqual(stored_file.read(), raw_bytes)

        component = Component.objects.get()
        self.assertEqual(component.name, "openssl")
        self.assertEqual(component.version, "3.0.0")
        self.assertEqual(
            component.purl,
            "pkg:generic/openssl@3.0.0",
        )
        self.assertEqual(
            component.properties,
            [{"name": "emba:source", "value": "firmware"}],
        )

        list_response = self.client.get(
            reverse("sboms_api:sbom-list")
        )
        detail_response = self.client.get(
            reverse("sboms_api:sbom-detail", args=[document.id])
        )
        component_response = self.client.get(
            reverse("sboms_api:component-list"),
            {"sbom_id": document.id, "has_cpe": "all"},
        )
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(list_response.json()["results"][0]["id"], document.id)
        self.assertEqual(detail_response.status_code, status.HTTP_200_OK)
        self.assertEqual(detail_response.json()["id"], document.id)
        self.assertEqual(
            component_response.status_code,
            status.HTTP_200_OK,
        )
        self.assertEqual(component_response.json()["count"], 1)
        component_row = component_response.json()["results"][0]
        self.assertEqual(component_row["sbom_document_id"], document.id)
        self.assertIsNone(component_row["image"])

    def test_minimal_document_without_components_is_allowed(self) -> None:
        response = self.post_document(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
            }
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.json()["component_count"], 0)
        document = SBOMDocument.objects.get()
        self.assertEqual(document.spec_version, "1.5")
        self.assertEqual(document.generator_name, "")
        self.assertEqual(Component.objects.count(), 0)
        self.assertEqual(len(self.stored_files()), 1)

    def test_original_filename_uses_safe_basename(self) -> None:
        cases = (
            ("../../device.cdx.json", "urn:uuid:posix-path"),
            (r"C:\fakepath\device.cdx.json", "urn:uuid:windows-path"),
        )

        for filename, serial_number in cases:
            with self.subTest(filename=filename):
                raw_bytes = self.encode_document(
                    self.build_document(serial_number=serial_number)
                )
                response = self.post_bytes(
                    raw_bytes,
                    filename=filename,
                )

                self.assertEqual(
                    response.status_code,
                    status.HTTP_201_CREATED,
                )
                document = SBOMDocument.objects.get(
                    pk=response.json()["id"]
                )
                digest = hashlib.sha256(raw_bytes).hexdigest()
                self.assertEqual(
                    document.original_filename,
                    "device.cdx.json",
                )
                self.assertEqual(
                    document.uploaded_file.name,
                    f"uploaded-sboms/{digest}.json",
                )

    def test_duplicate_bytes_return_existing_id_without_extra_file(
        self,
    ) -> None:
        raw_bytes = self.encode_document(self.build_document())
        first = self.post_bytes(raw_bytes, filename="first.json")
        existing_id = first.json()["id"]

        for filename in ("first.json", "renamed.json"):
            with self.subTest(filename=filename):
                response = self.post_bytes(
                    raw_bytes,
                    filename=filename,
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_409_CONFLICT,
                )
                self.assertEqual(
                    response.json(),
                    {
                        "code": "duplicate_sbom",
                        "detail": (
                            "An SBOM with the same SHA-256 is already "
                            "registered."
                        ),
                        "existing_sbom_id": existing_id,
                    },
                )

        self.assertEqual(SBOMDocument.objects.count(), 1)
        self.assertEqual(Component.objects.count(), 1)
        self.assertEqual(len(self.stored_files()), 1)

    def test_same_product_with_different_bytes_is_allowed(self) -> None:
        metadata = {
            "manufacturer": "Example Devices",
            "product_name": "Router 1000",
            "product_version": "1.2.3",
        }

        first = self.post_document(
            self.build_document(serial_number="urn:uuid:first"),
            **metadata,
        )
        second = self.post_document(
            self.build_document(serial_number="urn:uuid:second"),
            filename="second.json",
            **metadata,
        )

        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        self.assertEqual(second.status_code, status.HTTP_201_CREATED)
        self.assertEqual(SBOMDocument.objects.count(), 2)
        self.assertEqual(Component.objects.count(), 2)
        self.assertEqual(len(self.stored_files()), 2)

    def test_product_metadata_is_stored_without_inference_or_trimming(
        self,
    ) -> None:
        response = self.post_document(
            self.build_document(),
            manufacturer="  Example Devices  ",
            product_name="  Router 1000  ",
            product_version="  1.2.3  ",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        document = SBOMDocument.objects.get()
        self.assertEqual(document.manufacturer, "  Example Devices  ")
        self.assertEqual(document.product_name, "  Router 1000  ")
        self.assertEqual(document.product_version, "  1.2.3  ")

    def test_missing_file_is_rejected_without_side_effects(self) -> None:
        response = self.client.post(
            self.upload_url,
            {},
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("file", response.json())
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)
        self.assertEqual(self.stored_files(), [])

    def test_invalid_documents_are_rejected_without_side_effects(
        self,
    ) -> None:
        cases: tuple[tuple[str, bytes], ...] = (
            ("invalid-json", b"{not-json"),
            ("root-array", self.encode_document([])),
            (
                "wrong-format",
                self.encode_document(
                    {"bomFormat": "Other", "specVersion": "1.6"}
                ),
            ),
            (
                "missing-spec-version",
                self.encode_document({"bomFormat": "CycloneDX"}),
            ),
            (
                "non-string-spec-version",
                self.encode_document(
                    {"bomFormat": "CycloneDX", "specVersion": 1.6}
                ),
            ),
            (
                "empty-spec-version",
                self.encode_document(
                    {"bomFormat": "CycloneDX", "specVersion": ""}
                ),
            ),
            (
                "whitespace-spec-version",
                self.encode_document(
                    {"bomFormat": "CycloneDX", "specVersion": "  "}
                ),
            ),
            (
                "non-array-components",
                self.encode_document(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "components": {},
                    }
                ),
            ),
            (
                "spdx",
                self.encode_document(
                    {
                        "bomFormat": "SPDX",
                        "specVersion": "SPDX-2.3",
                    }
                ),
            ),
        )

        for name, content in cases:
            with self.subTest(name=name):
                response = self.post_bytes(
                    content,
                    filename=f"{name}.json",
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertEqual(response.json()["code"], "invalid_sbom")
                self.assertEqual(SBOMDocument.objects.count(), 0)
                self.assertEqual(Component.objects.count(), 0)
                self.assertEqual(self.stored_files(), [])

    def test_product_metadata_length_is_validated(self) -> None:
        response = self.post_document(
            self.build_document(),
            manufacturer="x" * 256,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("manufacturer", response.json())
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(self.stored_files(), [])

    def test_component_failure_rolls_back_database_and_file(self) -> None:
        existing_bytes = self.encode_document(
            self.build_document(serial_number="urn:uuid:existing")
        )
        existing_response = self.post_bytes(
            existing_bytes,
            filename="existing.json",
        )
        existing = SBOMDocument.objects.get(
            pk=existing_response.json()["id"]
        )
        existing_path = self.media_root / existing.uploaded_file.name

        with (
            mock.patch(
                "sboms.uploads.create_components_from_parsed",
                side_effect=RuntimeError("intentional component failure"),
            ),
            self.assertLogs("sboms.api.views", level="ERROR"),
        ):
            response = self.post_document(
                self.build_document(serial_number="urn:uuid:failed"),
                filename="failed.json",
            )

        self.assertEqual(
            response.status_code,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        self.assertEqual(
            response.json(),
            {
                "code": "sbom_import_failed",
                "detail": "The SBOM could not be imported.",
            },
        )
        self.assertNotIn(
            str(self.media_root),
            response.content.decode("utf-8"),
        )
        self.assertEqual(SBOMDocument.objects.count(), 1)
        self.assertEqual(Component.objects.count(), 1)
        self.assertEqual(self.stored_files(), [existing_path])
        self.assertEqual(existing_path.read_bytes(), existing_bytes)

    def test_integrity_error_race_returns_duplicate_response(self) -> None:
        raw_bytes = self.encode_document(self.build_document())
        existing_response = self.post_bytes(
            raw_bytes,
            filename="existing.json",
        )
        existing = SBOMDocument.objects.get(
            pk=existing_response.json()["id"]
        )
        existing_path = self.media_root / existing.uploaded_file.name

        with (
            mock.patch(
                "sboms.uploads._existing_document_id",
                side_effect=[None, existing.id],
            ),
            mock.patch(
                "sboms.uploads.SBOMDocument.objects.create",
                side_effect=IntegrityError("concurrent duplicate"),
            ),
        ):
            response = self.post_bytes(raw_bytes)

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(
            response.json()["existing_sbom_id"],
            existing.id,
        )
        self.assertEqual(SBOMDocument.objects.count(), 1)
        self.assertEqual(Component.objects.count(), 1)
        self.assertEqual(self.stored_files(), [existing_path])
        self.assertEqual(existing_path.read_bytes(), raw_bytes)

    def test_unrelated_integrity_error_is_not_reported_as_duplicate(
        self,
    ) -> None:
        with (
            mock.patch(
                "sboms.uploads._existing_document_id",
                side_effect=[None, None],
            ),
            mock.patch(
                "sboms.uploads.SBOMDocument.objects.create",
                side_effect=IntegrityError("unrelated constraint"),
            ),
            self.assertLogs("sboms.api.views", level="ERROR"),
        ):
            response = self.post_document(self.build_document())

        self.assertEqual(
            response.status_code,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        self.assertEqual(response.json()["code"], "sbom_import_failed")
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)
        self.assertEqual(self.stored_files(), [])

    def test_existing_storage_path_is_not_deleted(self) -> None:
        raw_bytes = self.encode_document(self.build_document())
        digest = hashlib.sha256(raw_bytes).hexdigest()
        existing_path = (
            self.media_root
            / "uploaded-sboms"
            / f"{digest}.json"
        )
        existing_path.parent.mkdir(parents=True)
        existing_path.write_bytes(b"pre-existing storage file")

        with self.assertLogs("sboms.api.views", level="ERROR"):
            response = self.post_bytes(raw_bytes)

        self.assertEqual(
            response.status_code,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)
        self.assertEqual(
            existing_path.read_bytes(),
            b"pre-existing storage file",
        )
        self.assertEqual(self.stored_files(), [existing_path])

    def test_storage_renamed_file_cleans_up_returned_name_only(
        self,
    ) -> None:
        raw_bytes = self.encode_document(self.build_document())
        digest = hashlib.sha256(raw_bytes).hexdigest()
        expected_name = f"uploaded-sboms/{digest}.json"
        returned_name = f"uploaded-sboms/{digest}_1.json"
        storage = SBOMDocument._meta.get_field(
            "uploaded_file"
        ).storage

        with (
            mock.patch.object(storage, "exists", return_value=False),
            mock.patch.object(
                storage,
                "save",
                return_value=returned_name,
            ),
            mock.patch.object(storage, "delete") as delete_mock,
            self.assertLogs("sboms.api.views", level="ERROR"),
        ):
            response = self.post_bytes(raw_bytes)

        self.assertEqual(
            response.status_code,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        self.assertNotEqual(returned_name, expected_name)
        delete_mock.assert_called_once_with(returned_name)
        self.assertEqual(SBOMDocument.objects.count(), 0)
        self.assertEqual(Component.objects.count(), 0)
        self.assertEqual(self.stored_files(), [])

    def test_upload_endpoint_only_accepts_post(self) -> None:
        response = self.client.get(self.upload_url)

        self.assertEqual(
            response.status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

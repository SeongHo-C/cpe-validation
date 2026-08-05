from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.test import APITestCase

from sboms.models import Component, SBOMDocument


class SBOMDocumentAPITests(APITestCase):
    @staticmethod
    def create_document(
        suffix: str,
        **overrides,
    ) -> SBOMDocument:
        values = {
            "manufacturer": "NETGEAR",
            "product_name": "R7000",
            "product_version": "1.0.11.136",
            "original_filename": f"{suffix}.cdx.json",
            "source_path": f"private/storage/{suffix}.cdx.json",
            "file_sha256": suffix[0] * 64,
            "spec_version": "1.7",
            "serial_number": f"urn:uuid:{suffix}",
            "document_version": 3,
            "generator_name": "syft",
            "generator_version": "1.49.0",
            "generated_at": datetime(
                2026,
                8,
                1,
                3,
                4,
                5,
                tzinfo=timezone.utc,
            ),
        }
        values.update(overrides)
        return SBOMDocument.objects.create(**values)

    def test_empty_list_uses_standard_pagination(self) -> None:
        response = self.client.get(reverse("sboms_api:sbom-list"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {
                "count": 0,
                "page": 1,
                "page_size": 50,
                "total_pages": 1,
                "next": None,
                "previous": None,
                "results": [],
            },
        )

    def test_list_supports_dockerless_document_and_component_count(
        self,
    ) -> None:
        document = self.create_document("r")
        Component.objects.bulk_create(
            [
                Component(
                    sbom_document=document,
                    bom_ref=f"component-{index}",
                    component_type="library",
                    name=f"Component {index}",
                )
                for index in range(3)
            ]
        )

        response = self.client.get(reverse("sboms_api:sbom-list"))
        row = response.json()["results"][0]

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            set(row),
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
            },
        )
        self.assertEqual(row["id"], document.id)
        self.assertEqual(row["manufacturer"], "NETGEAR")
        self.assertEqual(row["product_name"], "R7000")
        self.assertEqual(row["product_version"], "1.0.11.136")
        self.assertEqual(row["original_filename"], "r.cdx.json")
        self.assertEqual(row["component_count"], 3)
        self.assertEqual(
            parse_datetime(row["uploaded_at"]),
            document.imported_at,
        )

    def test_list_uses_sbom_document_default_ordering(self) -> None:
        older = self.create_document(
            "a",
            manufacturer="",
            product_name="",
            product_version="",
            original_filename="",
        )
        newer = self.create_document("b")
        SBOMDocument.objects.filter(pk=older.pk).update(
            imported_at=newer.imported_at - timedelta(days=1)
        )

        response = self.client.get(reverse("sboms_api:sbom-list"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            [row["id"] for row in response.json()["results"]],
            [newer.id, older.id],
        )

    def test_detail_exposes_public_metadata_and_uploaded_alias(
        self,
    ) -> None:
        document = self.create_document("d")
        Component.objects.create(
            sbom_document=document,
            bom_ref="detail-component",
            component_type="library",
            name="Detail component",
        )

        response = self.client.get(
            reverse("sboms_api:sbom-detail", args=[document.id])
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
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
        self.assertEqual(body["file_sha256"], "d" * 64)
        self.assertEqual(body["spec_version"], "1.7")
        self.assertEqual(body["serial_number"], "urn:uuid:d")
        self.assertEqual(body["document_version"], 3)
        self.assertEqual(body["generator_name"], "syft")
        self.assertEqual(body["generator_version"], "1.49.0")
        self.assertEqual(
            parse_datetime(body["generated_at"]),
            document.generated_at,
        )
        self.assertEqual(
            parse_datetime(body["uploaded_at"]),
            document.imported_at,
        )
        self.assertEqual(body["component_count"], 1)

    def test_detail_returns_404_for_unknown_document(self) -> None:
        response = self.client.get(
            reverse("sboms_api:sbom-detail", args=[999999])
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_endpoints_are_read_only(self) -> None:
        document = self.create_document("w")
        requests = (
            ("post", reverse("sboms_api:sbom-list")),
            (
                "patch",
                reverse(
                    "sboms_api:sbom-detail",
                    args=[document.id],
                ),
            ),
        )
        for method, url in requests:
            with self.subTest(method=method):
                response = getattr(self.client, method)(url, {})
                self.assertEqual(
                    response.status_code,
                    status.HTTP_405_METHOD_NOT_ALLOWED,
                )

    def test_list_query_count_does_not_grow_per_document(self) -> None:
        for index, suffix in enumerate("efghij"):
            document = self.create_document(suffix)
            Component.objects.bulk_create(
                [
                    Component(
                        sbom_document=document,
                        bom_ref=f"{suffix}-{component_index}",
                        component_type="library",
                        name=f"Component {index}-{component_index}",
                    )
                    for component_index in range(index)
                ]
            )

        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(
                reverse("sboms_api:sbom-list"),
                {"page_size": 200},
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["count"], 6)
        self.assertEqual(len(queries), 2)

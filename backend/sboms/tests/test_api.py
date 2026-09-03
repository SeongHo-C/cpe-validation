from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch
from uuid import UUID

from django.db import DatabaseError, connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from cpe_dictionary.models import (
    CpeDictionarySnapshot,
    CpeName,
)
from sboms.exact_matching import match_cpes
from sboms.models import Component, DockerImage, SBOMDocument


class ReadOnlyAPITests(APITestCase):
    shared_cpe = (
        "cpe:2.3:a:example:shared:1.0:*:*:*:*:*:*:*"
    )
    search_cpe = (
        "cpe:2.3:a:CpeNeedle:search-product:"
        "VersionNeedle:*:*:*:*:*:*:*"
    )
    os_cpe = "cpe:2.3:o:example:system:2.0:*:*:*:*:*:*:*"
    invalid_cpe = (
        "cpe:2.3:x:example:invalid:1.0:*:*:*:*:*:*:*"
    )

    @classmethod
    def setUpTestData(cls) -> None:
        cls.beta_image = DockerImage.objects.create(
            repository="docker.io/library/beta",
            tag="2.0",
            manifest_digest="sha256:" + ("b" * 64),
            pinned_reference=(
                "docker.io/library/beta@sha256:" + ("b" * 64)
            ),
        )
        cls.alpha_image = DockerImage.objects.create(
            repository="docker.io/library/alpha",
            tag="1.0",
            manifest_digest="sha256:" + ("a" * 64),
            pinned_reference=(
                "docker.io/library/alpha@sha256:" + ("a" * 64)
            ),
        )
        cls.beta_sbom = SBOMDocument.objects.create(
            docker_image=cls.beta_image,
            source_path="fixtures/sboms/beta-2.0.cdx.json",
            file_sha256="2" * 64,
            spec_version="1.7",
            serial_number="urn:uuid:beta",
            generator_name="syft",
            generator_version="1.49.0",
        )
        cls.dictionary_snapshot = (
            CpeDictionarySnapshot.objects.create(
                snapshot_id="20260725T035002Z",
                status=CpeDictionarySnapshot.Status.COMPLETE,
                feed_last_modified=datetime(
                    2026,
                    7,
                    25,
                    3,
                    50,
                    2,
                    tzinfo=timezone.utc,
                ),
                manifest_sha256="d" * 64,
                archive_sha256="e" * 64,
                content_sha256="f" * 64,
                member_count=1,
                expected_record_count=2,
                record_count=2,
                active_count=1,
                deprecated_count=1,
                completed_at=datetime(
                    2026,
                    7,
                    27,
                    tzinfo=timezone.utc,
                ),
            )
        )
        cls.active_cpe_name_id = UUID(
            "11111111-1111-4111-8111-111111111111"
        )
        cls.deprecated_cpe_name_id = UUID(
            "22222222-2222-4222-8222-222222222222"
        )
        for cpe_name_id, raw_cpe, deprecated in (
            (
                cls.active_cpe_name_id,
                cls.search_cpe,
                False,
            ),
            (
                cls.deprecated_cpe_name_id,
                cls.os_cpe,
                True,
            ),
        ):
            CpeName.objects.create(
                snapshot=cls.dictionary_snapshot,
                cpe_name_id=cpe_name_id,
                cpe_name=raw_cpe,
                deprecated=deprecated,
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
        cls.alpha_sbom = SBOMDocument.objects.create(
            docker_image=cls.alpha_image,
            source_path="fixtures/sboms/alpha-1.0.cdx.json",
            file_sha256="1" * 64,
            spec_version="1.7",
            serial_number="urn:uuid:alpha",
            generator_name="syft",
            generator_version="1.49.0",
        )

        cls.alpha_shared = Component.objects.create(
            sbom_document=cls.alpha_sbom,
            bom_ref="alpha-shared",
            component_type="library",
            name="Alpha Shared",
            version="1.0",
            cpe=cls.shared_cpe,
        )
        cls.no_cpe_component = Component.objects.create(
            sbom_document=cls.alpha_sbom,
            bom_ref="without-cpe",
            component_type="library",
            name="Without CPE",
            version="1.0",
        )
        cls.invalid_component = Component.objects.create(
            sbom_document=cls.alpha_sbom,
            bom_ref="invalid-cpe",
            component_type="library",
            name="Invalid CPE",
            version="1.0",
            cpe=cls.invalid_cpe,
        )
        cls.search_component = Component.objects.create(
            sbom_document=cls.alpha_sbom,
            bom_ref="BomRefNeedle",
            component_type="library",
            name="NameNeedle",
            version="VersionNeedle",
            publisher="PublisherNeedle",
            purl="pkg:generic/PurlNeedle@1.0",
            cpe=cls.search_cpe,
            properties=[
                {
                    "name": "syft:cpe23",
                    "value": (
                        "cpe:2.3:a:candidate:search:"
                        "*:*:*:*:*:*:*:*"
                    ),
                }
            ],
        )
        cls.beta_shared = Component.objects.create(
            sbom_document=cls.beta_sbom,
            bom_ref="beta-shared",
            component_type="library",
            name="Beta Shared",
            version="1.0",
            cpe=cls.shared_cpe,
        )
        cls.os_component = Component.objects.create(
            sbom_document=cls.beta_sbom,
            bom_ref="beta-os",
            component_type="operating-system",
            name="Beta OS",
            version="2.0",
            cpe=cls.os_cpe,
        )
        Component.objects.bulk_create(
            [
                Component(
                    sbom_document=cls.beta_sbom,
                    bom_ref=f"filler-{index:02d}",
                    component_type="library",
                    name=f"Filler {index:02d}",
                    version=f"1.{index}",
                    publisher="Filler Publisher",
                    purl=f"pkg:generic/filler-{index}@1.{index}",
                    cpe=(
                        "cpe:2.3:a:example:"
                        f"filler-{index}:1.{index}:*:*:*:*:*:*:*"
                    ),
                )
                for index in range(52)
            ]
        )

    @staticmethod
    def model_counts() -> tuple[int, int, int, int, int]:
        return (
            DockerImage.objects.count(),
            SBOMDocument.objects.count(),
            Component.objects.count(),
            CpeDictionarySnapshot.objects.count(),
            CpeName.objects.count(),
        )

    def test_health_api(self) -> None:
        response = self.client.get(reverse("sboms_api:health"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {"status": "ok", "database": "ok"},
        )

    def test_health_api_hides_database_errors(self) -> None:
        with patch(
            "sboms.api.views.connection.cursor",
            side_effect=DatabaseError("sensitive connection details"),
        ):
            response = self.client.get(reverse("sboms_api:health"))

        self.assertEqual(
            response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            response.json(),
            {"status": "error", "database": "unavailable"},
        )
        self.assertNotContains(
            response,
            "sensitive connection details",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    def test_image_list_is_sorted_and_annotated(self) -> None:
        response = self.client.get(reverse("sboms_api:image-list"))
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            [row["repository"] for row in body],
            [
                "docker.io/library/alpha",
                "docker.io/library/beta",
            ],
        )
        alpha = body[0]
        self.assertEqual(alpha["sbom_count"], 1)
        self.assertEqual(alpha["total_components"], 4)
        self.assertEqual(alpha["components_with_primary_cpe"], 3)
        self.assertEqual(alpha["components_without_primary_cpe"], 1)
        self.assertEqual(alpha["unique_primary_cpes"], 3)
        self.assertAlmostEqual(alpha["primary_cpe_ratio"], 3 / 4)

    def test_image_detail_contains_documents_and_404s(self) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:image-detail",
                args=[self.alpha_image.id],
            )
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(body["sbom_documents"]), 1)
        self.assertEqual(
            body["sbom_documents"][0]["source_path"],
            self.alpha_sbom.source_path,
        )
        self.assertEqual(
            body["sbom_documents"][0]["generator_name"],
            "syft",
        )
        self.assertNotIn("components", body)

        missing_response = self.client.get(
            reverse("sboms_api:image-detail", args=[999999])
        )
        self.assertEqual(
            missing_response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_component_list_defaults_to_primary_cpe(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list")
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["count"], 57)
        self.assertEqual(body["page"], 1)
        self.assertEqual(body["page_size"], 50)
        self.assertEqual(body["total_pages"], 2)
        self.assertEqual(len(body["results"]), 50)
        self.assertTrue(
            all(row["cpe"] for row in body["results"])
        )
        self.assertTrue(
            all("dictionary_status" in row for row in body["results"])
        )
        self.assertTrue(
            all(
                "dictionary_match" not in row
                for row in body["results"]
            )
        )
        statuses = {
            row["id"]: row["dictionary_status"]
            for row in body["results"]
        }
        self.assertEqual(
            statuses[self.search_component.id],
            "OFFICIAL_ACTIVE",
        )
        self.assertEqual(
            statuses[self.invalid_component.id],
            "NOT_IN_DICTIONARY",
        )

    def test_has_cpe_false_returns_only_missing_cpes(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {"has_cpe": "FALSE"},
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["results"][0]["cpe"], "")
        self.assertEqual(
            body["results"][0]["dictionary_status"],
            "NOT_PRESENT",
        )

    def test_dictionary_status_filters_all_four_states(
        self,
    ) -> None:
        list_url = reverse("sboms_api:component-list")
        expected = {
            "OFFICIAL_ACTIVE": (
                1,
                {self.search_component.id},
            ),
            "OFFICIAL_DEPRECATED": (
                1,
                {self.os_component.id},
            ),
            "NOT_IN_DICTIONARY": (
                55,
                None,
            ),
            "NOT_PRESENT": (
                1,
                {self.no_cpe_component.id},
            ),
        }

        for requested_status, (
            expected_count,
            expected_ids,
        ) in expected.items():
            with self.subTest(
                dictionary_status=requested_status
            ):
                response = self.client.get(
                    list_url,
                    {
                        "dictionary_status": requested_status,
                        "page_size": 200,
                    },
                )
                body = response.json()
                self.assertEqual(
                    response.status_code,
                    status.HTTP_200_OK,
                )
                self.assertEqual(body["count"], expected_count)
                self.assertTrue(
                    all(
                        row["dictionary_status"]
                        == requested_status
                        for row in body["results"]
                    )
                )
                if expected_ids is not None:
                    self.assertEqual(
                        {
                            row["id"]
                            for row in body["results"]
                        },
                        expected_ids,
                    )

    def test_invalid_dictionary_status_returns_400(self) -> None:
        list_url = reverse("sboms_api:component-list")

        for requested_status in (
            "UNKNOWN",
            "not_in_dictionary",
        ):
            with self.subTest(
                dictionary_status=requested_status
            ):
                response = self.client.get(
                    list_url,
                    {"dictionary_status": requested_status},
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertEqual(
                    response.json()["code"],
                    "invalid_dictionary_status",
                )

    def test_incompatible_component_filters_return_400(
        self,
    ) -> None:
        list_url = reverse("sboms_api:component-list")
        combinations = (
            {
                "has_cpe": "true",
                "dictionary_status": "NOT_PRESENT",
            },
            {
                "has_cpe": "false",
                "dictionary_status": "OFFICIAL_ACTIVE",
            },
            {
                "has_cpe": "false",
                "dictionary_status": "OFFICIAL_DEPRECATED",
            },
            {
                "has_cpe": "false",
                "dictionary_status": "NOT_IN_DICTIONARY",
            },
        )

        for parameters in combinations:
            with self.subTest(parameters=parameters):
                response = self.client.get(
                    list_url,
                    parameters,
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertEqual(
                    response.json()["code"],
                    "incompatible_component_filters",
                )

    def test_dictionary_status_combines_with_existing_filters(
        self,
    ) -> None:
        list_url = reverse("sboms_api:component-list")

        active = self.client.get(
            list_url,
            {
                "dictionary_status": "OFFICIAL_ACTIVE",
                "image_id": self.alpha_image.id,
                "search": "NameNeedle",
            },
        ).json()
        self.assertEqual(active["count"], 1)
        self.assertEqual(
            active["results"][0]["id"],
            self.search_component.id,
        )

        deprecated = self.client.get(
            list_url,
            {
                "dictionary_status": "OFFICIAL_DEPRECATED",
                "image_id": self.beta_image.id,
            },
        ).json()
        self.assertEqual(deprecated["count"], 1)
        self.assertEqual(
            deprecated["results"][0]["id"],
            self.os_component.id,
        )

        not_in_dictionary = self.client.get(
            list_url,
            {
                "dictionary_status": "NOT_IN_DICTIONARY",
                "ordering": "-name",
                "page_size": 200,
            },
        ).json()
        names = [
            row["name"]
            for row in not_in_dictionary["results"]
        ]
        self.assertEqual(names, sorted(names, reverse=True))

    def test_reused_raw_cpe_has_consistent_list_status(
        self,
    ) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {
                "dictionary_status": "NOT_IN_DICTIONARY",
                "search": "Shared",
                "page_size": 200,
            },
        )
        rows = response.json()["results"]

        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row["id"] for row in rows},
            {self.alpha_shared.id, self.beta_shared.id},
        )
        self.assertEqual(
            {row["dictionary_status"] for row in rows},
            {"NOT_IN_DICTIONARY"},
        )

    def test_status_filter_applies_before_pagination(
        self,
    ) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {
                "dictionary_status": "NOT_IN_DICTIONARY",
                "page_size": 25,
            },
        )
        body = response.json()

        self.assertEqual(body["count"], 55)
        self.assertEqual(body["page_size"], 25)
        self.assertEqual(body["total_pages"], 3)
        self.assertEqual(len(body["results"]), 25)
        self.assertTrue(
            all(
                row["dictionary_status"]
                == "NOT_IN_DICTIONARY"
                for row in body["results"]
            )
        )

        large_page = self.client.get(
            reverse("sboms_api:component-list"),
            {
                "dictionary_status": "NOT_IN_DICTIONARY",
                "page_size": 200,
            },
        ).json()
        self.assertEqual(large_page["count"], 55)
        self.assertEqual(len(large_page["results"]), 55)

    def test_has_cpe_all_is_compatible_with_status_filter(
        self,
    ) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {
                "has_cpe": "all",
                "dictionary_status": "NOT_PRESENT",
            },
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)

    def test_has_cpe_all_returns_every_component(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {"has_cpe": "all", "page_size": 200},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["count"], 58)

    def test_invalid_has_cpe_returns_400(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {"has_cpe": "sometimes"},
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertEqual(
            response.json()["detail"],
            "has_cpe must be one of: true, false, all",
        )

    def test_image_id_filter(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {
                "image_id": self.alpha_image.id,
                "has_cpe": "all",
            },
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["count"], 4)
        self.assertTrue(
            all(
                row["image"]["id"] == self.alpha_image.id
                for row in body["results"]
            )
        )

    def test_invalid_image_id_returns_400(self) -> None:
        for image_id in ("not-a-number", "0", "-1"):
            with self.subTest(image_id=image_id):
                response = self.client.get(
                    reverse("sboms_api:component-list"),
                    {"image_id": image_id},
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertEqual(
                    response.json()["detail"],
                    "image_id must be a positive integer",
                )

    def test_sbom_id_filter_supports_dockerless_component_summary(
        self,
    ) -> None:
        document = SBOMDocument.objects.create(
            docker_image=None,
            manufacturer="NETGEAR",
            product_name="R7000",
            product_version="1.0.11.136",
            original_filename="r7000.cdx.json",
            source_path="private/storage/r7000.cdx.json",
            file_sha256="9" * 64,
            spec_version="1.7",
            generator_name="uploaded",
            generator_version="1.0",
        )
        component = Component.objects.create(
            sbom_document=document,
            bom_ref="dockerless-component",
            component_type="firmware",
            name="R7000 firmware",
            version="1.0.11.136",
            cpe=self.search_cpe,
        )
        expected_sbom = {
            "id": document.id,
            "manufacturer": "NETGEAR",
            "product_name": "R7000",
            "product_version": "1.0.11.136",
            "original_filename": "r7000.cdx.json",
        }

        list_response = self.client.get(
            reverse("sboms_api:component-list"),
            {"sbom_id": document.id},
        )
        list_body = list_response.json()

        self.assertEqual(
            list_response.status_code,
            status.HTTP_200_OK,
        )
        self.assertEqual(list_body["count"], 1)
        self.assertEqual(list_body["results"][0]["id"], component.id)
        self.assertEqual(list_body["results"][0]["sbom"], expected_sbom)
        self.assertIsNone(list_body["results"][0]["image"])

        detail_response = self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[component.id],
            )
        )
        self.assertEqual(
            detail_response.status_code,
            status.HTTP_200_OK,
        )
        self.assertEqual(detail_response.json()["sbom"], expected_sbom)
        self.assertIsNone(detail_response.json()["image"])

    def test_invalid_sbom_id_returns_400(self) -> None:
        for sbom_id in ("not-a-number", "0", "-1"):
            with self.subTest(sbom_id=sbom_id):
                response = self.client.get(
                    reverse("sboms_api:component-list"),
                    {"sbom_id": sbom_id},
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertEqual(
                    response.json()["detail"],
                    "sbom_id must be a positive integer",
                )

    def test_component_list_rejects_image_and_sbom_filters(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {
                "image_id": self.alpha_image.id,
                "sbom_id": self.alpha_sbom.id,
            },
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertEqual(
            response.json()["detail"],
            "image_id and sbom_id cannot be used together",
        )

    def test_search_covers_all_allowed_fields(self) -> None:
        for search_value in (
            "NameNeedle",
            "VersionNeedle",
            "PublisherNeedle",
            "PurlNeedle",
            "CpeNeedle",
            "BomRefNeedle",
        ):
            with self.subTest(search_value=search_value):
                response = self.client.get(
                    reverse("sboms_api:component-list"),
                    {"search": search_value},
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_200_OK,
                )
                self.assertEqual(response.json()["count"], 1)
                self.assertEqual(
                    response.json()["results"][0]["id"],
                    self.search_component.id,
                )

    def test_ordering_supports_direction_and_relations(self) -> None:
        list_url = reverse("sboms_api:component-list")
        response = self.client.get(
            list_url,
            {
                "has_cpe": "all",
                "page_size": 200,
                "ordering": "name",
            },
        )
        actual_ids = [row["id"] for row in response.json()["results"]]
        expected_ids = list(
            Component.objects.order_by("name").values_list(
                "id",
                flat=True,
            )
        )
        self.assertEqual(actual_ids, expected_ids)

        descending = self.client.get(
            list_url,
            {
                "has_cpe": "all",
                "page_size": 200,
                "ordering": "-name",
            },
        )
        descending_ids = [
            row["id"] for row in descending.json()["results"]
        ]
        self.assertEqual(descending_ids, list(reversed(expected_ids)))

        relational = self.client.get(
            list_url,
            {
                "has_cpe": "all",
                "page_size": 200,
                "ordering": "repository,name",
            },
        )
        relational_ids = [
            row["id"] for row in relational.json()["results"]
        ]
        expected_relational_ids = list(
            Component.objects.order_by(
                "sbom_document__docker_image__repository",
                "name",
            ).values_list("id", flat=True)
        )
        self.assertEqual(
            relational_ids,
            expected_relational_ids,
        )

    def test_invalid_ordering_returns_400(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {"ordering": "name,password"},
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertEqual(
            response.json()["detail"],
            "ordering contains unsupported field(s): password",
        )

    def test_pagination_size_and_validation(self) -> None:
        list_url = reverse("sboms_api:component-list")
        response = self.client.get(list_url, {"page_size": 5})
        body = response.json()
        self.assertEqual(body["count"], 57)
        self.assertEqual(body["page_size"], 5)
        self.assertEqual(body["total_pages"], 12)
        self.assertEqual(len(body["results"]), 5)

        capped = self.client.get(list_url, {"page_size": 500})
        self.assertEqual(capped.json()["page_size"], 200)
        self.assertEqual(len(capped.json()["results"]), 57)

        for invalid_page_size in ("0", "-1", "text"):
            with self.subTest(page_size=invalid_page_size):
                invalid = self.client.get(
                    list_url,
                    {"page_size": invalid_page_size},
                )
                self.assertEqual(
                    invalid.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
        invalid_page = self.client.get(list_url, {"page": 0})
        self.assertEqual(
            invalid_page.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_component_list_contains_cpe_structure_only(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {"search": "NameNeedle"},
        )
        row = response.json()["results"][0]

        self.assertEqual(
            row["structural_status"],
            "STRUCTURALLY_VALID",
        )
        self.assertEqual(row["cpe_fields"]["vendor"], "CpeNeedle")
        self.assertEqual(
            row["cpe_fields"]["version"],
            "VersionNeedle",
        )
        self.assertNotIn("properties", row)
        self.assertNotIn("bom_ref", row)
        self.assertNotIn("file_sha256", row)
        self.assertNotIn("manifest_digest", row)

        invalid_response = self.client.get(
            reverse("sboms_api:component-list"),
            {"search": "Invalid CPE"},
        )
        invalid_row = invalid_response.json()["results"][0]
        self.assertEqual(
            invalid_row["structural_status"],
            "INVALID_PART",
        )
        self.assertEqual(
            invalid_row["dictionary_status"],
            "NOT_IN_DICTIONARY",
        )

    def test_component_detail_includes_expected_research_fields(
        self,
    ) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[self.search_component.id],
            )
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["bom_ref"], "BomRefNeedle")
        self.assertEqual(
            body["properties"],
            self.search_component.properties,
        )
        self.assertEqual(
            body["sbom_document"]["source_path"],
            self.alpha_sbom.source_path,
        )
        self.assertEqual(
            body["structural_status"],
            "STRUCTURALLY_VALID",
        )
        self.assertIsNone(body["structural_error_message"])
        self.assertEqual(
            body["dictionary_status"],
            "OFFICIAL_ACTIVE",
        )
        self.assertEqual(
            body["dictionary_match"],
            {
                "snapshot_id": (
                    self.dictionary_snapshot.snapshot_id
                ),
                "cpe_name_id": str(self.active_cpe_name_id),
                "matched_cpe_name": self.search_cpe,
                "deprecated": False,
            },
        )

        missing = self.client.get(
            reverse("sboms_api:component-detail", args=[999999])
        )
        self.assertEqual(
            missing.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_component_without_cpe_detail(self) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[self.no_cpe_component.id],
            )
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["cpe"], "")
        self.assertEqual(body["structural_status"], "NOT_PRESENT")
        self.assertIsNone(body["cpe_fields"])
        self.assertIsNone(body["structural_error_message"])
        self.assertEqual(
            body["dictionary_status"],
            "NOT_PRESENT",
        )
        self.assertEqual(
            body["dictionary_match"],
            {
                "snapshot_id": (
                    self.dictionary_snapshot.snapshot_id
                ),
                "cpe_name_id": None,
                "matched_cpe_name": None,
                "deprecated": None,
            },
        )

    def test_structurally_invalid_cpe_is_represented(self) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[self.invalid_component.id],
            )
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["structural_status"], "INVALID_PART")
        self.assertIsNone(body["cpe_fields"])
        self.assertTrue(body["structural_error_message"])
        self.assertEqual(
            body["dictionary_status"],
            "NOT_IN_DICTIONARY",
        )
        self.assertEqual(
            body["dictionary_match"]["snapshot_id"],
            self.dictionary_snapshot.snapshot_id,
        )

    def test_deprecated_dictionary_match_is_represented(
        self,
    ) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[self.os_component.id],
            )
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            body["dictionary_status"],
            "OFFICIAL_DEPRECATED",
        )
        self.assertEqual(
            body["dictionary_match"]["cpe_name_id"],
            str(self.deprecated_cpe_name_id),
        )
        self.assertEqual(
            body["dictionary_match"]["matched_cpe_name"],
            self.os_cpe,
        )
        self.assertIs(body["dictionary_match"]["deprecated"], True)

    @override_settings(CPE_DICTIONARY_SNAPSHOT_ID="missing")
    def test_configured_missing_snapshot_returns_503(self) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[self.search_component.id],
            )
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            response.json()["code"],
            "cpe_dictionary_snapshot_unavailable",
        )
        self.assertIn("does not exist", response.json()["detail"])

        list_response = self.client.get(
            reverse("sboms_api:component-list")
        )
        self.assertEqual(
            list_response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            list_response.json()["code"],
            response.json()["code"],
        )

    @override_settings(CPE_DICTIONARY_SNAPSHOT_ID=None)
    def test_ambiguous_snapshot_configuration_returns_503(
        self,
    ) -> None:
        CpeDictionarySnapshot.objects.create(
            snapshot_id="20260726T035002Z",
            status=CpeDictionarySnapshot.Status.COMPLETE,
            feed_last_modified=datetime(
                2026,
                7,
                26,
                3,
                50,
                2,
                tzinfo=timezone.utc,
            ),
            manifest_sha256="1" * 64,
            archive_sha256="2" * 64,
            content_sha256="3" * 64,
            member_count=1,
            expected_record_count=0,
            record_count=0,
            active_count=0,
            deprecated_count=0,
            completed_at=datetime(
                2026,
                7,
                27,
                tzinfo=timezone.utc,
            ),
        )

        response = self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[self.search_component.id],
            )
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            response.json()["code"],
            "cpe_dictionary_snapshot_ambiguous",
        )

        list_response = self.client.get(
            reverse("sboms_api:component-list")
        )
        self.assertEqual(
            list_response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            list_response.json()["code"],
            response.json()["code"],
        )

    @override_settings(
        CPE_DICTIONARY_SNAPSHOT_ID="20260725T035002Z"
    )
    def test_list_rejects_non_complete_configured_snapshot(
        self,
    ) -> None:
        CpeDictionarySnapshot.objects.filter(
            pk=self.dictionary_snapshot.pk
        ).update(status=CpeDictionarySnapshot.Status.IMPORTING)

        response = self.client.get(
            reverse("sboms_api:component-list")
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            response.json()["code"],
            "cpe_dictionary_snapshot_unavailable",
        )

    @override_settings(CPE_DICTIONARY_SNAPSHOT_ID=None)
    def test_list_requires_one_complete_snapshot(self) -> None:
        CpeDictionarySnapshot.objects.filter(
            pk=self.dictionary_snapshot.pk
        ).update(status=CpeDictionarySnapshot.Status.IMPORTING)

        response = self.client.get(
            reverse("sboms_api:component-list")
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            response.json()["code"],
            "cpe_dictionary_snapshot_unavailable",
        )

    @override_settings(
        CPE_DICTIONARY_SNAPSHOT_ID="20260725T035002Z"
    )
    def test_configured_snapshot_is_reused_when_multiple_exist(
        self,
    ) -> None:
        CpeDictionarySnapshot.objects.create(
            snapshot_id="20260726T035002Z",
            status=CpeDictionarySnapshot.Status.COMPLETE,
            feed_last_modified=datetime(
                2026,
                7,
                26,
                3,
                50,
                2,
                tzinfo=timezone.utc,
            ),
            manifest_sha256="1" * 64,
            archive_sha256="2" * 64,
            content_sha256="3" * 64,
            member_count=1,
            expected_record_count=0,
            record_count=0,
            active_count=0,
            deprecated_count=0,
            completed_at=datetime(
                2026,
                7,
                27,
                tzinfo=timezone.utc,
            ),
        )

        response = self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[self.search_component.id],
            )
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json()["dictionary_match"]["snapshot_id"],
            "20260725T035002Z",
        )

    def test_detail_exact_match_uses_three_queries(self) -> None:
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(
                reverse(
                    "sboms_api:component-detail",
                    args=[self.search_component.id],
                )
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(queries), 3)

    def test_write_methods_are_not_allowed(self) -> None:
        requests = (
            ("post", reverse("sboms_api:image-list")),
            ("post", reverse("sboms_api:component-list")),
            (
                "put",
                reverse(
                    "sboms_api:component-detail",
                    args=[self.search_component.id],
                ),
            ),
            (
                "patch",
                reverse(
                    "sboms_api:component-detail",
                    args=[self.search_component.id],
                ),
            ),
            (
                "delete",
                reverse(
                    "sboms_api:component-detail",
                    args=[self.search_component.id],
                ),
            ),
        )
        for method, url in requests:
            with self.subTest(method=method, url=url):
                response = getattr(self.client, method)(url, {})
                self.assertEqual(
                    response.status_code,
                    status.HTTP_405_METHOD_NOT_ALLOWED,
                )

    def test_get_requests_do_not_change_database_counts(self) -> None:
        counts_before = self.model_counts()

        self.client.get(reverse("sboms_api:image-list"))
        self.client.get(reverse("sboms_api:component-list"))
        self.client.get(
            reverse(
                "sboms_api:component-detail",
                args=[self.search_component.id],
            )
        )

        self.assertEqual(self.model_counts(), counts_before)

    def test_list_queries_do_not_grow_with_page_size(self) -> None:
        component_url = reverse("sboms_api:component-list")
        with CaptureQueriesContext(connection) as small_page_queries:
            response = self.client.get(
                component_url,
                {"page_size": 25},
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        with CaptureQueriesContext(connection) as large_page_queries:
            response = self.client.get(
                component_url,
                {"page_size": 200},
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(len(small_page_queries), 4)
        self.assertEqual(len(large_page_queries), 4)
        for captured_queries in (
            small_page_queries,
            large_page_queries,
        ):
            dictionary_lookups = [
                query
                for query in captured_queries.captured_queries
                if 'FROM "cpe_dictionary_cpename"' in query["sql"]
            ]
            snapshot_lookups = [
                query
                for query in captured_queries.captured_queries
                if (
                    'FROM "cpe_dictionary_cpedictionarysnapshot"'
                    in query["sql"]
                )
            ]
            self.assertEqual(len(dictionary_lookups), 1)
            self.assertEqual(len(snapshot_lookups), 1)

        matched_page_cpes: list[str] = []

        def capture_bulk_match(raw_cpes, snapshot):
            values = list(raw_cpes)
            matched_page_cpes.extend(values)
            return match_cpes(values, snapshot)

        with patch(
            "sboms.api.views.match_cpes",
            side_effect=capture_bulk_match,
        ) as bulk_match:
            response = self.client.get(
                component_url,
                {"page_size": 200},
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        bulk_match.assert_called_once()
        self.assertEqual(
            len(matched_page_cpes),
            57,
        )

        with CaptureQueriesContext(connection) as image_queries:
            response = self.client.get(reverse("sboms_api:image-list"))
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertLessEqual(len(image_queries), 1)

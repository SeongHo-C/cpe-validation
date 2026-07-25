from __future__ import annotations

from unittest.mock import patch

from django.db import DatabaseError, connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

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
            source_path="pilot/results/sboms/beta-2.0.cdx.json",
            file_sha256="2" * 64,
            spec_version="1.7",
            serial_number="urn:uuid:beta",
            generator_name="syft",
            generator_version="1.49.0",
        )
        cls.alpha_sbom = SBOMDocument.objects.create(
            docker_image=cls.alpha_image,
            source_path="pilot/results/sboms/alpha-1.0.cdx.json",
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
    def model_counts() -> tuple[int, int, int]:
        return (
            DockerImage.objects.count(),
            SBOMDocument.objects.count(),
            Component.objects.count(),
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

    def test_dashboard_summary_uses_current_database(self) -> None:
        response = self.client.get(
            reverse("sboms_api:dashboard-summary")
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["total_images"], 2)
        self.assertEqual(body["total_sboms"], 2)
        self.assertEqual(body["total_components"], 58)
        self.assertEqual(body["components_with_primary_cpe"], 57)
        self.assertEqual(body["components_without_primary_cpe"], 1)
        self.assertEqual(body["unique_primary_cpes"], 56)
        self.assertEqual(
            body["structural_status_counts"],
            {
                "STRUCTURALLY_VALID": 56,
                "INVALID_PREFIX": 0,
                "INVALID_FIELD_COUNT": 0,
                "INVALID_ESCAPE": 0,
                "INVALID_PART": 1,
            },
        )
        self.assertEqual(body["part_counts"], {"a": 55, "o": 1, "h": 0})
        self.assertEqual(
            sum(body["structural_status_counts"].values()),
            body["components_with_primary_cpe"],
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

    def test_has_cpe_false_returns_only_missing_cpes(self) -> None:
        response = self.client.get(
            reverse("sboms_api:component-list"),
            {"has_cpe": "FALSE"},
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["results"][0]["cpe"], "")

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
            "UNVALIDATED",
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
            "UNVALIDATED",
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
            "UNVALIDATED",
        )

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

        self.client.get(reverse("sboms_api:dashboard-summary"))
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
        with CaptureQueriesContext(connection) as two_row_queries:
            response = self.client.get(
                component_url,
                {"page_size": 2},
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        with CaptureQueriesContext(connection) as twenty_row_queries:
            response = self.client.get(
                component_url,
                {"page_size": 20},
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertLessEqual(
            abs(len(twenty_row_queries) - len(two_row_queries)),
            1,
        )
        self.assertLessEqual(len(twenty_row_queries), 3)

        with CaptureQueriesContext(connection) as image_queries:
            response = self.client.get(reverse("sboms_api:image-list"))
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertLessEqual(len(image_queries), 1)

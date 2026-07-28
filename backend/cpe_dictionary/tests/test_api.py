from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch
from uuid import UUID

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from cpe_dictionary.models import CpeDictionarySnapshot, CpeName


def create_snapshot(
    snapshot_id: str,
    *,
    status_value: str = CpeDictionarySnapshot.Status.COMPLETE,
) -> CpeDictionarySnapshot:
    return CpeDictionarySnapshot.objects.create(
        snapshot_id=snapshot_id,
        status=status_value,
        feed_last_modified=datetime(
            2026,
            7,
            25,
            3,
            50,
            2,
            tzinfo=timezone.utc,
        ),
        manifest_sha256=snapshot_id[-1] * 64,
        archive_sha256="a" * 64,
        content_sha256="b" * 64,
        member_count=1,
        expected_record_count=0,
        record_count=0,
        active_count=0,
        deprecated_count=0,
        completed_at=(
            datetime(2026, 7, 27, tzinfo=timezone.utc)
            if status_value
            == CpeDictionarySnapshot.Status.COMPLETE
            else None
        ),
    )


def create_cpe(
    snapshot: CpeDictionarySnapshot,
    number: int,
    *,
    part: str = "a",
    vendor: str = "haxx",
    product: str = "curl",
    version: str = "8.14.1",
    deprecated: bool = False,
    titles: list[object] | None = None,
    references: list[object] | None = None,
) -> CpeName:
    raw_cpe = (
        f"cpe:2.3:{part}:{vendor}:{product}:{version}:"
        "*:*:*:*:*:*:*"
    )
    return CpeName.objects.create(
        snapshot=snapshot,
        cpe_name_id=UUID(int=number),
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
        part=part,
        vendor=vendor,
        product=product,
        version=version,
        update="*",
        edition="*",
        language="*",
        sw_edition="*",
        target_sw="*",
        target_hw="*",
        other="*",
        titles=titles or [],
        references=references or [],
        deprecated_by=["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        if deprecated
        else [],
        deprecates=["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"],
    )


@override_settings(CPE_DICTIONARY_SNAPSHOT_ID=None)
class CpeDictionaryReadOnlyAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = create_snapshot("20260725T035002Z")
        cls.other_snapshot = create_snapshot(
            "20260724T035002Y",
            status_value=CpeDictionarySnapshot.Status.IMPORTING,
        )
        cls.curl = create_cpe(
            cls.snapshot,
            1,
            titles=[
                {"lang": "fr", "title": "Curl français"},
                {"lang": "en", "title": "curl command line tool"},
            ],
            references=[
                {
                    "ref": "https://curl.se/",
                    "type": "Vendor",
                }
            ],
        )
        cls.deprecated_curl = create_cpe(
            cls.snapshot,
            2,
            vendor="oldvendor",
            product="curl-old",
            version="7.0",
            deprecated=True,
            titles=[{"lang": "en-US", "title": "Old curl"}],
        )
        cls.openssl = create_cpe(
            cls.snapshot,
            3,
            vendor="openssl",
            product="openssl",
            version="3.5.1",
            titles=[{"lang": "de", "title": "OpenSSL title"}],
        )
        cls.vendor_alias = create_cpe(
            cls.snapshot,
            4,
            vendor="curl",
            product="libcurl",
            version="8.14.1",
        )
        cls.other_snapshot_cpe = create_cpe(
            cls.other_snapshot,
            5,
            vendor="hidden",
            product="hidden",
            version="1",
        )

    @property
    def search_url(self) -> str:
        return reverse("cpe_dictionary_api:cpe-name-search")

    def detail_url(self, cpe_name_id: UUID) -> str:
        return reverse(
            "cpe_dictionary_api:cpe-name-detail",
            args=[cpe_name_id],
        )

    @property
    def snapshot_url(self) -> str:
        return reverse("cpe_dictionary_api:snapshot")

    def assert_error(
        self,
        parameters: dict[str, object],
        code: str,
    ) -> None:
        response = self.client.get(self.search_url, parameters)
        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertEqual(response.json()["code"], code)

    def test_requires_a_search_term(self) -> None:
        for parameters in ({}, {"part": "a"}, {"deprecated": "all"}):
            with self.subTest(parameters=parameters):
                self.assert_error(
                    parameters,
                    "cpe_search_term_required",
                )

    def test_validates_query_part_and_deprecated(self) -> None:
        cases = (
            ({"q": "x"}, "invalid_search_query"),
            ({"q": "curl", "part": "x"}, "invalid_cpe_part"),
            (
                {"q": "curl", "deprecated": "maybe"},
                "invalid_deprecated_filter",
            ),
            ({"q": "curl", "part": "A"}, "invalid_cpe_part"),
        )
        for parameters, code in cases:
            with self.subTest(parameters=parameters):
                self.assert_error(parameters, code)

    def test_validates_page_and_allowed_page_sizes(self) -> None:
        cases = (
            ({"q": "curl", "page": "zero"}, "invalid_page"),
            ({"q": "curl", "page": "0"}, "invalid_page"),
            (
                {"q": "curl", "page_size": "zero"},
                "invalid_page_size",
            ),
            (
                {"q": "curl", "page_size": "10"},
                "invalid_page_size",
            ),
        )
        for parameters, code in cases:
            with self.subTest(parameters=parameters):
                self.assert_error(parameters, code)

        for page_size in (25, 50, 100):
            with self.subTest(page_size=page_size):
                response = self.client.get(
                    self.search_url,
                    {"q": "curl", "page_size": page_size},
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_200_OK,
                )
                self.assertEqual(response.json()["page_size"], page_size)

    def test_keyword_search_is_case_insensitive_across_fields(
        self,
    ) -> None:
        for query in (
            "CURL",
            "HAXX",
            "8.14",
            "COMMAND LINE",
            "CPE:2.3:A:HAXX",
        ):
            with self.subTest(query=query):
                response = self.client.get(
                    self.search_url,
                    {"q": query, "deprecated": "all"},
                )
                ids = {
                    item["cpe_name_id"]
                    for item in response.json()["results"]
                }
                self.assertIn(str(self.curl.cpe_name_id), ids)

    def test_structured_filters_are_case_insensitive_exact(
        self,
    ) -> None:
        response = self.client.get(
            self.search_url,
            {
                "vendor": "HAXX",
                "product": "CURL",
                "version": "8.14.1",
                "part": "a",
                "deprecated": "all",
            },
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(
            response.json()["results"][0]["cpe_name_id"],
            str(self.curl.cpe_name_id),
        )

    def test_exact_raw_cpe_search(self) -> None:
        response = self.client.get(
            self.search_url,
            {"cpe_name": self.curl.cpe_name},
        )

        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(
            response.json()["results"][0]["cpe_name"],
            self.curl.cpe_name,
        )

    def test_alias_and_version_normalization_are_not_applied(
        self,
    ) -> None:
        alias_response = self.client.get(
            self.search_url,
            {"vendor": "curl", "product": "curl"},
        )
        normalized_response = self.client.get(
            self.search_url,
            {
                "vendor": "haxx",
                "product": "curl",
                "version": "8.14.1-r1",
            },
        )

        self.assertEqual(alias_response.json()["count"], 0)
        self.assertEqual(normalized_response.json()["count"], 0)

    def test_deprecated_filter_defaults_active_and_supports_all(
        self,
    ) -> None:
        active = self.client.get(self.search_url, {"q": "curl"})
        deprecated = self.client.get(
            self.search_url,
            {"q": "curl", "deprecated": "deprecated"},
        )
        all_records = self.client.get(
            self.search_url,
            {"q": "curl", "deprecated": "all"},
        )

        self.assertEqual(active.json()["count"], 2)
        self.assertFalse(
            any(item["deprecated"] for item in active.json()["results"])
        )
        self.assertEqual(deprecated.json()["count"], 1)
        self.assertTrue(deprecated.json()["results"][0]["deprecated"])
        self.assertEqual(all_records.json()["count"], 3)

    def test_results_are_ordered_deterministically(self) -> None:
        create_cpe(
            self.snapshot,
            10,
            vendor="aaa",
            product="curl",
            version="2",
        )
        create_cpe(
            self.snapshot,
            11,
            vendor="aaa",
            product="curl",
            version="1",
        )

        response = self.client.get(
            self.search_url,
            {"q": "curl", "deprecated": "all"},
        )
        results = response.json()["results"]
        ordering = [
            (
                item["deprecated"],
                item["vendor"],
                item["product"],
                item["version"],
                item["cpe_name"],
            )
            for item in results
        ]
        self.assertEqual(ordering, sorted(ordering))

    def test_pagination_returns_only_requested_page(self) -> None:
        CpeName.objects.bulk_create(
            [
                CpeName(
                    snapshot=self.snapshot,
                    cpe_name_id=UUID(int=100 + index),
                    cpe_name=(
                        "cpe:2.3:a:page:needle-"
                        f"{index:02d}:1:*:*:*:*:*:*:*"
                    ),
                    deprecated=False,
                    created_at_nvd=datetime(
                        2020, 1, 1, tzinfo=timezone.utc
                    ),
                    last_modified_at_nvd=datetime(
                        2026, 1, 1, tzinfo=timezone.utc
                    ),
                    part="a",
                    vendor="page",
                    product=f"needle-{index:02d}",
                    version="1",
                    update="*",
                    edition="*",
                    language="*",
                    sw_edition="*",
                    target_sw="*",
                    target_hw="*",
                    other="*",
                )
                for index in range(27)
            ]
        )

        response = self.client.get(
            self.search_url,
            {"q": "needle", "page": 2, "page_size": 25},
        )

        self.assertEqual(response.json()["count"], 27)
        self.assertEqual(response.json()["page"], 2)
        self.assertEqual(len(response.json()["results"]), 2)

    def test_list_uses_representative_title_and_omits_references(
        self,
    ) -> None:
        response = self.client.get(
            self.search_url,
            {"cpe_name": self.curl.cpe_name},
        )
        item = response.json()["results"][0]

        self.assertEqual(item["title"], "curl command line tool")
        self.assertNotIn("references", item)
        self.assertEqual(
            item["snapshot_id"],
            self.snapshot.snapshot_id,
        )

        fallback = self.client.get(
            self.search_url,
            {"cpe_name": self.openssl.cpe_name},
        )
        self.assertEqual(
            fallback.json()["results"][0]["title"],
            "OpenSSL title",
        )

    def test_snapshot_provenance_is_returned(self) -> None:
        response = self.client.get(self.search_url, {"q": "curl"})

        self.assertEqual(
            response.json()["snapshot"],
            {
                "snapshot_id": self.snapshot.snapshot_id,
                "manifest_sha256": self.snapshot.manifest_sha256,
                "status": "COMPLETE",
            },
        )
        self.assertEqual(
            response.json()["query"]["deprecated"],
            "active",
        )

        snapshot_response = self.client.get(self.snapshot_url)
        self.assertEqual(
            snapshot_response.json(),
            {
                "snapshot_id": self.snapshot.snapshot_id,
                "manifest_sha256": self.snapshot.manifest_sha256,
                "status": "COMPLETE",
            },
        )

    def test_other_snapshot_records_are_not_returned(self) -> None:
        response = self.client.get(
            self.search_url,
            {"q": "hidden", "deprecated": "all"},
        )

        self.assertEqual(response.json()["count"], 0)

    @override_settings(
        CPE_DICTIONARY_SNAPSHOT_ID="20260725T035002Z"
    )
    def test_explicit_complete_snapshot_is_selected(self) -> None:
        create_snapshot("20260726T035002X")

        response = self.client.get(self.search_url, {"q": "curl"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json()["snapshot"]["snapshot_id"],
            self.snapshot.snapshot_id,
        )

    @override_settings(CPE_DICTIONARY_SNAPSHOT_ID="missing")
    def test_unavailable_snapshot_returns_503(self) -> None:
        response = self.client.get(self.search_url, {"q": "curl"})

        self.assertEqual(
            response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            response.json()["code"],
            "cpe_dictionary_snapshot_unavailable",
        )

    def test_ambiguous_snapshot_returns_503(self) -> None:
        create_snapshot("20260726T035002X")

        response = self.client.get(self.search_url, {"q": "curl"})

        self.assertEqual(
            response.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            response.json()["code"],
            "cpe_dictionary_snapshot_ambiguous",
        )

    def test_detail_returns_all_fields_and_normalized_references(
        self,
    ) -> None:
        response = self.client.get(
            self.detail_url(self.curl.cpe_name_id)
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["cpe_name"], self.curl.cpe_name)
        self.assertEqual(body["snapshot_id"], self.snapshot.snapshot_id)
        self.assertEqual(
            body["snapshot_manifest_sha256"],
            self.snapshot.manifest_sha256,
        )
        self.assertEqual(body["titles"], self.curl.titles)
        self.assertEqual(
            body["references"],
            [{"url": "https://curl.se/", "type": "Vendor"}],
        )
        self.assertEqual(body["part"], "a")
        self.assertIn("sw_edition", body)

    def test_detail_returns_deprecation_information(self) -> None:
        response = self.client.get(
            self.detail_url(self.deprecated_curl.cpe_name_id)
        )

        self.assertTrue(response.json()["deprecated"])
        self.assertEqual(
            response.json()["deprecated_by"],
            ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        )
        self.assertTrue(response.json()["deprecates"])

    def test_detail_not_found_and_other_snapshot_are_404(self) -> None:
        for cpe_name_id in (
            UUID(int=999),
            self.other_snapshot_cpe.cpe_name_id,
        ):
            with self.subTest(cpe_name_id=cpe_name_id):
                response = self.client.get(
                    self.detail_url(cpe_name_id)
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_404_NOT_FOUND,
                )
                self.assertEqual(
                    response.json()["code"],
                    "cpe_name_not_found",
                )

    def test_endpoints_are_get_only_and_do_not_write(self) -> None:
        counts_before = (
            CpeDictionarySnapshot.objects.count(),
            CpeName.objects.count(),
        )
        requests = (
            ("post", self.search_url),
            ("post", self.snapshot_url),
            ("put", self.detail_url(self.curl.cpe_name_id)),
            ("patch", self.detail_url(self.curl.cpe_name_id)),
            ("delete", self.detail_url(self.curl.cpe_name_id)),
        )
        for method, url in requests:
            with self.subTest(method=method):
                response = getattr(self.client, method)(url, {})
                self.assertEqual(
                    response.status_code,
                    status.HTTP_405_METHOD_NOT_ALLOWED,
                )
        self.client.get(self.search_url, {"q": "curl"})
        self.client.get(self.detail_url(self.curl.cpe_name_id))
        self.assertEqual(
            (
                CpeDictionarySnapshot.objects.count(),
                CpeName.objects.count(),
            ),
            counts_before,
        )

    def test_list_query_count_is_constant_across_page_sizes(
        self,
    ) -> None:
        query_counts = []
        for page_size in (25, 100):
            with CaptureQueriesContext(connection) as queries:
                response = self.client.get(
                    self.search_url,
                    {"q": "curl", "page_size": page_size},
                )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            query_counts.append(len(queries))
        self.assertEqual(query_counts, [3, 3])

    def test_search_slices_queryset_without_iteration(
        self,
    ) -> None:
        with patch(
            "cpe_dictionary.api.views.QuerySet.iterator"
        ) as iterator:
            response = self.client.get(
                self.search_url,
                {"q": "curl"},
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        iterator.assert_not_called()

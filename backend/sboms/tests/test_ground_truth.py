from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    DockerImage,
    SBOMDocument,
)


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
        manifest_sha256="1" * 64,
        archive_sha256="2" * 64,
        content_sha256="3" * 64,
        member_count=1,
        expected_record_count=1,
        record_count=1,
        active_count=1,
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
) -> CpeName:
    return CpeName.objects.create(
        snapshot=snapshot,
        cpe_name_id=UUID(int=number),
        cpe_name=(
            "cpe:2.3:a:example:product:"
            f"{number}:*:*:*:*:*:*:*"
        ),
        deprecated=False,
        created_at_nvd=datetime(
            2020, 1, 1, tzinfo=timezone.utc
        ),
        last_modified_at_nvd=datetime(
            2026, 1, 1, tzinfo=timezone.utc
        ),
        part="a",
        vendor="example",
        product="product",
        version=str(number),
        update="*",
        edition="*",
        language="*",
        sw_edition="*",
        target_sw="*",
        target_hw="*",
        other="*",
    )


def create_component() -> Component:
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
        source_path="pilot/results/sboms/example-1.0.cdx.json",
        file_sha256="b" * 64,
        spec_version="1.7",
        serial_number="urn:uuid:example",
        generator_name="syft",
        generator_version="1.49.0",
    )
    return Component.objects.create(
        sbom_document=document,
        bom_ref="pkg:generic/example@1.0",
        component_type="library",
        name="example",
        version="1.0",
        cpe="cpe:2.3:a:syft:example:1.0:*:*:*:*:*:*:*",
    )


class ComponentCpeGroundTruthModelTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = create_snapshot("20260725T035002Z")
        cls.other_snapshot = create_snapshot(
            "20260724T035002Z",
            status_value=CpeDictionarySnapshot.Status.IMPORTING,
        )
        cls.cpe = create_cpe(cls.snapshot, 1)
        cls.other_cpe = create_cpe(cls.other_snapshot, 2)
        cls.component = create_component()

    def test_saves_ground_truth_with_official_cpe(self) -> None:
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=self.cpe,
            decision_type="Vendor difference",
        )

        self.assertEqual(ground_truth.ground_truth_cpe, self.cpe)

    def test_saves_ground_truth_without_cpe(self) -> None:
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=None,
            decision_type="Review deferred",
            note="Insufficient evidence",
        )

        self.assertIsNone(ground_truth.ground_truth_cpe)

    def test_saves_and_trims_manual_cpe(self) -> None:
        manual_cpe = (
            "cpe:2.3:a:Example:Manual:1.2.4:*:*:*:*:*:*:*"
        )

        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            manual_ground_truth_cpe=f"  {manual_cpe}  ",
            decision_type="Manual version",
        )

        self.assertEqual(
            ground_truth.manual_ground_truth_cpe,
            manual_cpe,
        )

    def test_rejects_dictionary_and_manual_cpe_together(
        self,
    ) -> None:
        with self.assertRaises(ValidationError):
            ComponentCpeGroundTruth.objects.create(
                component=self.component,
                snapshot=self.snapshot,
                ground_truth_cpe=self.cpe,
                manual_ground_truth_cpe=(
                    "cpe:2.3:a:example:manual:1.0:*:*:*:*:*:*:*"
                ),
                decision_type="Conflicting inputs",
            )

    def test_rejects_invalid_manual_cpe(self) -> None:
        with self.assertRaises(ValidationError):
            ComponentCpeGroundTruth.objects.create(
                component=self.component,
                snapshot=self.snapshot,
                manual_ground_truth_cpe="not-a-cpe",
                decision_type="Invalid manual input",
            )

    def test_rejects_empty_or_whitespace_decision_type(self) -> None:
        for decision_type in ("", "   "):
            with self.subTest(decision_type=decision_type):
                with self.assertRaises(ValidationError):
                    ComponentCpeGroundTruth.objects.create(
                        component=self.component,
                        snapshot=self.snapshot,
                        decision_type=decision_type,
                    )

    def test_trims_only_decision_type_outer_whitespace(self) -> None:
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            decision_type="  Vendor Difference  ",
        )

        self.assertEqual(
            ground_truth.decision_type,
            "Vendor Difference",
        )

    def test_rejects_duplicate_component_and_snapshot(self) -> None:
        ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            decision_type="First review",
        )

        with self.assertRaises(ValidationError):
            ComponentCpeGroundTruth.objects.create(
                component=self.component,
                snapshot=self.snapshot,
                decision_type="Second review",
            )

    def test_rejects_cpe_from_another_snapshot(self) -> None:
        with self.assertRaises(ValidationError):
            ComponentCpeGroundTruth.objects.create(
                component=self.component,
                snapshot=self.snapshot,
                ground_truth_cpe=self.other_cpe,
                decision_type="Wrong snapshot",
            )

    def test_rejects_nonexistent_component_and_cpe(self) -> None:
        ground_truth = ComponentCpeGroundTruth(
            component_id=999999,
            snapshot=self.snapshot,
            ground_truth_cpe_id=999999,
            decision_type="Invalid references",
        )

        with self.assertRaises(ValidationError) as raised:
            ground_truth.save()

        self.assertIn("component", raised.exception.message_dict)
        self.assertIn(
            "ground_truth_cpe",
            raised.exception.message_dict,
        )

    def test_does_not_change_original_component_cpe(self) -> None:
        original_cpe = self.component.cpe

        ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=self.cpe,
            decision_type="Product difference",
        )

        self.component.refresh_from_db()
        self.assertEqual(self.component.cpe, original_cpe)


@override_settings(CPE_DICTIONARY_SNAPSHOT_ID=None)
class ComponentCpeGroundTruthAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = create_snapshot("20260725T035002Z")
        cls.other_snapshot = create_snapshot(
            "20260724T035002Z",
            status_value=CpeDictionarySnapshot.Status.IMPORTING,
        )
        cls.cpe = create_cpe(cls.snapshot, 10)
        cls.other_cpe = create_cpe(cls.other_snapshot, 11)
        cls.component = create_component()

    @property
    def url(self) -> str:
        return reverse(
            "sboms_api:component-cpe-ground-truth",
            args=[self.component.id],
        )

    def test_get_without_saved_record_returns_null(self) -> None:
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json(),
            {
                "component_id": self.component.id,
                "snapshot_id": self.snapshot.snapshot_id,
                "ground_truth": None,
            },
        )

    def test_get_returns_saved_record(self) -> None:
        saved = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=self.cpe,
            decision_type="Vendor difference",
            note="Upstream vendor evidence",
        )

        response = self.client.get(self.url)
        body = response.json()["ground_truth"]

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(body["id"], saved.id)
        self.assertEqual(body["source"], "DICTIONARY")
        self.assertEqual(
            body["dictionary_cpe"]["id"],
            self.cpe.id,
        )
        self.assertEqual(
            body["ground_truth_cpe"]["id"],
            self.cpe.id,
        )
        self.assertEqual(
            body["ground_truth_cpe"]["cpe_uuid"],
            str(self.cpe.cpe_name_id),
        )
        self.assertEqual(body["decision_type"], "Vendor difference")
        self.assertEqual(body["note"], "Upstream vendor evidence")

    def test_get_returns_manual_and_no_cpe_sources(self) -> None:
        manual_cpe = (
            "cpe:2.3:a:example:manual:2.0:*:*:*:*:*:*:*"
        )
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            manual_ground_truth_cpe=manual_cpe,
            decision_type="Manual candidate",
        )

        manual_body = self.client.get(self.url).json()[
            "ground_truth"
        ]
        self.assertEqual(manual_body["source"], "MANUAL")
        self.assertEqual(manual_body["manual_cpe"], manual_cpe)
        self.assertIsNone(manual_body["dictionary_cpe"])

        ground_truth.manual_ground_truth_cpe = ""
        ground_truth.decision_type = "No applicable CPE"
        ground_truth.save()
        none_body = self.client.get(self.url).json()["ground_truth"]
        self.assertEqual(none_body["source"], "NONE")
        self.assertIsNone(none_body["manual_cpe"])
        self.assertIsNone(none_body["dictionary_cpe"])

    def test_put_creates_record_with_official_cpe(self) -> None:
        original_cpe = self.component.cpe

        response = self.client.put(
            self.url,
            {
                "ground_truth_cpe_id": self.cpe.id,
                "decision_type": "  Vendor Difference  ",
                "note": "Human review",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        saved = ComponentCpeGroundTruth.objects.get()
        self.assertEqual(saved.ground_truth_cpe, self.cpe)
        self.assertEqual(saved.decision_type, "Vendor Difference")
        self.component.refresh_from_db()
        self.assertEqual(self.component.cpe, original_cpe)

    def test_put_creates_record_without_cpe(self) -> None:
        response = self.client.put(
            self.url,
            {
                "ground_truth_cpe_id": None,
                "decision_type": "Review deferred",
                "note": "Insufficient evidence",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        saved = ComponentCpeGroundTruth.objects.get()
        self.assertIsNone(saved.ground_truth_cpe)
        self.assertEqual(
            response.json()["ground_truth"]["source"],
            "NONE",
        )

    def test_put_creates_manual_cpe_record(self) -> None:
        manual_cpe = (
            "cpe:2.3:a:Example:Manual:3.0:*:*:*:*:*:*:*"
        )

        response = self.client.put(
            self.url,
            {
                "dictionary_cpe_id": None,
                "manual_cpe": f"  {manual_cpe}  ",
                "decision_type": "Manual version",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        saved = ComponentCpeGroundTruth.objects.get()
        self.assertEqual(saved.manual_ground_truth_cpe, manual_cpe)
        self.assertEqual(
            response.json()["ground_truth"]["source"],
            "MANUAL",
        )

    def test_put_creates_dictionary_cpe_with_canonical_field(
        self,
    ) -> None:
        response = self.client.put(
            self.url,
            {
                "dictionary_cpe_id": self.cpe.id,
                "manual_cpe": None,
                "decision_type": "Official CPE",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json()["ground_truth"]["dictionary_cpe"][
                "id"
            ],
            self.cpe.id,
        )

    def test_put_updates_existing_record_in_place(self) -> None:
        saved = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=self.cpe,
            decision_type="Initial review",
        )

        response = self.client.put(
            self.url,
            {
                "ground_truth_cpe_id": None,
                "decision_type": "Review deferred",
                "note": "Updated evidence",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            ComponentCpeGroundTruth.objects.count(),
            1,
        )
        saved.refresh_from_db()
        self.assertIsNone(saved.ground_truth_cpe)
        self.assertEqual(saved.decision_type, "Review deferred")
        self.assertEqual(saved.note, "Updated evidence")

    def test_put_switches_between_dictionary_manual_and_none(
        self,
    ) -> None:
        ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=self.cpe,
            decision_type="Dictionary",
        )
        manual_cpe = (
            "cpe:2.3:a:example:manual:4.0:*:*:*:*:*:*:*"
        )

        manual_response = self.client.put(
            self.url,
            {
                "dictionary_cpe_id": None,
                "manual_cpe": manual_cpe,
                "decision_type": "Manual",
            },
            format="json",
        )
        self.assertEqual(
            manual_response.json()["ground_truth"]["source"],
            "MANUAL",
        )

        dictionary_response = self.client.put(
            self.url,
            {
                "dictionary_cpe_id": self.cpe.id,
                "manual_cpe": None,
                "decision_type": "Dictionary again",
            },
            format="json",
        )
        self.assertEqual(
            dictionary_response.json()["ground_truth"]["source"],
            "DICTIONARY",
        )

        none_response = self.client.put(
            self.url,
            {
                "dictionary_cpe_id": None,
                "manual_cpe": None,
                "decision_type": "No CPE",
            },
            format="json",
        )
        self.assertEqual(
            none_response.json()["ground_truth"]["source"],
            "NONE",
        )
        saved = ComponentCpeGroundTruth.objects.get()
        self.assertIsNone(saved.ground_truth_cpe)
        self.assertEqual(saved.manual_ground_truth_cpe, "")

    def test_put_rejects_invalid_or_conflicting_manual_cpe(
        self,
    ) -> None:
        for payload, expected_field in (
            (
                {
                    "dictionary_cpe_id": None,
                    "manual_cpe": "invalid",
                    "decision_type": "Invalid",
                },
                "manual_cpe",
            ),
            (
                {
                    "dictionary_cpe_id": self.cpe.id,
                    "manual_cpe": (
                        "cpe:2.3:a:example:manual:"
                        "1.0:*:*:*:*:*:*:*"
                    ),
                    "decision_type": "Conflicting",
                },
                "manual_cpe",
            ),
        ):
            with self.subTest(payload=payload):
                response = self.client.put(
                    self.url,
                    payload,
                    format="json",
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertIn(expected_field, response.json())

    def test_put_rejects_empty_decision_type(self) -> None:
        for decision_type in ("", "   "):
            with self.subTest(decision_type=decision_type):
                response = self.client.put(
                    self.url,
                    {
                        "ground_truth_cpe_id": None,
                        "decision_type": decision_type,
                    },
                    format="json",
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )

    def test_missing_component_returns_404(self) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:component-cpe-ground-truth",
                args=[999999],
            )
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_put_rejects_missing_or_other_snapshot_cpe(self) -> None:
        for cpe_id, expected_fragment in (
            (999999, "Invalid pk"),
            (self.other_cpe.id, "current Dictionary snapshot"),
        ):
            with self.subTest(cpe_id=cpe_id):
                response = self.client.put(
                    self.url,
                    {
                        "ground_truth_cpe_id": cpe_id,
                        "decision_type": "Review",
                    },
                    format="json",
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertIn(
                    expected_fragment,
                    str(response.json()),
                )

    def test_put_rejects_client_snapshot_id(self) -> None:
        response = self.client.put(
            self.url,
            {
                "snapshot_id": self.other_snapshot.snapshot_id,
                "ground_truth_cpe_id": None,
                "decision_type": "Review",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertIn("snapshot_id", response.json())

    def test_snapshot_unavailable_and_ambiguous_contract(self) -> None:
        CpeDictionarySnapshot.objects.filter(
            pk=self.snapshot.pk
        ).update(status=CpeDictionarySnapshot.Status.IMPORTING)
        unavailable = self.client.get(self.url)
        self.assertEqual(
            unavailable.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            unavailable.json()["code"],
            "cpe_dictionary_snapshot_unavailable",
        )

        CpeDictionarySnapshot.objects.filter(
            pk=self.snapshot.pk
        ).update(status=CpeDictionarySnapshot.Status.COMPLETE)
        create_snapshot("20260726T035002Z")
        ambiguous = self.client.get(self.url)
        self.assertEqual(
            ambiguous.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            ambiguous.json()["code"],
            "cpe_dictionary_snapshot_ambiguous",
        )

    def test_dictionary_api_remains_read_only(self) -> None:
        response = self.client.put(
            reverse("cpe_dictionary_api:cpe-name-search"),
            {"q": "curl"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )


@override_settings(CPE_DICTIONARY_SNAPSHOT_ID=None)
class GroundTruthComponentListAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = create_snapshot("20260725T035002Z")
        cls.dictionary_cpe = create_cpe(cls.snapshot, 100)
        cls.unreviewed = create_component()
        document = cls.unreviewed.sbom_document
        cls.official = Component.objects.create(
            sbom_document=document,
            bom_ref="official",
            component_type="library",
            name="Official component",
            version="1.0",
            cpe=cls.dictionary_cpe.cpe_name,
        )
        cls.manual = Component.objects.create(
            sbom_document=document,
            bom_ref="manual",
            component_type="library",
            name="Manual component",
            version="2.0",
            cpe=(
                "cpe:2.3:a:example:manual-source:"
                "2.0:*:*:*:*:*:*:*"
            ),
        )
        cls.no_cpe = Component.objects.create(
            sbom_document=document,
            bom_ref="no-cpe",
            component_type="library",
            name="No CPE",
        )
        ComponentCpeGroundTruth.objects.create(
            component=cls.official,
            snapshot=cls.snapshot,
            ground_truth_cpe=cls.dictionary_cpe,
            decision_type="Official review",
        )
        ComponentCpeGroundTruth.objects.create(
            component=cls.manual,
            snapshot=cls.snapshot,
            manual_ground_truth_cpe=(
                "cpe:2.3:a:example:manual-target:"
                "2.1:*:*:*:*:*:*:*"
            ),
            decision_type="Manual review",
        )
        Component.objects.bulk_create(
            [
                Component(
                    sbom_document=document,
                    bom_ref=f"filler-{index}",
                    component_type="library",
                    name=f"Filler {index:02d}",
                    version="1.0",
                    cpe=(
                        "cpe:2.3:a:example:"
                        f"filler-{index}:1.0:*:*:*:*:*:*:*"
                    ),
                )
                for index in range(52)
            ]
        )

        cls.other_image = DockerImage.objects.create(
            repository="docker.io/library/other",
            tag="2.0",
            manifest_digest="sha256:" + ("c" * 64),
            pinned_reference=(
                "docker.io/library/other@sha256:" + ("c" * 64)
            ),
        )
        other_document = SBOMDocument.objects.create(
            docker_image=cls.other_image,
            source_path="pilot/results/sboms/other-2.0.cdx.json",
            file_sha256="d" * 64,
            spec_version="1.7",
            serial_number="urn:uuid:other",
            generator_name="syft",
            generator_version="1.49.0",
        )
        cls.other_component = Component.objects.create(
            sbom_document=other_document,
            bom_ref="other",
            component_type="library",
            name="Other image component",
            version="2.0",
            cpe=(
                "cpe:2.3:a:example:other:"
                "2.0:*:*:*:*:*:*:*"
            ),
        )

    @property
    def url(self) -> str:
        return reverse("sboms_api:ground-truth-component-list")

    def test_default_scope_summary_and_stable_ordering(
        self,
    ) -> None:
        response = self.client.get(
            self.url,
            {"page_size": 200},
        )
        body = response.json()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [row["id"] for row in body["results"]]
        self.assertNotIn(self.no_cpe.id, ids)
        self.assertEqual(ids, sorted(ids))
        rows = {row["id"]: row for row in body["results"]}
        self.assertEqual(
            rows[self.unreviewed.id]["ground_truth_status"],
            "UNREVIEWED",
        )
        self.assertEqual(
            rows[self.official.id]["ground_truth_status"],
            "COMPLETED",
        )
        self.assertEqual(
            rows[self.official.id]["ground_truth"]["source"],
            "DICTIONARY",
        )
        self.assertEqual(
            rows[self.manual.id]["ground_truth"]["source"],
            "MANUAL",
        )
        self.assertEqual(
            rows[self.manual.id]["decision_type"],
            "Manual review",
        )

    def test_ground_truth_status_filters(self) -> None:
        completed = self.client.get(
            self.url,
            {
                "ground_truth_status": "COMPLETED",
                "page_size": 200,
            },
        ).json()
        unreviewed = self.client.get(
            self.url,
            {
                "ground_truth_status": "UNREVIEWED",
                "page_size": 200,
            },
        ).json()

        self.assertEqual(
            {row["id"] for row in completed["results"]},
            {self.official.id, self.manual.id},
        )
        self.assertNotIn(
            self.official.id,
            {row["id"] for row in unreviewed["results"]},
        )

    def test_exact_match_image_and_keyword_filters(self) -> None:
        official = self.client.get(
            self.url,
            {"dictionary_status": "OFFICIAL_ACTIVE"},
        ).json()
        self.assertEqual(official["count"], 1)
        self.assertEqual(
            official["results"][0]["id"],
            self.official.id,
        )

        image = self.client.get(
            self.url,
            {"image_id": self.other_image.id},
        ).json()
        self.assertEqual(image["count"], 1)
        self.assertEqual(
            image["results"][0]["id"],
            self.other_component.id,
        )

        keyword = self.client.get(
            self.url,
            {"search": "Manual component"},
        ).json()
        self.assertEqual(keyword["count"], 1)
        self.assertEqual(
            keyword["results"][0]["id"],
            self.manual.id,
        )

    def test_pagination_and_descending_ordering(self) -> None:
        first = self.client.get(
            self.url,
            {"page_size": 5, "ordering": "-id"},
        ).json()
        second = self.client.get(
            self.url,
            {"page_size": 5, "page": 2, "ordering": "-id"},
        ).json()

        self.assertEqual(first["page_size"], 5)
        self.assertEqual(len(first["results"]), 5)
        self.assertTrue(first["next"])
        self.assertGreater(
            first["results"][-1]["id"],
            second["results"][0]["id"],
        )

    def test_navigation_preserves_filters_and_ordering(self) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:ground-truth-component-navigation",
                args=[self.manual.id],
            ),
            {
                "ground_truth_status": "COMPLETED",
                "ordering": "id",
            },
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.json()["previous_component_id"],
            self.official.id,
        )
        self.assertIsNone(
            response.json()["next_component_id"]
        )

    def test_ground_truth_lookup_has_no_n_plus_one_queries(
        self,
    ) -> None:
        with CaptureQueriesContext(connection) as one_row_queries:
            one_row = self.client.get(
                self.url,
                {"page_size": 1},
            )
            self.assertEqual(one_row.status_code, status.HTTP_200_OK)
        with CaptureQueriesContext(connection) as many_row_queries:
            many_rows = self.client.get(
                self.url,
                {"page_size": 50},
            )
            self.assertEqual(
                many_rows.status_code,
                status.HTTP_200_OK,
            )

        self.assertLessEqual(
            len(many_row_queries),
            len(one_row_queries) + 1,
        )

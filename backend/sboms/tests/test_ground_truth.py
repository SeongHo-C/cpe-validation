from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
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

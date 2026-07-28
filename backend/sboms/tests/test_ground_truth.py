from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import connection
from django.db.models.deletion import ProtectedError
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
    GroundTruthDecisionType,
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
        cls.decision_type = GroundTruthDecisionType.objects.create(
            name="Vendor difference"
        )
        cls.other_decision_type = (
            GroundTruthDecisionType.objects.create(
                name="Review deferred"
            )
        )

    def test_saves_ground_truth_with_official_cpe(self) -> None:
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=self.cpe,
            decision_type=self.decision_type,
        )

        self.assertEqual(ground_truth.ground_truth_cpe, self.cpe)

    def test_saves_ground_truth_without_cpe(self) -> None:
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=None,
            decision_type=self.decision_type,
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
            decision_type=self.decision_type,
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
                decision_type=self.decision_type,
            )

    def test_rejects_invalid_manual_cpe(self) -> None:
        with self.assertRaises(ValidationError):
            ComponentCpeGroundTruth.objects.create(
                component=self.component,
                snapshot=self.snapshot,
                manual_ground_truth_cpe="not-a-cpe",
                decision_type=self.decision_type,
            )

    def test_rejects_duplicate_component_and_snapshot(self) -> None:
        ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            decision_type=self.decision_type,
        )

        with self.assertRaises(ValidationError):
            ComponentCpeGroundTruth.objects.create(
                component=self.component,
                snapshot=self.snapshot,
                decision_type=self.other_decision_type,
            )

    def test_rejects_cpe_from_another_snapshot(self) -> None:
        with self.assertRaises(ValidationError):
            ComponentCpeGroundTruth.objects.create(
                component=self.component,
                snapshot=self.snapshot,
                ground_truth_cpe=self.other_cpe,
                decision_type=self.decision_type,
            )

    def test_rejects_nonexistent_component_and_cpe(self) -> None:
        ground_truth = ComponentCpeGroundTruth(
            component_id=999999,
            snapshot=self.snapshot,
            ground_truth_cpe_id=999999,
            decision_type=self.decision_type,
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
            decision_type=self.decision_type,
        )

        self.component.refresh_from_db()
        self.assertEqual(self.component.cpe, original_cpe)


class GroundTruthDecisionTypeModelTests(TestCase):
    def test_trims_name_and_description_and_preserves_casing(
        self,
    ) -> None:
        decision_type = GroundTruthDecisionType.objects.create(
            name="  Vendor Difference  ",
            description="  Supporting evidence  ",
        )

        self.assertEqual(decision_type.name, "Vendor Difference")
        self.assertEqual(
            decision_type.description,
            "Supporting evidence",
        )
        self.assertTrue(decision_type.is_active)

        decision_type.is_active = False
        decision_type.save()
        decision_type.is_active = True
        decision_type.save()
        self.assertTrue(decision_type.is_active)

    def test_rejects_blank_and_case_insensitive_duplicate_names(
        self,
    ) -> None:
        GroundTruthDecisionType.objects.create(name="Review")

        for name in ("", "   ", "review", " REVIEW "):
            with self.subTest(name=name):
                with self.assertRaises(ValidationError):
                    GroundTruthDecisionType.objects.create(name=name)

    def test_rejects_hangul_in_name_or_description(self) -> None:
        for values, expected_field in (
            ({"name": "한국어 유형"}, "name"),
            (
                {
                    "name": "English name",
                    "description": "한국어 설명",
                },
                "description",
            ),
            ({"name": "Jamo ㄱ type"}, "name"),
        ):
            with self.subTest(values=values):
                with self.assertRaises(ValidationError) as raised:
                    GroundTruthDecisionType.objects.create(**values)
                self.assertIn(
                    expected_field,
                    raised.exception.message_dict,
                )

    def test_uses_stable_name_then_id_ordering(self) -> None:
        second = GroundTruthDecisionType.objects.create(name="Zulu")
        first = GroundTruthDecisionType.objects.create(name="Alpha")

        self.assertEqual(
            list(
                GroundTruthDecisionType.objects.filter(
                    id__in=(first.id, second.id)
                ).values_list(
                    "id", flat=True
                )
            ),
            [first.id, second.id],
        )

    def test_protects_a_referenced_decision_type_from_deletion(
        self,
    ) -> None:
        decision_type = GroundTruthDecisionType.objects.create(
            name="Protected review"
        )
        ComponentCpeGroundTruth.objects.create(
            component=create_component(),
            snapshot=create_snapshot("20260725T035002Z"),
            decision_type=decision_type,
        )

        with self.assertRaises(ProtectedError):
            decision_type.delete()


class GroundTruthDecisionTypeAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.active = GroundTruthDecisionType.objects.create(
            name="Active review",
            description="Used for active reviews",
        )
        cls.inactive = GroundTruthDecisionType.objects.create(
            name="Archived review",
            is_active=False,
        )
        snapshot = create_snapshot("20260725T035002Z")
        ComponentCpeGroundTruth.objects.create(
            component=create_component(),
            snapshot=snapshot,
            decision_type=cls.active,
        )

    @property
    def list_url(self) -> str:
        return reverse(
            "sboms_api:ground-truth-decision-type-list"
        )

    def test_list_defaults_to_active_with_usage_count(self) -> None:
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_items = {
            item["id"]: item for item in response.json()
        }
        self.assertIn(self.active.id, response_items)
        self.assertNotIn(self.inactive.id, response_items)
        self.assertEqual(
            response_items[self.active.id]["usage_count"],
            1,
        )

    def test_list_filters_searches_and_orders_stably(self) -> None:
        another = GroundTruthDecisionType.objects.create(
            name="zulu review",
            description="Searchable description",
        )

        all_response = self.client.get(
            self.list_url,
            {"is_active": "all"},
        )
        search_response = self.client.get(
            self.list_url,
            {"search": "searchable"},
        )
        inactive_response = self.client.get(
            self.list_url,
            {"is_active": "false"},
        )

        all_names = [item["name"] for item in all_response.json()]
        self.assertEqual(
            all_names,
            sorted(all_names, key=str.casefold),
        )
        self.assertIn("Active review", all_names)
        self.assertIn("Archived review", all_names)
        self.assertIn("zulu review", all_names)
        self.assertEqual(
            [item["id"] for item in search_response.json()],
            [another.id],
        )
        self.assertEqual(
            [item["id"] for item in inactive_response.json()],
            [self.inactive.id],
        )

    def test_create_trims_and_rejects_blank_or_duplicate_name(
        self,
    ) -> None:
        created = self.client.post(
            self.list_url,
            {
                "name": "  New Review  ",
                "description": "  Explanation  ",
            },
            format="json",
        )

        self.assertEqual(
            created.status_code,
            status.HTTP_201_CREATED,
        )
        self.assertEqual(created.json()["name"], "New Review")
        self.assertEqual(
            created.json()["description"],
            "Explanation",
        )
        for name in ("   ", "ACTIVE REVIEW"):
            with self.subTest(name=name):
                rejected = self.client.post(
                    self.list_url,
                    {"name": name},
                    format="json",
                )
                self.assertEqual(
                    rejected.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )

    def test_create_rejects_hangul_name_and_description(
        self,
    ) -> None:
        for payload, expected_field in (
            (
                {
                    "name": "한국어 유형",
                    "description": "English description",
                },
                "name",
            ),
            (
                {
                    "name": "English name",
                    "description": "한국어 설명",
                },
                "description",
            ),
        ):
            with self.subTest(payload=payload):
                response = self.client.post(
                    self.list_url,
                    payload,
                    format="json",
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertIn(expected_field, response.json())

    def test_patch_updates_only_description_and_active_state(
        self,
    ) -> None:
        url = reverse(
            "sboms_api:ground-truth-decision-type-detail",
            args=[self.active.id],
        )
        updated = self.client.patch(
            url,
            {
                "description": "  Updated  ",
                "is_active": False,
            },
            format="json",
        )
        renamed = self.client.patch(
            url,
            {"name": "Renamed"},
            format="json",
        )
        deleted = self.client.delete(url)

        self.assertEqual(updated.status_code, status.HTTP_200_OK)
        self.assertEqual(updated.json()["description"], "Updated")
        self.assertFalse(updated.json()["is_active"])
        reactivated = self.client.patch(
            url,
            {"is_active": True},
            format="json",
        )
        self.assertEqual(
            reactivated.status_code,
            status.HTTP_200_OK,
        )
        self.assertTrue(reactivated.json()["is_active"])
        hangul_description = self.client.patch(
            url,
            {"description": "한국어 설명"},
            format="json",
        )
        self.assertEqual(
            hangul_description.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertIn(
            "description",
            hangul_description.json(),
        )
        self.assertEqual(
            renamed.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertIn("name", renamed.json())
        self.assertEqual(
            deleted.status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )


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
        cls.decision_type = GroundTruthDecisionType.objects.create(
            name="Vendor difference"
        )
        cls.other_decision_type = (
            GroundTruthDecisionType.objects.create(
                name="Review deferred"
            )
        )
        cls.inactive_decision_type = (
            GroundTruthDecisionType.objects.create(
                name="Legacy review",
                is_active=False,
            )
        )

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
            decision_type=self.decision_type,
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
        self.assertEqual(
            body["decision_type"],
            {
                "id": self.decision_type.id,
                "name": "Vendor difference",
                "description": "",
                "is_active": True,
            },
        )
        self.assertEqual(body["note"], "Upstream vendor evidence")

    def test_get_returns_manual_and_no_cpe_sources(self) -> None:
        manual_cpe = (
            "cpe:2.3:a:example:manual:2.0:*:*:*:*:*:*:*"
        )
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            manual_ground_truth_cpe=manual_cpe,
            decision_type=self.decision_type,
        )

        manual_body = self.client.get(self.url).json()[
            "ground_truth"
        ]
        self.assertEqual(manual_body["source"], "MANUAL")
        self.assertEqual(manual_body["manual_cpe"], manual_cpe)
        self.assertIsNone(manual_body["dictionary_cpe"])

        ground_truth.manual_ground_truth_cpe = ""
        ground_truth.decision_type = self.other_decision_type
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
                "decision_type_id": self.decision_type.id,
                "note": "Human review",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        saved = ComponentCpeGroundTruth.objects.get()
        self.assertEqual(saved.ground_truth_cpe, self.cpe)
        self.assertEqual(saved.decision_type, self.decision_type)
        self.component.refresh_from_db()
        self.assertEqual(self.component.cpe, original_cpe)

    def test_put_creates_record_without_cpe(self) -> None:
        response = self.client.put(
            self.url,
            {
                "ground_truth_cpe_id": None,
                "decision_type_id": self.decision_type.id,
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
                "decision_type_id": self.decision_type.id,
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
                "decision_type_id": self.decision_type.id,
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
            decision_type=self.decision_type,
        )

        response = self.client.put(
            self.url,
            {
                "ground_truth_cpe_id": None,
                "decision_type_id": self.other_decision_type.id,
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
        self.assertEqual(
            saved.decision_type,
            self.other_decision_type,
        )
        self.assertEqual(saved.note, "Updated evidence")

    def test_put_switches_between_dictionary_manual_and_none(
        self,
    ) -> None:
        ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            ground_truth_cpe=self.cpe,
            decision_type=self.decision_type,
        )
        manual_cpe = (
            "cpe:2.3:a:example:manual:4.0:*:*:*:*:*:*:*"
        )

        manual_response = self.client.put(
            self.url,
            {
                "dictionary_cpe_id": None,
                "manual_cpe": manual_cpe,
                "decision_type_id": self.decision_type.id,
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
                "decision_type_id": self.decision_type.id,
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
                "decision_type_id": self.decision_type.id,
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
                    "decision_type_id": self.decision_type.id,
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
                    "decision_type_id": self.decision_type.id,
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

    def test_put_requires_managed_decision_type_id(self) -> None:
        for payload in (
            {"ground_truth_cpe_id": None},
            {
                "ground_truth_cpe_id": None,
                "decision_type_id": 999999,
            },
            {
                "ground_truth_cpe_id": None,
                "decision_type": "Legacy free text",
            },
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

    def test_put_rejects_new_inactive_decision_type(self) -> None:
        response = self.client.put(
            self.url,
            {
                "ground_truth_cpe_id": None,
                "decision_type_id": self.inactive_decision_type.id,
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertIn("decision_type_id", response.json())

    def test_put_allows_retaining_existing_inactive_type(self) -> None:
        ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            decision_type=self.inactive_decision_type,
        )

        response = self.client.put(
            self.url,
            {
                "ground_truth_cpe_id": None,
                "decision_type_id": self.inactive_decision_type.id,
                "note": "Retained during note edit",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(
            response.json()["ground_truth"]["decision_type"][
                "is_active"
            ]
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
                        "decision_type_id": self.decision_type.id,
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
                "decision_type_id": self.decision_type.id,
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
        cls.official_decision_type = (
            GroundTruthDecisionType.objects.create(
                name="Official review"
            )
        )
        cls.manual_decision_type = (
            GroundTruthDecisionType.objects.create(
                name="Manual review",
                is_active=False,
            )
        )
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
            decision_type=cls.official_decision_type,
        )
        ComponentCpeGroundTruth.objects.create(
            component=cls.manual,
            snapshot=cls.snapshot,
            manual_ground_truth_cpe=(
                "cpe:2.3:a:example:manual-target:"
                "2.1:*:*:*:*:*:*:*"
            ),
            decision_type=cls.manual_decision_type,
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
            rows[self.manual.id]["decision_type"]["name"],
            "Manual review",
        )
        self.assertFalse(
            rows[self.manual.id]["decision_type"]["is_active"]
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

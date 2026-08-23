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

from cpe.cpe23 import parse_cpe23_formatted_string
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    DockerImage,
    GroundTruthCorrectionType,
    GroundTruthDecision,
    GroundTruthDiscrepancyType,
    GroundTruthResolutionOutcome,
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
    *,
    raw_cpe: str | None = None,
) -> CpeName:
    cpe_name = raw_cpe or (
        "cpe:2.3:a:example:product:"
        f"{number}:*:*:*:*:*:*:*"
    )
    parsed = parse_cpe23_formatted_string(cpe_name)
    if not parsed.is_structurally_valid:
        raise AssertionError(parsed.error_message)
    return CpeName.objects.create(
        snapshot=snapshot,
        cpe_name_id=UUID(int=number),
        cpe_name=cpe_name,
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
        part=parsed.part_raw,
        vendor=parsed.vendor_raw,
        product=parsed.product_raw,
        version=parsed.version_raw,
        update=parsed.update_raw,
        edition=parsed.edition_raw,
        language=parsed.language_raw,
        sw_edition=parsed.sw_edition_raw,
        target_sw=parsed.target_sw_raw,
        target_hw=parsed.target_hw_raw,
        other=parsed.other_raw,
    )


def create_component(
    *,
    suffix: str = "example",
    cpe: str = (
        "cpe:2.3:a:syft:example:1.0:*:*:*:*:*:*:*"
    ),
) -> Component:
    digest_character = chr(97 + (sum(map(ord, suffix)) % 20))
    image = DockerImage.objects.create(
        repository=f"docker.io/library/{suffix}",
        tag="1.0",
        manifest_digest="sha256:" + (digest_character * 64),
        pinned_reference=(
            f"docker.io/library/{suffix}@sha256:"
            + (digest_character * 64)
        ),
    )
    document = SBOMDocument.objects.create(
        docker_image=image,
        source_path=f"pilot/results/sboms/{suffix}-1.0.cdx.json",
        file_sha256=digest_character.upper() * 64,
        spec_version="1.7",
        serial_number=f"urn:uuid:{suffix}",
        generator_name="syft",
        generator_version="1.49.0",
    )
    return Component.objects.create(
        sbom_document=document,
        bom_ref=f"pkg:generic/{suffix}@1.0",
        component_type="library",
        name=suffix,
        version="1.0",
        cpe=cpe,
    )


def create_correction_type(
    code: str,
    *,
    name: str | None = None,
    is_active: bool = True,
) -> GroundTruthCorrectionType:
    correction_type, _ = (
        GroundTruthCorrectionType.objects.update_or_create(
            code=code,
            defaults={
                "name": name or code.replace("_", " ").title(),
                "description": f"Evidence for {code}",
                "is_active": is_active,
            },
        )
    )
    return correction_type


def create_discrepancy_type(
    code: str,
    *,
    name: str | None = None,
    is_active: bool = True,
    display_order: int | None = None,
) -> GroundTruthDiscrepancyType:
    defaults = {
        "name": name or code.replace("_", " ").title(),
        "description": f"Evidence for {code}",
        "is_active": is_active,
    }
    if display_order is not None:
        defaults["display_order"] = display_order
    discrepancy_type, _ = (
        GroundTruthDiscrepancyType.objects.update_or_create(
            code=code,
            defaults=defaults,
        )
    )
    return discrepancy_type


class ComponentCpeGroundTruthModelTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = create_snapshot("20260725T035002Z")
        cls.other_snapshot = create_snapshot(
            "20260724T035002Z",
            status_value=CpeDictionarySnapshot.Status.IMPORTING,
        )
        cls.component = create_component()
        cls.original_cpe = create_cpe(
            cls.snapshot,
            1,
            raw_cpe=cls.component.cpe,
        )
        cls.corrected_cpe = create_cpe(cls.snapshot, 2)
        cls.other_cpe = create_cpe(cls.other_snapshot, 3)

    def test_derives_all_resolution_outcomes(self) -> None:
        cases = (
            (
                {
                    "decision": GroundTruthDecision.CPE_CONFIRMED,
                    "ground_truth_cpe": self.original_cpe,
                },
                (
                    GroundTruthResolutionOutcome
                    .ORIGINAL_OFFICIAL_CONFIRMED
                ),
            ),
            (
                {
                    "decision": GroundTruthDecision.OFFICIAL_CPE_MAPPED,
                    "ground_truth_cpe": self.corrected_cpe,
                },
                (
                    GroundTruthResolutionOutcome
                    .CORRECTED_TO_DICTIONARY
                ),
            ),
            (
                {
                    "decision": GroundTruthDecision.OFFICIAL_CPE_MAPPED,
                    "manual_ground_truth_cpe": (
                        "cpe:2.3:a:example:manual:"
                        "1.0:*:*:*:*:*:*:*"
                    )
                },
                (
                    GroundTruthResolutionOutcome
                    .MANUAL_FROM_OFFICIAL_FAMILY
                ),
            ),
            (
                {
                    "decision": (
                        GroundTruthDecision
                        .DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
                    )
                },
                (
                    GroundTruthResolutionOutcome
                    .DIRECT_OFFICIAL_NOT_CONFIRMED
                ),
            ),
        )
        for index, (values, expected) in enumerate(cases):
            component = (
                self.component
                if index == 0
                else Component.objects.create(
                    sbom_document=self.component.sbom_document,
                    bom_ref=f"case-{index}",
                    component_type="library",
                    name=f"case-{index}",
                    cpe=self.component.cpe,
                )
            )
            with self.subTest(expected=expected):
                ground_truth = (
                    ComponentCpeGroundTruth.objects.create(
                        component=component,
                        snapshot=self.snapshot,
                        **values,
                    )
                )
                self.assertEqual(
                    ground_truth.resolution_outcome,
                    expected,
                )

    def test_recalculates_outcome_when_ground_truth_changes(
        self,
    ) -> None:
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            decision=GroundTruthDecision.CPE_CONFIRMED,
            ground_truth_cpe=self.original_cpe,
        )
        ground_truth.decision = GroundTruthDecision.OFFICIAL_CPE_MAPPED
        ground_truth.ground_truth_cpe = self.corrected_cpe
        ground_truth.save(update_fields={"ground_truth_cpe"})
        ground_truth.refresh_from_db()

        self.assertEqual(
            ground_truth.resolution_outcome,
            (
                GroundTruthResolutionOutcome
                .CORRECTED_TO_DICTIONARY
            ),
        )

    def test_trims_manual_cpe_and_preserves_original_component(
        self,
    ) -> None:
        original = self.component.cpe
        manual = (
            "cpe:2.3:a:Example:Manual:1.2.4:*:*:*:*:*:*:*"
        )
        ground_truth = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            decision=GroundTruthDecision.OFFICIAL_CPE_MAPPED,
            manual_ground_truth_cpe=f"  {manual}  ",
        )

        self.assertEqual(
            ground_truth.manual_ground_truth_cpe,
            manual,
        )
        self.component.refresh_from_db()
        self.assertEqual(self.component.cpe, original)

    def test_rejects_invalid_source_combinations_and_snapshot(
        self,
    ) -> None:
        for values in (
            {
                "ground_truth_cpe": self.corrected_cpe,
                "manual_ground_truth_cpe": (
                    "cpe:2.3:a:example:manual:"
                    "1.0:*:*:*:*:*:*:*"
                ),
            },
            {"manual_ground_truth_cpe": "not-a-cpe"},
            {"ground_truth_cpe": self.other_cpe},
        ):
            with self.subTest(values=values):
                with self.assertRaises(ValidationError):
                    ComponentCpeGroundTruth.objects.create(
                        component=self.component,
                        snapshot=self.snapshot,
                        decision=(
                            GroundTruthDecision.OFFICIAL_CPE_MAPPED
                        ),
                        **values,
                    )


class GroundTruthCorrectionTypeModelTests(TestCase):
    def test_normalizes_and_manages_correction_type(self) -> None:
        correction_type = GroundTruthCorrectionType.objects.create(
            code="  model_vendor_corrected  ",
            name="  Model vendor corrected  ",
            description="  Canonical vendor  ",
        )

        self.assertEqual(
            correction_type.code,
            "model_vendor_corrected",
        )
        self.assertEqual(
            correction_type.name,
            "Model vendor corrected",
        )
        self.assertEqual(
            correction_type.description,
            "Canonical vendor",
        )
        correction_type.is_active = False
        correction_type.save()
        correction_type.is_active = True
        correction_type.save()
        self.assertTrue(correction_type.is_active)

    def test_rejects_invalid_code_duplicate_and_hangul(self) -> None:
        create_correction_type(
            "unique_vendor_corrected",
            name="Unique vendor corrected",
        )
        invalid_values = (
            {
                "code": "Vendor corrected",
                "name": "Other type",
            },
            {
                "code": "unique_vendor_corrected",
                "name": "Duplicate code",
            },
            {
                "code": "other_type",
                "name": "Unique Vendor Corrected",
            },
            {
                "code": "hangul_type",
                "name": "한국어 유형",
            },
            {
                "code": "hangul_description",
                "name": "English name",
                "description": "한국어 설명",
            },
        )
        for values in invalid_values:
            with self.subTest(values=values):
                with self.assertRaises(ValidationError):
                    GroundTruthCorrectionType.objects.create(
                        **values
                    )


class GroundTruthCorrectionTypeAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.active = create_correction_type(
            "vendor_corrected",
            name="Vendor corrected",
        )
        cls.inactive = create_correction_type(
            "archived_correction",
            name="Archived correction",
            is_active=False,
        )
        snapshot = create_snapshot("20260725T035002Z")
        component = create_component()
        cpe = create_cpe(snapshot, 10)
        record = ComponentCpeGroundTruth.objects.create(
            component=component,
            snapshot=snapshot,
            decision=GroundTruthDecision.OFFICIAL_CPE_MAPPED,
            ground_truth_cpe=cpe,
        )
        record.correction_types.add(cls.active)

    @property
    def list_url(self) -> str:
        return reverse(
            "sboms_api:ground-truth-correction-type-list"
        )

    def test_list_search_active_filter_and_usage_count(self) -> None:
        active = self.client.get(self.list_url)
        all_rows = self.client.get(
            self.list_url,
            {"is_active": "all"},
        )
        search = self.client.get(
            self.list_url,
            {"search": "vendor_corrected"},
        )

        self.assertEqual(active.status_code, status.HTTP_200_OK)
        self.assertIn(
            self.active.id,
            [row["id"] for row in active.json()],
        )
        self.assertNotIn(
            self.inactive.id,
            [row["id"] for row in active.json()],
        )
        self.assertTrue(
            {self.active.id, self.inactive.id}.issubset(
                {row["id"] for row in all_rows.json()}
            )
        )
        self.assertEqual(search.json()[0]["usage_count"], 1)

    def test_create_validates_code_name_and_english_text(self) -> None:
        created = self.client.post(
            self.list_url,
            {
                "code": " api_product_corrected ",
                "name": " API product corrected ",
                "description": " Canonical product ",
            },
            format="json",
        )
        self.assertEqual(
            created.status_code,
            status.HTTP_201_CREATED,
        )
        self.assertEqual(
            created.json()["code"],
            "api_product_corrected",
        )

        for payload, expected_field in (
            (
                {
                    "code": "Product corrected",
                    "name": "Another type",
                },
                "code",
            ),
            (
                {
                    "code": "other_code",
                    "name": "Vendor corrected",
                },
                "name",
            ),
            (
                {
                    "code": "hangul_type",
                    "name": "한국어 유형",
                },
                "name",
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

    def test_patch_toggles_active_but_code_and_name_are_immutable(
        self,
    ) -> None:
        url = reverse(
            "sboms_api:ground-truth-correction-type-detail",
            args=[self.active.id],
        )
        updated = self.client.patch(
            url,
            {
                "description": " Updated ",
                "is_active": False,
            },
            format="json",
        )
        renamed = self.client.patch(
            url,
            {"name": "Renamed", "code": "renamed"},
            format="json",
        )
        deleted = self.client.delete(url)

        self.assertEqual(updated.status_code, status.HTTP_200_OK)
        self.assertEqual(updated.json()["description"], "Updated")
        self.assertFalse(updated.json()["is_active"])
        self.assertEqual(
            renamed.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertEqual(
            deleted.status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )


class GroundTruthDiscrepancyTypeAPITests(APITestCase):
    def test_list_uses_all_cpe23_fields_in_canonical_order(
        self,
    ) -> None:
        response = self.client.get(
            reverse(
                "sboms_api:ground-truth-discrepancy-type-list"
            )
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            [item["code"] for item in response.json()],
            [
                "PART",
                "VENDOR",
                "PRODUCT",
                "VERSION",
                "UPDATE",
                "EDITION",
                "LANGUAGE",
                "SW_EDITION",
                "TARGET_SW",
                "TARGET_HW",
                "OTHER",
            ],
        )
        part = next(
            item
            for item in response.json()
            if item["code"] == "PART"
        )
        self.assertEqual(
            part["name"],
            "Part (Application / OS / Hardware)",
        )
        self.assertEqual(
            part["description"],
            (
                "The part attribute in the original CPE is incorrect "
                "(application, operating system, or hardware)."
            ),
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
        cls.component = create_component()
        cls.original_cpe = create_cpe(
            cls.snapshot,
            20,
            raw_cpe=cls.component.cpe,
        )
        cls.corrected_cpe = create_cpe(cls.snapshot, 21)
        cls.other_cpe = create_cpe(cls.other_snapshot, 22)
        cls.vendor = create_correction_type(
            "vendor_corrected",
            name="Vendor corrected",
        )
        cls.product = create_correction_type(
            "product_corrected",
            name="Product corrected",
        )
        cls.inactive = create_correction_type(
            "archived_correction",
            name="Archived correction",
            is_active=False,
        )
        cls.vendor_discrepancy = create_discrepancy_type(
            "VENDOR",
            name="Vendor",
        )
        cls.product_discrepancy = create_discrepancy_type(
            "PRODUCT",
            name="Product",
        )
        cls.version_discrepancy = create_discrepancy_type(
            "VERSION",
            name="Version",
        )
        cls.inactive_discrepancy = create_discrepancy_type(
            "ARCHIVED_DISCREPANCY",
            name="Archived discrepancy",
            is_active=False,
        )

    @property
    def url(self) -> str:
        return reverse(
            "sboms_api:component-cpe-ground-truth",
            args=[self.component.id],
        )

    def put(self, **payload):
        dictionary_cpe_id = payload.get("dictionary_cpe_id")
        manual_cpe = payload.get("manual_cpe")
        inferred_decision = (
            GroundTruthDecision.CPE_CONFIRMED
            if dictionary_cpe_id == self.original_cpe.id
            else (
                GroundTruthDecision.OFFICIAL_CPE_MAPPED
                if dictionary_cpe_id is not None or manual_cpe
                else (
                    GroundTruthDecision
                    .DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
                )
            )
        )
        defaults = {
            "decision": inferred_decision,
            "dictionary_cpe_id": None,
            "manual_cpe": None,
            "correction_type_ids": [],
            "discrepancy_type_ids": (
                [self.vendor_discrepancy.id]
                if inferred_decision
                == GroundTruthDecision.OFFICIAL_CPE_MAPPED
                else []
            ),
            "note": "",
        }
        defaults.update(payload)
        return self.client.put(
            self.url,
            defaults,
            format="json",
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

    def test_dictionary_outcomes_are_derived_from_raw_string(
        self,
    ) -> None:
        original = self.put(
            dictionary_cpe_id=self.original_cpe.id,
        )
        self.assertEqual(
            original.json()["ground_truth"]["decision"],
            {
                "code": "CPE_CONFIRMED",
                "name": "CPE Confirmed",
            },
        )
        self.assertEqual(
            original.json()["ground_truth"]["resolution_outcome"],
            {
                "code": "ORIGINAL_OFFICIAL_CONFIRMED",
                "label": "Original CPE confirmed",
            },
        )

        corrected = self.put(
            dictionary_cpe_id=self.corrected_cpe.id,
            correction_type_ids=[
                self.vendor.id,
                self.product.id,
            ],
            discrepancy_type_ids=[
                self.vendor_discrepancy.id,
                self.product_discrepancy.id,
            ],
        )
        body = corrected.json()["ground_truth"]
        self.assertEqual(
            body["dictionary_cpe"]["id"],
            self.corrected_cpe.id,
        )
        self.assertNotIn("ground_truth_cpe", body)
        self.assertEqual(
            body["resolution_outcome"]["code"],
            "CORRECTED_TO_DICTIONARY",
        )
        self.assertEqual(
            {item["code"] for item in body["correction_types"]},
            {"vendor_corrected", "product_corrected"},
        )
        self.assertEqual(
            body["decision"]["code"],
            "OFFICIAL_CPE_MAPPED",
        )
        self.assertEqual(
            {item["code"] for item in body["discrepancy_types"]},
            {"VENDOR", "PRODUCT"},
        )
        saved = ComponentCpeGroundTruth.objects.get()
        self.assertEqual(saved.component.cpe, self.component.cpe)

    def test_manual_and_none_outcomes_are_derived(self) -> None:
        manual = self.put(
            manual_cpe=(
                "cpe:2.3:a:example:manual:"
                "3.0:*:*:*:*:*:*:*"
            ),
        )
        self.assertEqual(
            manual.json()["ground_truth"]["resolution_outcome"][
                "code"
            ],
            "MANUAL_FROM_OFFICIAL_FAMILY",
        )
        none = self.put()
        self.assertEqual(
            none.json()["ground_truth"]["decision"]["code"],
            "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
        )
        self.assertEqual(
            none.json()["ground_truth"]["resolution_outcome"][
                "code"
            ],
            "DIRECT_OFFICIAL_NOT_CONFIRMED",
        )
        self.assertEqual(
            none.json()["ground_truth"]["correction_types"],
            [],
        )

    def test_client_cannot_set_resolution_outcome(self) -> None:
        response = self.put(
            resolution_outcome="ORIGINAL_OFFICIAL_CONFIRMED",
        )
        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertIn("resolution_outcome", response.json())

    def test_update_recalculates_outcome_and_replaces_corrections(
        self,
    ) -> None:
        self.put(
            dictionary_cpe_id=self.corrected_cpe.id,
            correction_type_ids=[self.vendor.id],
            discrepancy_type_ids=[self.vendor_discrepancy.id],
        )
        updated = self.put(
            manual_cpe=(
                "cpe:2.3:a:example:manual:"
                "4.0:*:*:*:*:*:*:*"
            ),
            correction_type_ids=[self.product.id],
            discrepancy_type_ids=[self.product_discrepancy.id],
        )

        self.assertEqual(
            ComponentCpeGroundTruth.objects.count(),
            1,
        )
        self.assertEqual(
            updated.json()["ground_truth"]["resolution_outcome"][
                "code"
            ],
            "MANUAL_FROM_OFFICIAL_FAMILY",
        )
        self.assertEqual(
            {
                item["code"]
                for item in updated.json()["ground_truth"][
                    "correction_types"
                ]
            },
            {"product_corrected"},
        )
        self.assertEqual(
            {
                item["code"]
                for item in updated.json()["ground_truth"][
                    "discrepancy_types"
                ]
            },
            {"PRODUCT"},
        )

    def test_create_and_update_support_version_mismatch(self) -> None:
        created = self.put(
            dictionary_cpe_id=self.corrected_cpe.id,
            discrepancy_type_ids=[self.vendor_discrepancy.id],
        )
        updated = self.put(
            dictionary_cpe_id=self.corrected_cpe.id,
            discrepancy_type_ids=[self.version_discrepancy.id],
        )

        self.assertEqual(created.status_code, status.HTTP_200_OK)
        self.assertEqual(updated.status_code, status.HTTP_200_OK)
        self.assertEqual(ComponentCpeGroundTruth.objects.count(), 1)
        self.assertEqual(
            [
                item["code"]
                for item in updated.json()["ground_truth"][
                    "discrepancy_types"
                ]
            ],
            ["VERSION"],
        )

    def test_multiple_incorrect_fields_persist_after_retrieval(
        self,
    ) -> None:
        saved = self.put(
            dictionary_cpe_id=self.corrected_cpe.id,
            discrepancy_type_ids=[
                self.vendor_discrepancy.id,
                self.product_discrepancy.id,
            ],
        )
        restored = self.client.get(self.url)

        self.assertEqual(saved.status_code, status.HTTP_200_OK)
        self.assertEqual(restored.status_code, status.HTTP_200_OK)
        self.assertEqual(
            {
                item["code"]
                for item in restored.json()["ground_truth"][
                    "discrepancy_types"
                ]
            },
            {"VENDOR", "PRODUCT"},
        )

    def test_mapped_requires_cpe_and_discrepancy(self) -> None:
        missing_cpe = self.put(
            decision=GroundTruthDecision.OFFICIAL_CPE_MAPPED,
            discrepancy_type_ids=[self.vendor_discrepancy.id],
        )
        missing_discrepancy = self.put(
            decision=GroundTruthDecision.OFFICIAL_CPE_MAPPED,
            dictionary_cpe_id=self.corrected_cpe.id,
            discrepancy_type_ids=[],
        )

        self.assertEqual(
            missing_cpe.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertIn("decision", missing_cpe.json())
        self.assertEqual(
            missing_discrepancy.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertIn(
            "discrepancy_type_ids",
            missing_discrepancy.json(),
        )

    def test_direct_requires_empty_cpe_and_allows_discrepancies(
        self,
    ) -> None:
        with_cpe = self.put(
            decision=(
                GroundTruthDecision
                .DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
            ),
            dictionary_cpe_id=self.corrected_cpe.id,
            discrepancy_type_ids=[],
        )
        valid = self.put(
            decision=(
                GroundTruthDecision
                .DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
            ),
            discrepancy_type_ids=[self.vendor_discrepancy.id],
        )

        self.assertEqual(with_cpe.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("decision", with_cpe.json())
        self.assertEqual(valid.status_code, status.HTTP_200_OK)
        self.assertEqual(
            valid.json()["ground_truth"]["discrepancy_types"][0][
                "code"
            ],
            "VENDOR",
        )

    def test_decision_is_required(self) -> None:
        response = self.client.put(
            self.url,
            {
                "dictionary_cpe_id": None,
                "manual_cpe": None,
                "discrepancy_type_ids": [],
                "note": "",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("decision", response.json())

    def test_new_decisions_are_saved_as_internal_codes(self) -> None:
        for decision, expected_name in (
            (
                GroundTruthDecision.VERSION_NOT_IN_DICTIONARY,
                "Product Found, Version Not Registered",
            ),
            (
                GroundTruthDecision.NVD_CONFIGURATION_ONLY,
                "Found Only in NVD Configuration",
            ),
        ):
            with self.subTest(decision=decision):
                response = self.put(
                    decision=decision,
                    discrepancy_type_ids=[],
                )

                self.assertEqual(
                    response.status_code,
                    status.HTTP_200_OK,
                )
                self.assertEqual(
                    response.json()["ground_truth"]["decision"],
                    {
                        "code": decision,
                        "name": expected_name,
                    },
                )
                self.assertEqual(
                    ComponentCpeGroundTruth.objects.get().decision,
                    decision,
                )

    def test_rejects_duplicate_and_new_inactive_corrections(
        self,
    ) -> None:
        for ids in (
            [self.vendor.id, self.vendor.id],
            [self.inactive.id],
        ):
            with self.subTest(ids=ids):
                response = self.put(
                    dictionary_cpe_id=self.corrected_cpe.id,
                    correction_type_ids=ids,
                )
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertIn(
                    "correction_type_ids",
                    response.json(),
                )

    def test_allows_retaining_existing_inactive_correction(
        self,
    ) -> None:
        record = ComponentCpeGroundTruth.objects.create(
            component=self.component,
            snapshot=self.snapshot,
            decision=GroundTruthDecision.OFFICIAL_CPE_MAPPED,
            ground_truth_cpe=self.corrected_cpe,
        )
        record.correction_types.add(self.inactive)

        response = self.put(
            dictionary_cpe_id=self.corrected_cpe.id,
            correction_type_ids=[self.inactive.id],
            note="Retained",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(
            response.json()["ground_truth"]["correction_types"][
                0
            ]["is_active"]
        )

    def test_forbids_corrections_for_original_and_direct_outcomes(
        self,
    ) -> None:
        for values in (
            {
                "dictionary_cpe_id": self.original_cpe.id,
                "correction_type_ids": [self.vendor.id],
            },
            {"correction_type_ids": [self.vendor.id]},
        ):
            with self.subTest(values=values):
                response = self.put(**values)
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertIn(
                    "correction_type_ids",
                    response.json(),
                )

    def test_rejects_invalid_cpe_source_snapshot_and_client_snapshot(
        self,
    ) -> None:
        cases = (
            (
                {
                    "manual_cpe": "invalid",
                },
                "manual_cpe",
            ),
            (
                {
                    "dictionary_cpe_id": self.corrected_cpe.id,
                    "manual_cpe": (
                        "cpe:2.3:a:example:manual:"
                        "1.0:*:*:*:*:*:*:*"
                    ),
                },
                "manual_cpe",
            ),
            (
                {"dictionary_cpe_id": self.other_cpe.id},
                "dictionary_cpe_id",
            ),
            (
                {"snapshot_id": self.other_snapshot.snapshot_id},
                "snapshot_id",
            ),
        )
        for values, expected_field in cases:
            with self.subTest(values=values):
                response = self.put(**values)
                self.assertEqual(
                    response.status_code,
                    status.HTTP_400_BAD_REQUEST,
                )
                self.assertIn(expected_field, response.json())

    def test_snapshot_and_missing_component_contracts(self) -> None:
        missing = self.client.get(
            reverse(
                "sboms_api:component-cpe-ground-truth",
                args=[999999],
            )
        )
        self.assertEqual(
            missing.status_code,
            status.HTTP_404_NOT_FOUND,
        )

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


@override_settings(CPE_DICTIONARY_SNAPSHOT_ID=None)
class GroundTruthComponentListAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = create_snapshot("20260725T035002Z")
        cls.vendor = create_correction_type(
            "vendor_corrected",
            name="Vendor corrected",
        )
        cls.product = create_correction_type(
            "product_corrected",
            name="Product corrected",
            is_active=False,
        )
        cls.vendor_discrepancy = create_discrepancy_type(
            "VENDOR",
            name="Vendor",
        )
        cls.product_discrepancy = create_discrepancy_type(
            "PRODUCT",
            name="Product",
            is_active=False,
        )
        cls.version_discrepancy = create_discrepancy_type(
            "VERSION",
            name="Version",
        )
        cls.unreviewed = create_component()
        document = cls.unreviewed.sbom_document
        cls.original = Component.objects.create(
            sbom_document=document,
            bom_ref="original",
            component_type="library",
            name="Original component",
            version="1.0",
            cpe=(
                "cpe:2.3:a:example:original:"
                "1.0:*:*:*:*:*:*:*"
            ),
        )
        original_cpe = create_cpe(
            cls.snapshot,
            100,
            raw_cpe=cls.original.cpe,
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
        original_record = ComponentCpeGroundTruth.objects.create(
            component=cls.original,
            snapshot=cls.snapshot,
            decision=GroundTruthDecision.CPE_CONFIRMED,
            ground_truth_cpe=original_cpe,
        )
        cls.manual_record = ComponentCpeGroundTruth.objects.create(
            component=cls.manual,
            snapshot=cls.snapshot,
            decision=GroundTruthDecision.OFFICIAL_CPE_MAPPED,
            manual_ground_truth_cpe=(
                "cpe:2.3:a:canonical:manual-target:"
                "2.1:*:*:*:*:*:*:*"
            ),
        )
        cls.manual_record.correction_types.add(
            cls.vendor,
            cls.product,
        )
        cls.manual_record.discrepancy_types.add(
            cls.vendor_discrepancy,
            cls.product_discrepancy,
        )
        cls.original_record = original_record

        for index in range(8):
            component = Component.objects.create(
                sbom_document=document,
                bom_ref=f"reviewed-{index}",
                component_type="library",
                name=f"Reviewed {index}",
                version="1.0",
                cpe=(
                    "cpe:2.3:a:example:"
                    f"reviewed-{index}:1.0:*:*:*:*:*:*:*"
                ),
            )
            record = ComponentCpeGroundTruth.objects.create(
                component=component,
                snapshot=cls.snapshot,
                decision=(
                    GroundTruthDecision
                    .DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
                ),
            )
            if index == 0:
                record.discrepancy_types.add(
                    cls.version_discrepancy
                )
                cls.version_component = component

    @property
    def url(self) -> str:
        return reverse("sboms_api:ground-truth-component-list")

    def test_list_serializes_outcome_and_multiple_corrections(
        self,
    ) -> None:
        response = self.client.get(
            self.url,
            {"page_size": 200},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        rows = {
            row["id"]: row for row in response.json()["results"]
        }
        self.assertEqual(
            rows[self.original.id]["resolution_outcome"]["code"],
            "ORIGINAL_OFFICIAL_CONFIRMED",
        )
        self.assertEqual(
            rows[self.original.id]["decision"]["code"],
            "CPE_CONFIRMED",
        )
        self.assertEqual(
            {
                item["code"]
                for item in rows[self.manual.id][
                    "discrepancy_types"
                ]
            },
            {"VENDOR", "PRODUCT"},
        )
        self.assertEqual(
            {
                item["code"]
                for item in rows[self.manual.id][
                    "correction_types"
                ]
            },
            {"vendor_corrected", "product_corrected"},
        )
        self.assertFalse(
            next(
                item
                for item in rows[self.manual.id][
                    "correction_types"
                ]
                if item["code"] == "product_corrected"
            )["is_active"]
        )
        self.assertEqual(
            rows[self.original.id]["sbom"],
            {
                "id": self.original.sbom_document_id,
                "manufacturer": "",
                "product_name": "",
                "product_version": "",
                "original_filename": "",
            },
        )

    def test_resolution_and_correction_filters(self) -> None:
        manual = self.client.get(
            self.url,
            {
                "resolution_outcome": (
                    "MANUAL_FROM_OFFICIAL_FAMILY"
                ),
                "page_size": 200,
            },
        )
        vendor = self.client.get(
            self.url,
            {
                "correction_type": "vendor_corrected",
                "page_size": 200,
            },
        )
        invalid = self.client.get(
            self.url,
            {"resolution_outcome": "INVALID"},
        )

        self.assertEqual(
            {row["id"] for row in manual.json()["results"]},
            {self.manual.id},
        )
        self.assertEqual(
            {row["id"] for row in vendor.json()["results"]},
            {self.manual.id},
        )
        self.assertEqual(
            invalid.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_decision_and_discrepancy_filters(self) -> None:
        mapped = self.client.get(
            self.url,
            {
                "decision": "OFFICIAL_CPE_MAPPED",
                "page_size": 200,
            },
        )
        vendor = self.client.get(
            self.url,
            {
                "discrepancy_type": "VENDOR",
                "page_size": 200,
            },
        )
        invalid = self.client.get(
            self.url,
            {"decision": "INVALID"},
        )
        version = self.client.get(
            self.url,
            {
                "discrepancy_type": "VERSION",
                "page_size": 200,
            },
        )

        self.assertEqual(
            {row["id"] for row in mapped.json()["results"]},
            {self.manual.id},
        )
        self.assertEqual(
            {row["id"] for row in vendor.json()["results"]},
            {self.manual.id},
        )
        self.assertEqual(
            {row["id"] for row in version.json()["results"]},
            {self.version_component.id},
        )
        self.assertEqual(
            invalid.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_summary_aggregates_decisions_and_multi_select_types(
        self,
    ) -> None:
        response = self.client.get(
            reverse("sboms_api:ground-truth-summary")
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        body = response.json()
        self.assertEqual(body["total_records"], 10)
        decisions = {
            item["code"]: item["count"]
            for item in body["decision_distribution"]
        }
        self.assertEqual(decisions["CPE_CONFIRMED"], 1)
        self.assertEqual(decisions["OFFICIAL_CPE_MAPPED"], 1)
        self.assertEqual(decisions["VERSION_NOT_IN_DICTIONARY"], 0)
        self.assertEqual(decisions["NVD_CONFIGURATION_ONLY"], 0)
        self.assertEqual(
            decisions["DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"],
            8,
        )
        self.assertEqual(decisions["UNRESOLVED"], 0)
        discrepancies = {
            item["code"]: item["count"]
            for item in body["discrepancy_type_distribution"]
        }
        self.assertEqual(discrepancies["VENDOR"], 1)
        self.assertEqual(discrepancies["VERSION"], 1)
        self.assertNotIn("PRODUCT", discrepancies)
        self.assertEqual(
            [
                item["code"]
                for item in body["discrepancy_type_distribution"]
            ],
            [
                "PART",
                "VENDOR",
                "VERSION",
                "UPDATE",
                "EDITION",
                "LANGUAGE",
                "SW_EDITION",
                "TARGET_SW",
                "TARGET_HW",
                "OTHER",
            ],
        )

    def test_existing_status_search_order_and_pagination_remain(
        self,
    ) -> None:
        completed = self.client.get(
            self.url,
            {
                "ground_truth_status": "COMPLETED",
                "search": "Manual",
                "ordering": "-id",
                "page_size": 25,
            },
        )
        unreviewed = self.client.get(
            self.url,
            {
                "ground_truth_status": "UNREVIEWED",
                "page_size": 25,
            },
        )

        self.assertEqual(
            [row["id"] for row in completed.json()["results"]],
            [self.manual.id],
        )
        self.assertIn(
            self.unreviewed.id,
            {
                row["id"]
                for row in unreviewed.json()["results"]
            },
        )

    def test_sbom_and_image_scope_filters_remain_compatible(
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
            bom_ref="dockerless-ground-truth",
            component_type="firmware",
            name="R7000 firmware",
            version="1.0.11.136",
            cpe=(
                "cpe:2.3:o:netgear:r7000_firmware:"
                "1.0.11.136:*:*:*:*:*:*:*"
            ),
        )

        sbom_response = self.client.get(
            self.url,
            {"sbom_id": document.id},
        )
        sbom_body = sbom_response.json()

        self.assertEqual(
            sbom_response.status_code,
            status.HTTP_200_OK,
        )
        self.assertEqual(sbom_body["count"], 1)
        self.assertEqual(sbom_body["results"][0]["id"], component.id)
        self.assertEqual(
            sbom_body["results"][0]["sbom"],
            {
                "id": document.id,
                "manufacturer": "NETGEAR",
                "product_name": "R7000",
                "product_version": "1.0.11.136",
                "original_filename": "r7000.cdx.json",
            },
        )
        self.assertIsNone(sbom_body["results"][0]["image"])

        image_id = self.unreviewed.sbom_document.docker_image_id
        image_response = self.client.get(
            self.url,
            {"image_id": image_id, "page_size": 200},
        )
        self.assertEqual(
            image_response.status_code,
            status.HTTP_200_OK,
        )
        self.assertEqual(image_response.json()["count"], 11)
        self.assertTrue(
            all(
                row["image"]["id"] == image_id
                for row in image_response.json()["results"]
            )
        )

    def test_ground_truth_list_validates_sbom_scope(self) -> None:
        invalid = self.client.get(
            self.url,
            {"sbom_id": "not-a-number"},
        )
        conflicting = self.client.get(
            self.url,
            {
                "image_id": self.unreviewed.sbom_document.docker_image_id,
                "sbom_id": self.unreviewed.sbom_document_id,
            },
        )

        self.assertEqual(
            invalid.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertEqual(
            invalid.json()["detail"],
            "sbom_id must be a positive integer",
        )
        self.assertEqual(
            conflicting.status_code,
            status.HTTP_400_BAD_REQUEST,
        )
        self.assertEqual(
            conflicting.json()["detail"],
            "image_id and sbom_id cannot be used together",
        )

    def test_list_prefetches_correction_types_without_n_plus_one(
        self,
    ) -> None:
        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(
                self.url,
                {"page_size": 200},
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertLessEqual(len(captured), 10)

    def test_navigation_uses_new_filters(self) -> None:
        url = reverse(
            "sboms_api:ground-truth-component-navigation",
            args=[self.manual.id],
        )
        response = self.client.get(
            url,
            {
                "resolution_outcome": (
                    "MANUAL_FROM_OFFICIAL_FAMILY"
                ),
                "correction_type": "vendor_corrected",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.json()["previous_component_id"])
        self.assertIsNone(response.json()["next_component_id"])

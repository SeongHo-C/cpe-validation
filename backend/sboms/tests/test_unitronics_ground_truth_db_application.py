import uuid
from unittest import mock

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cpe.cpe23_canonical import parse_cpe23
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from nvd_cve.models import NvdCveSnapshot
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    GroundTruthDecision,
    GroundTruthResolutionOutcome,
    SBOMDocument,
)
from sboms.unitronics_ground_truth_db_application import (
    CANDIDATE_COMPONENTS_RELATIVE,
    CPE_SNAPSHOT_ID,
    EXPECTED_ARTIFACT_HASHES,
    EXPECTED_DECISION_COUNTS,
    NVD_SNAPSHOT_ID,
    SBOM_DOCUMENT_ID,
    SBOM_SHA256,
    WPA_CPE,
    ApplicationPlan,
    CandidateRow,
    UnitronicsGroundTruthApplicationError,
    apply_application_plan,
    load_application_plan,
)


class UnitronicsGroundTruthApplicationArtifactTests(SimpleTestCase):
    def test_final_artifacts_form_exact_application_plan(self) -> None:
        plan = load_application_plan()

        self.assertEqual(len(plan.rows), 582)
        self.assertEqual(
            len({row.component_id for row in plan.rows}),
            582,
        )
        self.assertEqual(plan.decision_counts, EXPECTED_DECISION_COUNTS)
        self.assertEqual(plan.cpe_present_count, 39)
        self.assertEqual(
            plan.artifact_hashes[CANDIDATE_COMPONENTS_RELATIVE],
            EXPECTED_ARTIFACT_HASHES[CANDIDATE_COMPONENTS_RELATIVE],
        )

    def test_wpa_supplicant_final_values_are_preserved(self) -> None:
        plan = load_application_plan()
        wpa = next(row for row in plan.rows if row.name == "wpa_supplicant")

        self.assertEqual(wpa.actual_product_version, "2.11-devel")
        self.assertEqual(wpa.proposed_gt_cpe, WPA_CPE)
        self.assertEqual(
            wpa.proposed_decision,
            GroundTruthDecision.VERSION_NOT_IN_DICTIONARY,
        )


class UnitronicsGroundTruthApplicationTransactionTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        now = timezone.now()
        cls.cpe_snapshot = CpeDictionarySnapshot.objects.create(
            snapshot_id=CPE_SNAPSHOT_ID,
            status=CpeDictionarySnapshot.Status.COMPLETE,
            feed_last_modified=now,
            manifest_sha256=(
                "d0353e020f67a19070ebf297615cba0a91b636f3f89bd580f73fd786719fddce"
            ),
            archive_sha256="0" * 64,
            content_sha256=(
                "9035416631831f5f50d3c723d813370532e7ceee0c5a93c8473897d5a97bfd7a"
            ),
            member_count=1,
            expected_record_count=1811261,
            record_count=1811261,
            active_count=1711630,
            deprecated_count=99631,
            completed_at=now,
        )
        NvdCveSnapshot.objects.create(
            snapshot_id=NVD_SNAPSHOT_ID,
            status=NvdCveSnapshot.Status.COMPLETE,
            manifest_sha256=(
                "80b6107f5225923794d725b252527f575ad2b0c800765fc5ce6d0b07c18d94eb"
            ),
            content_sha256=(
                "a8a1b6ca66a0383272a3ca035559229b1fc59535f029828b984a3998234c6eab"
            ),
            feed_count=1,
            record_count=380865,
            configuration_count=760120,
            cpe_match_count=3170148,
            completed_at=now,
        )
        cls.sbom = SBOMDocument.objects.create(
            id=SBOM_DOCUMENT_ID,
            manufacturer="Unitronics",
            product_name="UCR-ST-B8",
            product_version="52.07.13.7",
            source_path="test/unitronics.cdx.json",
            file_sha256=SBOM_SHA256,
            spec_version="1.5",
            generator_name="test",
            generator_version="1",
        )
        confirmed_cpe = "cpe:2.3:a:example:confirmed:1.0:*:*:*:*:*:*:*"
        mapped_cpe = "cpe:2.3:a:example:mapped:2.0:*:*:*:*:*:*:*"
        originals = [
            ("confirmed", "1.0", confirmed_cpe),
            (
                "mapped",
                "2.0",
                "cpe:2.3:a:wrong:mapped:2.0:*:*:*:*:*:*:*",
            ),
            (
                "wpa_supplicant",
                "2.11",
                "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:*:*:*:*:*:*:*",
            ),
            (
                "no-direct",
                "3.0",
                "cpe:2.3:a:unknown:no-direct:3.0:*:*:*:*:*:*:*",
            ),
            (
                "unresolved",
                "4.0",
                "cpe:2.3:a:unknown:unresolved:4.0:*:*:*:*:*:*:*",
            ),
        ]
        cls.components = [
            Component.objects.create(
                sbom_document=cls.sbom,
                bom_ref=f"component-{index}",
                component_type="library",
                name=name,
                version=version,
                cpe=original_cpe,
            )
            for index, (name, version, original_cpe) in enumerate(originals)
        ]
        cls._create_cpe(confirmed_cpe)
        cls._create_cpe(mapped_cpe)
        cls.confirmed_cpe = confirmed_cpe
        cls.mapped_cpe = mapped_cpe

    @classmethod
    def _create_cpe(cls, value: str) -> CpeName:
        parsed = parse_cpe23(value)
        assert parsed.name is not None
        fields = parsed.name.fields
        return CpeName.objects.create(
            snapshot=cls.cpe_snapshot,
            cpe_name_id=uuid.uuid4(),
            cpe_name=value,
            deprecated=False,
            created_at_nvd=timezone.now(),
            last_modified_at_nvd=timezone.now(),
            titles=[],
            references=[],
            deprecated_by=[],
            deprecates=[],
            **fields,
        )

    def application_plan(self) -> ApplicationPlan:
        confirmed, mapped, wpa, no_direct, unresolved = self.components
        rows = (
            CandidateRow(
                component_id=confirmed.id,
                name=confirmed.name,
                observed_version=confirmed.version,
                original_cpe=confirmed.cpe,
                actual_product_version="1.0",
                proposed_gt_cpe=self.confirmed_cpe,
                proposed_decision=GroundTruthDecision.CPE_CONFIRMED,
                cpe_resolution_path="ACTIVE_EXACT",
                decision_reason="test",
            ),
            CandidateRow(
                component_id=mapped.id,
                name=mapped.name,
                observed_version=mapped.version,
                original_cpe=mapped.cpe,
                actual_product_version="2.0",
                proposed_gt_cpe=self.mapped_cpe,
                proposed_decision=GroundTruthDecision.OFFICIAL_CPE_MAPPED,
                cpe_resolution_path="ACTIVE_EXACT",
                decision_reason="test",
            ),
            CandidateRow(
                component_id=wpa.id,
                name=wpa.name,
                observed_version=wpa.version,
                original_cpe=wpa.cpe,
                actual_product_version="2.11-devel",
                proposed_gt_cpe=WPA_CPE,
                proposed_decision=(
                    GroundTruthDecision.VERSION_NOT_IN_DICTIONARY
                ),
                cpe_resolution_path="VERSION_NOT_IN_DICTIONARY",
                decision_reason="test",
            ),
            CandidateRow(
                component_id=no_direct.id,
                name=no_direct.name,
                observed_version=no_direct.version,
                original_cpe=no_direct.cpe,
                actual_product_version="3.0",
                proposed_gt_cpe="",
                proposed_decision=(
                    GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
                ),
                cpe_resolution_path="NO_DIRECT_CPE",
                decision_reason="test",
            ),
            CandidateRow(
                component_id=unresolved.id,
                name=unresolved.name,
                observed_version=unresolved.version,
                original_cpe=unresolved.cpe,
                actual_product_version="",
                proposed_gt_cpe="",
                proposed_decision=GroundTruthDecision.UNRESOLVED,
                cpe_resolution_path="UNRESOLVED",
                decision_reason="test",
            ),
        )
        return ApplicationPlan(
            rows=rows,
            artifact_hashes=dict(EXPECTED_ARTIFACT_HASHES),
        )

    def test_apply_uses_existing_fields_and_refuses_second_run(self) -> None:
        plan = self.application_plan()

        preflight, result = apply_application_plan(plan)

        self.assertEqual(preflight.ground_truth_count_before, 0)
        self.assertEqual(result.record_count, 5)
        self.assertEqual(result.cpe_present_count, 3)
        self.assertEqual(result.cpe_null_count, 2)
        self.assertEqual(result.candidate_cpe_mismatch_count, 0)
        self.assertEqual(result.candidate_decision_mismatch_count, 0)
        self.assertEqual(result.discrepancy_assignment_count, 0)
        self.assertEqual(result.correction_assignment_count, 0)

        records = {
            record.component.name: record
            for record in ComponentCpeGroundTruth.objects.select_related(
                "component",
                "ground_truth_cpe",
            )
        }
        self.assertIsNotNone(records["confirmed"].ground_truth_cpe)
        self.assertEqual(records["confirmed"].manual_ground_truth_cpe, "")
        self.assertIsNotNone(records["mapped"].ground_truth_cpe)
        self.assertEqual(records["mapped"].manual_ground_truth_cpe, "")
        self.assertIsNone(records["wpa_supplicant"].ground_truth_cpe)
        self.assertEqual(
            records["wpa_supplicant"].manual_ground_truth_cpe,
            WPA_CPE,
        )
        self.assertEqual(
            records["wpa_supplicant"].resolution_outcome,
            GroundTruthResolutionOutcome.MANUAL_FROM_OFFICIAL_FAMILY,
        )
        self.assertIsNone(records["no-direct"].ground_truth_cpe)
        self.assertEqual(records["no-direct"].manual_ground_truth_cpe, "")
        self.assertEqual(
            records["unresolved"].resolution_outcome,
            GroundTruthResolutionOutcome.UNRESOLVED,
        )
        self.assertIn(
            f"candidate_component_id={records['confirmed'].component_id}",
            records["confirmed"].note,
        )

        with self.assertRaises(UnitronicsGroundTruthApplicationError):
            apply_application_plan(plan)
        self.assertEqual(ComponentCpeGroundTruth.objects.count(), 5)

    def test_any_save_failure_rolls_back_all_records(self) -> None:
        plan = self.application_plan()
        original_save = ComponentCpeGroundTruth.save
        calls = 0

        def fail_on_third_save(instance, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise ValidationError("forced test failure")
            return original_save(instance, *args, **kwargs)

        with (
            mock.patch.object(
                ComponentCpeGroundTruth,
                "save",
                new=fail_on_third_save,
            ),
            self.assertRaises(UnitronicsGroundTruthApplicationError),
        ):
            apply_application_plan(plan)

        self.assertEqual(ComponentCpeGroundTruth.objects.count(), 0)

import uuid
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cpe.cpe23_canonical import parse_cpe23
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    GroundTruthDecision,
    SBOMDocument,
)
from sboms.unitronics_ground_truth_candidate_build import (
    APPROVED_DERIVED_SPLITS,
)
from sboms.unitronics_representative_finalization import (
    DatabaseState,
    FinalizationPlan,
    UnitronicsRepresentativeFinalizationError,
    apply_representative_finalization,
    load_finalization_plan,
)


class UnitronicsRepresentativeFinalizationArtifactTests(SimpleTestCase):
    def test_final_candidate_is_exactly_582_rows_with_39_distinct_cpes(self):
        plan = load_finalization_plan()

        self.assertEqual(len(plan.candidates), 582)
        self.assertEqual(len(plan.by_id), 582)
        self.assertEqual(
            sum(bool(row.proposed_gt_cpe) for row in plan.candidates),
            39,
        )
        self.assertEqual(
            len(
                {
                    row.proposed_gt_cpe
                    for row in plan.candidates
                    if row.proposed_gt_cpe
                }
            ),
            39,
        )

    def test_all_eight_approved_splits_have_null_cpe_and_no_direct_result(self):
        plan = load_finalization_plan()

        for name, policy in APPROVED_DERIVED_SPLITS.items():
            with self.subTest(name=name):
                row = plan.by_name[name]
                representative = plan.by_name[policy.representative]
                self.assertEqual(row.proposed_gt_cpe, "")
                self.assertEqual(
                    row.proposed_decision,
                    GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED,
                )
                self.assertEqual(
                    representative.proposed_gt_cpe,
                    policy.expected_parent_cpe,
                )

    def test_curl_and_libcurl_remain_distinct_cpe_products(self):
        plan = load_finalization_plan()
        curl = plan.by_name["curl"]
        libcurl = plan.by_name["libcurl4"]

        self.assertTrue(curl.proposed_gt_cpe)
        self.assertTrue(libcurl.proposed_gt_cpe)
        self.assertNotEqual(curl.proposed_gt_cpe, libcurl.proposed_gt_cpe)

    def test_wireguard_tools_is_final_no_direct_cpe(self):
        row = load_finalization_plan().by_name["wireguard-tools"]

        self.assertEqual(row.actual_product, "wireguard-tools")
        self.assertEqual(row.actual_product_version, "1.0.20210223")
        self.assertEqual(row.proposed_gt_cpe, "")
        self.assertEqual(
            row.proposed_decision,
            GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED,
        )


class UnitronicsRepresentativeFinalizationRollbackTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        now = timezone.now()
        cls.snapshot = CpeDictionarySnapshot.objects.create(
            snapshot_id="20260819T035002Z",
            status=CpeDictionarySnapshot.Status.COMPLETE,
            feed_last_modified=now,
            manifest_sha256="1" * 64,
            archive_sha256="2" * 64,
            content_sha256="3" * 64,
            member_count=1,
            expected_record_count=1,
            record_count=1,
            active_count=1,
            deprecated_count=0,
            completed_at=now,
        )
        cls.sbom = SBOMDocument.objects.create(
            manufacturer="Unitronics",
            product_name="UCR-ST-B8",
            product_version="52.07.13.7",
            source_path="test/unitronics.cdx.json",
            file_sha256="4" * 64,
            spec_version="1.5",
            generator_name="test",
            generator_version="1",
        )
        cpe_rows: dict[str, CpeName] = {}
        cls.records = []
        for index, (name, policy) in enumerate(
            APPROVED_DERIVED_SPLITS.items()
        ):
            component = Component.objects.create(
                id=int(policy.component_id),
                sbom_document=cls.sbom,
                bom_ref=f"component-{index}",
                component_type="library",
                name=name,
                version="test",
                cpe=f"original-{index}",
            )
            dictionary_cpe = None
            manual_cpe = ""
            if (
                policy.expected_current_decision
                == GroundTruthDecision.OFFICIAL_CPE_MAPPED
            ):
                dictionary_cpe = cpe_rows.get(policy.expected_parent_cpe)
                if dictionary_cpe is None:
                    parsed = parse_cpe23(policy.expected_parent_cpe)
                    assert parsed.name is not None
                    dictionary_cpe = CpeName.objects.create(
                        snapshot=cls.snapshot,
                        cpe_name_id=uuid.uuid4(),
                        cpe_name=policy.expected_parent_cpe,
                        deprecated=False,
                        created_at_nvd=now,
                        last_modified_at_nvd=now,
                        titles=[],
                        references=[],
                        deprecated_by=[],
                        deprecates=[],
                        **parsed.name.fields,
                    )
                    cpe_rows[policy.expected_parent_cpe] = dictionary_cpe
            else:
                manual_cpe = policy.expected_parent_cpe
            cls.records.append(
                ComponentCpeGroundTruth.objects.create(
                    component=component,
                    snapshot=cls.snapshot,
                    ground_truth_cpe=dictionary_cpe,
                    manual_ground_truth_cpe=manual_cpe,
                    decision=policy.expected_current_decision,
                )
            )

    def test_post_update_verification_failure_rolls_back_all_eight(self):
        records = list(
            ComponentCpeGroundTruth.objects.select_related(
                "component", "ground_truth_cpe"
            )
            .prefetch_related("discrepancy_types", "correction_types")
            .order_by("id")
        )
        before = DatabaseState(
            records=records,
            component_count=8,
            global_ground_truth_count=8,
            component_fingerprint="test-component-fingerprint",
            ground_truth_fingerprint="test-ground-truth-fingerprint",
            decision_counts={},
            cpe_present_count=8,
            cpe_null_count=0,
            distinct_canonical_gt_cpes=7,
            duplicate_canonical_gt_cpe_groups=1,
            duplicate_group_component_count=2,
            canonical_parse_failure_count=0,
            deprecated_final_gt_count=0,
            discrepancy_assignment_count=0,
            correction_assignment_count=0,
        )
        plan = FinalizationPlan(candidates=(), candidate_sha256="test")

        with (
            mock.patch(
                "sboms.unitronics_representative_finalization.database_preflight",
                return_value=before,
            ),
            mock.patch(
                "sboms.unitronics_representative_finalization.verify_final_database",
                side_effect=UnitronicsRepresentativeFinalizationError(
                    "forced post-update verification failure"
                ),
            ),
            self.assertRaises(UnitronicsRepresentativeFinalizationError),
        ):
            apply_representative_finalization(plan)

        for record in self.records:
            record.refresh_from_db()
            policy = APPROVED_DERIVED_SPLITS[record.component.name]
            self.assertEqual(record.decision, policy.expected_current_decision)
            effective_cpe = (
                record.ground_truth_cpe.cpe_name
                if record.ground_truth_cpe_id
                else record.manual_ground_truth_cpe
            )
            self.assertEqual(effective_cpe, policy.expected_parent_cpe)

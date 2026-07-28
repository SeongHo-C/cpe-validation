from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import UUID

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from cpe_dictionary.models import (
    CpeDictionarySnapshot,
    CpeName,
)
from cpe_dictionary.snapshot_selection import (
    CpeDictionarySnapshotAmbiguousError,
    CpeDictionarySnapshotUnavailableError,
    select_cpe_dictionary_snapshot,
)
from sboms.exact_matching import (
    CPEExactMatchIntegrityError,
    CPEExactMatchStatus,
    match_cpe,
    match_cpes,
)


ACTIVE_CPE = (
    r"cpe:2.3:a:example:product\:server:1.0:*:*:*:*:*:*:*"
)
DEPRECATED_CPE = (
    "cpe:2.3:o:example:system:2.0:*:*:*:*:*:*:*"
)


def create_snapshot(
    snapshot_id: str,
    *,
    status: str = CpeDictionarySnapshot.Status.COMPLETE,
) -> CpeDictionarySnapshot:
    return CpeDictionarySnapshot.objects.create(
        snapshot_id=snapshot_id,
        status=status,
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
        expected_record_count=2,
        record_count=2,
        active_count=1,
        deprecated_count=1,
        completed_at=(
            datetime(2026, 7, 27, tzinfo=timezone.utc)
            if status == CpeDictionarySnapshot.Status.COMPLETE
            else None
        ),
    )


def create_cpe_name(
    snapshot: CpeDictionarySnapshot,
    *,
    cpe_name_id: UUID,
    cpe_name: str,
    deprecated: bool,
) -> CpeName:
    return CpeName.objects.create(
        snapshot=snapshot,
        cpe_name_id=cpe_name_id,
        cpe_name=cpe_name,
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


class SnapshotSelectionTests(TestCase):
    def test_selects_explicit_complete_snapshot(self) -> None:
        selected = create_snapshot("20260725T035002Z")
        create_snapshot("20260726T035002Z")

        actual = select_cpe_dictionary_snapshot(
            selected.snapshot_id
        )

        self.assertEqual(actual.id, selected.id)

    def test_auto_selects_exactly_one_complete_snapshot(self) -> None:
        selected = create_snapshot("20260725T035002Z")
        create_snapshot(
            "20260726T035002Z",
            status=CpeDictionarySnapshot.Status.IMPORTING,
        )

        actual = select_cpe_dictionary_snapshot()

        self.assertEqual(actual.id, selected.id)

    def test_rejects_missing_complete_snapshot(self) -> None:
        create_snapshot(
            "20260725T035002Z",
            status=CpeDictionarySnapshot.Status.IMPORTING,
        )

        with self.assertRaises(
            CpeDictionarySnapshotUnavailableError
        ):
            select_cpe_dictionary_snapshot()

    def test_rejects_ambiguous_complete_snapshots(self) -> None:
        create_snapshot("20260725T035002Z")
        create_snapshot("20260726T035002Z")

        with self.assertRaises(
            CpeDictionarySnapshotAmbiguousError
        ):
            select_cpe_dictionary_snapshot()

    def test_rejects_unknown_explicit_snapshot(self) -> None:
        with self.assertRaisesRegex(
            CpeDictionarySnapshotUnavailableError,
            "does not exist",
        ):
            select_cpe_dictionary_snapshot("missing")

    def test_rejects_non_complete_explicit_snapshot(self) -> None:
        snapshot = create_snapshot(
            "20260725T035002Z",
            status=CpeDictionarySnapshot.Status.IMPORTING,
        )

        with self.assertRaisesRegex(
            CpeDictionarySnapshotUnavailableError,
            "is not COMPLETE",
        ):
            select_cpe_dictionary_snapshot(snapshot.snapshot_id)


class ExactMatchingTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.snapshot = create_snapshot("20260725T035002Z")
        cls.active_record = create_cpe_name(
            cls.snapshot,
            cpe_name_id=UUID(
                "11111111-1111-4111-8111-111111111111"
            ),
            cpe_name=ACTIVE_CPE,
            deprecated=False,
        )
        cls.deprecated_record = create_cpe_name(
            cls.snapshot,
            cpe_name_id=UUID(
                "22222222-2222-4222-8222-222222222222"
            ),
            cpe_name=DEPRECATED_CPE,
            deprecated=True,
        )

    def test_matches_active_raw_string(self) -> None:
        result = match_cpe(ACTIVE_CPE, self.snapshot)

        self.assertEqual(
            result.status,
            CPEExactMatchStatus.OFFICIAL_ACTIVE,
        )
        self.assertEqual(result.input_cpe, ACTIVE_CPE)
        self.assertEqual(
            result.matched_cpe_name_id,
            str(self.active_record.cpe_name_id),
        )
        self.assertEqual(result.matched_cpe_name, ACTIVE_CPE)
        self.assertIs(result.deprecated, False)

    def test_matches_deprecated_raw_string(self) -> None:
        result = match_cpe(DEPRECATED_CPE, self.snapshot)

        self.assertEqual(
            result.status,
            CPEExactMatchStatus.OFFICIAL_DEPRECATED,
        )
        self.assertEqual(
            result.matched_cpe_name_id,
            str(self.deprecated_record.cpe_name_id),
        )
        self.assertIs(result.deprecated, True)

    def test_returns_not_in_dictionary(self) -> None:
        raw_cpe = (
            "cpe:2.3:a:example:missing:1.0:*:*:*:*:*:*:*"
        )

        result = match_cpe(raw_cpe, self.snapshot)

        self.assertEqual(
            result.status,
            CPEExactMatchStatus.NOT_IN_DICTIONARY,
        )
        self.assertEqual(result.input_cpe, raw_cpe)
        self.assertIsNone(result.matched_cpe_name_id)
        self.assertIsNone(result.matched_cpe_name)
        self.assertIsNone(result.deprecated)

    def test_structural_validation_is_not_a_match_prerequisite(
        self,
    ) -> None:
        structurally_invalid = (
            "not-a-structurally-valid-cpe-but-still-raw-evidence"
        )
        record = create_cpe_name(
            self.snapshot,
            cpe_name_id=UUID(
                "33333333-3333-4333-8333-333333333333"
            ),
            cpe_name=structurally_invalid,
            deprecated=False,
        )

        result = match_cpe(structurally_invalid, self.snapshot)

        self.assertEqual(
            result.status,
            CPEExactMatchStatus.OFFICIAL_ACTIVE,
        )
        self.assertEqual(
            result.matched_cpe_name_id,
            str(record.cpe_name_id),
        )

    def test_none_and_empty_are_not_present(self) -> None:
        with self.assertNumQueries(0):
            results = match_cpes([None, ""], self.snapshot)

        self.assertEqual(
            results[None].status,
            CPEExactMatchStatus.NOT_PRESENT,
        )
        self.assertEqual(
            results[""].status,
            CPEExactMatchStatus.NOT_PRESENT,
        )
        self.assertIsNone(results[None].input_cpe)
        self.assertEqual(results[""].input_cpe, "")

    def test_does_not_normalize_raw_strings(self) -> None:
        variants = (
            ACTIVE_CPE.replace("example", "Example"),
            ACTIVE_CPE.replace(r"product\:server", "product:server"),
            f" {ACTIVE_CPE}",
            f"{ACTIVE_CPE} ",
            ACTIVE_CPE.replace("example", "example-inc"),
            ACTIVE_CPE.replace(
                r"product\:server",
                r"product_server",
            ),
        )

        results = match_cpes(variants, self.snapshot)

        for raw_cpe in variants:
            with self.subTest(raw_cpe=raw_cpe):
                self.assertEqual(
                    results[raw_cpe].status,
                    CPEExactMatchStatus.NOT_IN_DICTIONARY,
                )

    def test_bulk_deduplicates_and_uses_one_query(self) -> None:
        missing = (
            "cpe:2.3:a:example:missing:1.0:*:*:*:*:*:*:*"
        )
        inputs = [
            ACTIVE_CPE,
            ACTIVE_CPE,
            DEPRECATED_CPE,
            missing,
            None,
            "",
        ]

        with CaptureQueriesContext(connection) as queries:
            results = match_cpes(inputs, self.snapshot)

        self.assertEqual(len(queries), 1)
        self.assertEqual(
            list(results),
            [ACTIVE_CPE, DEPRECATED_CPE, missing, None, ""],
        )
        self.assertEqual(
            results[ACTIVE_CPE].status,
            CPEExactMatchStatus.OFFICIAL_ACTIVE,
        )
        self.assertEqual(
            results[DEPRECATED_CPE].status,
            CPEExactMatchStatus.OFFICIAL_DEPRECATED,
        )
        self.assertEqual(
            results[missing].status,
            CPEExactMatchStatus.NOT_IN_DICTIONARY,
        )

    def test_empty_bulk_input_uses_no_queries(self) -> None:
        with self.assertNumQueries(0):
            results = match_cpes([], self.snapshot)

        self.assertEqual(results, {})

    def test_bulk_result_is_keyed_by_exact_input(self) -> None:
        case_variant = ACTIVE_CPE.replace("example", "Example")

        results = match_cpes(
            [case_variant, ACTIVE_CPE],
            self.snapshot,
        )

        self.assertEqual(results[case_variant].input_cpe, case_variant)
        self.assertEqual(results[ACTIVE_CPE].input_cpe, ACTIVE_CPE)
        self.assertEqual(
            results[case_variant].status,
            CPEExactMatchStatus.NOT_IN_DICTIONARY,
        )
        self.assertEqual(
            results[ACTIVE_CPE].status,
            CPEExactMatchStatus.OFFICIAL_ACTIVE,
        )

    def test_duplicate_dictionary_results_are_not_silently_used(
        self,
    ) -> None:
        duplicate = MagicMock(
            cpe_name=ACTIVE_CPE,
            cpe_name_id=self.active_record.cpe_name_id,
            deprecated=False,
        )
        queryset = MagicMock()
        queryset.only.return_value = [duplicate, duplicate]

        with (
            patch(
                "sboms.exact_matching.CpeName.objects.filter",
                return_value=queryset,
            ),
            self.assertRaises(CPEExactMatchIntegrityError),
        ):
            match_cpes([ACTIVE_CPE], self.snapshot)

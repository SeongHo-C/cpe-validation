from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from django.db import IntegrityError, transaction
from django.test import TestCase

from cpe_dictionary.models import (
    CpeDictionarySnapshot,
    CpeName,
)


SNAPSHOT_ID = "20260725T035002Z"
FIRST_UUID = UUID("11111111-1111-4111-8111-111111111111")
SECOND_UUID = UUID("22222222-2222-4222-8222-222222222222")
FIRST_CPE = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
SECOND_CPE = "cpe:2.3:o:vendor:system:2.0:*:*:*:*:*:*:*"


def create_snapshot() -> CpeDictionarySnapshot:
    return CpeDictionarySnapshot.objects.create(
        snapshot_id=SNAPSHOT_ID,
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
        manifest_sha256="1" * 64,
        archive_sha256="2" * 64,
        content_sha256="3" * 64,
        member_count=2,
        expected_record_count=1,
        record_count=1,
        active_count=1,
        deprecated_count=0,
        completed_at=datetime(
            2026,
            7,
            27,
            tzinfo=timezone.utc,
        ),
    )


def create_cpe_name(
    snapshot: CpeDictionarySnapshot,
    *,
    cpe_name_id: UUID = FIRST_UUID,
    cpe_name: str = FIRST_CPE,
) -> CpeName:
    return CpeName.objects.create(
        snapshot=snapshot,
        cpe_name_id=cpe_name_id,
        cpe_name=cpe_name,
        deprecated=False,
        created_at_nvd=datetime(
            2020,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        last_modified_at_nvd=datetime(
            2021,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        part="a",
        vendor="vendor",
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


class CpeDictionaryModelTests(TestCase):
    def test_creates_snapshot_and_cpe_name_models(self) -> None:
        snapshot = create_snapshot()
        cpe_name = create_cpe_name(snapshot)

        self.assertEqual(
            snapshot.status,
            CpeDictionarySnapshot.Status.COMPLETE,
        )
        self.assertEqual(cpe_name.snapshot, snapshot)
        self.assertEqual(cpe_name.cpe_name_id, FIRST_UUID)
        self.assertEqual(cpe_name.titles, [])
        self.assertEqual(cpe_name.references, [])
        self.assertEqual(cpe_name.deprecated_by, [])
        self.assertEqual(cpe_name.deprecates, [])

    def test_snapshot_and_cpe_name_id_are_unique(self) -> None:
        snapshot = create_snapshot()
        create_cpe_name(snapshot)

        with (
            self.assertRaises(IntegrityError),
            transaction.atomic(),
        ):
            create_cpe_name(
                snapshot,
                cpe_name_id=FIRST_UUID,
                cpe_name=SECOND_CPE,
            )

    def test_snapshot_and_cpe_name_are_unique(self) -> None:
        snapshot = create_snapshot()
        create_cpe_name(snapshot)

        with (
            self.assertRaises(IntegrityError),
            transaction.atomic(),
        ):
            create_cpe_name(
                snapshot,
                cpe_name_id=SECOND_UUID,
                cpe_name=FIRST_CPE,
            )

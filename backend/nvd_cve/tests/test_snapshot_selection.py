from datetime import datetime, timezone

from django.conf import settings
from django.test import TestCase, override_settings

from nvd_cve.models import NvdCveRecord, NvdCveSnapshot
from nvd_cve.snapshot_selection import (
    NvdCveSnapshotAmbiguousError,
    NvdCveSnapshotUnavailableError,
    select_nvd_cve_snapshot,
)


def create_snapshot(
    snapshot_id: str,
    *,
    status: str = NvdCveSnapshot.Status.COMPLETE,
) -> NvdCveSnapshot:
    return NvdCveSnapshot.objects.create(
        snapshot_id=snapshot_id,
        status=status,
        manifest_sha256="1" * 64,
        content_sha256="2" * 64,
        feed_count=25,
        record_count=1,
        configuration_count=1,
        cpe_match_count=1,
        completed_at=(
            datetime(2026, 8, 20, tzinfo=timezone.utc)
            if status == NvdCveSnapshot.Status.COMPLETE
            else None
        ),
    )


@override_settings(NVD_CVE_SNAPSHOT_ID=None)
class NvdCveSnapshotSelectionTests(TestCase):
    @override_settings(NVD_CVE_SNAPSHOT_ID="20260820T110357Z")
    def test_selects_configured_complete_snapshot(self) -> None:
        selected = create_snapshot("20260820T110357Z")

        actual = select_nvd_cve_snapshot(
            settings.NVD_CVE_SNAPSHOT_ID
        )

        self.assertEqual(actual.id, selected.id)

    @override_settings(NVD_CVE_SNAPSHOT_ID="missing")
    def test_rejects_unknown_configured_snapshot(self) -> None:
        with self.assertRaisesRegex(
            NvdCveSnapshotUnavailableError,
            "does not exist",
        ):
            select_nvd_cve_snapshot(settings.NVD_CVE_SNAPSHOT_ID)

    @override_settings(NVD_CVE_SNAPSHOT_ID="20260820T110357Z")
    def test_rejects_non_complete_configured_snapshot(self) -> None:
        create_snapshot(
            "20260820T110357Z",
            status=NvdCveSnapshot.Status.IMPORTING,
        )

        with self.assertRaisesRegex(
            NvdCveSnapshotUnavailableError,
            "is not COMPLETE",
        ):
            select_nvd_cve_snapshot(settings.NVD_CVE_SNAPSHOT_ID)

    def test_rejects_when_no_complete_snapshot_exists(self) -> None:
        create_snapshot(
            "20260820T110357Z",
            status=NvdCveSnapshot.Status.IMPORTING,
        )

        with self.assertRaises(
            NvdCveSnapshotUnavailableError
        ):
            select_nvd_cve_snapshot()

    def test_auto_selects_exactly_one_complete_snapshot(self) -> None:
        selected = create_snapshot("20260820T110357Z")
        create_snapshot(
            "20260821T110357Z",
            status=NvdCveSnapshot.Status.IMPORTING,
        )

        actual = select_nvd_cve_snapshot()

        self.assertEqual(actual.id, selected.id)

    def test_rejects_ambiguous_complete_snapshots(self) -> None:
        create_snapshot("20260820T110357Z")
        create_snapshot("20260821T110357Z")

        with self.assertRaises(
            NvdCveSnapshotAmbiguousError
        ):
            select_nvd_cve_snapshot()

    @override_settings(NVD_CVE_SNAPSHOT_ID="20260820T110357Z")
    def test_explicit_id_selects_exact_snapshot_when_multiple_exist(
        self,
    ) -> None:
        selected = create_snapshot("20260820T110357Z")
        create_snapshot("20260821T110357Z")

        actual = select_nvd_cve_snapshot(
            settings.NVD_CVE_SNAPSHOT_ID
        )

        self.assertEqual(actual.id, selected.id)

    @override_settings(NVD_CVE_SNAPSHOT_ID="20260820T110357Z")
    def test_selection_preserves_other_snapshot_data(self) -> None:
        selected = create_snapshot("20260820T110357Z")
        other = create_snapshot("20260821T110357Z")
        published = datetime(2026, 8, 20, tzinfo=timezone.utc)
        for snapshot in (selected, other):
            NvdCveRecord.objects.create(
                snapshot=snapshot,
                cve_id="CVE-2026-1234",
                published_at_nvd=published,
                last_modified_at_nvd=published,
                vuln_status="Analyzed",
                configurations=None,
            )

        actual = select_nvd_cve_snapshot(
            settings.NVD_CVE_SNAPSHOT_ID
        )

        self.assertEqual(actual.id, selected.id)
        self.assertEqual(actual.cve_records.count(), 1)
        self.assertEqual(other.cve_records.count(), 1)
        self.assertEqual(NvdCveRecord.objects.count(), 2)

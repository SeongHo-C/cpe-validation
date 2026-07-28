from __future__ import annotations

from cpe_dictionary.models import CpeDictionarySnapshot


class CpeDictionarySnapshotSelectionError(Exception):
    error_code = "cpe_dictionary_snapshot_unavailable"


class CpeDictionarySnapshotUnavailableError(
    CpeDictionarySnapshotSelectionError
):
    pass


class CpeDictionarySnapshotAmbiguousError(
    CpeDictionarySnapshotSelectionError
):
    error_code = "cpe_dictionary_snapshot_ambiguous"


def select_cpe_dictionary_snapshot(
    snapshot_id: str | None = None,
) -> CpeDictionarySnapshot:
    """Select one COMPLETE snapshot without an implicit latest rule."""

    if snapshot_id is not None:
        snapshot = (
            CpeDictionarySnapshot.objects.filter(
                snapshot_id=snapshot_id
            )
            .only(
                "id",
                "snapshot_id",
                "status",
                "manifest_sha256",
                "record_count",
                "active_count",
                "deprecated_count",
            )
            .first()
        )
        if snapshot is None:
            raise CpeDictionarySnapshotUnavailableError(
                "Configured CPE Dictionary snapshot does not exist: "
                f"{snapshot_id}"
            )
        if snapshot.status != CpeDictionarySnapshot.Status.COMPLETE:
            raise CpeDictionarySnapshotUnavailableError(
                "Configured CPE Dictionary snapshot is not COMPLETE: "
                f"{snapshot_id} ({snapshot.status})"
            )
        return snapshot

    complete_snapshots = list(
        CpeDictionarySnapshot.objects.filter(
            status=CpeDictionarySnapshot.Status.COMPLETE
        )
        .only(
            "id",
            "snapshot_id",
            "status",
            "manifest_sha256",
            "record_count",
            "active_count",
            "deprecated_count",
        )[:2]
    )
    if not complete_snapshots:
        raise CpeDictionarySnapshotUnavailableError(
            "No COMPLETE CPE Dictionary snapshot is available."
        )
    if len(complete_snapshots) > 1:
        raise CpeDictionarySnapshotAmbiguousError(
            "Multiple COMPLETE CPE Dictionary snapshots are available; "
            "configure an explicit snapshot ID."
        )
    return complete_snapshots[0]

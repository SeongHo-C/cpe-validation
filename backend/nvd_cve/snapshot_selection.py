from __future__ import annotations

from nvd_cve.models import NvdCveSnapshot


class NvdCveSnapshotSelectionError(Exception):
    error_code = "nvd_cve_snapshot_unavailable"


class NvdCveSnapshotUnavailableError(NvdCveSnapshotSelectionError):
    pass


class NvdCveSnapshotAmbiguousError(NvdCveSnapshotSelectionError):
    error_code = "nvd_cve_snapshot_ambiguous"


def select_nvd_cve_snapshot(
    snapshot_id: str | None = None,
) -> NvdCveSnapshot:
    """Select one COMPLETE snapshot without an implicit latest rule."""

    if snapshot_id is not None:
        snapshot = (
            NvdCveSnapshot.objects.filter(snapshot_id=snapshot_id)
            .only(
                "id",
                "snapshot_id",
                "status",
                "manifest_sha256",
                "content_sha256",
                "record_count",
                "configuration_count",
                "cpe_match_count",
            )
            .first()
        )
        if snapshot is None:
            raise NvdCveSnapshotUnavailableError(
                "Configured NVD CVE snapshot does not exist: "
                f"{snapshot_id}"
            )
        if snapshot.status != NvdCveSnapshot.Status.COMPLETE:
            raise NvdCveSnapshotUnavailableError(
                "Configured NVD CVE snapshot is not COMPLETE: "
                f"{snapshot_id} ({snapshot.status})"
            )
        return snapshot

    complete_snapshots = list(
        NvdCveSnapshot.objects.filter(
            status=NvdCveSnapshot.Status.COMPLETE
        )
        .only(
            "id",
            "snapshot_id",
            "status",
            "manifest_sha256",
            "content_sha256",
            "record_count",
            "configuration_count",
            "cpe_match_count",
        )[:2]
    )
    if not complete_snapshots:
        raise NvdCveSnapshotUnavailableError(
            "No COMPLETE NVD CVE snapshot is available."
        )
    if len(complete_snapshots) > 1:
        raise NvdCveSnapshotAmbiguousError(
            "Multiple COMPLETE NVD CVE snapshots are available; "
            "configure an explicit snapshot ID."
        )
    return complete_snapshots[0]

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO
from uuid import uuid4

from sboms.models import (
    FILE_SHA256_PATTERN,
    SourceArtifact,
    source_archive_suffix,
    source_artifact_upload_path,
)


EXTRACTION_MARKER_FILENAME = ".extraction-complete.json"
EXTRACTION_MARKER_VERSION = 1


class SourceArtifactExtractionError(Exception):
    """Raised when source evidence cannot be safely extracted."""


@dataclass(frozen=True)
class SourceArtifactExtractionResult:
    extraction_directory: Path
    file_count: int
    directory_count: int
    file_sha256: str
    skipped: bool


@dataclass(frozen=True)
class _ValidatedArchiveMember:
    archive_member: tarfile.TarInfo | zipfile.ZipInfo
    name: str
    destination: Path
    kind: str
    target_candidates: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ExtractionPlan:
    members: tuple[_ValidatedArchiveMember, ...]
    link_order: tuple[_ValidatedArchiveMember, ...]
    direct_targets: dict[str, _ValidatedArchiveMember]
    final_targets: dict[str, _ValidatedArchiveMember]


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _archive_path(source_artifact: SourceArtifact) -> Path:
    stored_name = source_artifact.source_archive.name
    if not stored_name:
        raise SourceArtifactExtractionError(
            "SourceArtifact has no stored archive path."
        )
    try:
        expected_stored_name = source_artifact_upload_path(
            source_artifact,
            source_artifact.original_filename,
        )
    except ValueError as error:
        raise SourceArtifactExtractionError(str(error)) from error
    if stored_name != expected_stored_name:
        raise SourceArtifactExtractionError(
            "Stored source archive path does not match the SourceArtifact "
            f"provenance: expected {expected_stored_name}, got {stored_name}."
        )

    storage = source_artifact.source_archive.storage
    try:
        exists = storage.exists(stored_name)
    except OSError as error:
        raise SourceArtifactExtractionError(
            f"Could not check stored archive {stored_name!r}."
        ) from error
    if not exists:
        raise SourceArtifactExtractionError(
            f"Stored source archive does not exist: {stored_name}"
        )

    try:
        storage_root = Path(storage.path("")).resolve()
        archive_path = Path(storage.path(stored_name))
    except (NotImplementedError, OSError, ValueError) as error:
        raise SourceArtifactExtractionError(
            "Source artifact extraction requires filesystem-backed storage."
        ) from error

    if archive_path.is_symlink():
        raise SourceArtifactExtractionError(
            "Stored source archive must not be a symbolic link."
        )
    try:
        resolved_archive_path = archive_path.resolve(strict=True)
    except OSError as error:
        raise SourceArtifactExtractionError(
            f"Stored source archive is not accessible: {stored_name}"
        ) from error
    if not resolved_archive_path.is_file():
        raise SourceArtifactExtractionError(
            f"Stored source archive is not a regular file: {stored_name}"
        )
    if not _path_is_within(resolved_archive_path, storage_root):
        raise SourceArtifactExtractionError(
            "Stored source archive resolves outside the configured storage."
        )
    return resolved_archive_path


def _calculate_archive_metadata(archive_path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with archive_path.open("rb") as archive_file:
            for chunk in iter(lambda: archive_file.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise SourceArtifactExtractionError(
            f"Could not read stored source archive: {archive_path}"
        ) from error
    return digest.hexdigest(), size


def _validated_archive_suffix(
    source_artifact: SourceArtifact,
    archive_path: Path,
) -> str:
    original_suffix = source_archive_suffix(
        source_artifact.original_filename
    )
    stored_suffix = source_archive_suffix(archive_path.name)
    if original_suffix is None or stored_suffix is None:
        raise SourceArtifactExtractionError(
            "SourceArtifact does not use a supported archive format."
        )
    if original_suffix != stored_suffix:
        raise SourceArtifactExtractionError(
            "Stored archive suffix does not match its original filename."
        )
    return stored_suffix


def _validated_member_path(
    extraction_root: Path,
    member_name: str,
) -> tuple[str, Path]:
    if not member_name or "\x00" in member_name:
        raise SourceArtifactExtractionError(
            "Archive contains an empty or invalid member path."
        )

    normalized_name = member_name.replace("\\", "/")
    posix_path = PurePosixPath(normalized_name)
    windows_path = PureWindowsPath(member_name)
    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or bool(windows_path.root)
    ):
        raise SourceArtifactExtractionError(
            f"Archive member uses an absolute path: {member_name!r}"
        )
    if ".." in posix_path.parts:
        raise SourceArtifactExtractionError(
            f"Archive member attempts path traversal: {member_name!r}"
        )

    relative_parts = tuple(
        part for part in posix_path.parts if part not in {"", "."}
    )
    normalized_member_name = "/".join(relative_parts)
    destination = extraction_root.joinpath(*relative_parts)
    resolved_root = extraction_root.resolve()
    resolved_destination = destination.resolve(strict=False)
    if not _path_is_within(resolved_destination, resolved_root):
        raise SourceArtifactExtractionError(
            f"Archive member resolves outside extraction root: {member_name!r}"
        )
    return normalized_member_name, destination


def _link_target_candidates(
    extraction_root: Path,
    *,
    member_name: str,
    link_target: str,
    include_archive_root_target: bool,
) -> tuple[str, ...]:
    if not link_target or "\x00" in link_target:
        raise SourceArtifactExtractionError(
            f"Archive link has an empty or invalid target: {member_name!r}"
        )

    normalized_target = link_target.replace("\\", "/")
    posix_target = PurePosixPath(normalized_target)
    windows_target = PureWindowsPath(link_target)
    if (
        posix_target.is_absolute()
        or windows_target.is_absolute()
        or bool(windows_target.drive)
        or bool(windows_target.root)
    ):
        raise SourceArtifactExtractionError(
            f"Archive link uses an absolute target: {member_name!r} -> "
            f"{link_target!r}"
        )

    member_parent = posixpath.dirname(member_name)
    parent_relative_target = posixpath.normpath(
        posixpath.join(member_parent, normalized_target)
    )
    if parent_relative_target == ".." or parent_relative_target.startswith(
        "../"
    ):
        raise SourceArtifactExtractionError(
            f"Archive link target escapes extraction root: {member_name!r} "
            f"-> {link_target!r}"
        )
    parent_target_name, _ = _validated_member_path(
        extraction_root,
        parent_relative_target,
    )
    candidates = [parent_target_name]

    if include_archive_root_target:
        archive_root_target = posixpath.normpath(normalized_target)
        if not (
            archive_root_target == ".."
            or archive_root_target.startswith("../")
        ):
            root_target_name, _ = _validated_member_path(
                extraction_root,
                archive_root_target,
            )
            if root_target_name not in candidates:
                candidates.append(root_target_name)
    return tuple(candidates)


def _validate_destination_tree(
    registry: dict[str, _ValidatedArchiveMember],
) -> None:
    for member_name in registry:
        parent_name = posixpath.dirname(member_name)
        while parent_name not in {"", "."}:
            parent_member = registry.get(parent_name)
            if (
                parent_member is not None
                and parent_member.kind != "directory"
            ):
                raise SourceArtifactExtractionError(
                    "Archive member would write through a non-directory "
                    f"parent: {member_name!r} under {parent_name!r}"
                )
            parent_name = posixpath.dirname(parent_name)


def _validate_link_graph(
    registry: dict[str, _ValidatedArchiveMember],
) -> tuple[
    tuple[_ValidatedArchiveMember, ...],
    dict[str, _ValidatedArchiveMember],
    dict[str, _ValidatedArchiveMember],
]:
    states: dict[str, str] = {}
    direct_targets: dict[str, _ValidatedArchiveMember] = {}
    final_targets: dict[str, _ValidatedArchiveMember] = {}
    link_order: list[_ValidatedArchiveMember] = []

    def resolve_link(
        member: _ValidatedArchiveMember,
    ) -> _ValidatedArchiveMember:
        state = states.get(member.name)
        if state == "visiting":
            raise SourceArtifactExtractionError(
                f"Archive link cycle detected at {member.name!r}."
            )
        if state == "resolved":
            return final_targets[member.name]

        states[member.name] = "visiting"
        direct_target = next(
            (
                registry[candidate]
                for candidate in member.target_candidates
                if candidate in registry
            ),
            None,
        )
        if direct_target is None:
            target_display = " or ".join(
                repr(candidate) for candidate in member.target_candidates
            )
            raise SourceArtifactExtractionError(
                f"Archive link target does not exist: {member.name!r} -> "
                f"{target_display}"
            )
        direct_targets[member.name] = direct_target

        if direct_target.kind in {"symlink", "hardlink"}:
            final_target = resolve_link(direct_target)
        else:
            final_target = direct_target
        if final_target.kind not in {"regular", "directory"}:
            raise SourceArtifactExtractionError(
                f"Archive link has an invalid final target: {member.name!r}"
            )
        if member.kind == "hardlink" and final_target.kind != "regular":
            raise SourceArtifactExtractionError(
                f"Archive hard link must resolve to a regular file: "
                f"{member.name!r}"
            )
        if member.kind == "symlink" and final_target.kind == "directory":
            link_parent = PurePosixPath(member.name).parent
            target_path = PurePosixPath(final_target.name)
            if link_parent == target_path or target_path in link_parent.parents:
                raise SourceArtifactExtractionError(
                    "Archive directory symlink would create a cycle: "
                    f"{member.name!r} -> {final_target.name!r}"
                )

        states[member.name] = "resolved"
        final_targets[member.name] = final_target
        link_order.append(member)
        return final_target

    for member in registry.values():
        if member.kind in {"symlink", "hardlink"}:
            resolve_link(member)
    return tuple(link_order), direct_targets, final_targets


def _build_extraction_plan(
    members: list[_ValidatedArchiveMember],
) -> _ExtractionPlan:
    registry: dict[str, _ValidatedArchiveMember] = {}
    retained_members: list[_ValidatedArchiveMember] = []
    for member in members:
        if not member.name:
            if member.kind == "directory":
                continue
            raise SourceArtifactExtractionError(
                "Archive file or link member has no destination filename."
            )
        if member.name in registry:
            raise SourceArtifactExtractionError(
                f"Archive has duplicate destination: {member.name!r}"
            )
        registry[member.name] = member
        retained_members.append(member)

    _validate_destination_tree(registry)
    link_order, direct_targets, final_targets = _validate_link_graph(
        registry
    )
    return _ExtractionPlan(
        members=tuple(retained_members),
        link_order=link_order,
        direct_targets=direct_targets,
        final_targets=final_targets,
    )


def _create_directory(path: Path, extraction_root: Path) -> bool:
    if path == extraction_root:
        return False
    if path.is_symlink():
        raise SourceArtifactExtractionError(
            f"Archive member conflicts with a symbolic link: {path}"
        )
    if path.exists():
        if not path.is_dir():
            raise SourceArtifactExtractionError(
                f"Archive members conflict at destination: {path}"
            )
        return False
    path.mkdir(parents=True)
    return True


def _write_regular_file(
    source: BinaryIO,
    destination: Path,
    extraction_root: Path,
) -> None:
    _create_directory(destination.parent, extraction_root)
    if destination.is_symlink() or destination.exists():
        raise SourceArtifactExtractionError(
            f"Archive members conflict at destination: {destination}"
        )
    with destination.open("xb") as destination_file:
        shutil.copyfileobj(source, destination_file, length=1024 * 1024)


def _create_validated_links(
    extraction_root: Path,
    plan: _ExtractionPlan,
) -> None:
    resolved_root = extraction_root.resolve()
    for member in plan.link_order:
        destination = member.destination
        _create_directory(destination.parent, extraction_root)
        if destination.is_symlink() or destination.exists():
            raise SourceArtifactExtractionError(
                f"Archive link would overwrite an existing path: "
                f"{member.name!r}"
            )

        direct_target = plan.direct_targets[member.name]
        final_target = plan.final_targets[member.name]
        if member.kind == "symlink":
            relative_target = posixpath.relpath(
                direct_target.name,
                posixpath.dirname(member.name) or ".",
            )
            os.symlink(
                relative_target,
                destination,
                target_is_directory=final_target.kind == "directory",
            )
            resolved_link = destination.resolve(strict=True)
            resolved_final_target = final_target.destination.resolve(
                strict=True
            )
            if (
                not _path_is_within(resolved_link, resolved_root)
                or resolved_link != resolved_final_target
            ):
                raise SourceArtifactExtractionError(
                    f"Created symlink does not resolve to its validated "
                    f"target: {member.name!r}"
                )
        else:
            if (
                final_target.destination.is_symlink()
                or not final_target.destination.is_file()
            ):
                raise SourceArtifactExtractionError(
                    f"Hard link target is not a staged regular file: "
                    f"{member.name!r}"
                )
            os.link(
                final_target.destination,
                destination,
                follow_symlinks=False,
            )
            if not os.path.samefile(destination, final_target.destination):
                raise SourceArtifactExtractionError(
                    f"Created hard link does not match its validated target: "
                    f"{member.name!r}"
                )


def _validated_zip_plan(
    archive: zipfile.ZipFile,
    extraction_root: Path,
) -> _ExtractionPlan:
    members: list[_ValidatedArchiveMember] = []
    for archive_member in archive.infolist():
        member_name, destination = _validated_member_path(
            extraction_root,
            archive_member.filename,
        )
        unix_mode = archive_member.external_attr >> 16
        file_type = stat.S_IFMT(unix_mode)
        target_candidates: tuple[str, ...] = ()
        if file_type == stat.S_IFLNK:
            if archive_member.file_size > 4096:
                raise SourceArtifactExtractionError(
                    f"ZIP symlink target is too long: {member_name!r}"
                )
            try:
                link_target = archive.read(archive_member).decode("utf-8")
            except UnicodeDecodeError as error:
                raise SourceArtifactExtractionError(
                    f"ZIP symlink target is not valid UTF-8: {member_name!r}"
                ) from error
            target_candidates = _link_target_candidates(
                extraction_root,
                member_name=member_name,
                link_target=link_target,
                include_archive_root_target=False,
            )
            kind = "symlink"
        elif archive_member.is_dir():
            if file_type not in {0, stat.S_IFDIR}:
                raise SourceArtifactExtractionError(
                    f"ZIP special entries are not allowed: "
                    f"{archive_member.filename!r}"
                )
            kind = "directory"
        elif file_type in {0, stat.S_IFREG}:
            kind = "regular"
        else:
            raise SourceArtifactExtractionError(
                f"ZIP special entries are not allowed: "
                f"{archive_member.filename!r}"
            )
        members.append(
            _ValidatedArchiveMember(
                archive_member=archive_member,
                name=member_name,
                destination=destination,
                kind=kind,
                target_candidates=target_candidates,
            )
        )
    return _build_extraction_plan(members)


def _validated_tar_plan(
    archive: tarfile.TarFile,
    extraction_root: Path,
) -> _ExtractionPlan:
    members: list[_ValidatedArchiveMember] = []
    for archive_member in archive.getmembers():
        member_name, destination = _validated_member_path(
            extraction_root,
            archive_member.name,
        )
        target_candidates: tuple[str, ...] = ()
        if archive_member.issym() or archive_member.islnk():
            is_hardlink = archive_member.islnk()
            target_candidates = _link_target_candidates(
                extraction_root,
                member_name=member_name,
                link_target=archive_member.linkname,
                include_archive_root_target=is_hardlink,
            )
            kind = "hardlink" if is_hardlink else "symlink"
        elif archive_member.isdir():
            kind = "directory"
        elif archive_member.isfile():
            kind = "regular"
        else:
            raise SourceArtifactExtractionError(
                f"TAR special entries are not allowed: "
                f"{archive_member.name!r}"
            )
        members.append(
            _ValidatedArchiveMember(
                archive_member=archive_member,
                name=member_name,
                destination=destination,
                kind=kind,
                target_candidates=target_candidates,
            )
        )
    return _build_extraction_plan(members)


def _extract_zip(
    archive_path: Path,
    extraction_root: Path,
) -> tuple[int, int]:
    file_count = 0
    directory_count = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            plan = _validated_zip_plan(archive, extraction_root)
            for member in plan.members:
                if member.kind == "directory":
                    if _create_directory(
                        member.destination,
                        extraction_root,
                    ):
                        directory_count += 1
                    continue
                if member.kind != "regular":
                    continue
                with archive.open(member.archive_member, "r") as source:
                    _write_regular_file(
                        source,
                        member.destination,
                        extraction_root,
                    )
                file_count += 1
            _create_validated_links(extraction_root, plan)
            file_count += len(plan.link_order)
    except SourceArtifactExtractionError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise SourceArtifactExtractionError(
            f"Could not safely read ZIP archive: {archive_path}"
        ) from error
    return file_count, directory_count


def _extract_tar(
    archive_path: Path,
    extraction_root: Path,
) -> tuple[int, int]:
    file_count = 0
    directory_count = 0
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            plan = _validated_tar_plan(archive, extraction_root)
            for member in plan.members:
                if member.kind == "directory":
                    if _create_directory(
                        member.destination,
                        extraction_root,
                    ):
                        directory_count += 1
                    continue
                if member.kind != "regular":
                    continue
                source = archive.extractfile(member.archive_member)
                if source is None:
                    raise SourceArtifactExtractionError(
                        f"Could not read TAR member: {member.name!r}"
                    )
                with source:
                    _write_regular_file(
                        source,
                        member.destination,
                        extraction_root,
                    )
                file_count += 1
            _create_validated_links(extraction_root, plan)
            file_count += len(plan.link_order)
    except SourceArtifactExtractionError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise SourceArtifactExtractionError(
            f"Could not safely read TAR archive: {archive_path}"
        ) from error
    return file_count, directory_count


def _marker_payload(
    source_artifact: SourceArtifact,
    *,
    archive_name: str,
    file_count: int,
    directory_count: int,
) -> dict[str, int | str]:
    return {
        "schema_version": EXTRACTION_MARKER_VERSION,
        "sbom_document_id": source_artifact.sbom_document_id,
        "source_artifact_id": source_artifact.pk,
        "source_archive": archive_name,
        "source_sha256": source_artifact.file_sha256,
        "file_count": file_count,
        "directory_count": directory_count,
    }


def _completed_counts(
    final_root: Path,
    expected_marker: dict[str, int | str],
) -> tuple[int, int] | None:
    if final_root.is_symlink() or not final_root.is_dir():
        return None
    extraction_directory = final_root / "extracted"
    marker_path = final_root / EXTRACTION_MARKER_FILENAME
    if (
        extraction_directory.is_symlink()
        or not extraction_directory.is_dir()
        or marker_path.is_symlink()
        or not marker_path.is_file()
    ):
        return None
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(marker, dict):
        return None
    for key, value in expected_marker.items():
        if key in {"file_count", "directory_count"}:
            continue
        if marker.get(key) != value:
            return None
    file_count = marker.get("file_count")
    directory_count = marker.get("directory_count")
    if (
        not isinstance(file_count, int)
        or isinstance(file_count, bool)
        or file_count < 0
        or not isinstance(directory_count, int)
        or isinstance(directory_count, bool)
        or directory_count < 0
    ):
        return None
    return file_count, directory_count


def _publish_staged_extraction(
    staging_root: Path,
    final_root: Path,
    *,
    force: bool,
) -> None:
    if not final_root.exists():
        staging_root.rename(final_root)
        return
    if final_root.is_symlink() or not final_root.is_dir():
        raise SourceArtifactExtractionError(
            f"Extraction target is not a safe directory: {final_root}"
        )
    if not force:
        raise SourceArtifactExtractionError(
            "Extraction target appeared during extraction; rerun the command."
        )

    backup_root = final_root.with_name(
        f".{final_root.name}.backup-{uuid4().hex}"
    )
    final_root.rename(backup_root)
    try:
        staging_root.rename(final_root)
    except OSError:
        backup_root.rename(final_root)
        raise
    try:
        shutil.rmtree(backup_root)
    except OSError as error:
        raise SourceArtifactExtractionError(
            "Extraction completed, but the previous extraction backup "
            f"could not be removed: {backup_root}"
        ) from error


def extract_source_artifact(
    source_artifact: SourceArtifact,
    *,
    force: bool = False,
) -> SourceArtifactExtractionResult:
    """Verify and safely extract one filesystem-backed SourceArtifact."""

    if source_artifact.pk is None:
        raise SourceArtifactExtractionError(
            "SourceArtifact must be saved before extraction."
        )
    expected_sha256 = source_artifact.file_sha256
    if FILE_SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise SourceArtifactExtractionError(
            "SourceArtifact has an invalid stored SHA-256."
        )

    archive_path = _archive_path(source_artifact)
    archive_suffix = _validated_archive_suffix(
        source_artifact,
        archive_path,
    )
    actual_sha256, actual_size = _calculate_archive_metadata(archive_path)
    if actual_sha256 != expected_sha256:
        raise SourceArtifactExtractionError(
            "Source archive SHA-256 mismatch: "
            f"expected {expected_sha256}, got {actual_sha256}."
        )
    if actual_size != source_artifact.size:
        raise SourceArtifactExtractionError(
            "Source archive size mismatch: "
            f"expected {source_artifact.size}, got {actual_size}."
        )

    final_root = archive_path.parent / expected_sha256
    extraction_directory = final_root / "extracted"
    expected_marker = _marker_payload(
        source_artifact,
        archive_name=source_artifact.source_archive.name,
        file_count=0,
        directory_count=0,
    )
    if final_root.exists() and not force:
        completed_counts = _completed_counts(
            final_root,
            expected_marker,
        )
        if completed_counts is None:
            raise SourceArtifactExtractionError(
                "Extraction target exists without a valid completion marker; "
                "rerun with --force to replace this artifact's extraction."
            )
        file_count, directory_count = completed_counts
        return SourceArtifactExtractionResult(
            extraction_directory=extraction_directory,
            file_count=file_count,
            directory_count=directory_count,
            file_sha256=actual_sha256,
            skipped=True,
        )
    if final_root.is_symlink() or (
        final_root.exists() and not final_root.is_dir()
    ):
        raise SourceArtifactExtractionError(
            f"Extraction target is not a safe directory: {final_root}"
        )

    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f".{expected_sha256}.extract-",
            dir=archive_path.parent,
        )
    )
    staging_extraction_directory = staging_root / "extracted"
    staging_extraction_directory.mkdir()
    try:
        if archive_suffix == ".zip":
            file_count, directory_count = _extract_zip(
                archive_path,
                staging_extraction_directory,
            )
        else:
            file_count, directory_count = _extract_tar(
                archive_path,
                staging_extraction_directory,
            )

        marker = _marker_payload(
            source_artifact,
            archive_name=source_artifact.source_archive.name,
            file_count=file_count,
            directory_count=directory_count,
        )
        marker_path = staging_root / EXTRACTION_MARKER_FILENAME
        marker_path.write_text(
            json.dumps(marker, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _publish_staged_extraction(
            staging_root,
            final_root,
            force=force,
        )
    except SourceArtifactExtractionError:
        raise
    except OSError as error:
        raise SourceArtifactExtractionError(
            f"Could not publish source artifact extraction: {error}"
        ) from error
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root, ignore_errors=True)

    return SourceArtifactExtractionResult(
        extraction_directory=extraction_directory,
        file_count=file_count,
        directory_count=directory_count,
        file_sha256=actual_sha256,
        skipped=False,
    )

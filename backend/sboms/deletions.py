from __future__ import annotations

import logging
import shutil
from functools import partial
from pathlib import Path

from django.core.files.storage import Storage
from django.db import transaction
from django.db.models.deletion import ProtectedError

from sboms.models import (
    ComponentCpeGroundTruth,
    FILE_SHA256_PATTERN,
    SBOMDocument,
    SourceArtifact,
    source_artifact_upload_path,
)


logger = logging.getLogger(__name__)


class SBOMDeleteConflictError(Exception):
    """Raised when a protected dependency prevents an SBOM deletion."""


def _delete_unreferenced_uploaded_file(
    storage: Storage,
    stored_name: str,
    *,
    using: str,
) -> None:
    """Best-effort cleanup after the database deletion has committed."""

    try:
        if (
            SBOMDocument.objects.using(using)
            .filter(uploaded_file=stored_name)
            .exists()
        ):
            logger.warning(
                "Preserving shared SBOM upload %s after document deletion",
                stored_name,
            )
            return
        storage.delete(stored_name)
    except Exception:
        logger.exception(
            "Could not clean up deleted SBOM upload %s",
            stored_name,
        )


def _delete_unreferenced_source_archive(
    storage: Storage,
    stored_name: str,
    extraction_root: Path | None,
    *,
    using: str,
) -> None:
    """Best-effort source evidence cleanup after the database commit."""

    try:
        is_referenced = (
            SourceArtifact.objects.using(using)
            .filter(source_archive=stored_name)
            .exists()
        )
    except Exception:
        logger.exception(
            "Could not verify source archive references for %s",
            stored_name,
        )
        return
    if is_referenced:
        logger.warning(
            "Preserving shared source archive %s after SBOM deletion",
            stored_name,
        )
        return
    try:
        storage.delete(stored_name)
    except Exception:
        logger.exception(
            "Could not clean up deleted source archive %s",
            stored_name,
        )
    if extraction_root is None:
        return
    try:
        if extraction_root.is_symlink():
            logger.warning(
                "Preserving unsafe source extraction symlink %s",
                extraction_root,
            )
        elif extraction_root.exists():
            if not extraction_root.is_dir():
                logger.warning(
                    "Preserving non-directory source extraction path %s",
                    extraction_root,
                )
                return
            shutil.rmtree(extraction_root)
    except Exception:
        logger.exception(
            "Could not clean up source extraction %s",
            extraction_root,
        )


def _source_extraction_root(
    source_artifact: SourceArtifact,
) -> Path | None:
    """Resolve only the deterministic extraction root for this artifact."""

    source_sha256 = source_artifact.file_sha256
    if FILE_SHA256_PATTERN.fullmatch(source_sha256) is None:
        return None
    stored_name = source_artifact.source_archive.name
    if not stored_name:
        return None
    try:
        expected_stored_name = source_artifact_upload_path(
            source_artifact,
            source_artifact.original_filename,
        )
    except ValueError:
        return None
    if stored_name != expected_stored_name:
        return None
    storage = source_artifact.source_archive.storage
    try:
        storage_root = Path(storage.path("")).resolve()
        archive_path = Path(storage.path(stored_name)).resolve(strict=False)
        extraction_root = archive_path.parent / source_sha256
        extraction_root.resolve(strict=False).relative_to(storage_root)
    except (NotImplementedError, OSError, ValueError):
        return None
    return extraction_root


def delete_sbom_document(document: SBOMDocument) -> None:
    """Delete one SBOM, its owned review data, and its upload."""

    using = document._state.db or "default"

    try:
        with transaction.atomic(using=using):
            locked_document = (
                SBOMDocument.objects.using(using)
                .select_for_update()
                .get(pk=document.pk)
            )
            stored_name = locked_document.uploaded_file.name
            storage = (
                locked_document.uploaded_file.storage
                if stored_name
                else None
            )
            source_artifact = (
                SourceArtifact.objects.using(using)
                .filter(sbom_document=locked_document)
                .first()
            )
            source_stored_name = (
                source_artifact.source_archive.name
                if source_artifact is not None
                else ""
            )
            source_storage = (
                source_artifact.source_archive.storage
                if source_stored_name and source_artifact is not None
                else None
            )
            source_extraction_root = (
                _source_extraction_root(source_artifact)
                if source_artifact is not None
                else None
            )

            ComponentCpeGroundTruth.objects.using(using).filter(
                component__sbom_document=locked_document
            ).delete()
            locked_document.delete(using=using)
            if storage is not None and stored_name:
                transaction.on_commit(
                    partial(
                        _delete_unreferenced_uploaded_file,
                        storage,
                        stored_name,
                        using=using,
                    ),
                    using=using,
                )
            if source_storage is not None and source_stored_name:
                transaction.on_commit(
                    partial(
                        _delete_unreferenced_source_archive,
                        source_storage,
                        source_stored_name,
                        source_extraction_root,
                        using=using,
                    ),
                    using=using,
                )
    except ProtectedError as error:
        raise SBOMDeleteConflictError(
            "This SBOM cannot be deleted because protected data outside "
            "its owned component review records depends on it."
        ) from error

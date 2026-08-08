from __future__ import annotations

import logging
from functools import partial

from django.core.files.storage import Storage
from django.db import transaction
from django.db.models.deletion import ProtectedError

from sboms.models import SBOMDocument


logger = logging.getLogger(__name__)


class SBOMDeleteConflictError(Exception):
    """Raised when protected review data prevents an SBOM deletion."""


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


def delete_sbom_document(document: SBOMDocument) -> None:
    """Delete one SBOM and clean up its unshared upload after commit."""

    using = document._state.db or "default"
    stored_name = document.uploaded_file.name
    storage = document.uploaded_file.storage if stored_name else None

    try:
        with transaction.atomic(using=using):
            document.delete(using=using)
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
    except ProtectedError as error:
        raise SBOMDeleteConflictError(
            "This SBOM cannot be deleted while its components have "
            "protected review data."
        ) from error

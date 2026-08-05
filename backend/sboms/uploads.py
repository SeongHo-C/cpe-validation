from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from django.core.files.storage import Storage
from django.db import IntegrityError, transaction

from sboms.importers import (
    ImporterError,
    create_components_from_parsed,
    parse_cyclonedx_document_data,
)
from sboms.models import SBOMDocument, sbom_uploaded_file_path


logger = logging.getLogger(__name__)


class DuplicateSBOMError(Exception):
    """Raised when the uploaded bytes are already registered."""

    def __init__(self, existing_sbom_id: int) -> None:
        self.existing_sbom_id = existing_sbom_id
        super().__init__("The uploaded SBOM is already registered.")


@dataclass(frozen=True)
class UploadedSBOMResult:
    document: SBOMDocument
    component_count: int


def _rewind(uploaded_file: Any) -> None:
    try:
        uploaded_file.seek(0)
    except (AttributeError, OSError, ValueError) as error:
        raise ImporterError(
            "uploaded SBOM stream could not be reset"
        ) from error


def calculate_uploaded_file_sha256(uploaded_file: Any) -> str:
    """Hash the original upload bytes and restore the stream position."""

    digest = hashlib.sha256()
    _rewind(uploaded_file)
    try:
        for chunk in uploaded_file.chunks():
            digest.update(chunk)
    except (AttributeError, OSError, ValueError) as error:
        raise ImporterError("uploaded SBOM could not be read") from error
    finally:
        _rewind(uploaded_file)
    return digest.hexdigest()


def load_uploaded_json(uploaded_file: Any) -> Any:
    """Load UTF-8 JSON from an upload and restore the stream position."""

    _rewind(uploaded_file)
    try:
        document = json.load(uploaded_file)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ImporterError(
            "uploaded SBOM is not valid UTF-8 JSON"
        ) from error
    except (OSError, ValueError) as error:
        raise ImporterError("uploaded SBOM could not be read") from error
    finally:
        _rewind(uploaded_file)
    return document


def _delete_uploaded_file(
    storage: Storage | None,
    stored_name: str | None,
) -> None:
    if storage is None or not stored_name:
        return
    try:
        storage.delete(stored_name)
    except Exception:
        logger.exception(
            "Could not clean up failed SBOM upload %s",
            stored_name,
        )


def _existing_document_id(file_sha256: str) -> int | None:
    return (
        SBOMDocument.objects.filter(file_sha256=file_sha256)
        .values_list("id", flat=True)
        .first()
    )


def safe_original_filename(uploaded_file: Any) -> str:
    """Return a basename for both POSIX and Windows-style upload names."""

    raw_name = getattr(uploaded_file, "name", "")
    if not isinstance(raw_name, str):
        raise ImporterError("uploaded SBOM filename is invalid")
    original_filename = PurePosixPath(
        raw_name.replace("\\", "/")
    ).name
    if original_filename in {"", ".", ".."}:
        raise ImporterError("uploaded SBOM filename is invalid")
    return original_filename


def import_uploaded_cyclonedx_sbom(
    *,
    uploaded_file: Any,
    manufacturer: str = "",
    product_name: str = "",
    product_version: str = "",
) -> UploadedSBOMResult:
    """Validate, store, and import one uploaded CycloneDX document."""

    file_sha256 = calculate_uploaded_file_sha256(uploaded_file)
    existing_sbom_id = _existing_document_id(file_sha256)
    if existing_sbom_id is not None:
        raise DuplicateSBOMError(existing_sbom_id)

    raw_document = load_uploaded_json(uploaded_file)
    parsed = parse_cyclonedx_document_data(
        raw_document,
        "uploaded SBOM",
        allow_missing_components=True,
        require_syft_generator=False,
    )
    if not parsed.spec_version.strip():
        raise ImporterError(
            "uploaded SBOM.specVersion must be a non-empty string"
        )
    original_filename = safe_original_filename(uploaded_file)
    storage: Storage | None = None
    stored_name: str | None = None

    try:
        with transaction.atomic():
            try:
                with transaction.atomic():
                    document = SBOMDocument.objects.create(
                        docker_image=None,
                        manufacturer=manufacturer,
                        product_name=product_name,
                        product_version=product_version,
                        original_filename=original_filename,
                        source_path="",
                        file_sha256=file_sha256,
                        format=(
                            SBOMDocument.Format.CYCLONEDX_JSON
                        ),
                        spec_version=parsed.spec_version,
                        serial_number=parsed.serial_number,
                        document_version=parsed.document_version,
                        generator_name=parsed.generator_name,
                        generator_version=parsed.generator_version,
                        source_type="upload",
                        scope="document",
                        generated_at=parsed.generated_at,
                    )
            except IntegrityError as error:
                existing_sbom_id = _existing_document_id(
                    file_sha256
                )
                if existing_sbom_id is not None:
                    raise DuplicateSBOMError(
                        existing_sbom_id
                    ) from error
                raise

            storage = document.uploaded_file.storage
            expected_name = sbom_uploaded_file_path(
                document,
                original_filename,
            )
            if storage.exists(expected_name):
                raise RuntimeError(
                    "The deterministic SBOM storage path is unavailable."
                )

            _rewind(uploaded_file)
            stored_name = storage.save(
                expected_name,
                uploaded_file,
            )
            if stored_name != expected_name:
                raise RuntimeError(
                    "The storage backend changed the deterministic "
                    "SBOM path."
                )
            document.uploaded_file.name = stored_name
            document.save(update_fields=["uploaded_file"])
            component_count = create_components_from_parsed(
                document,
                parsed.components,
            )
    except Exception:
        _delete_uploaded_file(storage, stored_name)
        raise

    return UploadedSBOMResult(
        document=document,
        component_count=component_count,
    )

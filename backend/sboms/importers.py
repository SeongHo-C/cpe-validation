from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from django.db import transaction
from django.utils.dateparse import parse_datetime
from django.utils.timezone import is_aware

from .models import Component, DockerImage, SBOMDocument


DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
FILE_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class ImporterError(Exception):
    """Raised for an expected, user-correctable import failure."""


@dataclass(frozen=True)
class ImageRecord:
    repository: str
    tag: str
    platform: str
    manifest_digest: str
    pinned_reference: str
    expected_filename: str

    @property
    def display_name(self) -> str:
        return f"{self.repository}:{self.tag}"


@dataclass(frozen=True)
class ParsedComponent:
    bom_ref: str
    component_type: str
    group: str
    name: str
    version: str
    publisher: str
    purl: str
    cpe: str
    properties: list[Any]


@dataclass(frozen=True)
class ParsedSBOM:
    spec_version: str
    serial_number: str
    document_version: int
    generator_name: str
    generator_version: str
    generated_at: Any
    components: list[ParsedComponent]


@dataclass(frozen=True)
class FileImportResult:
    filename: str
    image: str
    manifest_digest: str
    sbom_status: str
    component_count: int
    components_with_primary_cpe: int
    components_without_primary_cpe: int


@dataclass
class ImportResult:
    images_created: int = 0
    images_existing: int = 0
    sboms_created: int = 0
    sboms_skipped: int = 0
    components_created: int = 0
    components_with_primary_cpe: int = 0
    components_without_primary_cpe: int = 0
    files_processed: int = 0
    files: list[FileImportResult] = field(default_factory=list)


def calculate_file_sha256(path: Path) -> str:
    """Calculate a file SHA-256 without loading the whole file at once."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as input_file:
            for chunk in iter(
                lambda: input_file.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)
    except OSError as error:
        raise ImporterError(f"cannot read SBOM file {path}: {error}") from error
    return digest.hexdigest()


def load_json_document(path: Path, label: str) -> Any:
    """Load one UTF-8 JSON file with a path-specific error."""

    try:
        with path.open("r", encoding="utf-8") as input_file:
            return json.load(input_file)
    except FileNotFoundError as error:
        raise ImporterError(f"{label} does not exist: {path}") from error
    except OSError as error:
        raise ImporterError(f"cannot read {label} {path}: {error}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ImporterError(
            f"{label} is not valid UTF-8 JSON: {path}: {error}"
        ) from error


def required_string(
    mapping: dict[str, Any],
    key: str,
    context: str,
) -> str:
    """Read one required non-empty string."""

    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ImporterError(f"{context}.{key} must be a non-empty string")
    return value


def optional_string(
    mapping: dict[str, Any],
    key: str,
    context: str,
) -> str:
    """Read an optional string, preserving it exactly when present."""

    if key not in mapping:
        return ""
    value = mapping[key]
    if not isinstance(value, str):
        raise ImporterError(f"{context}.{key} must be a string")
    return value


def load_digest_records(
    digest_file: Path,
    expected_image_count: int,
) -> list[ImageRecord]:
    """Parse and validate successful records from image-digests.json."""

    document = load_json_document(digest_file, "digest file")
    if not isinstance(document, dict):
        raise ImporterError("digest file root must be a JSON object")

    platform_value = document.get("platform")
    if not isinstance(platform_value, dict):
        raise ImporterError("digest file platform must be a JSON object")
    platform_os = required_string(
        platform_value,
        "os",
        "digest file platform",
    )
    platform_architecture = required_string(
        platform_value,
        "architecture",
        "digest file platform",
    )
    platform = f"{platform_os}/{platform_architecture}"

    images = document.get("images")
    if not isinstance(images, list):
        raise ImporterError("digest file images must be a JSON array")
    successful_images = [
        image
        for image in images
        if isinstance(image, dict) and image.get("status") == "success"
    ]
    if len(successful_images) != expected_image_count:
        raise ImporterError(
            "digest file must contain exactly "
            f"{expected_image_count} successful images; "
            f"found {len(successful_images)}"
        )

    records: list[ImageRecord] = []
    seen_digests: set[str] = set()
    seen_pinned_references: set[str] = set()
    seen_filenames: set[str] = set()
    for index, image in enumerate(successful_images):
        context = f"digest file images[{index}]"
        repository = required_string(
            image,
            "normalized_repository",
            context,
        )
        tag = required_string(image, "input_tag", context)
        manifest_digest = required_string(
            image,
            "platform_manifest_digest",
            context,
        )
        pinned_reference = required_string(
            image,
            "pinned_reference",
            context,
        )
        if DIGEST_PATTERN.fullmatch(manifest_digest) is None:
            raise ImporterError(
                f"{context}.platform_manifest_digest is invalid: "
                f"{manifest_digest!r}"
            )
        if pinned_reference != f"{repository}@{manifest_digest}":
            raise ImporterError(
                f"{context}.pinned_reference does not match repository "
                "and platform manifest digest"
            )
        if manifest_digest in seen_digests:
            raise ImporterError(
                f"duplicate platform manifest digest: {manifest_digest}"
            )
        if pinned_reference in seen_pinned_references:
            raise ImporterError(
                f"duplicate pinned reference: {pinned_reference}"
            )

        repository_basename = repository.rsplit("/", 1)[-1]
        if repository_basename in {"", ".", ".."}:
            raise ImporterError(
                f"{context}.normalized_repository has no safe basename"
            )
        if "/" in tag or "\\" in tag or tag in {".", ".."}:
            raise ImporterError(
                f"{context}.input_tag cannot form a safe filename"
            )
        expected_filename = (
            f"{repository_basename}-{tag}.cdx.json"
        )
        if expected_filename in seen_filenames:
            raise ImporterError(
                "multiple digest records map to the same SBOM file: "
                f"{expected_filename}"
            )

        seen_digests.add(manifest_digest)
        seen_pinned_references.add(pinned_reference)
        seen_filenames.add(expected_filename)
        records.append(
            ImageRecord(
                repository=repository,
                tag=tag,
                platform=platform,
                manifest_digest=manifest_digest,
                pinned_reference=pinned_reference,
                expected_filename=expected_filename,
            )
        )
    return records


def match_sbom_files(
    records: list[ImageRecord],
    sbom_directory: Path,
) -> list[tuple[ImageRecord, Path]]:
    """Match every digest record to exactly one SBOM filename."""

    if not sbom_directory.is_dir():
        raise ImporterError(
            f"SBOM directory does not exist: {sbom_directory}"
        )
    actual_files = {
        path.name: path
        for path in sbom_directory.iterdir()
        if path.is_file() and path.name.endswith(".cdx.json")
    }
    expected_filenames = {
        record.expected_filename for record in records
    }
    missing = sorted(expected_filenames - actual_files.keys())
    extra = sorted(actual_files.keys() - expected_filenames)
    if missing:
        raise ImporterError(
            "missing expected SBOM files: " + ", ".join(missing)
        )
    if extra:
        raise ImporterError(
            "unmatched SBOM files: " + ", ".join(extra)
        )
    if len(actual_files) != len(records):
        raise ImporterError(
            "SBOM file count does not match successful digest record count"
        )
    return [
        (record, actual_files[record.expected_filename])
        for record in records
    ]


def extract_syft_generator(
    metadata: dict[str, Any],
    path: str | Path,
) -> tuple[str, str]:
    """Extract Syft name and version from supported CycloneDX layouts."""

    tools = metadata.get("tools")
    if isinstance(tools, dict):
        tool_entries = tools.get("components")
        if not isinstance(tool_entries, list):
            raise ImporterError(
                f"{path}: metadata.tools.components must be an array"
            )
    elif isinstance(tools, list):
        tool_entries = tools
    else:
        raise ImporterError(
            f"{path}: metadata.tools must be an object or array"
        )

    for index, tool in enumerate(tool_entries):
        if not isinstance(tool, dict):
            raise ImporterError(
                f"{path}: metadata tool at index {index} "
                "must be an object"
            )
        name = tool.get("name")
        if isinstance(name, str) and name.lower() == "syft":
            version = tool.get("version")
            if not isinstance(version, str) or not version:
                raise ImporterError(
                    f"{path}: Syft generator has no version"
                )
            return name, version
    raise ImporterError(f"{path}: metadata has no Syft generator")


def extract_optional_generator(
    metadata: dict[str, Any],
) -> tuple[str, str]:
    """Extract an EMBA-preferred generator when metadata provides one."""

    tools = metadata.get("tools")
    if isinstance(tools, dict):
        tool_entries = tools.get("components")
    elif isinstance(tools, list):
        tool_entries = tools
    else:
        return "", ""
    if not isinstance(tool_entries, list):
        return "", ""

    candidates: list[tuple[str, str]] = []
    for tool in tool_entries:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        version = tool.get("version", "")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(version, str):
            version = ""
        candidate = (name, version)
        if name.lower() == "emba":
            return candidate
        candidates.append(candidate)
    return candidates[0] if candidates else ("", "")


def parse_component_tree(
    entries: Any,
    path: str | Path,
) -> list[ParsedComponent]:
    """Recursively validate and flatten CycloneDX components."""

    parsed: list[ParsedComponent] = []
    seen_bom_refs: set[str] = set()

    def visit(component_entries: Any, context: str) -> None:
        if not isinstance(component_entries, list):
            raise ImporterError(f"{path}: {context} must be an array")
        for index, component in enumerate(component_entries):
            component_context = f"{context}[{index}]"
            if not isinstance(component, dict):
                raise ImporterError(
                    f"{path}: {component_context} must be an object"
                )
            bom_ref = required_string(
                component,
                "bom-ref",
                f"{path}: {component_context}",
            )
            if bom_ref in seen_bom_refs:
                raise ImporterError(
                    f"{path}: duplicate bom-ref: {bom_ref}"
                )
            seen_bom_refs.add(bom_ref)

            component_type = required_string(
                component,
                "type",
                f"{path}: {component_context}",
            )
            name = required_string(
                component,
                "name",
                f"{path}: {component_context}",
            )
            properties = component.get("properties", [])
            if not isinstance(properties, list):
                raise ImporterError(
                    f"{path}: {component_context}.properties "
                    "must be an array"
                )
            parsed.append(
                ParsedComponent(
                    bom_ref=bom_ref,
                    component_type=component_type,
                    group=optional_string(
                        component,
                        "group",
                        f"{path}: {component_context}",
                    ),
                    name=name,
                    version=optional_string(
                        component,
                        "version",
                        f"{path}: {component_context}",
                    ),
                    publisher=optional_string(
                        component,
                        "publisher",
                        f"{path}: {component_context}",
                    ),
                    purl=optional_string(
                        component,
                        "purl",
                        f"{path}: {component_context}",
                    ),
                    cpe=optional_string(
                        component,
                        "cpe",
                        f"{path}: {component_context}",
                    ),
                    properties=properties,
                )
            )
            if "components" in component:
                visit(
                    component["components"],
                    f"{component_context}.components",
                )

    visit(entries, "components")
    return parsed


def parse_cyclonedx_document_data(
    document: Any,
    label: str | Path,
    *,
    allow_missing_components: bool = False,
    require_syft_generator: bool = True,
) -> ParsedSBOM:
    """Parse supported CycloneDX fields from an in-memory document."""

    if not isinstance(document, dict):
        raise ImporterError(
            f"{label}: CycloneDX root must be an object"
        )
    if document.get("bomFormat") != "CycloneDX":
        raise ImporterError(
            f"{label}: bomFormat must be 'CycloneDX'"
        )
    spec_version = required_string(
        document,
        "specVersion",
        str(label),
    )
    if "components" in document:
        components = parse_component_tree(
            document["components"],
            label,
        )
    elif allow_missing_components:
        components = []
    else:
        components = parse_component_tree(None, label)

    serial_number = optional_string(
        document,
        "serialNumber",
        str(label),
    )
    document_version = document.get("version", 1)
    if (
        not isinstance(document_version, int)
        or isinstance(document_version, bool)
        or document_version < 1
    ):
        raise ImporterError(
            f"{label}: version must be a positive integer"
        )

    metadata = document.get("metadata")
    if metadata is None and not require_syft_generator:
        metadata = {}
    if not isinstance(metadata, dict):
        raise ImporterError(f"{label}: metadata must be an object")
    if require_syft_generator:
        generator_name, generator_version = extract_syft_generator(
            metadata,
            label,
        )
    else:
        generator_name, generator_version = extract_optional_generator(
            metadata
        )

    generated_at = None
    if "timestamp" in metadata:
        timestamp = metadata["timestamp"]
        if not isinstance(timestamp, str) or not timestamp:
            raise ImporterError(
                f"{label}: metadata.timestamp must be a non-empty string"
            )
        generated_at = parse_datetime(timestamp)
        if generated_at is None or not is_aware(generated_at):
            raise ImporterError(
                f"{label}: metadata.timestamp is not a timezone-aware "
                f"ISO datetime: {timestamp!r}"
            )

    return ParsedSBOM(
        spec_version=spec_version,
        serial_number=serial_number,
        document_version=document_version,
        generator_name=generator_name,
        generator_version=generator_version,
        generated_at=generated_at,
        components=components,
    )


def parse_cyclonedx_document(path: Path) -> ParsedSBOM:
    """Parse a Docker-import CycloneDX file with its legacy rules."""

    return parse_cyclonedx_document_data(
        load_json_document(path, "SBOM file"),
        path,
    )


def create_components_from_parsed(
    sbom_document: SBOMDocument,
    components: list[ParsedComponent],
) -> int:
    """Create parsed components with the importer's existing mapping."""

    Component.objects.bulk_create(
        [
            Component(
                sbom_document=sbom_document,
                bom_ref=component.bom_ref,
                component_type=component.component_type,
                group=component.group,
                name=component.name,
                version=component.version,
                publisher=component.publisher,
                purl=component.purl,
                cpe=component.cpe,
                properties=component.properties,
            )
            for component in components
        ],
        batch_size=1000,
    )
    return len(components)


def get_or_create_image(
    record: ImageRecord,
) -> tuple[DockerImage, bool]:
    """Create one image or reject conflicting existing metadata."""

    existing = DockerImage.objects.filter(
        manifest_digest=record.manifest_digest
    ).first()
    expected = {
        "repository": record.repository,
        "tag": record.tag,
        "platform": record.platform,
        "pinned_reference": record.pinned_reference,
    }
    if existing is not None:
        mismatches = [
            field_name
            for field_name, expected_value in expected.items()
            if getattr(existing, field_name) != expected_value
        ]
        if mismatches:
            raise ImporterError(
                "existing DockerImage metadata mismatch for "
                f"{record.manifest_digest}: "
                + ", ".join(mismatches)
            )
        return existing, False

    pinned_collision = DockerImage.objects.filter(
        pinned_reference=record.pinned_reference
    ).first()
    if pinned_collision is not None:
        raise ImporterError(
            "existing DockerImage pinned reference belongs to another "
            f"manifest digest: {record.pinned_reference}"
        )
    return (
        DockerImage.objects.create(
            manifest_digest=record.manifest_digest,
            **expected,
        ),
        True,
    )


def validate_existing_document(
    document: SBOMDocument,
    docker_image: DockerImage,
    source_path: str,
    parsed: ParsedSBOM,
) -> None:
    """Reject a file-hash match whose stored metadata differs."""

    expected = {
        "docker_image_id": docker_image.pk,
        "source_path": source_path,
        "spec_version": parsed.spec_version,
        "generator_name": parsed.generator_name,
        "generator_version": parsed.generator_version,
        "format": SBOMDocument.Format.CYCLONEDX_JSON,
    }
    mismatches = [
        field_name
        for field_name, expected_value in expected.items()
        if getattr(document, field_name) != expected_value
    ]
    if mismatches:
        raise ImporterError(
            "existing SBOMDocument metadata mismatch for file SHA-256 "
            f"{document.file_sha256}: "
            + ", ".join(mismatches)
        )


def relative_source_path(
    path: Path,
    repository_root: Path,
) -> str:
    """Return a repository-relative POSIX path."""

    try:
        return path.resolve(strict=True).relative_to(
            repository_root.resolve(strict=True)
        ).as_posix()
    except (OSError, ValueError) as error:
        raise ImporterError(
            f"SBOM file must be inside repository root: {path}"
        ) from error


def _import_sboms(
    matched_files: list[tuple[ImageRecord, Path]],
    repository_root: Path,
) -> ImportResult:
    result = ImportResult()
    for record, path in matched_files:
        file_sha256 = calculate_file_sha256(path)
        if FILE_SHA256_PATTERN.fullmatch(file_sha256) is None:
            raise ImporterError(
                f"{path}: calculated file SHA-256 is invalid"
            )
        parsed = parse_cyclonedx_document(path)
        source_path = relative_source_path(path, repository_root)
        with_primary_cpe = sum(
            bool(component.cpe) for component in parsed.components
        )
        without_primary_cpe = (
            len(parsed.components) - with_primary_cpe
        )

        docker_image, image_created = get_or_create_image(record)
        if image_created:
            result.images_created += 1
        else:
            result.images_existing += 1

        existing_document = SBOMDocument.objects.filter(
            file_sha256=file_sha256
        ).first()
        if existing_document is not None:
            validate_existing_document(
                existing_document,
                docker_image,
                source_path,
                parsed,
            )
            sbom_status = "skipped"
            result.sboms_skipped += 1
        else:
            sbom_document = SBOMDocument.objects.create(
                docker_image=docker_image,
                source_path=source_path,
                file_sha256=file_sha256,
                format=SBOMDocument.Format.CYCLONEDX_JSON,
                spec_version=parsed.spec_version,
                serial_number=parsed.serial_number,
                document_version=parsed.document_version,
                generator_name=parsed.generator_name,
                generator_version=parsed.generator_version,
                source_type="registry",
                scope="squashed",
                generated_at=parsed.generated_at,
            )
            create_components_from_parsed(
                sbom_document,
                parsed.components,
            )
            sbom_status = "created"
            result.sboms_created += 1
            result.components_created += len(parsed.components)

        result.components_with_primary_cpe += with_primary_cpe
        result.components_without_primary_cpe += without_primary_cpe
        result.files_processed += 1
        result.files.append(
            FileImportResult(
                filename=path.name,
                image=record.display_name,
                manifest_digest=record.manifest_digest,
                sbom_status=sbom_status,
                component_count=len(parsed.components),
                components_with_primary_cpe=with_primary_cpe,
                components_without_primary_cpe=without_primary_cpe,
            )
        )
    return result


def import_sboms(
    *,
    sbom_directory: Path,
    digest_file: Path,
    repository_root: Path,
    dry_run: bool = False,
    expected_image_count: int = 10,
) -> ImportResult:
    """Import a complete matched SBOM set in one atomic transaction."""

    records = load_digest_records(
        digest_file,
        expected_image_count=expected_image_count,
    )
    matched_files = match_sbom_files(records, sbom_directory)
    with transaction.atomic():
        result = _import_sboms(matched_files, repository_root)
        if dry_run:
            transaction.set_rollback(True)
    return result

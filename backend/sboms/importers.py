from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.utils.dateparse import parse_datetime
from django.utils.timezone import is_aware

from .models import Component, SBOMDocument


class ImporterError(Exception):
    """Raised for an expected, user-correctable import failure."""


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

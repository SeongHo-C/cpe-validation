from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum

from cpe.cpe23_canonical import (
    CPE23Name,
    canonicalize_cpe23,
    parse_cpe23,
)


NON_VERSION_TEMPLATE_ATTRIBUTES = (
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


class StableTemplateStatus(str, Enum):
    UNIQUE_STABLE_TEMPLATE = "UNIQUE_STABLE_TEMPLATE"
    MULTIPLE_COMPATIBLE_TEMPLATES = "MULTIPLE_COMPATIBLE_TEMPLATES"
    NO_STABLE_TEMPLATE = "NO_STABLE_TEMPLATE"


@dataclass(frozen=True)
class StableTemplateResult:
    status: StableTemplateStatus
    family: tuple[str, str, str]
    compatible_cpes: tuple[str, ...]
    templates: tuple[tuple[str, ...], ...]
    selected_template: tuple[str, ...] | None
    generated_cpe: str | None
    review_required: bool
    review_reason: str


def resolve_stable_template(
    active_cpes: Iterable[str],
    *,
    family: tuple[str, str, str],
    normalized_version: str,
    compatibility: Callable[[CPE23Name], bool] | None = None,
) -> StableTemplateResult:
    """Resolve one evidence-compatible non-version family template.

    ``compatibility`` is deliberately explicit: release/platform evidence is
    supplied by the caller. The helper never chooses the first family row.
    """

    compatible_names: list[CPE23Name] = []
    compatible_cpes: list[str] = []
    for raw_cpe in active_cpes:
        parsed = parse_cpe23(raw_cpe)
        if not parsed.is_valid or parsed.name is None:
            continue
        if parsed.name.family != family:
            continue
        if compatibility is not None and not compatibility(parsed.name):
            continue
        compatible_names.append(parsed.name)
        compatible_cpes.append(canonicalize_cpe23(raw_cpe))

    templates = sorted(
        {
            tuple(
                name.attribute(attribute).canonical
                for attribute in NON_VERSION_TEMPLATE_ATTRIBUTES
            )
            for name in compatible_names
        }
    )
    if not templates:
        return StableTemplateResult(
            status=StableTemplateStatus.NO_STABLE_TEMPLATE,
            family=family,
            compatible_cpes=tuple(sorted(set(compatible_cpes))),
            templates=(),
            selected_template=None,
            generated_cpe=None,
            review_required=True,
            review_reason=(
                "No evidence-compatible Active family record supplies a "
                "non-version template."
            ),
        )
    if len(templates) > 1:
        return StableTemplateResult(
            status=StableTemplateStatus.MULTIPLE_COMPATIBLE_TEMPLATES,
            family=family,
            compatible_cpes=tuple(sorted(set(compatible_cpes))),
            templates=tuple(templates),
            selected_template=None,
            generated_cpe=None,
            review_required=True,
            review_reason=(
                "More than one evidence-compatible non-version template "
                "remains; automatic selection is prohibited."
            ),
        )

    selected = templates[0]
    fields = (
        family[0],
        family[1],
        family[2],
        normalized_version,
        *selected,
    )
    generated_cpe = canonicalize_cpe23("cpe:2.3:" + ":".join(fields))
    return StableTemplateResult(
        status=StableTemplateStatus.UNIQUE_STABLE_TEMPLATE,
        family=family,
        compatible_cpes=tuple(sorted(set(compatible_cpes))),
        templates=tuple(templates),
        selected_template=selected,
        generated_cpe=generated_cpe,
        review_required=False,
        review_reason="",
    )


@dataclass(frozen=True)
class CPEReferenceRecord:
    identifier: str
    cpe_name: str
    deprecated: bool
    deprecated_by: tuple[str, ...] = ()


class DeprecatedResolutionStatus(str, Enum):
    RESOLVED_ACTIVE = "RESOLVED_ACTIVE"
    MULTIPLE_COMPATIBLE_ENDPOINTS = "MULTIPLE_COMPATIBLE_ENDPOINTS"
    CYCLE_DETECTED = "CYCLE_DETECTED"
    MISSING_REFERENCE = "MISSING_REFERENCE"
    DEPRECATED_DEAD_END = "DEPRECATED_DEAD_END"
    NO_COMPATIBLE_ACTIVE_ENDPOINT = "NO_COMPATIBLE_ACTIVE_ENDPOINT"
    INVALID_START = "INVALID_START"


@dataclass(frozen=True)
class DeprecatedResolutionResult:
    starting_deprecated_cpe: str
    replacement_depth: int
    replacement_chains: tuple[tuple[str, ...], ...]
    replacement_count: int
    candidate_active_endpoints: tuple[str, ...]
    compatible_active_endpoints: tuple[str, ...]
    resolved_active_endpoint: str | None
    resolution_status: DeprecatedResolutionStatus
    review_required: bool
    review_reason: str
    cycle_detected: bool
    missing_references: tuple[str, ...]
    deprecated_dead_ends: tuple[str, ...]


def resolve_deprecated_cpe(
    records: Mapping[str, CPEReferenceRecord],
    starting_identifier: str,
    *,
    compatibility: Callable[[CPE23Name], bool] | None = None,
) -> DeprecatedResolutionResult:
    start = records.get(starting_identifier)
    if start is None or not start.deprecated:
        reason = (
            "Starting identifier is missing."
            if start is None
            else "Starting CPE is not Deprecated."
        )
        return DeprecatedResolutionResult(
            starting_deprecated_cpe=(
                start.cpe_name if start is not None else starting_identifier
            ),
            replacement_depth=0,
            replacement_chains=(),
            replacement_count=0,
            candidate_active_endpoints=(),
            compatible_active_endpoints=(),
            resolved_active_endpoint=None,
            resolution_status=DeprecatedResolutionStatus.INVALID_START,
            review_required=True,
            review_reason=reason,
            cycle_detected=False,
            missing_references=(),
            deprecated_dead_ends=(),
        )

    chains: list[tuple[str, ...]] = []
    active_endpoints: set[str] = set()
    missing_references: set[str] = set()
    deprecated_dead_ends: set[str] = set()
    cycle_detected = False

    def walk(
        identifier: str,
        path_identifiers: tuple[str, ...],
        path_cpes: tuple[str, ...],
    ) -> None:
        nonlocal cycle_detected
        record = records[identifier]
        if not record.deprecated:
            active_endpoints.add(canonicalize_cpe23(record.cpe_name))
            chains.append(path_cpes)
            return
        if not record.deprecated_by:
            deprecated_dead_ends.add(record.cpe_name)
            chains.append(path_cpes)
            return

        for replacement_identifier in record.deprecated_by:
            if replacement_identifier in path_identifiers:
                cycle_detected = True
                repeated = records.get(replacement_identifier)
                repeated_name = (
                    repeated.cpe_name
                    if repeated is not None
                    else replacement_identifier
                )
                chains.append((*path_cpes, repeated_name))
                continue
            replacement = records.get(replacement_identifier)
            if replacement is None:
                missing_references.add(replacement_identifier)
                chains.append((*path_cpes, f"MISSING:{replacement_identifier}"))
                continue
            walk(
                replacement_identifier,
                (*path_identifiers, replacement_identifier),
                (*path_cpes, replacement.cpe_name),
            )

    walk(starting_identifier, (starting_identifier,), (start.cpe_name,))

    compatible_endpoints: set[str] = set()
    for endpoint in active_endpoints:
        parsed = parse_cpe23(endpoint)
        if parsed.name is None:
            continue
        if compatibility is None or compatibility(parsed.name):
            compatible_endpoints.add(endpoint)

    resolved: str | None = None
    if cycle_detected:
        status = DeprecatedResolutionStatus.CYCLE_DETECTED
        reason = "At least one replacement branch contains a cycle."
    elif missing_references:
        status = DeprecatedResolutionStatus.MISSING_REFERENCE
        reason = "At least one deprecatedBy target is absent from the snapshot."
    elif deprecated_dead_ends:
        status = DeprecatedResolutionStatus.DEPRECATED_DEAD_END
        reason = "At least one replacement branch terminates as Deprecated."
    elif len(compatible_endpoints) > 1:
        status = DeprecatedResolutionStatus.MULTIPLE_COMPATIBLE_ENDPOINTS
        reason = (
            "More than one compatible Active endpoint remains; automatic "
            "selection is prohibited."
        )
    elif len(compatible_endpoints) == 1:
        status = DeprecatedResolutionStatus.RESOLVED_ACTIVE
        resolved = next(iter(compatible_endpoints))
        reason = ""
    else:
        status = DeprecatedResolutionStatus.NO_COMPATIBLE_ACTIVE_ENDPOINT
        reason = "No replacement branch reaches a compatible Active endpoint."

    return DeprecatedResolutionResult(
        starting_deprecated_cpe=start.cpe_name,
        replacement_depth=max((len(chain) - 1 for chain in chains), default=0),
        replacement_chains=tuple(sorted(set(chains))),
        replacement_count=len(start.deprecated_by),
        candidate_active_endpoints=tuple(sorted(active_endpoints)),
        compatible_active_endpoints=tuple(sorted(compatible_endpoints)),
        resolved_active_endpoint=resolved,
        resolution_status=status,
        review_required=status is not DeprecatedResolutionStatus.RESOLVED_ACTIVE,
        review_reason=reason,
        cycle_detected=cycle_detected,
        missing_references=tuple(sorted(missing_references)),
        deprecated_dead_ends=tuple(sorted(deprecated_dead_ends)),
    )


class DeprecatedFamilyStatus(str, Enum):
    RESOLVED_ACTIVE_FAMILY = "RESOLVED_ACTIVE_FAMILY"
    MULTIPLE_ACTIVE_FAMILIES = "MULTIPLE_ACTIVE_FAMILIES"
    NO_ACTIVE_FAMILY = "NO_ACTIVE_FAMILY"
    GRAPH_ERROR = "GRAPH_ERROR"


@dataclass(frozen=True)
class DeprecatedFamilyResolutionResult:
    status: DeprecatedFamilyStatus
    candidate_active_families: tuple[tuple[str, str, str], ...]
    resolved_active_family: tuple[str, str, str] | None
    member_resolutions: tuple[DeprecatedResolutionResult, ...]
    review_required: bool


def resolve_deprecated_family_alias(
    records: Mapping[str, CPEReferenceRecord],
    starting_identifiers: Iterable[str],
    *,
    compatibility: Callable[[CPE23Name], bool] | None = None,
) -> DeprecatedFamilyResolutionResult:
    resolutions = tuple(
        resolve_deprecated_cpe(
            records,
            identifier,
            compatibility=compatibility,
        )
        for identifier in starting_identifiers
    )
    graph_errors = {
        DeprecatedResolutionStatus.CYCLE_DETECTED,
        DeprecatedResolutionStatus.MISSING_REFERENCE,
        DeprecatedResolutionStatus.DEPRECATED_DEAD_END,
        DeprecatedResolutionStatus.INVALID_START,
    }
    if any(result.resolution_status in graph_errors for result in resolutions):
        status = DeprecatedFamilyStatus.GRAPH_ERROR
        families: set[tuple[str, str, str]] = set()
    else:
        families = set()
        for result in resolutions:
            for endpoint in result.compatible_active_endpoints:
                parsed = parse_cpe23(endpoint)
                if parsed.name is not None:
                    families.add(parsed.name.family)
        if len(families) == 1:
            status = DeprecatedFamilyStatus.RESOLVED_ACTIVE_FAMILY
        elif len(families) > 1:
            status = DeprecatedFamilyStatus.MULTIPLE_ACTIVE_FAMILIES
        else:
            status = DeprecatedFamilyStatus.NO_ACTIVE_FAMILY

    resolved_family = next(iter(families)) if len(families) == 1 else None
    return DeprecatedFamilyResolutionResult(
        status=status,
        candidate_active_families=tuple(sorted(families)),
        resolved_active_family=resolved_family,
        member_resolutions=resolutions,
        review_required=(
            status is not DeprecatedFamilyStatus.RESOLVED_ACTIVE_FAMILY
        ),
    )


class ConfigurationGateStatus(str, Enum):
    BLOCKED_ACTIVE_PRODUCT = "BLOCKED_ACTIVE_PRODUCT"
    BLOCKED_DEPRECATED_PRODUCT = "BLOCKED_DEPRECATED_PRODUCT"
    ALLOWED = "ALLOWED"


@dataclass(frozen=True)
class ConfigurationGateResult:
    status: ConfigurationGateStatus
    dictionary_product_present_active: bool
    dictionary_product_present_deprecated: bool
    configuration_lookup_allowed: bool


def configuration_only_gate(
    *,
    active_product_count: int,
    deprecated_product_count: int,
) -> ConfigurationGateResult:
    if active_product_count:
        status = ConfigurationGateStatus.BLOCKED_ACTIVE_PRODUCT
    elif deprecated_product_count:
        status = ConfigurationGateStatus.BLOCKED_DEPRECATED_PRODUCT
    else:
        status = ConfigurationGateStatus.ALLOWED
    return ConfigurationGateResult(
        status=status,
        dictionary_product_present_active=bool(active_product_count),
        dictionary_product_present_deprecated=bool(deprecated_product_count),
        configuration_lookup_allowed=status is ConfigurationGateStatus.ALLOWED,
    )

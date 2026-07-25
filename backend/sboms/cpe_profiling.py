from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from django.db.models import Count, Q

from sboms.cpe23 import (
    CPE23_ATTRIBUTE_NAMES,
    CPE23ParseResult,
    CPE23StructuralStatus,
    parse_cpe23_formatted_string,
)
from sboms.models import Component, DockerImage, SBOMDocument


SCHEMA_VERSION = 1
SCOPE = "component.cpe only"
VALIDATION_LEVEL = (
    "CPE 2.3 formatted-string structural validation"
)

SUMMARY_FILENAME = "summary.json"
IMAGE_SUMMARY_FILENAME = "image_summary.csv"
COMPONENT_CPES_FILENAME = "component_cpes.csv"
CPE_USAGE_FILENAME = "cpe_usage.csv"
VENDOR_PRODUCT_SUMMARY_FILENAME = "vendor_product_summary.csv"
STRUCTURALLY_INVALID_CPES_FILENAME = (
    "structurally_invalid_cpes.csv"
)
OUTPUT_FILENAMES = (
    SUMMARY_FILENAME,
    IMAGE_SUMMARY_FILENAME,
    COMPONENT_CPES_FILENAME,
    CPE_USAGE_FILENAME,
    VENDOR_PRODUCT_SUMMARY_FILENAME,
    STRUCTURALLY_INVALID_CPES_FILENAME,
)

IMAGE_SUMMARY_FIELDS = (
    "repository",
    "tag",
    "platform",
    "total_components",
    "components_with_primary_cpe",
    "components_without_primary_cpe",
    "primary_cpe_ratio",
    "structurally_valid_components",
    "structurally_invalid_components",
    "unique_primary_cpes",
)
COMPONENT_CPES_FIELDS = (
    "component_id",
    "repository",
    "tag",
    "sbom_source_path",
    "bom_ref",
    "component_type",
    "component_name",
    "component_version",
    "publisher",
    "purl",
    "raw_cpe",
    "structural_status",
    "error_message",
    "part_raw",
    "vendor_raw",
    "product_raw",
    "version_raw",
    "update_raw",
    "edition_raw",
    "language_raw",
    "sw_edition_raw",
    "target_sw_raw",
    "target_hw_raw",
    "other_raw",
)
CPE_USAGE_FIELDS = (
    "raw_cpe",
    "structural_status",
    "part_raw",
    "vendor_raw",
    "product_raw",
    "version_raw",
    "component_count",
    "image_count",
    "sbom_count",
    "component_name_count",
    "repositories",
    "component_names",
)
VENDOR_PRODUCT_SUMMARY_FIELDS = (
    "part_raw",
    "vendor_raw",
    "product_raw",
    "component_count",
    "unique_cpe_count",
    "image_count",
)
STRUCTURALLY_INVALID_CPES_FIELDS = (
    "raw_cpe",
    "structural_status",
    "error_message",
    "component_count",
    "image_count",
    "repositories",
    "component_names",
)


@dataclass(frozen=True)
class CPEProfile:
    summary: dict[str, Any]
    image_summary: list[dict[str, Any]]
    component_cpes: list[dict[str, Any]]
    cpe_usage: list[dict[str, Any]]
    vendor_product_summary: list[dict[str, Any]]
    structurally_invalid_cpes: list[dict[str, Any]]


@dataclass
class _Aggregate:
    component_count: int = 0
    raw_cpes: set[str] = field(default_factory=set)
    image_ids: set[int] = field(default_factory=set)

    def add(self, raw_cpe: str, image_id: int) -> None:
        self.component_count += 1
        self.raw_cpes.add(raw_cpe)
        self.image_ids.add(image_id)


@dataclass
class _CPEUsage:
    parse_result: CPE23ParseResult
    component_count: int = 0
    image_ids: set[int] = field(default_factory=set)
    sbom_ids: set[int] = field(default_factory=set)
    repositories: set[str] = field(default_factory=set)
    component_names: set[str] = field(default_factory=set)

    def add(
        self,
        *,
        image_id: int,
        sbom_id: int,
        repository: str,
        component_name: str,
    ) -> None:
        self.component_count += 1
        self.image_ids.add(image_id)
        self.sbom_ids.add(sbom_id)
        self.repositories.add(repository)
        self.component_names.add(component_name)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _raw_fields(parse_result: CPE23ParseResult) -> dict[str, str]:
    if not parse_result.is_structurally_valid:
        return {
            f"{attribute_name}_raw": ""
            for attribute_name in CPE23_ATTRIBUTE_NAMES
        }
    return {
        f"{attribute_name}_raw": parse_result.raw_field(
            attribute_name
        )
        for attribute_name in CPE23_ATTRIBUTE_NAMES
    }


def _version_category(version_raw: str) -> str:
    if version_raw == "*":
        return "wildcard"
    if version_raw == "-":
        return "NA"
    return "explicit"


def _join_sorted(values: Iterable[str]) -> str:
    return "|".join(sorted(set(values)))


def build_cpe_profile() -> CPEProfile:
    """Build a deterministic profile without modifying database records."""

    images = list(
        DockerImage.objects.order_by("repository", "tag", "id").values(
            "id",
            "repository",
            "tag",
            "platform",
        )
    )
    count_rows = Component.objects.values(
        "sbom_document__docker_image_id"
    ).annotate(
        total_components=Count("id"),
        components_with_primary_cpe=Count(
            "id",
            filter=~Q(cpe=""),
        ),
    )
    component_counts = {
        row["sbom_document__docker_image_id"]: row
        for row in count_rows
    }

    image_profiles: dict[int, dict[str, Any]] = {}
    for image in images:
        image_id = image["id"]
        counts = component_counts.get(image_id, {})
        total_components = counts.get("total_components", 0)
        with_primary_cpe = counts.get(
            "components_with_primary_cpe",
            0,
        )
        image_profiles[image_id] = {
            "repository": image["repository"],
            "tag": image["tag"],
            "platform": image["platform"],
            "total_components": total_components,
            "components_with_primary_cpe": with_primary_cpe,
            "components_without_primary_cpe": (
                total_components - with_primary_cpe
            ),
            "structurally_valid_components": 0,
            "structurally_invalid_components": 0,
            "raw_cpes": set(),
        }

    status_aggregates = {
        status: _Aggregate() for status in CPE23StructuralStatus
    }
    part_aggregates = {
        part: _Aggregate() for part in ("a", "o", "h")
    }
    version_aggregates = {
        category: _Aggregate()
        for category in ("wildcard", "NA", "explicit")
    }
    vendor_aggregates: defaultdict[str, _Aggregate] = defaultdict(
        _Aggregate
    )
    vendor_product_aggregates: defaultdict[
        tuple[str, str, str], _Aggregate
    ] = defaultdict(_Aggregate)
    usages: dict[str, _CPEUsage] = {}
    component_rows: list[dict[str, Any]] = []

    components = (
        Component.objects.exclude(cpe="")
        .select_related(
            "sbom_document",
            "sbom_document__docker_image",
        )
        .order_by(
            "sbom_document__docker_image__repository",
            "sbom_document__docker_image__tag",
            "name",
            "version",
            "id",
        )
    )
    for component in components:
        sbom = component.sbom_document
        image = sbom.docker_image
        raw_cpe = component.cpe
        parse_result = parse_cpe23_formatted_string(raw_cpe)
        status_aggregates[parse_result.status].add(
            raw_cpe,
            image.id,
        )

        image_profile = image_profiles[image.id]
        image_profile["raw_cpes"].add(raw_cpe)
        if parse_result.is_structurally_valid:
            image_profile["structurally_valid_components"] += 1
        else:
            image_profile["structurally_invalid_components"] += 1

        usage = usages.get(raw_cpe)
        if usage is None:
            usage = _CPEUsage(parse_result=parse_result)
            usages[raw_cpe] = usage
        usage.add(
            image_id=image.id,
            sbom_id=sbom.id,
            repository=image.repository,
            component_name=component.name,
        )

        raw_fields = _raw_fields(parse_result)
        component_rows.append(
            {
                "component_id": component.id,
                "repository": image.repository,
                "tag": image.tag,
                "sbom_source_path": sbom.source_path,
                "bom_ref": component.bom_ref,
                "component_type": component.component_type,
                "component_name": component.name,
                "component_version": component.version,
                "publisher": component.publisher,
                "purl": component.purl,
                "raw_cpe": raw_cpe,
                "structural_status": parse_result.status.value,
                "error_message": parse_result.error_message,
                **raw_fields,
            }
        )

        if not parse_result.is_structurally_valid:
            continue

        part_aggregates[parse_result.part_raw].add(
            raw_cpe,
            image.id,
        )
        version_aggregates[
            _version_category(parse_result.version_raw)
        ].add(raw_cpe, image.id)
        vendor_aggregates[parse_result.vendor_raw].add(
            raw_cpe,
            image.id,
        )
        vendor_product_aggregates[
            (
                parse_result.part_raw,
                parse_result.vendor_raw,
                parse_result.product_raw,
            )
        ].add(raw_cpe, image.id)

    image_rows: list[dict[str, Any]] = []
    for image in images:
        profile = image_profiles[image["id"]]
        with_primary_cpe = profile["components_with_primary_cpe"]
        image_rows.append(
            {
                "repository": profile["repository"],
                "tag": profile["tag"],
                "platform": profile["platform"],
                "total_components": profile["total_components"],
                "components_with_primary_cpe": with_primary_cpe,
                "components_without_primary_cpe": profile[
                    "components_without_primary_cpe"
                ],
                "primary_cpe_ratio": _ratio(
                    with_primary_cpe,
                    profile["total_components"],
                ),
                "structurally_valid_components": profile[
                    "structurally_valid_components"
                ],
                "structurally_invalid_components": profile[
                    "structurally_invalid_components"
                ],
                "unique_primary_cpes": len(profile["raw_cpes"]),
            }
        )

    usage_rows: list[dict[str, Any]] = []
    invalid_rows: list[dict[str, Any]] = []
    for raw_cpe in sorted(usages):
        usage = usages[raw_cpe]
        parse_result = usage.parse_result
        raw_fields = _raw_fields(parse_result)
        usage_rows.append(
            {
                "raw_cpe": raw_cpe,
                "structural_status": parse_result.status.value,
                "part_raw": raw_fields["part_raw"],
                "vendor_raw": raw_fields["vendor_raw"],
                "product_raw": raw_fields["product_raw"],
                "version_raw": raw_fields["version_raw"],
                "component_count": usage.component_count,
                "image_count": len(usage.image_ids),
                "sbom_count": len(usage.sbom_ids),
                "component_name_count": len(
                    usage.component_names
                ),
                "repositories": _join_sorted(usage.repositories),
                "component_names": _join_sorted(
                    usage.component_names
                ),
            }
        )
        if not parse_result.is_structurally_valid:
            invalid_rows.append(
                {
                    "raw_cpe": raw_cpe,
                    "structural_status": parse_result.status.value,
                    "error_message": parse_result.error_message,
                    "component_count": usage.component_count,
                    "image_count": len(usage.image_ids),
                    "repositories": _join_sorted(
                        usage.repositories
                    ),
                    "component_names": _join_sorted(
                        usage.component_names
                    ),
                }
            )

    vendor_product_rows = [
        {
            "part_raw": part_raw,
            "vendor_raw": vendor_raw,
            "product_raw": product_raw,
            "component_count": aggregate.component_count,
            "unique_cpe_count": len(aggregate.raw_cpes),
            "image_count": len(aggregate.image_ids),
        }
        for (
            part_raw,
            vendor_raw,
            product_raw,
        ), aggregate in sorted(vendor_product_aggregates.items())
    ]

    total_components = sum(
        row["total_components"] for row in image_rows
    )
    components_with_primary_cpe = sum(
        row["components_with_primary_cpe"] for row in image_rows
    )
    structurally_valid_components = status_aggregates[
        CPE23StructuralStatus.STRUCTURALLY_VALID
    ].component_count
    structurally_invalid_components = (
        components_with_primary_cpe - structurally_valid_components
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "scope": SCOPE,
        "validation_level": VALIDATION_LEVEL,
        "total_images": len(images),
        "total_sboms": SBOMDocument.objects.count(),
        "total_components": total_components,
        "components_with_primary_cpe": components_with_primary_cpe,
        "components_without_primary_cpe": (
            total_components - components_with_primary_cpe
        ),
        "primary_cpe_ratio": _ratio(
            components_with_primary_cpe,
            total_components,
        ),
        "structurally_valid_components": (
            structurally_valid_components
        ),
        "structurally_invalid_components": (
            structurally_invalid_components
        ),
        "unique_primary_cpes": len(usages),
        "reused_primary_cpes": sum(
            usage.component_count > 1 for usage in usages.values()
        ),
        "status_counts": {
            status.value: {
                "component_count": status_aggregates[
                    status
                ].component_count,
                "unique_cpe_count": len(
                    status_aggregates[status].raw_cpes
                ),
            }
            for status in CPE23StructuralStatus
        },
        "part_counts": {
            part: {
                "component_count": part_aggregates[
                    part
                ].component_count,
                "unique_cpe_count": len(
                    part_aggregates[part].raw_cpes
                ),
            }
            for part in ("a", "o", "h")
        },
        "version_category_counts": {
            category: {
                "component_count": version_aggregates[
                    category
                ].component_count,
                "unique_cpe_count": len(
                    version_aggregates[category].raw_cpes
                ),
            }
            for category in ("wildcard", "NA", "explicit")
        },
        "vendor_counts": [
            {
                "vendor_raw": vendor_raw,
                "component_count": aggregate.component_count,
                "unique_cpe_count": len(aggregate.raw_cpes),
            }
            for vendor_raw, aggregate in sorted(
                vendor_aggregates.items()
            )
        ],
    }

    return CPEProfile(
        summary=summary,
        image_summary=image_rows,
        component_cpes=component_rows,
        cpe_usage=usage_rows,
        vendor_product_summary=vendor_product_rows,
        structurally_invalid_cpes=invalid_rows,
    )


def _render_csv(
    fieldnames: tuple[str, ...],
    rows: Iterable[dict[str, Any]],
) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=fieldnames,
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def render_cpe_profile(profile: CPEProfile) -> dict[str, str]:
    return {
        SUMMARY_FILENAME: (
            json.dumps(
                profile.summary,
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ),
        IMAGE_SUMMARY_FILENAME: _render_csv(
            IMAGE_SUMMARY_FIELDS,
            profile.image_summary,
        ),
        COMPONENT_CPES_FILENAME: _render_csv(
            COMPONENT_CPES_FIELDS,
            profile.component_cpes,
        ),
        CPE_USAGE_FILENAME: _render_csv(
            CPE_USAGE_FIELDS,
            profile.cpe_usage,
        ),
        VENDOR_PRODUCT_SUMMARY_FILENAME: _render_csv(
            VENDOR_PRODUCT_SUMMARY_FIELDS,
            profile.vendor_product_summary,
        ),
        STRUCTURALLY_INVALID_CPES_FILENAME: _render_csv(
            STRUCTURALLY_INVALID_CPES_FIELDS,
            profile.structurally_invalid_cpes,
        ),
    }


def write_cpe_profile(
    profile: CPEProfile,
    output_directory: Path,
) -> tuple[Path, ...]:
    """Atomically replace only the six known profile output files."""

    output_directory.mkdir(parents=True, exist_ok=True)
    rendered = render_cpe_profile(profile)
    temporary_paths: dict[str, Path] = {}
    try:
        for filename in OUTPUT_FILENAMES:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{filename}.",
                suffix=".tmp",
                dir=output_directory,
            )
            temporary_path = Path(temporary_name)
            temporary_paths[filename] = temporary_path
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="",
            ) as stream:
                stream.write(rendered[filename])
                stream.flush()
                os.fsync(stream.fileno())

        output_paths = tuple(
            output_directory / filename
            for filename in OUTPUT_FILENAMES
        )
        for filename, output_path in zip(
            OUTPUT_FILENAMES,
            output_paths,
            strict=True,
        ):
            os.replace(temporary_paths[filename], output_path)
        return output_paths
    finally:
        for temporary_path in temporary_paths.values():
            temporary_path.unlink(missing_ok=True)

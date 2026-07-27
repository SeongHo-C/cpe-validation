from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cpe_dictionary.models import CpeDictionarySnapshot
from sboms.exact_matching import (
    CPEExactMatchStatus,
    match_cpes,
)
from sboms.models import Component


SCHEMA_VERSION = 1
SUMMARY_FILENAME = "summary.json"
UNIQUE_CPE_MATCHES_FILENAME = "unique_cpe_matches.csv"
COMPONENT_MATCHES_FILENAME = "component_matches.csv"
OUTPUT_FILENAMES = (
    SUMMARY_FILENAME,
    UNIQUE_CPE_MATCHES_FILENAME,
    COMPONENT_MATCHES_FILENAME,
)

UNIQUE_CPE_MATCH_FIELDS = (
    "primary_cpe",
    "component_count",
    "status",
    "matched_cpe_name_id",
    "deprecated",
    "snapshot_id",
)
COMPONENT_MATCH_FIELDS = (
    "component_id",
    "image_id",
    "image_reference",
    "component_name",
    "component_version",
    "primary_cpe",
    "status",
    "matched_cpe_name_id",
    "deprecated",
    "snapshot_id",
)


class CPEExactMatchAnalysisError(Exception):
    pass


@dataclass(frozen=True)
class CPEExactMatchAnalysis:
    summary: dict[str, Any]
    unique_cpe_matches: tuple[dict[str, Any], ...]
    component_matches: tuple[dict[str, Any], ...]


def _status_counter() -> Counter[str]:
    return Counter(
        {
            status.value: 0
            for status in CPEExactMatchStatus
        }
    )


def build_cpe_exact_match_analysis(
    snapshot: CpeDictionarySnapshot,
) -> CPEExactMatchAnalysis:
    """Evaluate all Components without modifying database records."""

    components = list(
        Component.objects.select_related(
            "sbom_document__docker_image"
        )
        .order_by(
            "sbom_document__docker_image__repository",
            "sbom_document__docker_image__tag",
            "name",
            "version",
            "id",
        )
        .values(
            "id",
            "name",
            "version",
            "cpe",
            "sbom_document__docker_image_id",
            "sbom_document__docker_image__repository",
            "sbom_document__docker_image__tag",
        )
    )
    component_counts = Counter(
        component["cpe"]
        for component in components
        if component["cpe"]
    )
    raw_cpes: list[str | None] = [
        "",
        *sorted(component_counts),
    ]
    matches = match_cpes(raw_cpes, snapshot)

    unique_status_counts = _status_counter()
    unique_rows: list[dict[str, Any]] = []
    for raw_cpe in sorted(component_counts):
        result = matches[raw_cpe]
        unique_status_counts[result.status.value] += 1
        unique_rows.append(
            {
                "primary_cpe": raw_cpe,
                "component_count": component_counts[raw_cpe],
                "status": result.status.value,
                "matched_cpe_name_id": (
                    result.matched_cpe_name_id or ""
                ),
                "deprecated": (
                    result.deprecated
                    if result.deprecated is not None
                    else ""
                ),
                "snapshot_id": result.snapshot_id,
            }
        )

    component_status_counts = _status_counter()
    component_rows: list[dict[str, Any]] = []
    for component in components:
        raw_cpe = component["cpe"]
        result = matches[raw_cpe]
        component_status_counts[result.status.value] += 1
        repository = component[
            "sbom_document__docker_image__repository"
        ]
        tag = component["sbom_document__docker_image__tag"]
        component_rows.append(
            {
                "component_id": component["id"],
                "image_id": component[
                    "sbom_document__docker_image_id"
                ],
                "image_reference": f"{repository}:{tag}",
                "component_name": component["name"],
                "component_version": component["version"],
                "primary_cpe": raw_cpe,
                "status": result.status.value,
                "matched_cpe_name_id": (
                    result.matched_cpe_name_id or ""
                ),
                "deprecated": (
                    result.deprecated
                    if result.deprecated is not None
                    else ""
                ),
                "snapshot_id": result.snapshot_id,
            }
        )

    total_components = len(components)
    components_with_primary_cpe = sum(component_counts.values())
    summary = {
        "schema_version": SCHEMA_VERSION,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_manifest_sha256": snapshot.manifest_sha256,
        "total_components": total_components,
        "components_with_primary_cpe": components_with_primary_cpe,
        "components_without_primary_cpe": (
            total_components - components_with_primary_cpe
        ),
        "unique_primary_cpes": len(component_counts),
        "unique_status_counts": dict(unique_status_counts),
        "component_status_counts": dict(component_status_counts),
        "dictionary_record_count": snapshot.record_count,
        "dictionary_active_count": snapshot.active_count,
        "dictionary_deprecated_count": snapshot.deprecated_count,
    }
    analysis = CPEExactMatchAnalysis(
        summary=summary,
        unique_cpe_matches=tuple(unique_rows),
        component_matches=tuple(component_rows),
    )
    validate_cpe_exact_match_analysis(analysis)
    return analysis


def validate_cpe_exact_match_analysis(
    analysis: CPEExactMatchAnalysis,
) -> None:
    summary = analysis.summary
    failures: list[str] = []
    if (
        sum(summary["unique_status_counts"].values())
        != summary["unique_primary_cpes"]
    ):
        failures.append(
            "sum(unique_status_counts) != unique_primary_cpes"
        )
    if (
        sum(summary["component_status_counts"].values())
        != summary["total_components"]
    ):
        failures.append(
            "sum(component_status_counts) != total_components"
        )
    if (
        summary["components_with_primary_cpe"]
        + summary["components_without_primary_cpe"]
        != summary["total_components"]
    ):
        failures.append(
            "components_with_primary_cpe + "
            "components_without_primary_cpe != total_components"
        )
    if (
        len(analysis.unique_cpe_matches)
        != summary["unique_primary_cpes"]
    ):
        failures.append(
            "unique CPE row count != unique_primary_cpes"
        )
    if (
        len(analysis.component_matches)
        != summary["total_components"]
    ):
        failures.append(
            "Component row count != total_components"
        )
    if failures:
        raise CPEExactMatchAnalysisError("; ".join(failures))


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


def render_cpe_exact_match_analysis(
    analysis: CPEExactMatchAnalysis,
) -> dict[str, str]:
    validate_cpe_exact_match_analysis(analysis)
    return {
        SUMMARY_FILENAME: (
            json.dumps(
                analysis.summary,
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ),
        UNIQUE_CPE_MATCHES_FILENAME: _render_csv(
            UNIQUE_CPE_MATCH_FIELDS,
            analysis.unique_cpe_matches,
        ),
        COMPONENT_MATCHES_FILENAME: _render_csv(
            COMPONENT_MATCH_FIELDS,
            analysis.component_matches,
        ),
    }


def write_cpe_exact_match_analysis(
    analysis: CPEExactMatchAnalysis,
    output_directory: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, ...]:
    """Write known outputs atomically, refusing replacement by default."""

    output_paths = tuple(
        output_directory / filename
        for filename in OUTPUT_FILENAMES
    )
    existing_paths = [
        path for path in output_paths if path.exists()
    ]
    if existing_paths and not overwrite:
        raise CPEExactMatchAnalysisError(
            "Refusing to overwrite existing exact-match output(s): "
            + ", ".join(str(path) for path in existing_paths)
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    rendered = render_cpe_exact_match_analysis(analysis)
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

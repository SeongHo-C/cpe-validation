from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings


MANIFEST_RELATIVE_PATH = Path(
    "data/cpe_candidate_universe/manifest.json"
)


class CpeAnalysisManifestError(Exception):
    """Raised when analysis metadata cannot be loaded safely."""


@dataclass(frozen=True)
class CpeAnalysisSummary:
    positive_gt_components_at_validation: int
    searchable_candidate_families: int


def _positive_integer(data: dict[str, Any], field: str) -> int:
    value = data.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise CpeAnalysisManifestError(
            f"Manifest field {field!r} must be a positive integer."
        )
    return value


def load_cpe_analysis_summary() -> CpeAnalysisSummary:
    """Load the two UI summary values from the frozen universe manifest."""

    path = settings.REPOSITORY_ROOT / MANIFEST_RELATIVE_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CpeAnalysisManifestError(
            "CPE candidate universe manifest could not be read."
        ) from error

    if not isinstance(data, dict):
        raise CpeAnalysisManifestError(
            "CPE candidate universe manifest must contain an object."
        )

    return CpeAnalysisSummary(
        positive_gt_components_at_validation=_positive_integer(
            data,
            "positive_gt_components_at_validation",
        ),
        searchable_candidate_families=_positive_integer(
            data,
            "searchable_candidate_families",
        ),
    )

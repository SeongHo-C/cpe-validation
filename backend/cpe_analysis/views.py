from __future__ import annotations

import logging

from django.db.models import F
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from cpe_analysis.manifest import (
    CpeAnalysisManifestError,
    load_cpe_analysis_summary,
)
from cpe_analysis.models import (
    CPEAnalysisRun,
    CPEAnalysisRunStatus,
)


logger = logging.getLogger(__name__)


CPE_ANALYSIS_ALGORITHM_IDS = (
    "exact_match",
    "length_normalized_levenshtein",
    "jaro_winkler",
    "character_trigram_dice",
    "token_jaccard",
    "tfidf_cosine",
)


def _latest_completed_runs() -> dict[str, CPEAnalysisRun]:
    latest: dict[str, CPEAnalysisRun] = {}
    runs = (
        CPEAnalysisRun.objects.filter(
            algorithm_id__in=CPE_ANALYSIS_ALGORITHM_IDS,
            status=CPEAnalysisRunStatus.COMPLETED,
        )
        .order_by(
            "algorithm_id",
            F("completed_at").desc(nulls_last=True),
            F("id").desc(),
        )
    )
    for run in runs:
        latest.setdefault(run.algorithm_id, run)
    return latest


def _algorithm_result(
    algorithm_id: str,
    run: CPEAnalysisRun | None,
) -> dict[str, object]:
    if run is None:
        return {
            "algorithm_id": algorithm_id,
            "status": "NOT_RUN",
            "query_count": None,
            "candidate_family_count": None,
            "metrics": None,
        }
    return {
        "algorithm_id": algorithm_id,
        "status": CPEAnalysisRunStatus.COMPLETED,
        "query_count": run.query_count,
        "candidate_family_count": run.candidate_family_count,
        "metrics": {
            "top1_accuracy": run.top1_accuracy,
            "recall_at_5": run.recall_at_5,
            "recall_at_10": run.recall_at_10,
            "mrr": run.mrr,
        },
    }


class CpeAnalysisSummaryAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get(self, request) -> Response:
        try:
            summary = load_cpe_analysis_summary()
        except CpeAnalysisManifestError:
            logger.warning("CPE analysis manifest is unavailable")
            return Response(
                {
                    "code": "cpe_analysis_manifest_unavailable",
                    "detail": "CPE analysis metadata is unavailable.",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        latest_runs = _latest_completed_runs()

        return Response(
            {
                "positive_gt_components_at_validation": (
                    summary.positive_gt_components_at_validation
                ),
                "searchable_candidate_families": (
                    summary.searchable_candidate_families
                ),
                "method_count": len(CPE_ANALYSIS_ALGORITHM_IDS),
                "completed_method_count": len(latest_runs),
                "algorithms": [
                    _algorithm_result(
                        algorithm_id,
                        latest_runs.get(algorithm_id),
                    )
                    for algorithm_id in CPE_ANALYSIS_ALGORITHM_IDS
                ],
            }
        )

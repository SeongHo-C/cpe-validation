from __future__ import annotations

import logging

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from cpe_analysis.manifest import (
    CpeAnalysisManifestError,
    load_cpe_analysis_summary,
)


logger = logging.getLogger(__name__)


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

        return Response(
            {
                "positive_gt_components_at_validation": (
                    summary.positive_gt_components_at_validation
                ),
                "searchable_candidate_families": (
                    summary.searchable_candidate_families
                ),
            }
        )

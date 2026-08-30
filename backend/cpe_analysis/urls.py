from django.urls import path

from cpe_analysis.views import CpeAnalysisSummaryAPIView


app_name = "cpe_analysis_api"

urlpatterns = [
    path(
        "cpe-analysis/summary/",
        CpeAnalysisSummaryAPIView.as_view(),
        name="summary",
    ),
]

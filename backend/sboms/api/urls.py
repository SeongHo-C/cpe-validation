from django.urls import path

from sboms.api.views import (
    ComponentDetailAPIView,
    ComponentListAPIView,
    DashboardSummaryAPIView,
    DockerImageDetailAPIView,
    DockerImageListAPIView,
    HealthAPIView,
)


app_name = "sboms_api"

urlpatterns = [
    path("health/", HealthAPIView.as_view(), name="health"),
    path(
        "dashboard/summary/",
        DashboardSummaryAPIView.as_view(),
        name="dashboard-summary",
    ),
    path(
        "images/",
        DockerImageListAPIView.as_view(),
        name="image-list",
    ),
    path(
        "images/<int:pk>/",
        DockerImageDetailAPIView.as_view(),
        name="image-detail",
    ),
    path(
        "components/",
        ComponentListAPIView.as_view(),
        name="component-list",
    ),
    path(
        "components/<int:pk>/",
        ComponentDetailAPIView.as_view(),
        name="component-detail",
    ),
]

from django.urls import path

from sboms.api.views import (
    ComponentCpeGroundTruthAPIView,
    ComponentDetailAPIView,
    ComponentListAPIView,
    DashboardSummaryAPIView,
    DockerImageDetailAPIView,
    DockerImageListAPIView,
    GroundTruthComponentListAPIView,
    GroundTruthComponentNavigationAPIView,
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
    path(
        "components/<int:component_id>/cpe-ground-truth/",
        ComponentCpeGroundTruthAPIView.as_view(),
        name="component-cpe-ground-truth",
    ),
    path(
        "ground-truth/components/",
        GroundTruthComponentListAPIView.as_view(),
        name="ground-truth-component-list",
    ),
    path(
        (
            "ground-truth/components/<int:component_id>/"
            "navigation/"
        ),
        GroundTruthComponentNavigationAPIView.as_view(),
        name="ground-truth-component-navigation",
    ),
]

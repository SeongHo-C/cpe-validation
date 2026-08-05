from django.urls import path

from sboms.api.views import (
    ComponentCpeGroundTruthAPIView,
    ComponentDetailAPIView,
    ComponentListAPIView,
    DockerImageDetailAPIView,
    DockerImageListAPIView,
    GroundTruthComponentListAPIView,
    GroundTruthComponentNavigationAPIView,
    GroundTruthCorrectionTypeDetailAPIView,
    GroundTruthCorrectionTypeListCreateAPIView,
    HealthAPIView,
    SBOMDocumentDetailAPIView,
    SBOMDocumentListAPIView,
    SBOMDocumentUploadAPIView,
)


app_name = "sboms_api"

urlpatterns = [
    path("health/", HealthAPIView.as_view(), name="health"),
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
        "sboms/",
        SBOMDocumentListAPIView.as_view(),
        name="sbom-list",
    ),
    path(
        "sboms/upload/",
        SBOMDocumentUploadAPIView.as_view(),
        name="sbom-upload",
    ),
    path(
        "sboms/<int:pk>/",
        SBOMDocumentDetailAPIView.as_view(),
        name="sbom-detail",
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
        "ground-truth-correction-types/",
        GroundTruthCorrectionTypeListCreateAPIView.as_view(),
        name="ground-truth-correction-type-list",
    ),
    path(
        "ground-truth-correction-types/<int:pk>/",
        GroundTruthCorrectionTypeDetailAPIView.as_view(),
        name="ground-truth-correction-type-detail",
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

from __future__ import annotations

from collections import Counter

from django.db import DatabaseError, connection
from django.db.models import Count, Prefetch, Q, QuerySet
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from sboms.api.pagination import StandardPageNumberPagination
from sboms.api.serializers import (
    ComponentDetailSerializer,
    ComponentListSerializer,
    DockerImageDetailSerializer,
    DockerImageListSerializer,
)
from sboms.cpe23 import (
    CPE23StructuralStatus,
    parse_cpe23_formatted_string,
)
from sboms.models import Component, DockerImage, SBOMDocument


DEFAULT_COMPONENT_ORDERING = (
    "sbom_document__docker_image__repository",
    "sbom_document__docker_image__tag",
    "name",
    "version",
    "id",
)
COMPONENT_ORDERING_FIELDS = {
    "id": "id",
    "name": "name",
    "version": "version",
    "component_type": "component_type",
    "publisher": "publisher",
    "repository": "sbom_document__docker_image__repository",
    "tag": "sbom_document__docker_image__tag",
}


def _annotated_image_queryset() -> QuerySet[DockerImage]:
    """Return images with all list/detail statistics annotated."""

    component_path = "sbom_documents__components"
    return DockerImage.objects.annotate(
        sbom_count=Count("sbom_documents", distinct=True),
        total_components=Count(component_path),
        components_with_primary_cpe=Count(
            component_path,
            filter=~Q(sbom_documents__components__cpe=""),
        ),
        unique_primary_cpes=Count(
            "sbom_documents__components__cpe",
            filter=~Q(sbom_documents__components__cpe=""),
            distinct=True,
        ),
    ).order_by("repository", "tag", "id")


class HealthAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get(self, request) -> Response:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        except DatabaseError:
            return Response(
                {
                    "status": "error",
                    "database": "unavailable",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response({"status": "ok", "database": "ok"})


class DashboardSummaryAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get(self, request) -> Response:
        total_components = Component.objects.count()
        cpe_values = Component.objects.exclude(cpe="").values_list(
            "cpe",
            flat=True,
        )
        status_counts = Counter(
            {
                structural_status.value: 0
                for structural_status in CPE23StructuralStatus
            }
        )
        part_counts = Counter({"a": 0, "o": 0, "h": 0})
        unique_primary_cpes: set[str] = set()
        components_with_primary_cpe = 0
        for raw_cpe in cpe_values:
            components_with_primary_cpe += 1
            unique_primary_cpes.add(raw_cpe)
            parse_result = parse_cpe23_formatted_string(raw_cpe)
            status_counts[parse_result.status.value] += 1
            if parse_result.is_structurally_valid:
                part_counts[parse_result.part_raw] += 1

        return Response(
            {
                "total_images": DockerImage.objects.count(),
                "total_sboms": SBOMDocument.objects.count(),
                "total_components": total_components,
                "components_with_primary_cpe": (
                    components_with_primary_cpe
                ),
                "components_without_primary_cpe": (
                    total_components - components_with_primary_cpe
                ),
                "primary_cpe_ratio": (
                    components_with_primary_cpe / total_components
                    if total_components
                    else 0.0
                ),
                "unique_primary_cpes": len(unique_primary_cpes),
                "structural_status_counts": dict(status_counts),
                "part_counts": dict(part_counts),
            }
        )


class DockerImageListAPIView(generics.ListAPIView):
    serializer_class = DockerImageListSerializer
    pagination_class = None
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get_queryset(self) -> QuerySet[DockerImage]:
        return _annotated_image_queryset()


class DockerImageDetailAPIView(generics.RetrieveAPIView):
    serializer_class = DockerImageDetailSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get_queryset(self) -> QuerySet[DockerImage]:
        return _annotated_image_queryset().prefetch_related(
            Prefetch(
                "sbom_documents",
                queryset=SBOMDocument.objects.order_by("id"),
            )
        )


class ComponentListAPIView(generics.ListAPIView):
    serializer_class = ComponentListSerializer
    pagination_class = StandardPageNumberPagination
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get_queryset(self) -> QuerySet[Component]:
        queryset = Component.objects.select_related(
            "sbom_document",
            "sbom_document__docker_image",
        )
        parameters = self.request.query_params

        has_cpe = parameters.get("has_cpe", "true").lower()
        if has_cpe == "true":
            queryset = queryset.exclude(cpe="")
        elif has_cpe == "false":
            queryset = queryset.filter(cpe="")
        elif has_cpe != "all":
            raise ValidationError(
                {
                    "detail": (
                        "has_cpe must be one of: true, false, all"
                    )
                }
            )

        raw_image_id = parameters.get("image_id")
        if raw_image_id is not None:
            try:
                image_id = int(raw_image_id)
            except (TypeError, ValueError) as error:
                raise ValidationError(
                    {"detail": "image_id must be a positive integer"}
                ) from error
            if image_id < 1:
                raise ValidationError(
                    {"detail": "image_id must be a positive integer"}
                )
            queryset = queryset.filter(
                sbom_document__docker_image_id=image_id
            )

        search = parameters.get("search", "").strip()
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search)
                | Q(version__icontains=search)
                | Q(publisher__icontains=search)
                | Q(purl__icontains=search)
                | Q(cpe__icontains=search)
                | Q(bom_ref__icontains=search)
            )

        raw_ordering = parameters.get("ordering")
        if raw_ordering is None:
            return queryset.order_by(*DEFAULT_COMPONENT_ORDERING)

        ordering: list[str] = []
        invalid_fields: list[str] = []
        for requested_field in raw_ordering.split(","):
            requested_field = requested_field.strip()
            descending = requested_field.startswith("-")
            field_name = (
                requested_field[1:]
                if descending
                else requested_field
            )
            mapped_field = COMPONENT_ORDERING_FIELDS.get(field_name)
            if mapped_field is None:
                invalid_fields.append(requested_field)
                continue
            ordering.append(
                f"-{mapped_field}" if descending else mapped_field
            )
        if invalid_fields:
            raise ValidationError(
                {
                    "detail": (
                        "ordering contains unsupported field(s): "
                        + ", ".join(invalid_fields)
                    )
                }
            )
        return queryset.order_by(*ordering)


class ComponentDetailAPIView(generics.RetrieveAPIView):
    serializer_class = ComponentDetailSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]
    queryset = Component.objects.select_related(
        "sbom_document",
        "sbom_document__docker_image",
    )

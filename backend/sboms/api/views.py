from __future__ import annotations

from collections import Counter

from django.db import DatabaseError, connection, transaction
from django.db.models import (
    Count,
    Exists,
    OuterRef,
    Prefetch,
    Q,
    QuerySet,
)
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from cpe.cpe23 import (
    CPE23StructuralStatus,
    parse_cpe23_formatted_string,
)
from cpe_dictionary.api.snapshot import (
    CpeDictionarySnapshotViewMixin,
)
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from sboms.api.pagination import StandardPageNumberPagination
from sboms.api.serializers import (
    ComponentCpeGroundTruthSerializer,
    ComponentCpeGroundTruthWriteSerializer,
    ComponentDetailSerializer,
    ComponentListSerializer,
    DockerImageDetailSerializer,
    DockerImageListSerializer,
)
from sboms.exact_matching import (
    CPEExactMatchStatus,
    match_cpes,
)
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    DockerImage,
    SBOMDocument,
)


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


class ComponentListAPIView(
    CpeDictionarySnapshotViewMixin,
    generics.ListAPIView,
):
    serializer_class = ComponentListSerializer
    pagination_class = StandardPageNumberPagination
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    @staticmethod
    def _parse_dictionary_status(
        raw_status: str | None,
    ) -> CPEExactMatchStatus | None:
        if raw_status is None:
            return None
        try:
            return CPEExactMatchStatus(raw_status)
        except ValueError as error:
            raise ValidationError(
                {
                    "code": "invalid_dictionary_status",
                    "detail": (
                        "dictionary_status must be one of: "
                        + ", ".join(
                            status_value.value
                            for status_value in CPEExactMatchStatus
                        )
                    ),
                }
            ) from error

    @staticmethod
    def _filter_dictionary_status(
        queryset: QuerySet[Component],
        dictionary_status: CPEExactMatchStatus,
        snapshot: CpeDictionarySnapshot,
    ) -> QuerySet[Component]:
        if dictionary_status == CPEExactMatchStatus.NOT_PRESENT:
            return queryset.filter(
                Q(cpe="") | Q(cpe__isnull=True)
            )

        matching_names = CpeName.objects.filter(
            snapshot=snapshot,
            cpe_name=OuterRef("cpe"),
        )
        if (
            dictionary_status
            == CPEExactMatchStatus.OFFICIAL_ACTIVE
        ):
            return queryset.exclude(cpe="").filter(
                Exists(matching_names.filter(deprecated=False))
            )
        if (
            dictionary_status
            == CPEExactMatchStatus.OFFICIAL_DEPRECATED
        ):
            return queryset.exclude(cpe="").filter(
                Exists(matching_names.filter(deprecated=True))
            )
        return queryset.exclude(cpe="").filter(
            ~Exists(matching_names)
        )

    def get_queryset(self) -> QuerySet[Component]:
        queryset = Component.objects.select_related(
            "sbom_document",
            "sbom_document__docker_image",
        )
        parameters = self.request.query_params
        dictionary_status = self._parse_dictionary_status(
            parameters.get("dictionary_status")
        )

        raw_has_cpe = parameters.get("has_cpe")
        if raw_has_cpe is None:
            has_cpe = (
                "false"
                if dictionary_status
                == CPEExactMatchStatus.NOT_PRESENT
                else "true"
            )
        else:
            has_cpe = raw_has_cpe.lower()
        if (
            dictionary_status == CPEExactMatchStatus.NOT_PRESENT
            and has_cpe == "true"
        ) or (
            dictionary_status is not None
            and dictionary_status
            != CPEExactMatchStatus.NOT_PRESENT
            and has_cpe == "false"
        ):
            raise ValidationError(
                {
                    "code": "incompatible_component_filters",
                    "detail": (
                        "has_cpe is incompatible with the requested "
                        "dictionary_status"
                    ),
                }
            )
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

        snapshot = self.get_cpe_dictionary_snapshot()
        if dictionary_status is not None:
            queryset = self._filter_dictionary_status(
                queryset,
                dictionary_status,
                snapshot,
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

    def list(self, request, *args, **kwargs) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is None:
            components = list(queryset)
        else:
            components = page
        snapshot = self.get_cpe_dictionary_snapshot()
        serializer_context = self.get_serializer_context()
        serializer_context["cpe_dictionary_matches"] = match_cpes(
            (component.cpe for component in components),
            snapshot,
        )
        serializer = self.get_serializer(
            components,
            many=True,
            context=serializer_context,
        )
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class ComponentDetailAPIView(
    CpeDictionarySnapshotViewMixin,
    generics.RetrieveAPIView,
):
    serializer_class = ComponentDetailSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]
    queryset = Component.objects.select_related(
        "sbom_document",
        "sbom_document__docker_image",
    )

    def get_serializer_context(self) -> dict:
        context = super().get_serializer_context()
        context[
            "cpe_dictionary_snapshot"
        ] = self.get_cpe_dictionary_snapshot()
        return context


class ComponentCpeGroundTruthAPIView(
    CpeDictionarySnapshotViewMixin,
    APIView,
):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "put", "head", "options"]

    @staticmethod
    def _response_body(
        component: Component,
        snapshot: CpeDictionarySnapshot,
        ground_truth: ComponentCpeGroundTruth | None,
    ) -> dict:
        return {
            "component_id": component.id,
            "snapshot_id": snapshot.snapshot_id,
            "ground_truth": (
                ComponentCpeGroundTruthSerializer(
                    ground_truth
                ).data
                if ground_truth is not None
                else None
            ),
        }

    @staticmethod
    def _component(component_id: int) -> Component:
        return get_object_or_404(
            Component.objects.only("id"),
            pk=component_id,
        )

    def get(self, request, component_id: int) -> Response:
        component = self._component(component_id)
        snapshot = self.get_cpe_dictionary_snapshot()
        ground_truth = (
            ComponentCpeGroundTruth.objects.select_related(
                "ground_truth_cpe"
            )
            .filter(
                component=component,
                snapshot=snapshot,
            )
            .first()
        )
        return Response(
            self._response_body(
                component,
                snapshot,
                ground_truth,
            )
        )

    def put(self, request, component_id: int) -> Response:
        component = self._component(component_id)
        snapshot = self.get_cpe_dictionary_snapshot()
        serializer = ComponentCpeGroundTruthWriteSerializer(
            data=request.data,
            context={"snapshot": snapshot},
        )
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            ground_truth, _ = (
                ComponentCpeGroundTruth.objects.update_or_create(
                    component=component,
                    snapshot=snapshot,
                    defaults=serializer.validated_data,
                )
            )
        ground_truth = (
            ComponentCpeGroundTruth.objects.select_related(
                "ground_truth_cpe"
            ).get(pk=ground_truth.pk)
        )
        return Response(
            self._response_body(
                component,
                snapshot,
                ground_truth,
            )
        )

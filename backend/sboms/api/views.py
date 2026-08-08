from __future__ import annotations

import logging

from django.core.exceptions import (
    ValidationError as DjangoValidationError,
)
from django.db import (
    DatabaseError,
    IntegrityError,
    connection,
    transaction,
)
from django.db.models import (
    Count,
    Exists,
    OuterRef,
    Prefetch,
    Q,
    QuerySet,
)
from django.db.models.functions import Lower
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

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
    GroundTruthComponentListSerializer,
    GroundTruthCorrectionTypeCreateSerializer,
    GroundTruthCorrectionTypeSerializer,
    GroundTruthCorrectionTypeUpdateSerializer,
    SBOMDocumentDetailSerializer,
    SBOMDocumentListSerializer,
    SBOMDocumentUploadSerializer,
)
from sboms.deletions import (
    SBOMDeleteConflictError,
    delete_sbom_document,
)
from sboms.exact_matching import (
    CPEExactMatchStatus,
    match_cpes,
)
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    DockerImage,
    GroundTruthCorrectionType,
    GroundTruthResolutionOutcome,
    SBOMDocument,
)
from sboms.importers import ImporterError
from sboms.uploads import (
    DuplicateSBOMError,
    import_uploaded_cyclonedx_sbom,
)


logger = logging.getLogger(__name__)


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


def _annotated_sbom_queryset() -> QuerySet[SBOMDocument]:
    """Return SBOM documents with their component totals."""

    return SBOMDocument.objects.annotate(
        component_count=Count("components")
    ).order_by("-imported_at", "-id")


def _parse_positive_id_filter(parameters, field_name: str) -> int | None:
    raw_value = parameters.get(field_name)
    if raw_value is None:
        return None
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as error:
        raise ValidationError(
            {"detail": f"{field_name} must be a positive integer"}
        ) from error
    if value < 1:
        raise ValidationError(
            {"detail": f"{field_name} must be a positive integer"}
        )
    return value


def _filter_component_scope(
    queryset: QuerySet[Component],
    parameters,
) -> QuerySet[Component]:
    if (
        parameters.get("image_id") is not None
        and parameters.get("sbom_id") is not None
    ):
        raise ValidationError(
            {
                "detail": (
                    "image_id and sbom_id cannot be used together"
                )
            }
        )

    image_id = _parse_positive_id_filter(parameters, "image_id")
    if image_id is not None:
        return queryset.filter(
            sbom_document__docker_image_id=image_id
        )

    sbom_id = _parse_positive_id_filter(parameters, "sbom_id")
    if sbom_id is not None:
        return queryset.filter(sbom_document_id=sbom_id)
    return queryset


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


class SBOMDocumentListAPIView(generics.ListAPIView):
    serializer_class = SBOMDocumentListSerializer
    pagination_class = StandardPageNumberPagination
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get_queryset(self) -> QuerySet[SBOMDocument]:
        return _annotated_sbom_queryset()


class SBOMDocumentDetailAPIView(generics.RetrieveAPIView):
    serializer_class = SBOMDocumentDetailSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "delete", "head", "options"]

    def get_queryset(self) -> QuerySet[SBOMDocument]:
        return _annotated_sbom_queryset()

    def delete(self, request, *args, **kwargs) -> Response:
        document = self.get_object()
        try:
            delete_sbom_document(document)
        except SBOMDeleteConflictError as error:
            return Response(
                {
                    "code": "sbom_delete_conflict",
                    "detail": str(error),
                },
                status=status.HTTP_409_CONFLICT,
            )
        return Response(status=status.HTTP_204_NO_CONTENT)


class SBOMDocumentUploadAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    parser_classes = [MultiPartParser, FormParser]
    http_method_names = ["post", "options"]

    def post(self, request) -> Response:
        input_serializer = SBOMDocumentUploadSerializer(
            data=request.data
        )
        input_serializer.is_valid(raise_exception=True)
        values = input_serializer.validated_data

        try:
            result = import_uploaded_cyclonedx_sbom(
                uploaded_file=values["file"],
                manufacturer=values["manufacturer"],
                product_name=values["product_name"],
                product_version=values["product_version"],
            )
        except DuplicateSBOMError as error:
            return Response(
                {
                    "code": "duplicate_sbom",
                    "detail": (
                        "An SBOM with the same SHA-256 is already "
                        "registered."
                    ),
                    "existing_sbom_id": error.existing_sbom_id,
                },
                status=status.HTTP_409_CONFLICT,
            )
        except ImporterError as error:
            return Response(
                {
                    "code": "invalid_sbom",
                    "detail": str(error),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            logger.exception("Unexpected uploaded SBOM import failure")
            return Response(
                {
                    "code": "sbom_import_failed",
                    "detail": "The SBOM could not be imported.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        result.document.component_count = result.component_count
        return Response(
            SBOMDocumentDetailSerializer(result.document).data,
            status=status.HTTP_201_CREATED,
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

        queryset = _filter_component_scope(queryset, parameters)

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


def _ground_truth_component_queryset(
    parameters,
    snapshot: CpeDictionarySnapshot,
) -> tuple[QuerySet[Component], str]:
    queryset = (
        Component.objects.select_related(
            "sbom_document",
            "sbom_document__docker_image",
        )
        .exclude(cpe="")
        .exclude(cpe__isnull=True)
    )
    ground_truth_records = ComponentCpeGroundTruth.objects.filter(
        component_id=OuterRef("pk"),
        snapshot=snapshot,
    )
    raw_ground_truth_status = parameters.get(
        "ground_truth_status"
    )
    if raw_ground_truth_status in (None, "", "ALL"):
        pass
    elif raw_ground_truth_status == "UNREVIEWED":
        queryset = queryset.filter(~Exists(ground_truth_records))
    elif raw_ground_truth_status == "COMPLETED":
        queryset = queryset.filter(Exists(ground_truth_records))
    else:
        raise ValidationError(
            {
                "code": "invalid_ground_truth_status",
                "detail": (
                    "ground_truth_status must be one of: "
                    "UNREVIEWED, COMPLETED"
                ),
            }
        )

    raw_resolution_outcome = parameters.get(
        "resolution_outcome"
    )
    if raw_resolution_outcome:
        try:
            resolution_outcome = GroundTruthResolutionOutcome(
                raw_resolution_outcome
            )
        except ValueError as error:
            raise ValidationError(
                {
                    "code": "invalid_resolution_outcome",
                    "detail": (
                        "resolution_outcome must be one of: "
                        + ", ".join(
                            outcome.value
                            for outcome in (
                                GroundTruthResolutionOutcome
                            )
                        )
                    ),
                }
            ) from error
        queryset = queryset.filter(
            Exists(
                ground_truth_records.filter(
                    resolution_outcome=resolution_outcome,
                )
            )
        )

    correction_type_code = parameters.get(
        "correction_type",
        "",
    ).strip()
    if correction_type_code:
        queryset = queryset.filter(
            Exists(
                ground_truth_records.filter(
                    correction_types__code=correction_type_code,
                )
            )
        )

    dictionary_status = (
        ComponentListAPIView._parse_dictionary_status(
            parameters.get("dictionary_status")
        )
    )
    if dictionary_status is not None:
        if dictionary_status == CPEExactMatchStatus.NOT_PRESENT:
            return queryset.none(), "id"
        queryset = ComponentListAPIView._filter_dictionary_status(
            queryset,
            dictionary_status,
            snapshot,
        )

    queryset = _filter_component_scope(queryset, parameters)

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

    ordering = parameters.get("ordering", "id")
    if ordering not in {"id", "-id"}:
        raise ValidationError(
            {"detail": "ordering must be one of: id, -id"}
        )
    return queryset.order_by(ordering), ordering


class GroundTruthCorrectionTypeListCreateAPIView(
    generics.ListCreateAPIView
):
    pagination_class = None
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "post", "head", "options"]

    def get_queryset(self) -> QuerySet[GroundTruthCorrectionType]:
        queryset = GroundTruthCorrectionType.objects.annotate(
            usage_count=Count(
                "ground_truth_records",
                distinct=True,
            )
        )
        raw_is_active = self.request.query_params.get("is_active")
        if raw_is_active is None:
            queryset = queryset.filter(is_active=True)
        else:
            is_active = raw_is_active.lower()
            if is_active == "true":
                queryset = queryset.filter(is_active=True)
            elif is_active == "false":
                queryset = queryset.filter(is_active=False)
            elif is_active != "all":
                raise ValidationError(
                    {
                        "detail": (
                            "is_active must be one of: "
                            "true, false, all"
                        )
                    }
                )
        search = self.request.query_params.get("search", "").strip()
        if search:
            queryset = queryset.filter(
                Q(code__icontains=search)
                | Q(name__icontains=search)
                | Q(description__icontains=search)
            )
        return queryset.order_by(Lower("name"), "id")

    def get_serializer_class(self):
        if self.request.method == "POST":
            return GroundTruthCorrectionTypeCreateSerializer
        return GroundTruthCorrectionTypeSerializer

    def create(self, request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            with transaction.atomic():
                correction_type = serializer.save()
        except (DjangoValidationError, IntegrityError) as error:
            raise ValidationError(
                {
                    "name": (
                        "A Correction Type with this name or code "
                        "already exists."
                    )
                }
            ) from error
        correction_type.usage_count = 0
        return Response(
            GroundTruthCorrectionTypeSerializer(
                correction_type
            ).data,
            status=status.HTTP_201_CREATED,
        )


class GroundTruthCorrectionTypeDetailAPIView(
    generics.RetrieveUpdateAPIView
):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "patch", "head", "options"]

    def get_queryset(self) -> QuerySet[GroundTruthCorrectionType]:
        return GroundTruthCorrectionType.objects.annotate(
            usage_count=Count(
                "ground_truth_records",
                distinct=True,
            )
        )

    def get_serializer_class(self):
        if self.request.method == "PATCH":
            return GroundTruthCorrectionTypeUpdateSerializer
        return GroundTruthCorrectionTypeSerializer

    def patch(self, request, *args, **kwargs) -> Response:
        correction_type = self.get_object()
        serializer = self.get_serializer(
            correction_type,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        correction_type.refresh_from_db()
        correction_type.usage_count = (
            correction_type.ground_truth_records.count()
        )
        return Response(
            GroundTruthCorrectionTypeSerializer(
                correction_type
            ).data
        )


class GroundTruthComponentListAPIView(
    CpeDictionarySnapshotViewMixin,
    generics.ListAPIView,
):
    serializer_class = GroundTruthComponentListSerializer
    pagination_class = StandardPageNumberPagination
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get_queryset(self) -> QuerySet[Component]:
        queryset, _ = _ground_truth_component_queryset(
            self.request.query_params,
            self.get_cpe_dictionary_snapshot(),
        )
        return queryset

    def list(self, request, *args, **kwargs) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        components = list(page if page is not None else queryset)
        snapshot = self.get_cpe_dictionary_snapshot()
        component_ids = [
            component.id for component in components
        ]
        ground_truth_records = {
            record.component_id: record
            for record in (
                ComponentCpeGroundTruth.objects.select_related(
                    "ground_truth_cpe",
                )
                .prefetch_related("correction_types")
                .filter(
                    snapshot=snapshot,
                    component_id__in=component_ids,
                )
            )
        }
        serializer_context = self.get_serializer_context()
        serializer_context.update(
            {
                "cpe_dictionary_matches": match_cpes(
                    (
                        component.cpe
                        for component in components
                    ),
                    snapshot,
                ),
                "ground_truth_records": ground_truth_records,
            }
        )
        serializer = self.get_serializer(
            components,
            many=True,
            context=serializer_context,
        )
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class GroundTruthComponentNavigationAPIView(
    CpeDictionarySnapshotViewMixin,
    APIView,
):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get(self, request, component_id: int) -> Response:
        get_object_or_404(
            Component.objects.exclude(cpe=""),
            pk=component_id,
        )
        queryset, ordering = _ground_truth_component_queryset(
            request.query_params,
            self.get_cpe_dictionary_snapshot(),
        )
        if ordering == "id":
            previous_id = (
                queryset.filter(id__lt=component_id)
                .order_by("-id")
                .values_list("id", flat=True)
                .first()
            )
            next_id = (
                queryset.filter(id__gt=component_id)
                .order_by("id")
                .values_list("id", flat=True)
                .first()
            )
        else:
            previous_id = (
                queryset.filter(id__gt=component_id)
                .order_by("id")
                .values_list("id", flat=True)
                .first()
            )
            next_id = (
                queryset.filter(id__lt=component_id)
                .order_by("-id")
                .values_list("id", flat=True)
                .first()
            )
        return Response(
            {
                "component_id": component_id,
                "previous_component_id": previous_id,
                "next_component_id": next_id,
            }
        )


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
            Component.objects.only("id", "cpe"),
            pk=component_id,
        )

    def get(self, request, component_id: int) -> Response:
        component = self._component(component_id)
        snapshot = self.get_cpe_dictionary_snapshot()
        ground_truth = (
            ComponentCpeGroundTruth.objects.select_related(
                "ground_truth_cpe",
            )
            .prefetch_related("correction_types")
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
        current_ground_truth = (
            ComponentCpeGroundTruth.objects.prefetch_related(
                "correction_types"
            )
            .filter(
                component=component,
                snapshot=snapshot,
            )
            .first()
        )
        serializer = ComponentCpeGroundTruthWriteSerializer(
            data=request.data,
            context={
                "snapshot": snapshot,
                "component": component,
                "current_ground_truth": current_ground_truth,
            },
        )
        serializer.is_valid(raise_exception=True)
        validated_data = dict(serializer.validated_data)
        correction_types = validated_data.pop(
            "correction_types",
        )
        with transaction.atomic():
            ground_truth, _ = (
                ComponentCpeGroundTruth.objects.update_or_create(
                    component=component,
                    snapshot=snapshot,
                    defaults=validated_data,
                )
            )
            ground_truth.correction_types.set(correction_types)
        ground_truth = (
            ComponentCpeGroundTruth.objects.select_related(
                "ground_truth_cpe",
            )
            .prefetch_related("correction_types")
            .get(pk=ground_truth.pk)
        )
        return Response(
            self._response_body(
                component,
                snapshot,
                ground_truth,
            )
        )

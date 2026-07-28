from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from django.db.models import Q, QuerySet, TextField
from django.db.models.functions import Cast
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from cpe_dictionary.api.serializers import (
    CpeNameDetailSerializer,
    CpeNameListSerializer,
)
from cpe_dictionary.api.snapshot import (
    CpeDictionarySnapshotViewMixin,
)
from cpe_dictionary.models import CpeName


ALLOWED_PAGE_SIZES = {25, 50, 100}
CPE_PARTS = {"a", "o", "h"}
DEPRECATED_FILTERS = {"all", "active", "deprecated"}
LIST_FIELDS = (
    "id",
    "snapshot_id",
    "cpe_name_id",
    "cpe_name",
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
    "deprecated",
    "titles",
)


def _validation_error(code: str, detail: str) -> ValidationError:
    return ValidationError({"code": code, "detail": detail})


def _positive_integer(
    raw_value: str | None,
    *,
    default: int,
    name: str,
) -> int:
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as error:
        raise _validation_error(
            f"invalid_{name}",
            f"{name} must be a positive integer.",
        ) from error
    if value < 1:
        raise _validation_error(
            f"invalid_{name}",
            f"{name} must be a positive integer.",
        )
    return value


@dataclass(frozen=True)
class CpeSearchParameters:
    q: str
    part: str
    vendor: str
    product: str
    version: str
    cpe_name: str
    deprecated: str
    page: int
    page_size: int

    @classmethod
    def from_query_params(cls, query_params) -> CpeSearchParameters:
        parameters = cls(
            q=query_params.get("q", "").strip(),
            part=query_params.get("part", "").strip(),
            vendor=query_params.get("vendor", "").strip(),
            product=query_params.get("product", "").strip(),
            version=query_params.get("version", "").strip(),
            cpe_name=query_params.get("cpe_name", "").strip(),
            deprecated=query_params.get(
                "deprecated",
                "active",
            ).strip(),
            page=_positive_integer(
                query_params.get("page"),
                default=1,
                name="page",
            ),
            page_size=_positive_integer(
                query_params.get("page_size"),
                default=25,
                name="page_size",
            ),
        )
        parameters.validate()
        return parameters

    def validate(self) -> None:
        if self.q and len(self.q) < 2:
            raise _validation_error(
                "invalid_search_query",
                "q must contain at least two characters.",
            )
        if self.part and self.part not in CPE_PARTS:
            raise _validation_error(
                "invalid_cpe_part",
                "part must be one of: a, o, h.",
            )
        if self.deprecated not in DEPRECATED_FILTERS:
            raise _validation_error(
                "invalid_deprecated_filter",
                "deprecated must be one of: all, active, deprecated.",
            )
        if self.page_size not in ALLOWED_PAGE_SIZES:
            raise _validation_error(
                "invalid_page_size",
                "page_size must be one of: 25, 50, 100.",
            )
        if not any(
            (
                self.q,
                self.vendor,
                self.product,
                self.version,
                self.cpe_name,
            )
        ):
            raise _validation_error(
                "cpe_search_term_required",
                (
                    "Provide q, vendor, product, version, or cpe_name "
                    "to search the Dictionary."
                ),
            )

    def response_query(self) -> dict[str, str]:
        return {
            "q": self.q,
            "part": self.part,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "cpe_name": self.cpe_name,
            "deprecated": self.deprecated,
        }


class CpeNameSearchAPIView(
    CpeDictionarySnapshotViewMixin,
    APIView,
):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    @staticmethod
    def _search_queryset(
        snapshot,
        parameters: CpeSearchParameters,
    ) -> QuerySet[CpeName]:
        queryset = CpeName.objects.filter(snapshot=snapshot)
        if parameters.deprecated == "active":
            queryset = queryset.filter(deprecated=False)
        elif parameters.deprecated == "deprecated":
            queryset = queryset.filter(deprecated=True)
        if parameters.part:
            queryset = queryset.filter(part=parameters.part)
        if parameters.vendor:
            queryset = queryset.filter(
                vendor__iexact=parameters.vendor
            )
        if parameters.product:
            queryset = queryset.filter(
                product__iexact=parameters.product
            )
        if parameters.version:
            queryset = queryset.filter(
                version__iexact=parameters.version
            )
        if parameters.cpe_name:
            queryset = queryset.filter(
                cpe_name=parameters.cpe_name
            )
        if parameters.q:
            queryset = queryset.annotate(
                _titles_text=Cast("titles", output_field=TextField())
            ).filter(
                Q(cpe_name__icontains=parameters.q)
                | Q(vendor__icontains=parameters.q)
                | Q(product__icontains=parameters.q)
                | Q(version__icontains=parameters.q)
                | Q(_titles_text__icontains=parameters.q)
            )
        return queryset.order_by(
            "deprecated",
            "vendor",
            "product",
            "version",
            "cpe_name",
        )

    def get(self, request) -> Response:
        parameters = CpeSearchParameters.from_query_params(
            request.query_params
        )
        snapshot = self.get_cpe_dictionary_snapshot()
        queryset = self._search_queryset(snapshot, parameters)
        count = queryset.count()
        offset = (parameters.page - 1) * parameters.page_size
        records = queryset.only(*LIST_FIELDS)[
            offset : offset + parameters.page_size
        ]
        serializer = CpeNameListSerializer(
            records,
            many=True,
            context={"snapshot_id": snapshot.snapshot_id},
        )
        return Response(
            {
                "snapshot": {
                    "snapshot_id": snapshot.snapshot_id,
                    "manifest_sha256": snapshot.manifest_sha256,
                    "status": snapshot.status,
                },
                "query": parameters.response_query(),
                "count": count,
                "page": parameters.page,
                "page_size": parameters.page_size,
                "results": serializer.data,
            }
        )


class CpeDictionarySnapshotAPIView(
    CpeDictionarySnapshotViewMixin,
    APIView,
):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get(self, request) -> Response:
        snapshot = self.get_cpe_dictionary_snapshot()
        return Response(
            {
                "snapshot_id": snapshot.snapshot_id,
                "manifest_sha256": snapshot.manifest_sha256,
                "status": snapshot.status,
            }
        )


class CpeNameDetailAPIView(
    CpeDictionarySnapshotViewMixin,
    APIView,
):
    permission_classes = [AllowAny]
    authentication_classes = []
    http_method_names = ["get", "head", "options"]

    def get(self, request, cpe_name_id: UUID) -> Response:
        snapshot = self.get_cpe_dictionary_snapshot()
        record = (
            CpeName.objects.select_related("snapshot")
            .filter(
                snapshot=snapshot,
                cpe_name_id=cpe_name_id,
            )
            .first()
        )
        if record is None:
            return Response(
                {
                    "code": "cpe_name_not_found",
                    "detail": (
                        "The CPE name was not found in the selected "
                        "Dictionary snapshot."
                    ),
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(CpeNameDetailSerializer(record).data)

from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class StandardPageNumberPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200
    page_query_param = "page"

    def get_page_size(self, request) -> int:
        raw_page_size = request.query_params.get(
            self.page_size_query_param
        )
        if raw_page_size is None:
            return self.page_size
        try:
            page_size = int(raw_page_size)
        except (TypeError, ValueError) as error:
            raise ValidationError(
                {"detail": "page_size must be a positive integer"}
            ) from error
        if page_size <= 0:
            raise ValidationError(
                {"detail": "page_size must be a positive integer"}
            )
        return min(page_size, self.max_page_size)

    def paginate_queryset(self, queryset, request, view=None):
        try:
            return super().paginate_queryset(
                queryset,
                request,
                view=view,
            )
        except NotFound as error:
            raise ValidationError(
                {"detail": "page must identify a valid page"}
            ) from error

    def get_paginated_response(self, data) -> Response:
        return Response(
            {
                "count": self.page.paginator.count,
                "page": self.page.number,
                "page_size": self.page.paginator.per_page,
                "total_pages": self.page.paginator.num_pages,
                "next": self.get_next_link(),
                "previous": self.get_previous_link(),
                "results": data,
            }
        )

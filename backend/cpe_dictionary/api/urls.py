from django.urls import path

from cpe_dictionary.api.views import (
    CpeDictionarySnapshotAPIView,
    CpeNameDetailAPIView,
    CpeNameSearchAPIView,
)


app_name = "cpe_dictionary_api"

urlpatterns = [
    path(
        "cpe-dictionary/",
        CpeNameSearchAPIView.as_view(),
        name="cpe-name-search",
    ),
    path(
        "cpe-dictionary/snapshot/",
        CpeDictionarySnapshotAPIView.as_view(),
        name="snapshot",
    ),
    path(
        "cpe-dictionary/<uuid:cpe_name_id>/",
        CpeNameDetailAPIView.as_view(),
        name="cpe-name-detail",
    ),
]

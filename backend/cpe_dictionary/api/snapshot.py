from __future__ import annotations

from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import APIException

from cpe_dictionary.models import CpeDictionarySnapshot
from cpe_dictionary.snapshot_selection import (
    CpeDictionarySnapshotSelectionError,
    select_cpe_dictionary_snapshot,
)


class CpeDictionarySnapshotAPIException(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_code = "cpe_dictionary_snapshot_unavailable"

    def __init__(
        self,
        selection_error: CpeDictionarySnapshotSelectionError,
    ) -> None:
        super().__init__(
            {
                "code": selection_error.error_code,
                "detail": str(selection_error),
            },
            code=selection_error.error_code,
        )


class CpeDictionarySnapshotViewMixin:
    _cpe_dictionary_snapshot: CpeDictionarySnapshot | None = None

    def get_cpe_dictionary_snapshot(
        self,
    ) -> CpeDictionarySnapshot:
        if self._cpe_dictionary_snapshot is None:
            try:
                self._cpe_dictionary_snapshot = (
                    select_cpe_dictionary_snapshot(
                        settings.CPE_DICTIONARY_SNAPSHOT_ID
                    )
                )
            except CpeDictionarySnapshotSelectionError as error:
                raise CpeDictionarySnapshotAPIException(
                    error
                ) from error
        return self._cpe_dictionary_snapshot

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
from datetime import datetime, timezone as datetime_timezone
from pathlib import Path
from uuid import UUID

from django.test import TestCase
from django.utils import timezone

from cpe_dictionary.importer import (
    DictionaryImportError,
    import_dictionary_snapshot,
)
from cpe_dictionary.models import (
    CpeDictionarySnapshot,
    CpeName,
)
from cpe_dictionary.snapshot import (
    ARCHIVE_FILENAME,
    MANIFEST_FILENAME,
)


SNAPSHOT_ID = "20260725T035002Z"
CHUNK_ROOT = "nvdcpe-2.0-chunks"


def chunk_name(sequence: int) -> str:
    return (
        f"{CHUNK_ROOT}/"
        f"nvdcpe-2.0-chunk-{sequence:05d}.json"
    )


def make_product(
    number: int,
    *,
    deprecated: bool = False,
    cpe_name_id: str | None = None,
    cpe_name: str | None = None,
) -> dict[str, object]:
    return {
        "cpe": {
            "cpeName": cpe_name
            or (
                "cpe:2.3:a:vendor:product:"
                f"{number}:update:edition:en-us:"
                "sw-edition:linux:x86:other"
            ),
            "cpeNameId": cpe_name_id
            or str(UUID(int=number)),
            "deprecated": deprecated,
            "created": "2020-01-02T03:04:05.000Z",
            "lastModified": "2026-07-24T23:50:02-04:00",
            "titles": [
                {"title": f"Product {number}", "lang": "en"}
            ],
            "refs": [
                {
                    "ref": f"https://example.test/{number}",
                    "type": "Vendor",
                }
            ],
            "deprecatedBy": [f"replacement-{number}"],
            "deprecates": [f"older-{number}"],
            "ignoredFutureField": "allowed",
        }
    }


def make_chunk(
    sequence: int,
    products: list[dict[str, object]],
    *,
    total_results: int,
    start_index: int | None = None,
) -> dict[str, object]:
    return {
        "format": "NVD_CPE",
        "version": "2.0",
        "timestamp": "2026-07-25T03:50:02.000Z",
        "resultsPerPage": len(products),
        "startIndex": (
            sequence if start_index is None else start_index
        ),
        "totalResults": total_results,
        "products": products,
        "allowedFutureField": {"value": True},
    }


def write_verified_snapshot(
    input_root: Path,
    chunks: list[dict[str, object]],
) -> Path:
    snapshot_path = input_root / SNAPSHOT_ID
    snapshot_path.mkdir(parents=True)
    encoded_chunks = [
        json.dumps(
            chunk,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        for chunk in chunks
    ]

    archive_buffer = io.BytesIO()
    with tarfile.open(
        fileobj=archive_buffer,
        mode="w:gz",
    ) as archive:
        directory = tarfile.TarInfo(f"{CHUNK_ROOT}/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for sequence, content in enumerate(
            encoded_chunks,
            start=1,
        ):
            member = tarfile.TarInfo(chunk_name(sequence))
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    archive_bytes = archive_buffer.getvalue()
    archive_path = snapshot_path / ARCHIVE_FILENAME
    archive_path.write_bytes(archive_bytes)

    aggregate = b"".join(encoded_chunks)
    manifest = {
        "schema_version": 2,
        "snapshot_id": SNAPSHOT_ID,
        "status": "VERIFIED",
        "source": "NVD CPE Dictionary 2.0",
        "source_meta_url": "https://example.test/meta",
        "source_feed_url": "https://example.test/feed",
        "source_schema_url": "https://example.test/schema",
        "feed_last_modified": "2026-07-25T03:50:02Z",
        "retrieved_at": "2026-07-27T00:00:00Z",
        "meta": {
            "size": len(aggregate),
            "zip_size": 0,
            "gz_size": len(archive_bytes),
            "sha256": hashlib.sha256(
                aggregate
            ).hexdigest(),
        },
        "archive": {
            "filename": ARCHIVE_FILENAME,
            "size": len(archive_bytes),
            "sha256": hashlib.sha256(
                archive_bytes
            ).hexdigest(),
        },
        "content": {
            "format": "chunked-json",
            "member_count": len(encoded_chunks),
            "ordering": "numeric-chunk-sequence",
            "separator": "none",
            "aggregate_size": len(aggregate),
            "aggregate_sha256": hashlib.sha256(
                aggregate
            ).hexdigest(),
            "members": [
                {
                    "sequence": sequence,
                    "name": chunk_name(sequence),
                    "size": len(content),
                    "sha256": hashlib.sha256(
                        content
                    ).hexdigest(),
                }
                for sequence, content in enumerate(
                    encoded_chunks,
                    start=1,
                )
            ],
        },
        "validation": {
            "archive_size_matches_meta": True,
            "safe_archive_members": True,
            "member_names_valid": True,
            "member_sequences_unique": True,
            "member_sequences_contiguous": True,
            "aggregate_size_matches_meta": True,
            "aggregate_sha256_matches_meta": True,
        },
    }
    (snapshot_path / MANIFEST_FILENAME).write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    return snapshot_path


class DictionaryImporterTests(TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.input_root = Path(
            self.temporary_directory.name
        ) / "snapshots"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write_default_snapshot(self) -> Path:
        return write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [make_product(1)],
                    total_results=2,
                ),
                make_chunk(
                    2,
                    [make_product(2, deprecated=True)],
                    total_results=2,
                ),
            ],
        )

    def _import(self, **kwargs):
        return import_dictionary_snapshot(
            self.input_root,
            SNAPSHOT_ID,
            batch_size=100,
            **kwargs,
        )

    def test_imports_two_chunks_and_preserves_fields(self) -> None:
        self._write_default_snapshot()
        messages: list[str] = []

        result = self._import(reporter=messages.append)

        self.assertEqual(result.member_count, 2)
        self.assertEqual(result.expected_record_count, 2)
        self.assertEqual(result.record_count, 2)
        self.assertEqual(result.active_count, 1)
        self.assertEqual(result.deprecated_count, 1)
        snapshot = CpeDictionarySnapshot.objects.get()
        self.assertEqual(
            snapshot.status,
            CpeDictionarySnapshot.Status.COMPLETE,
        )
        self.assertIsNotNone(snapshot.completed_at)
        first = CpeName.objects.get(cpe_name_id=UUID(int=1))
        self.assertEqual(first.part, "a")
        self.assertEqual(first.vendor, "vendor")
        self.assertEqual(first.product, "product")
        self.assertEqual(first.version, "1")
        self.assertEqual(first.update, "update")
        self.assertEqual(first.edition, "edition")
        self.assertEqual(first.language, "en-us")
        self.assertEqual(first.sw_edition, "sw-edition")
        self.assertEqual(first.target_sw, "linux")
        self.assertEqual(first.target_hw, "x86")
        self.assertEqual(first.other, "other")
        self.assertEqual(
            first.titles,
            [{"title": "Product 1", "lang": "en"}],
        )
        self.assertEqual(
            first.references,
            [
                {
                    "ref": "https://example.test/1",
                    "type": "Vendor",
                }
            ],
        )
        self.assertEqual(first.deprecated_by, ["replacement-1"])
        self.assertEqual(first.deprecates, ["older-1"])
        self.assertTrue(timezone.is_aware(first.created_at_nvd))
        self.assertTrue(
            timezone.is_aware(first.last_modified_at_nvd)
        )
        self.assertEqual(len(messages), 2)

    def test_dry_run_parses_everything_without_db_writes(self) -> None:
        self._write_default_snapshot()

        result = self._import(dry_run=True)

        self.assertTrue(result.dry_run)
        self.assertEqual(result.record_count, 2)
        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

    def test_naive_nvd_timestamps_are_stored_as_utc(self) -> None:
        product = make_product(1)
        product["cpe"]["created"] = "2007-08-23T21:05:57.937"
        product["cpe"]["lastModified"] = (
            "2011-01-12T14:35:43.723"
        )
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [product],
                    total_results=1,
                )
            ],
        )

        self._import()

        cpe_name = CpeName.objects.get()
        self.assertEqual(
            cpe_name.created_at_nvd,
            datetime(
                2007,
                8,
                23,
                21,
                5,
                57,
                937000,
                tzinfo=datetime_timezone.utc,
            ),
        )
        self.assertEqual(
            cpe_name.last_modified_at_nvd,
            datetime(
                2011,
                1,
                12,
                14,
                35,
                43,
                723000,
                tzinfo=datetime_timezone.utc,
            ),
        )

    def test_offset_aware_timestamps_are_converted_to_utc(
        self,
    ) -> None:
        product = make_product(1)
        product["cpe"]["created"] = (
            "2026-07-24T23:50:02.123-04:00"
        )
        product["cpe"]["lastModified"] = (
            "2026-07-25T13:20:02.456+09:30"
        )
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [product],
                    total_results=1,
                )
            ],
        )

        self._import()

        cpe_name = CpeName.objects.get()
        self.assertEqual(
            cpe_name.created_at_nvd,
            datetime(
                2026,
                7,
                25,
                3,
                50,
                2,
                123000,
                tzinfo=datetime_timezone.utc,
            ),
        )
        self.assertEqual(
            cpe_name.last_modified_at_nvd,
            datetime(
                2026,
                7,
                25,
                3,
                50,
                2,
                456000,
                tzinfo=datetime_timezone.utc,
            ),
        )

    def test_invalid_timestamp_still_fails_and_rolls_back(
        self,
    ) -> None:
        product = make_product(1)
        product["cpe"]["created"] = "not-a-date"
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [product],
                    total_results=1,
                )
            ],
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "valid ISO-8601",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

    def test_complete_snapshot_rerun_is_noop(self) -> None:
        self._write_default_snapshot()
        first_result = self._import()
        snapshot = CpeDictionarySnapshot.objects.get()
        completed_at = snapshot.completed_at

        second_result = self._import()

        snapshot.refresh_from_db()
        self.assertFalse(first_result.already_imported)
        self.assertTrue(second_result.already_imported)
        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            1,
        )
        self.assertEqual(CpeName.objects.count(), 2)
        self.assertEqual(snapshot.completed_at, completed_at)

    def test_missing_required_cpe_field_rolls_back(self) -> None:
        product = make_product(1)
        del product["cpe"]["lastModified"]
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [product],
                    total_results=1,
                )
            ],
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "missing required",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

    def test_cpe_parser_error_rolls_back(self) -> None:
        product = make_product(1)
        product["cpe"]["cpeName"] = "not-a-cpe"
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [product],
                    total_results=1,
                )
            ],
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "structurally invalid",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

    def test_duplicate_uuid_rolls_back_entire_import(self) -> None:
        duplicate_uuid = str(UUID(int=1))
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [
                        make_product(
                            1,
                            cpe_name_id=duplicate_uuid,
                        ),
                        make_product(
                            2,
                            cpe_name_id=duplicate_uuid,
                        ),
                    ],
                    total_results=2,
                )
            ],
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "integrity validation failed",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

    def test_duplicate_cpe_name_rolls_back_entire_import(
        self,
    ) -> None:
        duplicate_name = (
            "cpe:2.3:a:vendor:duplicate:1:*:*:*:*:*:*:*"
        )
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [
                        make_product(
                            1,
                            cpe_name=duplicate_name,
                        ),
                        make_product(
                            2,
                            cpe_name=duplicate_name,
                        ),
                    ],
                    total_results=2,
                )
            ],
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "integrity validation failed",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

    def test_pagination_mismatch_rolls_back(self) -> None:
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [make_product(1)],
                    total_results=1,
                    start_index=0,
                )
            ],
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "startIndex",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )

    def test_total_results_mismatch_rolls_back(self) -> None:
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    [make_product(1)],
                    total_results=2,
                ),
                make_chunk(
                    2,
                    [make_product(2)],
                    total_results=3,
                ),
            ],
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "totalResults is inconsistent",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

    def test_archive_hash_mismatch_fails_before_db_write(
        self,
    ) -> None:
        snapshot_path = self._write_default_snapshot()
        archive_path = snapshot_path / ARCHIVE_FILENAME
        archive_path.write_bytes(
            archive_path.read_bytes() + b"tampered"
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "Archive SHA-256",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

    def test_error_after_bulk_insert_rolls_back_everything(
        self,
    ) -> None:
        first_chunk_products = [
            make_product(number)
            for number in range(1, 101)
        ]
        invalid_product = make_product(101)
        del invalid_product["cpe"]["created"]
        write_verified_snapshot(
            self.input_root,
            [
                make_chunk(
                    1,
                    first_chunk_products,
                    total_results=101,
                ),
                make_chunk(
                    2,
                    [invalid_product],
                    total_results=101,
                ),
            ],
        )

        with self.assertRaisesRegex(
            DictionaryImportError,
            "missing required",
        ):
            self._import()

        self.assertEqual(
            CpeDictionarySnapshot.objects.count(),
            0,
        )
        self.assertEqual(CpeName.objects.count(), 0)

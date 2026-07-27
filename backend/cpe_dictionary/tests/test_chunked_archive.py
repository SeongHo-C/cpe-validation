from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from django.test import SimpleTestCase

from cpe_dictionary.snapshot import (
    ARCHIVE_FILENAME,
    ArchiveValidationError,
    IntegrityError,
    build_manifest,
    parse_metadata,
    validate_archive,
)


CHUNK_ROOT = "nvdcpe-2.0-chunks"


def chunk_name(sequence: int) -> str:
    return (
        f"{CHUNK_ROOT}/"
        f"nvdcpe-2.0-chunk-{sequence:05d}.json"
    )


def build_chunk_archive(
    members: list[tuple[str, bytes, bytes | None]],
    *,
    directory_name: str | None = f"{CHUNK_ROOT}/",
) -> bytes:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
        if directory_name is not None:
            directory = tarfile.TarInfo(directory_name)
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
        for name, content, member_type in members:
            member = tarfile.TarInfo(name)
            if member_type is None:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
                continue
            member.type = member_type
            if member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = chunk_name(1)
            archive.addfile(member)
    return archive_bytes.getvalue()


class ChunkedArchiveValidationTests(SimpleTestCase):
    def _validate(
        self,
        members: list[tuple[str, bytes, bytes | None]],
        *,
        expected_bytes: bytes | None = None,
        expected_size: int | None = None,
        expected_sha256: str | None = None,
        directory_name: str | None = f"{CHUNK_ROOT}/",
    ):
        archive_bytes = build_chunk_archive(
            members,
            directory_name=directory_name,
        )
        if expected_bytes is not None:
            expected_size = len(expected_bytes)
            expected_sha256 = hashlib.sha256(
                expected_bytes
            ).hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / ARCHIVE_FILENAME
            archive_path.write_bytes(archive_bytes)
            return validate_archive(
                archive_path,
                expected_size=expected_size,
                expected_sha256=expected_sha256,
            )

    def test_validates_multiple_chunks_in_numeric_order(self) -> None:
        first = b'{"chunk": 1}\n'
        second = b'{"chunk": 2}\n'
        third = b'{"chunk": 3}\n'
        result = self._validate(
            [
                (chunk_name(3), third, None),
                (chunk_name(1), first, None),
                (chunk_name(2), second, None),
            ],
            expected_bytes=first + second + third,
        )

        self.assertEqual(
            [member.sequence for member in result.members],
            [1, 2, 3],
        )
        self.assertEqual(
            [member.name for member in result.members],
            [chunk_name(1), chunk_name(2), chunk_name(3)],
        )

    def test_validates_one_chunk(self) -> None:
        content = b'{"products": []}\n'
        result = self._validate(
            [(chunk_name(1), content, None)],
            expected_bytes=content,
            directory_name=None,
        )

        self.assertEqual(len(result.members), 1)
        self.assertEqual(result.aggregate_size, len(content))

    def test_records_each_member_size_and_sha256(self) -> None:
        first = b"first raw bytes\n"
        second = b"second raw bytes\r\n"
        result = self._validate(
            [
                (chunk_name(1), first, None),
                (chunk_name(2), second, None),
            ],
            expected_bytes=first + second,
        )

        self.assertEqual(result.members[0].size, len(first))
        self.assertEqual(
            result.members[0].sha256,
            hashlib.sha256(first).hexdigest(),
        )
        self.assertEqual(result.members[1].size, len(second))
        self.assertEqual(
            result.members[1].sha256,
            hashlib.sha256(second).hexdigest(),
        )

    def test_aggregate_uses_no_separator(self) -> None:
        first = b'{"a": 1}'
        second = b'{"b": 2}'
        result = self._validate(
            [
                (chunk_name(1), first, None),
                (chunk_name(2), second, None),
            ],
            expected_bytes=first + second,
        )

        self.assertEqual(
            result.aggregate_sha256,
            hashlib.sha256(first + second).hexdigest(),
        )
        self.assertNotEqual(
            result.aggregate_sha256,
            hashlib.sha256(first + b"\n" + second).hexdigest(),
        )

    def test_aggregate_uses_raw_bytes_without_json_reserialization(
        self,
    ) -> None:
        first = b'{ "products" : [ ] }\r\n'
        second = b'{"products":[]}\n'
        raw_bytes = first + second
        normalized_bytes = (
            b'{"products":[]}\n{"products":[]}\n'
        )
        result = self._validate(
            [
                (chunk_name(1), first, None),
                (chunk_name(2), second, None),
            ],
            expected_bytes=raw_bytes,
        )

        self.assertEqual(
            result.aggregate_sha256,
            hashlib.sha256(raw_bytes).hexdigest(),
        )
        self.assertNotEqual(
            result.aggregate_sha256,
            hashlib.sha256(normalized_bytes).hexdigest(),
        )

    def test_tar_order_hash_differs_from_numeric_order_hash(self) -> None:
        first = b"one"
        second = b"two"
        result = self._validate(
            [
                (chunk_name(2), second, None),
                (chunk_name(1), first, None),
            ],
            expected_bytes=first + second,
        )

        self.assertNotEqual(
            result.aggregate_sha256,
            hashlib.sha256(second + first).hexdigest(),
        )

    def test_allows_both_documented_directory_spellings(self) -> None:
        for directory_name in (
            CHUNK_ROOT,
            f"{CHUNK_ROOT}/",
        ):
            with self.subTest(directory_name=directory_name):
                content = b"{}"
                result = self._validate(
                    [(chunk_name(1), content, None)],
                    expected_bytes=content,
                    directory_name=directory_name,
                )
                self.assertEqual(len(result.members), 1)

    def test_rejects_archive_without_chunks(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "does not contain",
        ):
            self._validate([])

    def test_rejects_unexpected_directory(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "unexpected directory",
        ):
            self._validate(
                [(chunk_name(1), b"{}", None)],
                directory_name="unexpected/",
            )

    def test_rejects_invalid_chunk_names(self) -> None:
        invalid_names = (
            "wrong/nvdcpe-2.0-chunk-00001.json",
            f"{CHUNK_ROOT}/wrong-00001.json",
            f"{CHUNK_ROOT}/nvdcpe-2.0-chunk-0001.json",
            f"{CHUNK_ROOT}/nvdcpe-2.0-chunk-00001.JSON",
            f"{CHUNK_ROOT}/nvdcpe-2.0-chunk-00001.txt",
        )
        for invalid_name in invalid_names:
            with (
                self.subTest(name=invalid_name),
                self.assertRaisesRegex(
                    ArchiveValidationError,
                    "unexpected regular file",
                ),
            ):
                self._validate(
                    [(invalid_name, b"{}", None)],
                    directory_name=None,
                )

    def test_rejects_duplicate_sequence(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "duplicate chunk sequence",
        ):
            self._validate(
                [
                    (chunk_name(1), b"first", None),
                    (chunk_name(1), b"duplicate", None),
                ]
            )

    def test_rejects_sequence_that_does_not_start_at_one(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "start at 1",
        ):
            self._validate([(chunk_name(2), b"{}", None)])

    def test_rejects_sequence_gap(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "contiguous",
        ):
            self._validate(
                [
                    (chunk_name(1), b"one", None),
                    (chunk_name(3), b"three", None),
                ]
            )

    def test_rejects_unexpected_regular_file(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "unexpected regular file",
        ):
            self._validate(
                [
                    (chunk_name(1), b"{}", None),
                    ("README.txt", b"unexpected", None),
                ]
            )

    def test_rejects_path_traversal(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "unsafe member path",
        ):
            self._validate(
                [("../" + chunk_name(1), b"{}", None)],
                directory_name=None,
            )

    def test_rejects_absolute_path(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "unsafe member path",
        ):
            self._validate(
                [("/" + chunk_name(1), b"{}", None)],
                directory_name=None,
            )

    def test_rejects_symbolic_link(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "link, device, or special",
        ):
            self._validate(
                [(chunk_name(1), b"", tarfile.SYMTYPE)]
            )

    def test_rejects_hard_link(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "link, device, or special",
        ):
            self._validate(
                [(chunk_name(1), b"", tarfile.LNKTYPE)]
            )

    def test_rejects_special_file(self) -> None:
        with self.assertRaisesRegex(
            ArchiveValidationError,
            "link, device, or special",
        ):
            self._validate(
                [(chunk_name(1), b"", tarfile.FIFOTYPE)]
            )

    def test_reports_aggregate_size_mismatch(self) -> None:
        content = b"raw content"
        with self.assertRaisesRegex(
            IntegrityError,
            rf"actual size={len(content)}, META size=999",
        ):
            self._validate(
                [(chunk_name(1), content, None)],
                expected_size=999,
                expected_sha256=hashlib.sha256(
                    content
                ).hexdigest(),
            )

    def test_reports_aggregate_sha256_mismatch(self) -> None:
        content = b"raw content"
        with self.assertRaisesRegex(
            IntegrityError,
            "SHA-256 matches=False",
        ):
            self._validate(
                [(chunk_name(1), content, None)],
                expected_size=len(content),
                expected_sha256="0" * 64,
            )

    def test_builds_schema_version_two_manifest(self) -> None:
        first = b"one\n"
        second = b"two\n"
        aggregate = first + second
        archive_bytes = build_chunk_archive(
            [
                (chunk_name(2), second, None),
                (chunk_name(1), first, None),
            ]
        )
        content = self._validate(
            [
                (chunk_name(2), second, None),
                (chunk_name(1), first, None),
            ],
            expected_bytes=aggregate,
        )
        metadata = parse_metadata(
            "\n".join(
                [
                    "lastModifiedDate:2026-07-24T23:50:02-04:00",
                    f"size:{len(aggregate)}",
                    "zipSize:0",
                    f"gzSize:{len(archive_bytes)}",
                    "sha256:"
                    + hashlib.sha256(aggregate).hexdigest(),
                ]
            )
        )

        manifest = build_manifest(
            snapshot_id="20260725T035002Z",
            metadata=metadata,
            meta_url="https://example.test/meta",
            feed_url="https://example.test/feed",
            schema_url="https://example.test/schema",
            retrieved_at=datetime(
                2026,
                7,
                27,
                tzinfo=timezone.utc,
            ),
            archive_size=len(archive_bytes),
            archive_sha256=hashlib.sha256(
                archive_bytes
            ).hexdigest(),
            content=content,
        )

        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["content"]["member_count"], 2)
        self.assertEqual(
            [
                member["sequence"]
                for member in manifest["content"]["members"]
            ],
            [1, 2],
        )
        self.assertEqual(
            manifest["content"]["aggregate_size"],
            len(aggregate),
        )
        self.assertTrue(all(manifest["validation"].values()))

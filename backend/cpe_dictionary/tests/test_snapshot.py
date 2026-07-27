from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request

from django.test import SimpleTestCase

from cpe_dictionary.snapshot import (
    ARCHIVE_FILENAME,
    MANIFEST_FILENAME,
    META_FILENAME,
    ArchiveValidationError,
    ExistingSnapshotError,
    IntegrityError,
    MetadataError,
    SnapshotPlan,
    SnapshotResult,
    acquire_snapshot,
    download_metadata,
    parse_metadata,
    snapshot_id_from_last_modified,
    validate_archive,
)


META_URL = "https://example.test/nvdcpe-2.0.meta"
FEED_URL = "https://example.test/nvdcpe-2.0.tar.gz"
SCHEMA_URL = "https://example.test/cpe-schema.json"
LAST_MODIFIED = "2026-07-24T23:50:02-04:00"
SNAPSHOT_ID = "20260725T035002Z"


def build_archive(
    content: bytes,
    *,
    member_name: str = (
        "nvdcpe-2.0-chunks/"
        "nvdcpe-2.0-chunk-00001.json"
    ),
    additional_json: bool = False,
    include_json: bool = True,
    link_type: bytes | None = None,
) -> bytes:
    archive_bytes = io.BytesIO()
    with tarfile.open(
        fileobj=archive_bytes,
        mode="w:gz",
    ) as archive:
        if include_json:
            member = tarfile.TarInfo(member_name)
            if link_type is None:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            else:
                member.type = link_type
                member.linkname = "target.json"
                archive.addfile(member)
        if additional_json:
            extra = tarfile.TarInfo(
                "nvdcpe-2.0-chunks/"
                "nvdcpe-2.0-chunk-00002.json"
            )
            extra.size = len(content)
            archive.addfile(extra, io.BytesIO(content))
        if not include_json:
            directory = tarfile.TarInfo("nvdcpe-2.0-chunks/")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
    return archive_bytes.getvalue()


def build_meta(
    content: bytes,
    archive: bytes,
    *,
    size: int | None = None,
    gz_size: int | None = None,
    sha256: str | None = None,
    extra: str = "",
) -> bytes:
    fields = [
        f"lastModifiedDate:{LAST_MODIFIED}",
        f"size:{len(content) if size is None else size}",
        "zipSize:0",
        f"gzSize:{len(archive) if gz_size is None else gz_size}",
        (
            "sha256:"
            + (
                hashlib.sha256(content).hexdigest()
                if sha256 is None
                else sha256
            )
        ),
    ]
    if extra:
        fields.append(extra)
    return ("\n".join(fields) + "\n").encode()


class FakeUrlOpen:
    def __init__(
        self,
        responses: dict[str, bytes | BaseException | list[object]],
    ) -> None:
        self.responses = responses
        self.calls: list[str] = []
        self.requests: list[Request] = []

    def __call__(
        self,
        request: Request,
        *,
        timeout: float,
    ) -> io.BytesIO:
        self.calls.append(request.full_url)
        self.requests.append(request)
        if timeout <= 0:
            raise AssertionError("timeout must be positive")
        response = self.responses[request.full_url]
        if isinstance(response, list):
            response = response.pop(0)
        if isinstance(response, BaseException):
            raise response
        if not isinstance(response, bytes):
            raise AssertionError("fake response must contain bytes")
        return io.BytesIO(response)


def fake_sources(
    content: bytes = b'{"products": []}\n',
) -> tuple[bytes, bytes, FakeUrlOpen]:
    archive = build_archive(content)
    meta = build_meta(content, archive)
    opener = FakeUrlOpen(
        {
            META_URL: meta,
            FEED_URL: archive,
        }
    )
    return meta, archive, opener


class MetadataParserTests(SimpleTestCase):
    def test_parses_valid_meta_and_preserves_unknown_fields(self) -> None:
        content = b"{}\n"
        archive = build_archive(content)
        metadata = parse_metadata(
            build_meta(
                content,
                archive,
                extra="unknownField:preserved",
            ).decode()
        )

        self.assertEqual(metadata.size, len(content))
        self.assertEqual(metadata.gz_size, len(archive))
        self.assertEqual(
            metadata.sha256,
            hashlib.sha256(content).hexdigest(),
        )
        self.assertEqual(
            metadata.raw_fields["unknownField"],
            "preserved",
        )

    def test_rejects_missing_required_meta_field(self) -> None:
        with self.assertRaisesRegex(
            MetadataError,
            "missing required",
        ):
            parse_metadata(
                "\n".join(
                    [
                        f"lastModifiedDate:{LAST_MODIFIED}",
                        "size:1",
                        "zipSize:1",
                        "gzSize:1",
                    ]
                )
            )

    def test_rejects_duplicate_meta_key(self) -> None:
        content = b"{}\n"
        archive = build_archive(content)
        raw_meta = (
            build_meta(content, archive).decode()
            + "size:3\n"
        )
        with self.assertRaisesRegex(MetadataError, "duplicate"):
            parse_metadata(raw_meta)

    def test_rejects_invalid_or_negative_sizes(self) -> None:
        content = b"{}\n"
        archive = build_archive(content)
        for invalid_size in ("text", "-1"):
            with self.subTest(size=invalid_size):
                raw_meta = build_meta(
                    content,
                    archive,
                ).decode()
                raw_meta = raw_meta.replace(
                    f"size:{len(content)}",
                    f"size:{invalid_size}",
                )
                with self.assertRaises(MetadataError):
                    parse_metadata(raw_meta)

    def test_rejects_invalid_sha256(self) -> None:
        content = b"{}\n"
        archive = build_archive(content)
        with self.assertRaisesRegex(MetadataError, "64 hexadecimal"):
            parse_metadata(
                build_meta(
                    content,
                    archive,
                    sha256="not-a-sha256",
                ).decode()
            )

    def test_rejects_invalid_or_naive_last_modified(self) -> None:
        content = b"{}\n"
        archive = build_archive(content)
        for invalid_date in (
            "not-a-date",
            "2026-07-25T03:50:02",
        ):
            with self.subTest(last_modified=invalid_date):
                raw_meta = build_meta(
                    content,
                    archive,
                ).decode()
                raw_meta = raw_meta.replace(
                    LAST_MODIFIED,
                    invalid_date,
                )
                with self.assertRaises(MetadataError):
                    parse_metadata(raw_meta)

    def test_snapshot_id_uses_utc_last_modified(self) -> None:
        value = datetime.fromisoformat(LAST_MODIFIED)
        self.assertEqual(
            snapshot_id_from_last_modified(value),
            SNAPSHOT_ID,
        )


class ArchiveValidationTests(SimpleTestCase):
    def _write_archive(
        self,
        root: Path,
        archive: bytes,
    ) -> Path:
        path = root / ARCHIVE_FILENAME
        path.write_bytes(archive)
        return path

    def test_validates_one_regular_json_chunk(self) -> None:
        content = b'{"products": [{"cpe": "value"}]}\n'
        archive = build_archive(content)
        with tempfile.TemporaryDirectory() as temp_dir:
            result = validate_archive(
                self._write_archive(Path(temp_dir), archive),
                expected_size=len(content),
                expected_sha256=hashlib.sha256(
                    content
                ).hexdigest(),
            )

        self.assertEqual(len(result.members), 1)
        self.assertEqual(result.members[0].sequence, 1)
        self.assertEqual(
            result.members[0].name,
            "nvdcpe-2.0-chunks/"
            "nvdcpe-2.0-chunk-00001.json",
        )
        self.assertEqual(result.aggregate_size, len(content))

    def test_rejects_uncompressed_size_mismatch(self) -> None:
        content = b"{}\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_archive(
                Path(temp_dir),
                build_archive(content),
            )
            with self.assertRaisesRegex(
                IntegrityError,
                "size",
            ):
                validate_archive(
                    path,
                    expected_size=len(content) + 1,
                )

    def test_rejects_uncompressed_sha256_mismatch(self) -> None:
        content = b"{}\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_archive(
                Path(temp_dir),
                build_archive(content),
            )
            with self.assertRaisesRegex(
                IntegrityError,
                "SHA-256",
            ):
                validate_archive(
                    path,
                    expected_sha256="0" * 64,
                )

    def test_rejects_archive_without_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_archive(
                Path(temp_dir),
                build_archive(b"text", include_json=False),
            )
            with self.assertRaisesRegex(
                ArchiveValidationError,
                "does not contain",
            ):
                validate_archive(path)

    def test_accepts_multiple_valid_json_chunks(self) -> None:
        content = b"{}\n"
        expected_content = content + content
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_archive(
                Path(temp_dir),
                build_archive(content, additional_json=True),
            )
            result = validate_archive(
                path,
                expected_size=len(expected_content),
                expected_sha256=hashlib.sha256(
                    expected_content
                ).hexdigest(),
            )

        self.assertEqual(
            [member.sequence for member in result.members],
            [1, 2],
        )

    def test_rejects_path_traversal_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_archive(
                Path(temp_dir),
                build_archive(
                    b"{}\n",
                    member_name="../outside.json",
                ),
            )
            with self.assertRaisesRegex(
                ArchiveValidationError,
                "unsafe member path",
            ):
                validate_archive(path)

    def test_rejects_symbolic_link_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_archive(
                Path(temp_dir),
                build_archive(
                    b"",
                    link_type=tarfile.SYMTYPE,
                ),
            )
            with self.assertRaisesRegex(
                ArchiveValidationError,
                "link, device, or special",
            ):
                validate_archive(path)

    def test_rejects_hard_link_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_archive(
                Path(temp_dir),
                build_archive(
                    b"",
                    link_type=tarfile.LNKTYPE,
                ),
            )
            with self.assertRaisesRegex(
                ArchiveValidationError,
                "link, device, or special",
            ):
                validate_archive(path)


class SnapshotAcquisitionTests(SimpleTestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.output_root = (
            Path(self.temporary_directory.name) / "snapshots"
        )
        self.fixed_now = datetime(
            2026,
            7,
            26,
            1,
            2,
            3,
            tzinfo=timezone.utc,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _acquire(
        self,
        opener: FakeUrlOpen,
        *,
        dry_run: bool = False,
    ) -> SnapshotPlan | SnapshotResult:
        return acquire_snapshot(
            self.output_root,
            meta_url=META_URL,
            feed_url=FEED_URL,
            schema_url=SCHEMA_URL,
            dry_run=dry_run,
            urlopen_func=opener,
            sleep_func=lambda seconds: None,
            now_func=lambda: self.fixed_now,
        )

    def test_dry_run_downloads_only_meta_and_creates_nothing(self) -> None:
        _, _, opener = fake_sources()
        result = self._acquire(opener, dry_run=True)

        self.assertIsInstance(result, SnapshotPlan)
        self.assertEqual(result.snapshot_id, SNAPSHOT_ID)
        self.assertEqual(opener.calls, [META_URL])
        self.assertFalse(self.output_root.exists())

    def test_creates_verified_snapshot_atomically(self) -> None:
        meta, archive, opener = fake_sources()
        result = self._acquire(opener)

        self.assertIsInstance(result, SnapshotResult)
        self.assertFalse(result.already_verified)
        snapshot_path = self.output_root / SNAPSHOT_ID
        self.assertEqual(
            (snapshot_path / META_FILENAME).read_bytes(),
            meta,
        )
        self.assertEqual(
            (snapshot_path / ARCHIVE_FILENAME).read_bytes(),
            archive,
        )
        self.assertTrue(
            (snapshot_path / MANIFEST_FILENAME).is_file()
        )
        self.assertEqual(
            list(self.output_root.glob(".*.tmp-*")),
            [],
        )

    def test_manifest_contains_verified_integrity_values(self) -> None:
        content = b'{"products": []}\n'
        _, archive, opener = fake_sources(content)
        result = self._acquire(opener)
        self.assertIsInstance(result, SnapshotResult)
        manifest = result.manifest

        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["snapshot_id"], SNAPSHOT_ID)
        self.assertEqual(manifest["status"], "VERIFIED")
        self.assertEqual(
            manifest["retrieved_at"],
            "2026-07-26T01:02:03Z",
        )
        self.assertEqual(
            manifest["archive"]["size"],
            len(archive),
        )
        self.assertEqual(
            manifest["archive"]["sha256"],
            hashlib.sha256(archive).hexdigest(),
        )
        self.assertEqual(
            manifest["content"]["aggregate_sha256"],
            hashlib.sha256(content).hexdigest(),
        )
        self.assertEqual(
            manifest["content"]["format"],
            "chunked-json",
        )
        self.assertEqual(
            manifest["content"]["member_count"],
            1,
        )
        self.assertEqual(
            manifest["content"]["ordering"],
            "numeric-chunk-sequence",
        )
        self.assertEqual(
            manifest["content"]["separator"],
            "none",
        )
        self.assertEqual(
            manifest["validation"],
            {
                "archive_size_matches_meta": True,
                "safe_archive_members": True,
                "member_names_valid": True,
                "member_sequences_unique": True,
                "member_sequences_contiguous": True,
                "aggregate_size_matches_meta": True,
                "aggregate_sha256_matches_meta": True,
            },
        )
        manifest_text = (
            result.snapshot_path / MANIFEST_FILENAME
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            self.temporary_directory.name,
            manifest_text,
        )

    def test_rejects_gz_size_mismatch(self) -> None:
        content = b"{}\n"
        archive = build_archive(content)
        opener = FakeUrlOpen(
            {
                META_URL: build_meta(
                    content,
                    archive,
                    gz_size=len(archive) + 1,
                ),
                FEED_URL: archive,
            }
        )
        with self.assertRaisesRegex(IntegrityError, "gzSize"):
            self._acquire(opener)

        self.assertFalse(
            (self.output_root / SNAPSHOT_ID).exists()
        )

    def test_failure_removes_temp_directories_and_parts(self) -> None:
        content = b"{}\n"
        archive = build_archive(content)
        opener = FakeUrlOpen(
            {
                META_URL: build_meta(
                    content,
                    archive,
                    sha256="0" * 64,
                ),
                FEED_URL: archive,
            }
        )
        with self.assertRaises(IntegrityError):
            self._acquire(opener)

        self.assertEqual(
            list(self.output_root.glob(".*.tmp-*")),
            [],
        )
        self.assertEqual(
            list(self.output_root.rglob("*.part")),
            [],
        )

    def test_verified_snapshot_rerun_is_noop(self) -> None:
        _, _, opener = fake_sources()
        first = self._acquire(opener)
        self.assertIsInstance(first, SnapshotResult)
        manifest_path = (
            self.output_root / SNAPSHOT_ID / MANIFEST_FILENAME
        )
        archive_path = (
            self.output_root / SNAPSHOT_ID / ARCHIVE_FILENAME
        )
        manifest_before = manifest_path.read_bytes()
        archive_before = archive_path.read_bytes()
        manifest_mtime = manifest_path.stat().st_mtime_ns
        archive_mtime = archive_path.stat().st_mtime_ns

        second = self._acquire(opener)

        self.assertIsInstance(second, SnapshotResult)
        self.assertTrue(second.already_verified)
        self.assertEqual(opener.calls.count(FEED_URL), 1)
        self.assertEqual(manifest_path.read_bytes(), manifest_before)
        self.assertEqual(archive_path.read_bytes(), archive_before)
        self.assertEqual(
            manifest_path.stat().st_mtime_ns,
            manifest_mtime,
        )
        self.assertEqual(
            archive_path.stat().st_mtime_ns,
            archive_mtime,
        )

    def test_incomplete_existing_snapshot_is_not_overwritten(self) -> None:
        _, _, opener = fake_sources()
        final_path = self.output_root / SNAPSHOT_ID
        final_path.mkdir(parents=True)
        marker = final_path / "manual-review.txt"
        marker.write_text("preserve", encoding="utf-8")

        with self.assertRaisesRegex(
            ExistingSnapshotError,
            "manifest.json is missing",
        ):
            self._acquire(opener)

        self.assertEqual(
            marker.read_text(encoding="utf-8"),
            "preserve",
        )
        self.assertEqual(opener.calls, [META_URL])

    def test_conflicting_existing_manifest_is_rejected(self) -> None:
        _, _, opener = fake_sources()
        self._acquire(opener)
        manifest_path = (
            self.output_root / SNAPSHOT_ID / MANIFEST_FILENAME
        )
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        manifest["meta"]["size"] += 1
        manifest_path.write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            ExistingSnapshotError,
            "current META",
        ):
            self._acquire(opener)
        self.assertEqual(opener.calls.count(FEED_URL), 1)

    def test_incomplete_existing_member_manifest_is_rejected(
        self,
    ) -> None:
        _, _, opener = fake_sources()
        self._acquire(opener)
        manifest_path = (
            self.output_root / SNAPSHOT_ID / MANIFEST_FILENAME
        )
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        manifest["content"]["member_count"] = 2
        manifest_path.write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            ExistingSnapshotError,
            "content manifest",
        ):
            self._acquire(opener)
        self.assertEqual(opener.calls.count(FEED_URL), 1)

    def test_invalid_existing_member_sequence_is_rejected(
        self,
    ) -> None:
        _, _, opener = fake_sources()
        self._acquire(opener)
        manifest_path = (
            self.output_root / SNAPSHOT_ID / MANIFEST_FILENAME
        )
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        manifest["content"]["members"][0]["sequence"] = 2
        manifest_path.write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            ExistingSnapshotError,
            "member manifest",
        ):
            self._acquire(opener)
        self.assertEqual(opener.calls.count(FEED_URL), 1)

    def test_existing_other_snapshot_is_preserved(self) -> None:
        other_snapshot = self.output_root / "20200101T000000Z"
        other_snapshot.mkdir(parents=True)
        marker = other_snapshot / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        _, _, opener = fake_sources()

        self._acquire(opener)

        self.assertEqual(
            marker.read_text(encoding="utf-8"),
            "keep",
        )

    def test_metadata_download_retries_with_user_agent(self) -> None:
        content = b"{}\n"
        archive = build_archive(content)
        meta = build_meta(content, archive)
        opener = FakeUrlOpen(
            {
                META_URL: [
                    URLError("temporary"),
                    meta,
                ]
            }
        )

        result = download_metadata(
            META_URL,
            urlopen_func=opener,
            sleep_func=lambda seconds: None,
        )

        self.assertEqual(result, meta)
        self.assertEqual(opener.calls, [META_URL, META_URL])
        self.assertEqual(
            opener.requests[0].get_header("User-agent"),
            "cpe-validation-research/1.0",
        )

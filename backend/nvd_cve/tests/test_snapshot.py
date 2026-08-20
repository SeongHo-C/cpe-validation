from __future__ import annotations

import gzip
import hashlib
import io
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request

from django.core.management import get_commands
from django.test import SimpleTestCase

from nvd_cve.snapshot import (
    DownloadError,
    ExistingSnapshotError,
    FeedValidationError,
    IntegrityError,
    MetadataError,
    SnapshotResult,
    acquire_snapshot,
    feed_filename,
    feed_url,
    meta_filename,
    meta_url,
    parse_metadata,
    snapshot_id_from_capture_started,
    verify_snapshot,
)


BASE_URL = "https://example.test/cve/2.0"
CAPTURED_AT = datetime(2003, 8, 20, 10, 55, tzinfo=timezone.utc)
SNAPSHOT_ID = "20030820T105500Z"


def make_document(
    cve_ids: list[str],
    *,
    results_per_page: int | None = None,
    start_index: int = 0,
    total_results: int | None = None,
) -> bytes:
    vulnerabilities = [{"cve": {"id": cve_id}} for cve_id in cve_ids]
    value = {
        "resultsPerPage": (
            len(vulnerabilities)
            if results_per_page is None
            else results_per_page
        ),
        "startIndex": start_index,
        "totalResults": (
            len(vulnerabilities)
            if total_results is None
            else total_results
        ),
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2003-08-20T10:55:00.000",
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def make_meta(
    content: bytes,
    compressed: bytes,
    *,
    last_modified: str = "2003-08-20T06:00:00-04:00",
    size: int | None = None,
    gz_size: int | None = None,
    sha256: str | None = None,
) -> bytes:
    values = (
        f"lastModifiedDate:{last_modified}",
        f"size:{len(content) if size is None else size}",
        "zipSize:0",
        f"gzSize:{len(compressed) if gz_size is None else gz_size}",
        "sha256:"
        + (
            hashlib.sha256(content).hexdigest()
            if sha256 is None
            else sha256
        ),
    )
    return ("\n".join(values) + "\n").encode("utf-8")


class FakeUrlOpen:
    def __init__(self, responses: dict[str, bytes | list[bytes]]) -> None:
        self.responses = responses
        self.calls: list[str] = []
        self.requests: list[Request] = []

    def __call__(
        self,
        request: Request,
        *,
        timeout: float,
    ) -> io.BytesIO:
        if timeout <= 0:
            raise AssertionError("timeout must be positive")
        self.calls.append(request.full_url)
        self.requests.append(request)
        if request.full_url not in self.responses:
            raise URLError("fixture URL missing")
        response = self.responses[request.full_url]
        if isinstance(response, list):
            if not response:
                raise AssertionError("fixture response sequence exhausted")
            response = response.pop(0)
        return io.BytesIO(response)


def make_sources(
    documents: dict[int, bytes] | None = None,
) -> tuple[dict[str, bytes | list[bytes]], dict[int, bytes]]:
    documents = documents or {
        2002: make_document(["CVE-2001-0001", "CVE-2002-0001"]),
        2003: make_document(["CVE-2003-0001"]),
    }
    responses: dict[str, bytes | list[bytes]] = {}
    for year, content in documents.items():
        compressed = gzip.compress(content, mtime=0)
        responses[meta_url(BASE_URL, year)] = make_meta(
            content,
            compressed,
        )
        responses[feed_url(BASE_URL, year)] = compressed
    return responses, documents


def acquire(
    output_root: Path,
    opener: FakeUrlOpen,
    *,
    now_func=lambda: CAPTURED_AT,
) -> SnapshotResult:
    return acquire_snapshot(
        output_root,
        base_url=BASE_URL,
        urlopen_func=opener,
        sleep_func=lambda delay: None,
        now_func=now_func,
    )


class MetadataTests(SimpleTestCase):
    def test_snapshot_id_uses_capture_start_in_utc(self) -> None:
        captured = datetime(
            2003,
            8,
            20,
            6,
            55,
            tzinfo=timezone(timedelta(hours=-4)),
        )
        self.assertEqual(
            snapshot_id_from_capture_started(captured),
            SNAPSHOT_ID,
        )

    def test_parses_valid_meta(self) -> None:
        content = b"{}"
        compressed = gzip.compress(content, mtime=0)
        metadata = parse_metadata(make_meta(content, compressed).decode())
        self.assertEqual(metadata.size, len(content))
        self.assertEqual(metadata.gz_size, len(compressed))
        self.assertEqual(
            metadata.sha256,
            hashlib.sha256(content).hexdigest(),
        )

    def test_rejects_malformed_meta(self) -> None:
        with self.assertRaisesRegex(MetadataError, "missing required"):
            parse_metadata("size:1\n")

    def test_management_command_is_registered(self) -> None:
        self.assertIn("download_nvd_cve_snapshot", get_commands())


class SnapshotAcquisitionTests(SimpleTestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.output_root = Path(self.temporary_directory.name) / "nvd-cve"

    def test_acquires_and_atomically_publishes_yearly_feeds(self) -> None:
        responses, documents = make_sources()
        result = acquire(self.output_root, FakeUrlOpen(responses))

        self.assertEqual(result.snapshot_id, SNAPSHOT_ID)
        self.assertFalse(result.already_verified)
        self.assertEqual(result.manifest["status"], "VERIFIED")
        self.assertEqual(result.manifest["feed_count"], 2)
        self.assertEqual(result.manifest["total_declared_count"], 3)
        self.assertEqual(result.manifest["total_parsed_count"], 3)
        self.assertEqual(result.manifest["duplicate_cve_count"], 0)
        self.assertEqual(
            result.manifest["content"]["aggregate_sha256"],
            hashlib.sha256(documents[2002] + documents[2003]).hexdigest(),
        )
        feeds_path = result.snapshot_path / "feeds"
        self.assertEqual(
            {path.name for path in feeds_path.iterdir()},
            {
                meta_filename(2002),
                feed_filename(2002),
                meta_filename(2003),
                feed_filename(2003),
            },
        )
        self.assertFalse(any(self.output_root.glob(".*.tmp-*")))
        verified = verify_snapshot(self.output_root, SNAPSHOT_ID)
        self.assertEqual(verified, result.manifest)

    def test_rejects_compressed_size_mismatch(self) -> None:
        responses, documents = make_sources()
        compressed = responses[feed_url(BASE_URL, 2003)]
        assert isinstance(compressed, bytes)
        responses[meta_url(BASE_URL, 2003)] = make_meta(
            documents[2003],
            compressed,
            gz_size=len(compressed) + 1,
        )
        with self.assertRaisesRegex(IntegrityError, "compressed size"):
            acquire(self.output_root, FakeUrlOpen(responses))
        self.assertEqual(list(self.output_root.iterdir()), [])

    def test_rejects_uncompressed_size_mismatch(self) -> None:
        responses, documents = make_sources()
        compressed = responses[feed_url(BASE_URL, 2003)]
        assert isinstance(compressed, bytes)
        responses[meta_url(BASE_URL, 2003)] = make_meta(
            documents[2003],
            compressed,
            size=len(documents[2003]) + 1,
        )
        with self.assertRaisesRegex(IntegrityError, "uncompressed size"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_uncompressed_sha256_mismatch(self) -> None:
        responses, documents = make_sources()
        compressed = responses[feed_url(BASE_URL, 2003)]
        assert isinstance(compressed, bytes)
        responses[meta_url(BASE_URL, 2003)] = make_meta(
            documents[2003],
            compressed,
            sha256="0" * 64,
        )
        with self.assertRaisesRegex(IntegrityError, "SHA-256"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_malformed_gzip(self) -> None:
        responses, documents = make_sources()
        invalid = b"not-a-gzip-file"
        responses[feed_url(BASE_URL, 2003)] = invalid
        responses[meta_url(BASE_URL, 2003)] = make_meta(
            documents[2003],
            invalid,
        )
        with self.assertRaisesRegex(FeedValidationError, "valid gzip"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_malformed_utf8(self) -> None:
        responses, _ = make_sources({
            2002: make_document(["CVE-2002-0001"]),
            2003: b"\xff",
        })
        with self.assertRaisesRegex(FeedValidationError, "valid UTF-8"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_malformed_json(self) -> None:
        responses, _ = make_sources({
            2002: make_document(["CVE-2002-0001"]),
            2003: b"{not-json}",
        })
        with self.assertRaisesRegex(FeedValidationError, "valid JSON"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_results_per_page_mismatch(self) -> None:
        responses, _ = make_sources({
            2002: make_document(["CVE-2002-0001"]),
            2003: make_document(
                ["CVE-2003-0001"],
                results_per_page=2,
            ),
        })
        with self.assertRaisesRegex(FeedValidationError, "resultsPerPage"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_total_results_mismatch(self) -> None:
        responses, _ = make_sources({
            2002: make_document(["CVE-2002-0001"]),
            2003: make_document(
                ["CVE-2003-0001"],
                total_results=2,
            ),
        })
        with self.assertRaisesRegex(FeedValidationError, "totalResults"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_start_index_mismatch(self) -> None:
        responses, _ = make_sources({
            2002: make_document(["CVE-2002-0001"]),
            2003: make_document(
                ["CVE-2003-0001"],
                start_index=1,
            ),
        })
        with self.assertRaisesRegex(FeedValidationError, "startIndex"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_cve_id_extraction_failure(self) -> None:
        responses, _ = make_sources({
            2002: make_document(["CVE-2002-0001"]),
            2003: make_document(["not-a-cve"]),
        })
        with self.assertRaisesRegex(FeedValidationError, "invalid CVE ID"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_missing_yearly_feed_and_cleans_staging(self) -> None:
        responses, _ = make_sources()
        del responses[feed_url(BASE_URL, 2003)]
        with self.assertRaises(DownloadError):
            acquire(self.output_root, FakeUrlOpen(responses))
        self.assertTrue(self.output_root.is_dir())
        self.assertEqual(list(self.output_root.iterdir()), [])

    def test_rejects_duplicate_cve_id_across_yearly_feeds(self) -> None:
        responses, _ = make_sources({
            2002: make_document(["CVE-2002-0001"]),
            2003: make_document(["CVE-2002-0001"]),
        })
        with self.assertRaisesRegex(FeedValidationError, "duplicate CVE ID"):
            acquire(self.output_root, FakeUrlOpen(responses))

    def test_rejects_meta_change_during_acquisition(self) -> None:
        responses, documents = make_sources()
        original = responses[meta_url(BASE_URL, 2003)]
        compressed = responses[feed_url(BASE_URL, 2003)]
        assert isinstance(original, bytes)
        assert isinstance(compressed, bytes)
        changed = make_meta(
            documents[2003],
            compressed,
            last_modified="2003-08-20T06:01:00-04:00",
        )
        responses[meta_url(BASE_URL, 2003)] = [original, changed]
        with self.assertRaisesRegex(IntegrityError, "changed"):
            acquire(self.output_root, FakeUrlOpen(responses))
        self.assertEqual(list(self.output_root.iterdir()), [])

    def test_existing_verified_snapshot_is_noop(self) -> None:
        responses, _ = make_sources()
        opener = FakeUrlOpen(responses)
        first = acquire(self.output_root, opener)
        manifest_before = (
            first.snapshot_path / "manifest.json"
        ).read_bytes()
        feed_calls_before = sum(
            call.endswith(".json.gz") for call in opener.calls
        )

        second = acquire(self.output_root, opener)

        self.assertTrue(second.already_verified)
        self.assertEqual(second.snapshot_path, first.snapshot_path)
        self.assertEqual(
            (second.snapshot_path / "manifest.json").read_bytes(),
            manifest_before,
        )
        self.assertEqual(
            sum(call.endswith(".json.gz") for call in opener.calls),
            feed_calls_before,
        )

    def test_conflicting_existing_snapshot_is_not_overwritten(self) -> None:
        final_path = self.output_root / SNAPSHOT_ID
        final_path.mkdir(parents=True)
        sentinel = final_path / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")
        responses, _ = make_sources()

        with self.assertRaises(ExistingSnapshotError):
            acquire(self.output_root, FakeUrlOpen(responses))

        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_aggregate_hash_is_deterministic_by_year(self) -> None:
        responses_one, documents = make_sources()
        responses_two, _ = make_sources()
        second_root = Path(self.temporary_directory.name) / "second"
        first = acquire(self.output_root, FakeUrlOpen(responses_one))
        second = acquire(second_root, FakeUrlOpen(responses_two))
        expected = hashlib.sha256(
            documents[2002] + documents[2003]
        ).hexdigest()
        self.assertEqual(
            first.manifest["content"]["ordering"],
            "feed-year-ascending",
        )
        self.assertEqual(first.manifest["content"]["separator"], "none")
        self.assertEqual(
            first.manifest["content"]["aggregate_sha256"],
            expected,
        )
        self.assertEqual(
            second.manifest["content"]["aggregate_sha256"],
            expected,
        )

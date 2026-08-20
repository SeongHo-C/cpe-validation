from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


NVD_CVE_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
SOURCE_NAME = "NVD CVE JSON 2.0 Yearly Feeds"
MANIFEST_FILENAME = "manifest.json"
FEEDS_DIRECTORY = "feeds"
MINIMUM_FEED_YEAR = 2002
USER_AGENT = "cpe-validation-research/1.0"
DEFAULT_TIMEOUT_SECONDS = 300
MAX_DOWNLOAD_ATTEMPTS = 3
CHUNK_SIZE = 1024 * 1024
PROGRESS_INTERVAL = 25 * 1024 * 1024
MAX_META_SIZE = 1024 * 1024
CONTENT_FORMAT = "nvd-cve-json-2.0-yearly-feeds"
CONTENT_ORDERING = "feed-year-ascending"
CONTENT_SEPARATOR = "none"
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
SNAPSHOT_ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z$")
CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
REQUIRED_META_FIELDS = {
    "lastModifiedDate",
    "size",
    "zipSize",
    "gzSize",
    "sha256",
}


class SnapshotError(Exception):
    """Base error for NVD CVE snapshot acquisition."""


class MetadataError(SnapshotError):
    """An NVD yearly feed META document is malformed."""


class DownloadError(SnapshotError):
    """An NVD source could not be downloaded after retries."""


class FeedValidationError(SnapshotError):
    """A yearly feed is malformed or internally inconsistent."""


class IntegrityError(SnapshotError):
    """Downloaded bytes do not match their NVD META document."""


class ExistingSnapshotError(SnapshotError):
    """An existing snapshot is incomplete or conflicts."""


class UrlOpen(Protocol):
    def __call__(
        self,
        request: Request,
        *,
        timeout: float,
    ) -> BinaryIO: ...


@dataclass(frozen=True)
class FeedMetadata:
    last_modified: datetime
    size: int
    zip_size: int
    gz_size: int
    sha256: str
    raw_fields: Mapping[str, str]


@dataclass(frozen=True)
class ValidatedFeed:
    year: int
    compressed_size: int
    compressed_sha256: str
    uncompressed_size: int
    uncompressed_sha256: str
    declared_count: int
    parsed_count: int
    cve_ids: frozenset[str]


@dataclass(frozen=True)
class SnapshotResult:
    snapshot_id: str
    snapshot_path: Path
    manifest: Mapping[str, object]
    already_verified: bool


Reporter = Callable[[str], None]
Sleep = Callable[[float], None]
Now = Callable[[], datetime]


def _silent_reporter(message: str) -> None:
    del message


def _utc_isoformat(value: datetime) -> str:
    if value.utcoffset() is None:
        raise MetadataError("Snapshot timestamp must include a UTC offset")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def snapshot_id_from_capture_started(capture_started: datetime) -> str:
    if capture_started.utcoffset() is None:
        raise MetadataError("Snapshot timestamp must include a UTC offset")
    return capture_started.astimezone(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )


def meta_filename(year: int) -> str:
    return f"nvdcve-2.0-{year}.meta"


def feed_filename(year: int) -> str:
    return f"nvdcve-2.0-{year}.json.gz"


def meta_url(base_url: str, year: int) -> str:
    return f"{base_url.rstrip('/')}/{meta_filename(year)}"


def feed_url(base_url: str, year: int) -> str:
    return f"{base_url.rstrip('/')}/{feed_filename(year)}"


def _request(url: str) -> Request:
    return Request(
        url,
        headers={
            "Accept": "*/*",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )


def _download_error_detail(error: BaseException) -> str:
    if isinstance(error, HTTPError):
        return f"HTTP {error.code} {error.reason}"
    if isinstance(error, URLError):
        return f"URL error: {error.reason}"
    return f"{type(error).__name__}: {error}"


def parse_metadata(text: str) -> FeedMetadata:
    fields: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        key, separator, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not separator or not key:
            raise MetadataError(
                f"META line {line_number} is not key:value"
            )
        if key in fields:
            raise MetadataError(f"META contains duplicate key: {key}")
        if not value:
            raise MetadataError(f"META value is empty: {key}")
        fields[key] = value

    missing = sorted(REQUIRED_META_FIELDS - fields.keys())
    if missing:
        raise MetadataError(
            "META is missing required field(s): " + ", ".join(missing)
        )

    integers: dict[str, int] = {}
    for key in ("size", "zipSize", "gzSize"):
        try:
            parsed = int(fields[key])
        except ValueError as error:
            raise MetadataError(f"META {key} must be an integer") from error
        if parsed < 0:
            raise MetadataError(f"META {key} must not be negative")
        integers[key] = parsed

    try:
        last_modified = datetime.fromisoformat(
            fields["lastModifiedDate"].replace("Z", "+00:00")
        )
    except ValueError as error:
        raise MetadataError(
            "META lastModifiedDate must be a valid ISO-8601 datetime"
        ) from error
    if last_modified.utcoffset() is None:
        raise MetadataError(
            "META lastModifiedDate must include a UTC offset"
        )

    raw_sha256 = fields["sha256"]
    if not SHA256_PATTERN.fullmatch(raw_sha256):
        raise MetadataError(
            "META sha256 must contain 64 hexadecimal characters"
        )

    return FeedMetadata(
        last_modified=last_modified,
        size=integers["size"],
        zip_size=integers["zipSize"],
        gz_size=integers["gzSize"],
        sha256=raw_sha256.lower(),
        raw_fields=MappingProxyType(dict(fields)),
    )


def download_metadata(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen_func: UrlOpen = urlopen,
    sleep_func: Sleep = time.sleep,
) -> bytes:
    last_error: BaseException | None = None
    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        try:
            with urlopen_func(
                _request(url),
                timeout=timeout,
            ) as response:
                chunks: list[bytes] = []
                total_size = 0
                while True:
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total_size += len(chunk)
                    if total_size > MAX_META_SIZE:
                        raise DownloadError(
                            "META response exceeds the maximum size"
                        )
                    chunks.append(chunk)
                return b"".join(chunks)
        except DownloadError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt < MAX_DOWNLOAD_ATTEMPTS:
                sleep_func(float(attempt))
    raise DownloadError(
        f"Unable to download META after {MAX_DOWNLOAD_ATTEMPTS} attempts"
    ) from last_error


def download_feed(
    url: str,
    destination: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen_func: UrlOpen = urlopen,
    sleep_func: Sleep = time.sleep,
    reporter: Reporter = _silent_reporter,
) -> tuple[int, str]:
    last_error: BaseException | None = None
    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        try:
            destination.unlink(missing_ok=True)
            digest = hashlib.sha256()
            total_size = 0
            next_progress = PROGRESS_INTERVAL
            with (
                urlopen_func(
                    _request(url),
                    timeout=timeout,
                ) as response,
                destination.open("xb") as output,
            ):
                while True:
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    output.write(chunk)
                    digest.update(chunk)
                    total_size += len(chunk)
                    if total_size >= next_progress:
                        reporter(f"Downloaded {total_size} bytes")
                        next_progress += PROGRESS_INTERVAL
                output.flush()
                os.fsync(output.fileno())
            return total_size, digest.hexdigest()
        except FileExistsError as error:
            destination.unlink(missing_ok=True)
            raise SnapshotError(
                f"Partial download already exists: {destination.name}"
            ) from error
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            last_error = error
            destination.unlink(missing_ok=True)
            reporter(
                f"Feed download attempt {attempt} failed: "
                f"{_download_error_detail(error)}"
            )
            if attempt < MAX_DOWNLOAD_ATTEMPTS:
                sleep_func(float(attempt))
    raise DownloadError(
        f"Unable to download Feed after {MAX_DOWNLOAD_ATTEMPTS} attempts"
        + (
            f": {_download_error_detail(last_error)}"
            if last_error is not None
            else ""
        )
    ) from last_error


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _is_nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _validate_feed_json(value: object, *, year: int) -> tuple[int, set[str]]:
    if not isinstance(value, dict):
        raise FeedValidationError(
            f"Feed {year} top-level value must be an object"
        )
    required = (
        "resultsPerPage",
        "startIndex",
        "totalResults",
        "format",
        "version",
        "timestamp",
        "vulnerabilities",
    )
    missing = [key for key in required if key not in value]
    if missing:
        raise FeedValidationError(
            f"Feed {year} is missing top-level field(s): "
            + ", ".join(missing)
        )

    results_per_page = value["resultsPerPage"]
    start_index = value["startIndex"]
    total_results = value["totalResults"]
    vulnerabilities = value["vulnerabilities"]
    if (
        not _is_nonnegative_integer(results_per_page)
        or not _is_nonnegative_integer(start_index)
        or not _is_nonnegative_integer(total_results)
        or not isinstance(vulnerabilities, list)
    ):
        raise FeedValidationError(
            f"Feed {year} pagination/vulnerabilities types are invalid"
        )
    if (
        value["format"] != "NVD_CVE"
        or value["version"] != "2.0"
        or not isinstance(value["timestamp"], str)
        or not value["timestamp"]
    ):
        raise FeedValidationError(
            f"Feed {year} JSON 2.0 identity fields are invalid"
        )
    if start_index != 0:
        raise FeedValidationError(f"Feed {year} startIndex must be 0")
    if results_per_page != len(vulnerabilities):
        raise FeedValidationError(
            f"Feed {year} resultsPerPage does not match vulnerabilities"
        )
    if total_results != len(vulnerabilities):
        raise FeedValidationError(
            f"Feed {year} totalResults does not match vulnerabilities"
        )

    cve_ids: set[str] = set()
    for index, item in enumerate(vulnerabilities, start=1):
        cve = item.get("cve") if isinstance(item, dict) else None
        cve_id = cve.get("id") if isinstance(cve, dict) else None
        if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
            raise FeedValidationError(
                f"Feed {year} vulnerability {index} has an invalid CVE ID"
            )
        if cve_id in cve_ids:
            raise FeedValidationError(
                f"Feed {year} contains duplicate CVE ID: {cve_id}"
            )
        cve_ids.add(cve_id)
    return total_results, cve_ids


def validate_yearly_feed(
    feed_path: Path,
    *,
    year: int,
    metadata: FeedMetadata,
    aggregate_digest: object | None = None,
) -> ValidatedFeed:
    compressed_size = feed_path.stat().st_size
    compressed_sha256 = file_sha256(feed_path)
    if compressed_size != metadata.gz_size:
        raise IntegrityError(
            f"Feed {year} compressed size does not match META gzSize"
        )

    content_digest = hashlib.sha256()
    uncompressed_size = 0
    try:
        with gzip.open(feed_path, mode="rb") as source:
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                content_digest.update(chunk)
                if aggregate_digest is not None:
                    aggregate_digest.update(chunk)
                uncompressed_size += len(chunk)
    except (gzip.BadGzipFile, EOFError, OSError) as error:
        raise FeedValidationError(
            f"Feed {year} is not a valid gzip file"
        ) from error

    uncompressed_sha256 = content_digest.hexdigest()
    if uncompressed_size != metadata.size:
        raise IntegrityError(
            f"Feed {year} uncompressed size does not match META size"
        )
    if uncompressed_sha256 != metadata.sha256:
        raise IntegrityError(
            f"Feed {year} uncompressed SHA-256 does not match META"
        )

    try:
        with gzip.open(feed_path, mode="rb") as binary:
            with io.TextIOWrapper(binary, encoding="utf-8") as text:
                value = json.load(text)
    except UnicodeError as error:
        raise FeedValidationError(
            f"Feed {year} content is not valid UTF-8"
        ) from error
    except json.JSONDecodeError as error:
        raise FeedValidationError(
            f"Feed {year} content is not valid JSON"
        ) from error
    except (gzip.BadGzipFile, EOFError, OSError) as error:
        raise FeedValidationError(
            f"Feed {year} could not be read as gzip JSON"
        ) from error

    declared_count, cve_ids = _validate_feed_json(value, year=year)
    return ValidatedFeed(
        year=year,
        compressed_size=compressed_size,
        compressed_sha256=compressed_sha256,
        uncompressed_size=uncompressed_size,
        uncompressed_sha256=uncompressed_sha256,
        declared_count=declared_count,
        parsed_count=len(cve_ids),
        cve_ids=frozenset(cve_ids),
    )


def _metadata_manifest(metadata: FeedMetadata) -> dict[str, object]:
    return {
        "size": metadata.size,
        "zip_size": metadata.zip_size,
        "gz_size": metadata.gz_size,
        "sha256": metadata.sha256,
    }


def _feed_manifest(
    *,
    year: int,
    metadata_bytes: bytes,
    metadata: FeedMetadata,
    feed: ValidatedFeed,
) -> dict[str, object]:
    return {
        "year": year,
        "meta_filename": meta_filename(year),
        "meta_size": len(metadata_bytes),
        "meta_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
        "feed_filename": feed_filename(year),
        "feed_last_modified": _utc_isoformat(metadata.last_modified),
        "meta": _metadata_manifest(metadata),
        "compressed_size": feed.compressed_size,
        "compressed_sha256": feed.compressed_sha256,
        "uncompressed_size": feed.uncompressed_size,
        "uncompressed_sha256": feed.uncompressed_sha256,
        "declared_count": feed.declared_count,
        "parsed_count": feed.parsed_count,
    }


def build_manifest(
    *,
    snapshot_id: str,
    base_url: str,
    capture_started_at: datetime,
    retrieved_at: datetime,
    capture_completed_at: datetime,
    feed_manifests: list[dict[str, object]],
    aggregate_size: int,
    aggregate_sha256: str,
    total_declared_count: int,
    total_parsed_count: int,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "snapshot_id": snapshot_id,
        "status": "VERIFIED",
        "source": SOURCE_NAME,
        "source_base_url": base_url.rstrip("/"),
        "capture_started_at": _utc_isoformat(capture_started_at),
        "retrieved_at": _utc_isoformat(retrieved_at),
        "capture_completed_at": _utc_isoformat(capture_completed_at),
        "feed_count": len(feed_manifests),
        "feeds": feed_manifests,
        "total_declared_count": total_declared_count,
        "total_parsed_count": total_parsed_count,
        "duplicate_cve_count": 0,
        "content": {
            "format": CONTENT_FORMAT,
            "ordering": CONTENT_ORDERING,
            "separator": CONTENT_SEPARATOR,
            "aggregate_size": aggregate_size,
            "aggregate_sha256": aggregate_sha256,
        },
        "validation": {
            "yearly_feed_range_complete": True,
            "meta_stable_during_acquisition": True,
            "compressed_sizes_match_meta": True,
            "uncompressed_sizes_match_meta": True,
            "uncompressed_sha256_matches_meta": True,
            "json_valid": True,
            "record_counts_match": True,
            "cve_ids_valid": True,
            "duplicate_cve_ids_absent": True,
        },
    }


def _write_bytes(path: Path, data: bytes) -> None:
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _write_json(path: Path, data: Mapping[str, object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(data, output, ensure_ascii=False, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def _load_manifest(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ExistingSnapshotError(
            "Existing snapshot manifest is unreadable"
        ) from error
    if not isinstance(value, dict):
        raise ExistingSnapshotError(
            "Existing snapshot manifest is not a JSON object"
        )
    return value


def _parse_manifest_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ExistingSnapshotError(f"Existing manifest {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ExistingSnapshotError(
            f"Existing manifest {field} is invalid"
        ) from error
    if parsed.utcoffset() is None:
        raise ExistingSnapshotError(
            f"Existing manifest {field} is not timezone-aware"
        )
    return parsed.astimezone(timezone.utc)


def _expected_validation() -> dict[str, bool]:
    return {
        "yearly_feed_range_complete": True,
        "meta_stable_during_acquisition": True,
        "compressed_sizes_match_meta": True,
        "uncompressed_sizes_match_meta": True,
        "uncompressed_sha256_matches_meta": True,
        "json_valid": True,
        "record_counts_match": True,
        "cve_ids_valid": True,
        "duplicate_cve_ids_absent": True,
    }


def _validate_existing_snapshot(
    *,
    final_path: Path,
    snapshot_id: str,
    years: tuple[int, ...],
    base_url: str,
    current_metadata: Mapping[int, FeedMetadata] | None,
) -> Mapping[str, object]:
    manifest_path = final_path / MANIFEST_FILENAME
    feeds_path = final_path / FEEDS_DIRECTORY
    if (
        final_path.is_symlink()
        or manifest_path.is_symlink()
        or feeds_path.is_symlink()
        or not manifest_path.is_file()
        or not feeds_path.is_dir()
    ):
        raise ExistingSnapshotError(
            "Existing snapshot is incomplete and will not be overwritten"
        )
    manifest = _load_manifest(manifest_path)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("snapshot_id") != snapshot_id
        or manifest.get("status") != "VERIFIED"
        or manifest.get("source") != SOURCE_NAME
        or manifest.get("source_base_url") != base_url.rstrip("/")
        or manifest.get("feed_count") != len(years)
        or manifest.get("validation") != _expected_validation()
    ):
        raise ExistingSnapshotError(
            "Existing snapshot manifest is incomplete or conflicting"
        )

    started = _parse_manifest_datetime(
        manifest.get("capture_started_at"),
        "capture_started_at",
    )
    retrieved = _parse_manifest_datetime(
        manifest.get("retrieved_at"),
        "retrieved_at",
    )
    completed = _parse_manifest_datetime(
        manifest.get("capture_completed_at"),
        "capture_completed_at",
    )
    if (
        snapshot_id_from_capture_started(started) != snapshot_id
        or years
        != tuple(range(MINIMUM_FEED_YEAR, started.year + 1))
        or not started <= retrieved <= completed
    ):
        raise ExistingSnapshotError(
            "Existing snapshot timestamps are inconsistent"
        )

    feed_entries = manifest.get("feeds")
    if not isinstance(feed_entries, list) or len(feed_entries) != len(years):
        raise ExistingSnapshotError(
            "Existing snapshot feed manifest is incomplete"
        )
    expected_files = {
        filename
        for year in years
        for filename in (meta_filename(year), feed_filename(year))
    }
    feed_paths = list(feeds_path.iterdir())
    actual_files = {path.name for path in feed_paths if path.is_file()}
    if actual_files != expected_files or any(
        path.is_symlink() or not path.is_file() for path in feed_paths
    ):
        raise ExistingSnapshotError(
            "Existing snapshot feed files are incomplete or unexpected"
        )

    aggregate_digest = hashlib.sha256()
    aggregate_size = 0
    total_declared = 0
    total_parsed = 0
    all_cve_ids: set[str] = set()
    for expected_year, entry in zip(years, feed_entries, strict=True):
        if not isinstance(entry, dict) or entry.get("year") != expected_year:
            raise ExistingSnapshotError(
                "Existing snapshot feed ordering is invalid"
            )
        meta_path = feeds_path / meta_filename(expected_year)
        feed_path = feeds_path / feed_filename(expected_year)
        try:
            metadata_bytes = meta_path.read_bytes()
            metadata = parse_metadata(metadata_bytes.decode("utf-8"))
        except (OSError, UnicodeError, MetadataError) as error:
            raise ExistingSnapshotError(
                f"Existing feed {expected_year} META is invalid"
            ) from error
        if (
            entry.get("meta_filename") != meta_filename(expected_year)
            or entry.get("feed_filename") != feed_filename(expected_year)
            or entry.get("meta_size") != len(metadata_bytes)
            or entry.get("meta_sha256")
            != hashlib.sha256(metadata_bytes).hexdigest()
            or entry.get("feed_last_modified")
            != _utc_isoformat(metadata.last_modified)
            or entry.get("meta") != _metadata_manifest(metadata)
        ):
            raise ExistingSnapshotError(
                f"Existing feed {expected_year} META manifest conflicts"
            )
        if (
            current_metadata is not None
            and metadata.raw_fields
            != current_metadata[expected_year].raw_fields
        ):
            raise ExistingSnapshotError(
                f"Existing feed {expected_year} META changed at source"
            )
        try:
            feed = validate_yearly_feed(
                feed_path,
                year=expected_year,
                metadata=metadata,
                aggregate_digest=aggregate_digest,
            )
        except SnapshotError as error:
            raise ExistingSnapshotError(
                f"Existing feed {expected_year} validation failed"
            ) from error
        expected_entry = _feed_manifest(
            year=expected_year,
            metadata_bytes=metadata_bytes,
            metadata=metadata,
            feed=feed,
        )
        if entry != expected_entry:
            raise ExistingSnapshotError(
                f"Existing feed {expected_year} manifest conflicts"
            )
        duplicate = all_cve_ids.intersection(feed.cve_ids)
        if duplicate:
            raise ExistingSnapshotError(
                "Existing snapshot contains duplicate CVE ID: "
                f"{min(duplicate)}"
            )
        all_cve_ids.update(feed.cve_ids)
        aggregate_size += feed.uncompressed_size
        total_declared += feed.declared_count
        total_parsed += feed.parsed_count

    content = manifest.get("content")
    if (
        manifest.get("total_declared_count") != total_declared
        or manifest.get("total_parsed_count") != total_parsed
        or manifest.get("duplicate_cve_count") != 0
        or content
        != {
            "format": CONTENT_FORMAT,
            "ordering": CONTENT_ORDERING,
            "separator": CONTENT_SEPARATOR,
            "aggregate_size": aggregate_size,
            "aggregate_sha256": aggregate_digest.hexdigest(),
        }
    ):
        raise ExistingSnapshotError(
            "Existing snapshot counts or aggregate content conflict"
        )
    return MappingProxyType(manifest)


def verify_snapshot(
    output_root: Path,
    snapshot_id: str,
) -> Mapping[str, object]:
    if not SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id):
        raise ExistingSnapshotError(
            "snapshot_id must use YYYYMMDDTHHMMSSZ format"
        )
    final_path = output_root.resolve() / snapshot_id
    manifest = _load_manifest(final_path / MANIFEST_FILENAME)
    entries = manifest.get("feeds")
    if not isinstance(entries, list):
        raise ExistingSnapshotError(
            "Existing snapshot feed manifest is incomplete"
        )
    years = tuple(
        entry.get("year") if isinstance(entry, dict) else None
        for entry in entries
    )
    if (
        not years
        or any(type(year) is not int for year in years)
        or years != tuple(range(MINIMUM_FEED_YEAR, years[-1] + 1))
    ):
        raise ExistingSnapshotError(
            "Existing snapshot feed year range is invalid"
        )
    base_url = manifest.get("source_base_url")
    if not isinstance(base_url, str) or not base_url:
        raise ExistingSnapshotError(
            "Existing snapshot source_base_url is invalid"
        )
    return _validate_existing_snapshot(
        final_path=final_path,
        snapshot_id=snapshot_id,
        years=years,
        base_url=base_url,
        current_metadata=None,
    )


def _download_all_metadata(
    *,
    years: tuple[int, ...],
    base_url: str,
    timeout: float,
    urlopen_func: UrlOpen,
    sleep_func: Sleep,
    reporter: Reporter,
) -> tuple[dict[int, bytes], dict[int, FeedMetadata]]:
    raw_by_year: dict[int, bytes] = {}
    parsed_by_year: dict[int, FeedMetadata] = {}
    for year in years:
        reporter(f"Downloading META for CVE-{year}")
        raw = download_metadata(
            meta_url(base_url, year),
            timeout=timeout,
            urlopen_func=urlopen_func,
            sleep_func=sleep_func,
        )
        try:
            parsed = parse_metadata(raw.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise MetadataError(f"META for CVE-{year} must be UTF-8") from error
        raw_by_year[year] = raw
        parsed_by_year[year] = parsed
    return raw_by_year, parsed_by_year


def acquire_snapshot(
    output_root: Path,
    *,
    base_url: str = NVD_CVE_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen_func: UrlOpen = urlopen,
    sleep_func: Sleep = time.sleep,
    now_func: Now = lambda: datetime.now(timezone.utc),
    reporter: Reporter = _silent_reporter,
) -> SnapshotResult:
    capture_started_at = now_func()
    snapshot_id = snapshot_id_from_capture_started(capture_started_at)
    current_year = capture_started_at.astimezone(timezone.utc).year
    if current_year < MINIMUM_FEED_YEAR:
        raise MetadataError(
            f"Capture year must be at least {MINIMUM_FEED_YEAR}"
        )
    years = tuple(range(MINIMUM_FEED_YEAR, current_year + 1))
    output_root = output_root.resolve()
    final_path = output_root / snapshot_id

    initial_meta_bytes, initial_metadata = _download_all_metadata(
        years=years,
        base_url=base_url,
        timeout=timeout,
        urlopen_func=urlopen_func,
        sleep_func=sleep_func,
        reporter=reporter,
    )
    if final_path.exists():
        if final_path.is_symlink() or not final_path.is_dir():
            raise ExistingSnapshotError(
                "Existing snapshot path is not a directory"
            )
        manifest = _validate_existing_snapshot(
            final_path=final_path,
            snapshot_id=snapshot_id,
            years=years,
            base_url=base_url,
            current_metadata=initial_metadata,
        )
        return SnapshotResult(
            snapshot_id=snapshot_id,
            snapshot_path=final_path,
            manifest=manifest,
            already_verified=True,
        )

    output_root.mkdir(parents=True, exist_ok=True)
    temporary_path = Path(
        tempfile.mkdtemp(
            prefix=f".{snapshot_id}.tmp-",
            dir=output_root,
        )
    )
    try:
        feeds_path = temporary_path / FEEDS_DIRECTORY
        feeds_path.mkdir()
        for year in years:
            _write_bytes(
                feeds_path / meta_filename(year),
                initial_meta_bytes[year],
            )

        aggregate_digest = hashlib.sha256()
        aggregate_size = 0
        total_declared = 0
        total_parsed = 0
        all_cve_ids: set[str] = set()
        feed_manifests: list[dict[str, object]] = []
        for index, year in enumerate(years, start=1):
            reporter(
                f"Downloading CVE-{year} feed ({index}/{len(years)})"
            )
            part_path = feeds_path / f"{feed_filename(year)}.part"
            downloaded_size, downloaded_sha256 = download_feed(
                feed_url(base_url, year),
                part_path,
                timeout=timeout,
                urlopen_func=urlopen_func,
                sleep_func=sleep_func,
                reporter=reporter,
            )
            metadata = initial_metadata[year]
            if downloaded_size != metadata.gz_size:
                raise IntegrityError(
                    f"Feed {year} compressed size does not match META gzSize"
                )
            feed = validate_yearly_feed(
                part_path,
                year=year,
                metadata=metadata,
                aggregate_digest=aggregate_digest,
            )
            if feed.compressed_sha256 != downloaded_sha256:
                raise IntegrityError(
                    f"Feed {year} compressed SHA-256 changed after download"
                )
            duplicate = all_cve_ids.intersection(feed.cve_ids)
            if duplicate:
                raise FeedValidationError(
                    "Yearly feeds contain duplicate CVE ID: "
                    f"{min(duplicate)}"
                )
            all_cve_ids.update(feed.cve_ids)
            aggregate_size += feed.uncompressed_size
            total_declared += feed.declared_count
            total_parsed += feed.parsed_count
            feed_manifests.append(
                _feed_manifest(
                    year=year,
                    metadata_bytes=initial_meta_bytes[year],
                    metadata=metadata,
                    feed=feed,
                )
            )
            part_path.rename(feeds_path / feed_filename(year))
            reporter(
                f"Validated CVE-{year}: {feed.parsed_count} CVEs"
            )

        retrieved_at = now_func()
        _, final_metadata = _download_all_metadata(
            years=years,
            base_url=base_url,
            timeout=timeout,
            urlopen_func=urlopen_func,
            sleep_func=sleep_func,
            reporter=reporter,
        )
        for year in years:
            if (
                initial_metadata[year].raw_fields
                != final_metadata[year].raw_fields
            ):
                raise IntegrityError(
                    f"META for CVE-{year} changed during acquisition"
                )

        capture_completed_at = now_func()
        manifest = build_manifest(
            snapshot_id=snapshot_id,
            base_url=base_url,
            capture_started_at=capture_started_at,
            retrieved_at=retrieved_at,
            capture_completed_at=capture_completed_at,
            feed_manifests=feed_manifests,
            aggregate_size=aggregate_size,
            aggregate_sha256=aggregate_digest.hexdigest(),
            total_declared_count=total_declared,
            total_parsed_count=total_parsed,
        )
        _write_json(temporary_path / MANIFEST_FILENAME, manifest)
        if final_path.exists():
            raise ExistingSnapshotError(
                "Snapshot path appeared during acquisition; refusing to overwrite"
            )
        temporary_path.rename(final_path)
    except BaseException:
        shutil.rmtree(temporary_path, ignore_errors=True)
        raise

    return SnapshotResult(
        snapshot_id=snapshot_id,
        snapshot_path=final_path,
        manifest=MappingProxyType(manifest),
        already_verified=False,
    )

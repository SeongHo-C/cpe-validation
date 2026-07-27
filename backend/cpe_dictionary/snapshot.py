from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import BinaryIO, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


NVD_CPE_META_URL = (
    "https://nvd.nist.gov/feeds/json/cpe/2.0/"
    "nvdcpe-2.0.meta"
)
NVD_CPE_FEED_URL = (
    "https://nvd.nist.gov/feeds/json/cpe/2.0/"
    "nvdcpe-2.0.tar.gz"
)
NVD_CPE_SCHEMA_URL = (
    "https://csrc.nist.gov/schema/nvd/api/2.0/"
    "cpe_api_json_2.0.schema"
)

META_FILENAME = "nvdcpe-2.0.meta"
ARCHIVE_FILENAME = "nvdcpe-2.0.tar.gz"
MANIFEST_FILENAME = "manifest.json"
SOURCE_NAME = "NVD CPE Dictionary 2.0"
USER_AGENT = "cpe-validation-research/1.0"
DEFAULT_TIMEOUT_SECONDS = 300
MAX_DOWNLOAD_ATTEMPTS = 3
CHUNK_SIZE = 1024 * 1024
PROGRESS_INTERVAL = 25 * 1024 * 1024
MAX_META_SIZE = 1024 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
CHUNK_MEMBER_PATTERN = re.compile(
    r"^nvdcpe-2\.0-chunks/"
    r"nvdcpe-2\.0-chunk-(\d{5})\.json$"
)
CHUNK_DIRECTORY_NAMES = {
    "nvdcpe-2.0-chunks",
    "nvdcpe-2.0-chunks/",
}
CONTENT_FORMAT = "chunked-json"
CONTENT_ORDERING = "numeric-chunk-sequence"
CONTENT_SEPARATOR = "none"
REQUIRED_META_FIELDS = {
    "lastModifiedDate",
    "size",
    "zipSize",
    "gzSize",
    "sha256",
}


class SnapshotError(Exception):
    """Base error for snapshot acquisition and validation."""


class MetadataError(SnapshotError):
    """The NVD META document is malformed."""


class DownloadError(SnapshotError):
    """A source could not be downloaded after retrying."""


class ArchiveValidationError(SnapshotError):
    """The downloaded tar archive is unsafe or malformed."""


class IntegrityError(SnapshotError):
    """Downloaded bytes do not match the NVD META document."""


class ExistingSnapshotError(SnapshotError):
    """An existing final snapshot is incomplete or inconsistent."""


class UrlOpen(Protocol):
    def __call__(
        self,
        request: Request,
        *,
        timeout: float,
    ) -> BinaryIO: ...


@dataclass(frozen=True)
class CpeFeedMetadata:
    last_modified: datetime
    size: int
    zip_size: int
    gz_size: int
    sha256: str
    raw_fields: Mapping[str, str]


@dataclass(frozen=True)
class ArchiveMember:
    sequence: int
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ArchiveContent:
    members: tuple[ArchiveMember, ...]
    aggregate_size: int
    aggregate_sha256: str


@dataclass(frozen=True)
class SnapshotPlan:
    snapshot_id: str
    snapshot_path: Path
    metadata: CpeFeedMetadata


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
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def parse_metadata(text: str) -> CpeFeedMetadata:
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

    missing_fields = sorted(REQUIRED_META_FIELDS - fields.keys())
    if missing_fields:
        raise MetadataError(
            "META is missing required field(s): "
            + ", ".join(missing_fields)
        )

    integers: dict[str, int] = {}
    for key in ("size", "zipSize", "gzSize"):
        try:
            parsed_value = int(fields[key])
        except ValueError as error:
            raise MetadataError(
                f"META {key} must be an integer"
            ) from error
        if parsed_value < 0:
            raise MetadataError(
                f"META {key} must not be negative"
            )
        integers[key] = parsed_value

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

    return CpeFeedMetadata(
        last_modified=last_modified,
        size=integers["size"],
        zip_size=integers["zipSize"],
        gz_size=integers["gzSize"],
        sha256=raw_sha256.lower(),
        raw_fields=MappingProxyType(dict(fields)),
    )


def snapshot_id_from_last_modified(last_modified: datetime) -> str:
    if last_modified.utcoffset() is None:
        raise MetadataError(
            "Snapshot timestamp must include a UTC offset"
        )
    return last_modified.astimezone(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )


def _request(url: str) -> Request:
    return Request(
        url,
        headers={
            "Accept": "*/*",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )


def _retry_delay(attempt: int) -> float:
    return float(attempt)


def _download_error_detail(error: BaseException) -> str:
    if isinstance(error, HTTPError):
        return f"HTTP {error.code} {error.reason}"
    if isinstance(error, URLError):
        return f"URL error: {error.reason}"
    return f"{type(error).__name__}: {error}"


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
                sleep_func(_retry_delay(attempt))
    raise DownloadError(
        f"Unable to download META after {MAX_DOWNLOAD_ATTEMPTS} attempts"
    ) from last_error


def download_archive(
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
                        reporter(
                            f"Downloaded {total_size} bytes"
                        )
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
                sleep_func(_retry_delay(attempt))
    raise DownloadError(
        f"Unable to download Feed after {MAX_DOWNLOAD_ATTEMPTS} attempts"
        + (
            f": {_download_error_detail(last_error)}"
            if last_error is not None
            else ""
        )
    ) from last_error


def _validate_member_path(member_name: str) -> None:
    member_path = PurePosixPath(member_name)
    if (
        not member_name
        or member_name.startswith("/")
        or member_path.is_absolute()
        or ".." in member_path.parts
    ):
        raise ArchiveValidationError(
            f"Archive contains an unsafe member path: {member_name}"
        )


def validate_archive(
    archive_path: Path,
    *,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> ArchiveContent:
    chunk_members: dict[int, tarfile.TarInfo] = {}
    verified_members: list[ArchiveMember] = []
    aggregate_digest = hashlib.sha256()
    aggregate_size = 0
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                _validate_member_path(member.name)
                if (
                    member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.isfifo()
                ):
                    raise ArchiveValidationError(
                        "Archive contains a link, device, or special file"
                    )
                if member.isdir():
                    if member.name not in CHUNK_DIRECTORY_NAMES:
                        raise ArchiveValidationError(
                            "Archive contains an unexpected directory: "
                            f"{member.name}"
                        )
                    continue
                if not member.isfile():
                    raise ArchiveValidationError(
                        "Archive contains an unsupported member type"
                    )
                match = CHUNK_MEMBER_PATTERN.fullmatch(member.name)
                if match is None:
                    raise ArchiveValidationError(
                        "Archive contains an unexpected regular file: "
                        f"{member.name}"
                    )
                sequence = int(match.group(1))
                if sequence in chunk_members:
                    raise ArchiveValidationError(
                        "Archive contains a duplicate chunk sequence: "
                        f"{sequence}"
                    )
                chunk_members[sequence] = member

            if not chunk_members:
                raise ArchiveValidationError(
                    "Archive does not contain a valid JSON chunk"
                )

            ordered_sequences = sorted(chunk_members)
            if ordered_sequences[0] != 1:
                raise ArchiveValidationError(
                    "Archive chunk sequence must start at 1"
                )
            expected_sequences = list(
                range(1, len(ordered_sequences) + 1)
            )
            if ordered_sequences != expected_sequences:
                raise ArchiveValidationError(
                    "Archive chunk sequence must be contiguous"
                )

            for sequence in ordered_sequences:
                member = chunk_members[sequence]
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ArchiveValidationError(
                        "Archive JSON chunk could not be opened: "
                        f"{member.name}"
                    )
                member_digest = hashlib.sha256()
                member_size = 0
                with extracted:
                    while True:
                        chunk = extracted.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        member_digest.update(chunk)
                        aggregate_digest.update(chunk)
                        member_size += len(chunk)
                        aggregate_size += len(chunk)
                verified_members.append(
                    ArchiveMember(
                        sequence=sequence,
                        name=member.name,
                        size=member_size,
                        sha256=member_digest.hexdigest(),
                    )
                )
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ArchiveValidationError(
            "Feed is not a valid gzip tar archive"
        ) from error

    aggregate_sha256 = aggregate_digest.hexdigest()
    size_matches = (
        expected_size is None
        or aggregate_size == expected_size
    )
    sha256_matches = (
        expected_sha256 is None
        or aggregate_sha256.lower() == expected_sha256.lower()
    )
    if not size_matches or not sha256_matches:
        expected_size_text = (
            str(expected_size)
            if expected_size is not None
            else "not provided"
        )
        expected_sha256_text = (
            expected_sha256.lower()
            if expected_sha256 is not None
            else "not provided"
        )
        raise IntegrityError(
            "Aggregate content verification failed: "
            f"actual size={aggregate_size}, "
            f"META size={expected_size_text}, "
            f"size matches={size_matches}; "
            f"actual SHA-256={aggregate_sha256}, "
            f"META SHA-256={expected_sha256_text}, "
            f"SHA-256 matches={sha256_matches}"
        )
    return ArchiveContent(
        members=tuple(verified_members),
        aggregate_size=aggregate_size,
        aggregate_sha256=aggregate_sha256,
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _metadata_manifest(metadata: CpeFeedMetadata) -> dict[str, object]:
    return {
        "size": metadata.size,
        "zip_size": metadata.zip_size,
        "gz_size": metadata.gz_size,
        "sha256": metadata.sha256,
    }


def build_manifest(
    *,
    snapshot_id: str,
    metadata: CpeFeedMetadata,
    meta_url: str,
    feed_url: str,
    schema_url: str,
    retrieved_at: datetime,
    archive_size: int,
    archive_sha256: str,
    content: ArchiveContent,
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "snapshot_id": snapshot_id,
        "status": "VERIFIED",
        "source": SOURCE_NAME,
        "source_meta_url": meta_url,
        "source_feed_url": feed_url,
        "source_schema_url": schema_url,
        "feed_last_modified": _utc_isoformat(
            metadata.last_modified
        ),
        "retrieved_at": _utc_isoformat(retrieved_at),
        "meta": _metadata_manifest(metadata),
        "archive": {
            "filename": ARCHIVE_FILENAME,
            "size": archive_size,
            "sha256": archive_sha256.lower(),
        },
        "content": {
            "format": CONTENT_FORMAT,
            "member_count": len(content.members),
            "ordering": CONTENT_ORDERING,
            "separator": CONTENT_SEPARATOR,
            "aggregate_size": content.aggregate_size,
            "aggregate_sha256": (
                content.aggregate_sha256.lower()
            ),
            "members": [
                {
                    "sequence": member.sequence,
                    "name": member.name,
                    "size": member.size,
                    "sha256": member.sha256.lower(),
                }
                for member in content.members
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


def _write_json(path: Path, data: Mapping[str, object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(
            data,
            output,
            ensure_ascii=False,
            indent=2,
        )
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def _load_existing_manifest(path: Path) -> dict[str, object]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ExistingSnapshotError(
            "Existing snapshot manifest is unreadable"
        ) from error
    if not isinstance(manifest, dict):
        raise ExistingSnapshotError(
            "Existing snapshot manifest is not a JSON object"
        )
    return manifest


def _is_nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _validate_existing_content_manifest(
    content: object,
    metadata: CpeFeedMetadata,
) -> None:
    if not isinstance(content, dict):
        raise ExistingSnapshotError(
            "Existing snapshot content manifest is incomplete"
        )
    members = content.get("members")
    member_count = content.get("member_count")
    if (
        content.get("format") != CONTENT_FORMAT
        or content.get("ordering") != CONTENT_ORDERING
        or content.get("separator") != CONTENT_SEPARATOR
        or not _is_nonnegative_integer(member_count)
        or member_count < 1
        or not isinstance(members, list)
        or member_count != len(members)
        or content.get("aggregate_size") != metadata.size
        or content.get("aggregate_sha256") != metadata.sha256
    ):
        raise ExistingSnapshotError(
            "Existing snapshot content manifest does not match META"
        )

    total_size = 0
    for expected_sequence, member in enumerate(members, start=1):
        if not isinstance(member, dict):
            raise ExistingSnapshotError(
                "Existing snapshot member manifest is invalid"
            )
        sequence = member.get("sequence")
        name = member.get("name")
        size = member.get("size")
        sha256 = member.get("sha256")
        match = (
            CHUNK_MEMBER_PATTERN.fullmatch(name)
            if isinstance(name, str)
            else None
        )
        if (
            type(sequence) is not int
            or sequence != expected_sequence
            or match is None
            or int(match.group(1)) != sequence
            or not _is_nonnegative_integer(size)
            or not isinstance(sha256, str)
            or not SHA256_PATTERN.fullmatch(sha256)
            or sha256 != sha256.lower()
        ):
            raise ExistingSnapshotError(
                "Existing snapshot member manifest is invalid"
            )
        total_size += size

    if total_size != metadata.size:
        raise ExistingSnapshotError(
            "Existing snapshot member sizes do not match META"
        )


def _validate_existing_snapshot(
    *,
    final_path: Path,
    snapshot_id: str,
    metadata: CpeFeedMetadata,
    meta_url: str,
    feed_url: str,
    schema_url: str,
) -> Mapping[str, object]:
    manifest_path = final_path / MANIFEST_FILENAME
    meta_path = final_path / META_FILENAME
    archive_path = final_path / ARCHIVE_FILENAME
    if not manifest_path.is_file():
        raise ExistingSnapshotError(
            "Existing snapshot is incomplete: manifest.json is missing"
        )
    if not meta_path.is_file() or not archive_path.is_file():
        raise ExistingSnapshotError(
            "Existing snapshot is incomplete and will not be overwritten"
        )

    try:
        stored_metadata = parse_metadata(
            meta_path.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, MetadataError) as error:
        raise ExistingSnapshotError(
            "Existing snapshot META is unreadable or invalid"
        ) from error
    if stored_metadata.raw_fields != metadata.raw_fields:
        raise ExistingSnapshotError(
            "Existing snapshot META does not match current META"
        )

    manifest = _load_existing_manifest(manifest_path)
    expected_values = {
        "schema_version": 2,
        "snapshot_id": snapshot_id,
        "status": "VERIFIED",
        "source": SOURCE_NAME,
        "source_meta_url": meta_url,
        "source_feed_url": feed_url,
        "source_schema_url": schema_url,
        "feed_last_modified": _utc_isoformat(
            metadata.last_modified
        ),
        "meta": _metadata_manifest(metadata),
    }
    for key, expected_value in expected_values.items():
        if manifest.get(key) != expected_value:
            raise ExistingSnapshotError(
                f"Existing snapshot manifest does not match current META: {key}"
            )

    archive = manifest.get("archive")
    if not isinstance(archive, dict):
        raise ExistingSnapshotError(
            "Existing snapshot archive manifest is incomplete"
        )
    archive_size = archive.get("size")
    archive_sha256 = archive.get("sha256")
    if (
        archive.get("filename") != ARCHIVE_FILENAME
        or not _is_nonnegative_integer(archive_size)
        or archive_size != metadata.gz_size
        or not isinstance(archive_sha256, str)
        or not SHA256_PATTERN.fullmatch(archive_sha256)
        or archive_sha256 != archive_sha256.lower()
    ):
        raise ExistingSnapshotError(
            "Existing snapshot archive manifest is invalid"
        )
    if archive_path.stat().st_size != archive_size:
        raise ExistingSnapshotError(
            "Existing snapshot archive size has changed"
        )
    if file_sha256(archive_path) != archive_sha256.lower():
        raise ExistingSnapshotError(
            "Existing snapshot archive SHA-256 has changed"
        )

    _validate_existing_content_manifest(
        manifest.get("content"),
        metadata,
    )

    expected_validation = {
        "archive_size_matches_meta": True,
        "safe_archive_members": True,
        "member_names_valid": True,
        "member_sequences_unique": True,
        "member_sequences_contiguous": True,
        "aggregate_size_matches_meta": True,
        "aggregate_sha256_matches_meta": True,
    }
    if manifest.get("validation") != expected_validation:
        raise ExistingSnapshotError(
            "Existing snapshot validation record is incomplete"
        )
    return MappingProxyType(manifest)


def acquire_snapshot(
    output_root: Path,
    *,
    meta_url: str = NVD_CPE_META_URL,
    feed_url: str = NVD_CPE_FEED_URL,
    schema_url: str = NVD_CPE_SCHEMA_URL,
    dry_run: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen_func: UrlOpen = urlopen,
    sleep_func: Sleep = time.sleep,
    now_func: Now = lambda: datetime.now(timezone.utc),
    reporter: Reporter = _silent_reporter,
) -> SnapshotPlan | SnapshotResult:
    reporter("Downloading NVD CPE Dictionary META")
    meta_bytes = download_metadata(
        meta_url,
        timeout=timeout,
        urlopen_func=urlopen_func,
        sleep_func=sleep_func,
    )
    try:
        meta_text = meta_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MetadataError("META must be UTF-8") from error
    metadata = parse_metadata(meta_text)
    snapshot_id = snapshot_id_from_last_modified(
        metadata.last_modified
    )
    output_root = output_root.resolve()
    final_path = output_root / snapshot_id

    if dry_run:
        return SnapshotPlan(
            snapshot_id=snapshot_id,
            snapshot_path=final_path,
            metadata=metadata,
        )

    if final_path.exists():
        if not final_path.is_dir():
            raise ExistingSnapshotError(
                "Existing snapshot path is not a directory"
            )
        manifest = _validate_existing_snapshot(
            final_path=final_path,
            snapshot_id=snapshot_id,
            metadata=metadata,
            meta_url=meta_url,
            feed_url=feed_url,
            schema_url=schema_url,
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
        part_path = temporary_path / f"{ARCHIVE_FILENAME}.part"
        reporter("Downloading NVD CPE Dictionary Feed")
        archive_size, archive_sha256 = download_archive(
            feed_url,
            part_path,
            timeout=timeout,
            urlopen_func=urlopen_func,
            sleep_func=sleep_func,
            reporter=reporter,
        )
        reporter("Feed download completed")
        if archive_size != metadata.gz_size:
            raise IntegrityError(
                "Compressed archive size does not match META gzSize"
            )

        reporter("Validating compressed JSON content")
        content = validate_archive(
            part_path,
            expected_size=metadata.size,
            expected_sha256=metadata.sha256,
        )
        reporter("Compressed JSON content verified")
        manifest = build_manifest(
            snapshot_id=snapshot_id,
            metadata=metadata,
            meta_url=meta_url,
            feed_url=feed_url,
            schema_url=schema_url,
            retrieved_at=now_func(),
            archive_size=archive_size,
            archive_sha256=archive_sha256,
            content=content,
        )

        (temporary_path / META_FILENAME).write_bytes(meta_bytes)
        _write_json(
            temporary_path / MANIFEST_FILENAME,
            manifest,
        )
        part_path.rename(temporary_path / ARCHIVE_FILENAME)

        if final_path.exists():
            raise ExistingSnapshotError(
                "Snapshot path appeared during download; refusing to overwrite"
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

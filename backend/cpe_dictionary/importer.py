from __future__ import annotations

import json
import re
import tarfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
from pathlib import Path
from types import MappingProxyType
from uuid import UUID

from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from cpe.cpe23 import (
    CPE23_ATTRIBUTE_NAMES,
    parse_cpe23_formatted_string,
)

from .models import CpeDictionarySnapshot, CpeName
from .snapshot import (
    ARCHIVE_FILENAME,
    CHUNK_MEMBER_PATTERN,
    MANIFEST_FILENAME,
    SHA256_PATTERN,
    file_sha256,
)


DEFAULT_BATCH_SIZE = 5000
MIN_BATCH_SIZE = 100
MAX_BATCH_SIZE = 20000
SNAPSHOT_ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z$")


class DictionaryImportError(Exception):
    """The verified Dictionary snapshot could not be imported safely."""


@dataclass(frozen=True)
class ManifestMember:
    sequence: int
    name: str


@dataclass(frozen=True)
class VerifiedDictionarySnapshot:
    snapshot_id: str
    snapshot_path: Path
    archive_path: Path
    manifest_sha256: str
    archive_sha256: str
    content_sha256: str
    feed_last_modified: datetime
    members: tuple[ManifestMember, ...]


@dataclass(frozen=True)
class ParsedCpeRecord:
    cpe_name_id: UUID
    cpe_name: str
    deprecated: bool
    created_at_nvd: datetime
    last_modified_at_nvd: datetime
    fields: Mapping[str, str]
    titles: list[object]
    references: list[object]
    deprecated_by: list[object]
    deprecates: list[object]


@dataclass(frozen=True)
class FeedCounts:
    expected_record_count: int
    record_count: int
    active_count: int
    deprecated_count: int


@dataclass(frozen=True)
class ImportResult:
    snapshot_id: str
    member_count: int
    expected_record_count: int
    record_count: int
    active_count: int
    deprecated_count: int
    dry_run: bool
    already_imported: bool


Reporter = Callable[[str], None]


def _silent_reporter(message: str) -> None:
    del message


def _load_json_object(path: Path, description: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DictionaryImportError(
            f"{description} is unreadable or invalid JSON"
        ) from error
    if not isinstance(value, dict):
        raise DictionaryImportError(
            f"{description} must be a JSON object"
        )
    return value


def _parse_aware_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise DictionaryImportError(
            f"{field_name} must be a non-empty datetime string"
        )
    parsed = parse_datetime(value)
    if parsed is None:
        raise DictionaryImportError(
            f"{field_name} must be a valid ISO-8601 datetime"
        )
    if timezone.is_naive(parsed):
        return parsed.replace(tzinfo=datetime_timezone.utc)
    return parsed.astimezone(datetime_timezone.utc)


def _is_nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def verify_dictionary_snapshot(
    input_root: Path,
    snapshot_id: str,
) -> VerifiedDictionarySnapshot:
    if not SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id):
        raise DictionaryImportError(
            "snapshot_id must use YYYYMMDDTHHMMSSZ format"
        )

    snapshot_path = input_root.resolve() / snapshot_id
    manifest_path = snapshot_path / MANIFEST_FILENAME
    archive_path = snapshot_path / ARCHIVE_FILENAME
    if not manifest_path.is_file():
        raise DictionaryImportError("Verified manifest.json is missing")
    if not archive_path.is_file():
        raise DictionaryImportError("Verified archive is missing")

    manifest = _load_json_object(
        manifest_path,
        "Snapshot manifest",
    )
    if manifest.get("schema_version") != 2:
        raise DictionaryImportError(
            "Snapshot manifest schema_version must be 2"
        )
    if manifest.get("status") != "VERIFIED":
        raise DictionaryImportError(
            "Snapshot manifest status must be VERIFIED"
        )
    if manifest.get("snapshot_id") != snapshot_id:
        raise DictionaryImportError(
            "Snapshot manifest snapshot_id does not match input"
        )

    archive = manifest.get("archive")
    content = manifest.get("content")
    if not isinstance(archive, dict) or not isinstance(content, dict):
        raise DictionaryImportError(
            "Snapshot manifest archive/content is incomplete"
        )
    archive_sha256 = archive.get("sha256")
    content_sha256 = content.get("aggregate_sha256")
    if (
        archive.get("filename") != ARCHIVE_FILENAME
        or not isinstance(archive_sha256, str)
        or not SHA256_PATTERN.fullmatch(archive_sha256)
        or archive_sha256 != archive_sha256.lower()
    ):
        raise DictionaryImportError(
            "Snapshot manifest archive information is invalid"
        )
    if (
        not isinstance(content_sha256, str)
        or not SHA256_PATTERN.fullmatch(content_sha256)
        or content_sha256 != content_sha256.lower()
    ):
        raise DictionaryImportError(
            "Snapshot manifest content SHA-256 is invalid"
        )

    manifest_members = content.get("members")
    member_count = content.get("member_count")
    if (
        not _is_nonnegative_integer(member_count)
        or member_count < 1
        or not isinstance(manifest_members, list)
        or member_count != len(manifest_members)
    ):
        raise DictionaryImportError(
            "Snapshot manifest member_count does not match members"
        )

    members: list[ManifestMember] = []
    for expected_sequence, value in enumerate(
        manifest_members,
        start=1,
    ):
        if not isinstance(value, dict):
            raise DictionaryImportError(
                "Snapshot manifest member entry is invalid"
            )
        sequence = value.get("sequence")
        name = value.get("name")
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
        ):
            raise DictionaryImportError(
                "Snapshot manifest member sequence/name is invalid"
            )
        members.append(
            ManifestMember(sequence=sequence, name=name)
        )

    feed_last_modified = _parse_aware_datetime(
        manifest.get("feed_last_modified"),
        "manifest.feed_last_modified",
    )
    actual_archive_sha256 = file_sha256(archive_path)
    if actual_archive_sha256 != archive_sha256:
        raise DictionaryImportError(
            "Archive SHA-256 does not match VERIFIED manifest"
        )

    try:
        with tarfile.open(archive_path, mode="r:gz") as tar:
            archive_members = {
                member.name: member
                for member in tar.getmembers()
            }
            for member in members:
                tar_member = archive_members.get(member.name)
                if tar_member is None or not tar_member.isfile():
                    raise DictionaryImportError(
                        "Manifest JSON member is missing from archive: "
                        f"{member.name}"
                    )
    except (tarfile.TarError, EOFError, OSError) as error:
        raise DictionaryImportError(
            "Verified archive is not a readable gzip tar archive"
        ) from error

    return VerifiedDictionarySnapshot(
        snapshot_id=snapshot_id,
        snapshot_path=snapshot_path,
        archive_path=archive_path,
        manifest_sha256=file_sha256(manifest_path),
        archive_sha256=archive_sha256,
        content_sha256=content_sha256,
        feed_last_modified=feed_last_modified,
        members=tuple(members),
    )


def _required_list(
    value: Mapping[str, object],
    field_name: str,
) -> list[object]:
    field_value = value.get(field_name, [])
    if not isinstance(field_value, list):
        raise DictionaryImportError(
            f"cpe.{field_name} must be an array when present"
        )
    return field_value


def _parse_product(
    product: object,
    *,
    chunk_sequence: int,
    product_index: int,
) -> ParsedCpeRecord:
    location = (
        f"chunk {chunk_sequence} product {product_index}"
    )
    if not isinstance(product, dict):
        raise DictionaryImportError(
            f"{location} must be an object"
        )
    cpe = product.get("cpe")
    if not isinstance(cpe, dict):
        raise DictionaryImportError(
            f"{location}.cpe must be an object"
        )

    required_fields = (
        "cpeName",
        "cpeNameId",
        "deprecated",
        "created",
        "lastModified",
    )
    missing = [key for key in required_fields if key not in cpe]
    if missing:
        raise DictionaryImportError(
            f"{location}.cpe is missing required field(s): "
            + ", ".join(missing)
        )

    cpe_name = cpe["cpeName"]
    if not isinstance(cpe_name, str) or not cpe_name:
        raise DictionaryImportError(
            f"{location}.cpe.cpeName must be a non-empty string"
        )
    cpe_name_id_value = cpe["cpeNameId"]
    if (
        not isinstance(cpe_name_id_value, str)
        or not cpe_name_id_value
    ):
        raise DictionaryImportError(
            f"{location}.cpe.cpeNameId must be a UUID string"
        )
    try:
        cpe_name_id = UUID(cpe_name_id_value)
    except ValueError as error:
        raise DictionaryImportError(
            f"{location}.cpe.cpeNameId must be a valid UUID"
        ) from error

    deprecated = cpe["deprecated"]
    if type(deprecated) is not bool:
        raise DictionaryImportError(
            f"{location}.cpe.deprecated must be boolean"
        )

    parsed_cpe = parse_cpe23_formatted_string(cpe_name)
    if not parsed_cpe.is_structurally_valid:
        raise DictionaryImportError(
            f"{location}.cpe.cpeName is structurally invalid: "
            f"{parsed_cpe.error_message}"
        )

    return ParsedCpeRecord(
        cpe_name_id=cpe_name_id,
        cpe_name=cpe_name,
        deprecated=deprecated,
        created_at_nvd=_parse_aware_datetime(
            cpe["created"],
            f"{location}.cpe.created",
        ),
        last_modified_at_nvd=_parse_aware_datetime(
            cpe["lastModified"],
            f"{location}.cpe.lastModified",
        ),
        fields=MappingProxyType(dict(parsed_cpe.fields)),
        titles=_required_list(cpe, "titles"),
        references=_required_list(cpe, "refs"),
        deprecated_by=_required_list(cpe, "deprecatedBy"),
        deprecates=_required_list(cpe, "deprecates"),
    )


def _to_model(
    record: ParsedCpeRecord,
    snapshot: CpeDictionarySnapshot,
) -> CpeName:
    cpe_fields = {
        name: record.fields[name]
        for name in CPE23_ATTRIBUTE_NAMES
    }
    return CpeName(
        snapshot=snapshot,
        cpe_name_id=record.cpe_name_id,
        cpe_name=record.cpe_name,
        deprecated=record.deprecated,
        created_at_nvd=record.created_at_nvd,
        last_modified_at_nvd=record.last_modified_at_nvd,
        titles=record.titles,
        references=record.references,
        deprecated_by=record.deprecated_by,
        deprecates=record.deprecates,
        **cpe_fields,
    )


def _validate_chunk(
    value: object,
    *,
    sequence: int,
    expected_total_results: int | None,
) -> tuple[list[object], int]:
    if not isinstance(value, dict):
        raise DictionaryImportError(
            f"Chunk {sequence} top-level value must be an object"
        )
    required_fields = (
        "resultsPerPage",
        "startIndex",
        "totalResults",
        "products",
    )
    missing = [key for key in required_fields if key not in value]
    if missing:
        raise DictionaryImportError(
            f"Chunk {sequence} is missing top-level field(s): "
            + ", ".join(missing)
        )

    results_per_page = value["resultsPerPage"]
    start_index = value["startIndex"]
    total_results = value["totalResults"]
    products = value["products"]
    if (
        not _is_nonnegative_integer(results_per_page)
        or not _is_nonnegative_integer(start_index)
        or not _is_nonnegative_integer(total_results)
        or not isinstance(products, list)
    ):
        raise DictionaryImportError(
            f"Chunk {sequence} pagination/products types are invalid"
        )
    if results_per_page != len(products):
        raise DictionaryImportError(
            f"Chunk {sequence} resultsPerPage does not match products"
        )
    if start_index != sequence:
        raise DictionaryImportError(
            f"Chunk {sequence} startIndex must equal chunk sequence"
        )
    if (
        expected_total_results is not None
        and total_results != expected_total_results
    ):
        raise DictionaryImportError(
            f"Chunk {sequence} totalResults is inconsistent"
        )
    return products, total_results


def _process_feed(
    verified: VerifiedDictionarySnapshot,
    *,
    batch_size: int,
    snapshot: CpeDictionarySnapshot | None,
    reporter: Reporter,
) -> FeedCounts:
    expected_record_count: int | None = None
    record_count = 0
    active_count = 0
    deprecated_count = 0
    batch: list[CpeName] = []

    try:
        with tarfile.open(
            verified.archive_path,
            mode="r:gz",
        ) as archive:
            archive_members = {
                member.name: member
                for member in archive.getmembers()
            }
            for descriptor in verified.members:
                member = archive_members[descriptor.name]
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise DictionaryImportError(
                        "Archive JSON chunk could not be opened: "
                        f"{descriptor.name}"
                    )
                try:
                    with extracted:
                        chunk = json.load(extracted)
                except (
                    UnicodeError,
                    json.JSONDecodeError,
                    OSError,
                ) as error:
                    raise DictionaryImportError(
                        f"Chunk {descriptor.sequence} is invalid JSON"
                    ) from error

                products, chunk_total_results = _validate_chunk(
                    chunk,
                    sequence=descriptor.sequence,
                    expected_total_results=expected_record_count,
                )
                if expected_record_count is None:
                    expected_record_count = chunk_total_results

                for product_index, product in enumerate(
                    products,
                    start=1,
                ):
                    record = _parse_product(
                        product,
                        chunk_sequence=descriptor.sequence,
                        product_index=product_index,
                    )
                    record_count += 1
                    if record.deprecated:
                        deprecated_count += 1
                    else:
                        active_count += 1

                    if snapshot is not None:
                        batch.append(_to_model(record, snapshot))
                        if len(batch) >= batch_size:
                            CpeName.objects.bulk_create(
                                batch,
                                batch_size=batch_size,
                            )
                            batch.clear()

                reporter(
                    "Processed chunk "
                    f"{descriptor.sequence}/{len(verified.members)}: "
                    f"{len(products)} records"
                )

            if snapshot is not None and batch:
                CpeName.objects.bulk_create(
                    batch,
                    batch_size=batch_size,
                )
                batch.clear()
    except DictionaryImportError:
        raise
    except (tarfile.TarError, EOFError, OSError) as error:
        raise DictionaryImportError(
            "Verified archive could not be processed"
        ) from error

    if expected_record_count is None:
        raise DictionaryImportError(
            "Dictionary Feed did not contain any chunks"
        )
    if record_count != expected_record_count:
        raise DictionaryImportError(
            "Parsed record count does not match totalResults: "
            f"parsed={record_count}, "
            f"totalResults={expected_record_count}"
        )
    if record_count != active_count + deprecated_count:
        raise DictionaryImportError(
            "Active/deprecated counts do not match parsed count"
        )

    return FeedCounts(
        expected_record_count=expected_record_count,
        record_count=record_count,
        active_count=active_count,
        deprecated_count=deprecated_count,
    )


def _existing_import_result(
    existing: CpeDictionarySnapshot,
    verified: VerifiedDictionarySnapshot,
) -> ImportResult:
    actual_count = CpeName.objects.filter(
        snapshot=existing
    ).count()
    is_consistent = (
        existing.status
        == CpeDictionarySnapshot.Status.COMPLETE
        and existing.manifest_sha256 == verified.manifest_sha256
        and existing.archive_sha256 == verified.archive_sha256
        and existing.content_sha256 == verified.content_sha256
        and existing.member_count == len(verified.members)
        and actual_count == existing.record_count
        and existing.expected_record_count == existing.record_count
        and existing.record_count
        == existing.active_count + existing.deprecated_count
        and existing.completed_at is not None
    )
    if not is_consistent:
        raise DictionaryImportError(
            "Existing Dictionary snapshot import is incomplete "
            "or conflicts with the VERIFIED snapshot"
        )
    return ImportResult(
        snapshot_id=existing.snapshot_id,
        member_count=existing.member_count,
        expected_record_count=existing.expected_record_count,
        record_count=existing.record_count,
        active_count=existing.active_count,
        deprecated_count=existing.deprecated_count,
        dry_run=False,
        already_imported=True,
    )


def import_dictionary_snapshot(
    input_root: Path,
    snapshot_id: str,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    dry_run: bool = False,
    reporter: Reporter = _silent_reporter,
) -> ImportResult:
    if (
        type(batch_size) is not int
        or not MIN_BATCH_SIZE <= batch_size <= MAX_BATCH_SIZE
    ):
        raise DictionaryImportError(
            f"batch_size must be between {MIN_BATCH_SIZE} "
            f"and {MAX_BATCH_SIZE}"
        )

    verified = verify_dictionary_snapshot(
        input_root,
        snapshot_id,
    )
    if dry_run:
        counts = _process_feed(
            verified,
            batch_size=batch_size,
            snapshot=None,
            reporter=reporter,
        )
        return ImportResult(
            snapshot_id=snapshot_id,
            member_count=len(verified.members),
            expected_record_count=counts.expected_record_count,
            record_count=counts.record_count,
            active_count=counts.active_count,
            deprecated_count=counts.deprecated_count,
            dry_run=True,
            already_imported=False,
        )

    existing = CpeDictionarySnapshot.objects.filter(
        snapshot_id=snapshot_id
    ).first()
    if existing is not None:
        return _existing_import_result(existing, verified)

    try:
        with transaction.atomic():
            snapshot = CpeDictionarySnapshot.objects.create(
                snapshot_id=snapshot_id,
                status=CpeDictionarySnapshot.Status.IMPORTING,
                feed_last_modified=verified.feed_last_modified,
                manifest_sha256=verified.manifest_sha256,
                archive_sha256=verified.archive_sha256,
                content_sha256=verified.content_sha256,
                member_count=len(verified.members),
                expected_record_count=0,
                record_count=0,
                active_count=0,
                deprecated_count=0,
            )
            counts = _process_feed(
                verified,
                batch_size=batch_size,
                snapshot=snapshot,
                reporter=reporter,
            )
            snapshot.status = (
                CpeDictionarySnapshot.Status.COMPLETE
            )
            snapshot.expected_record_count = (
                counts.expected_record_count
            )
            snapshot.record_count = counts.record_count
            snapshot.active_count = counts.active_count
            snapshot.deprecated_count = counts.deprecated_count
            snapshot.completed_at = timezone.now()
            snapshot.save(
                update_fields=[
                    "status",
                    "expected_record_count",
                    "record_count",
                    "active_count",
                    "deprecated_count",
                    "completed_at",
                ]
            )
    except IntegrityError as error:
        raise DictionaryImportError(
            "Dictionary uniqueness/integrity validation failed; "
            "the import was rolled back"
        ) from error

    return ImportResult(
        snapshot_id=snapshot_id,
        member_count=len(verified.members),
        expected_record_count=counts.expected_record_count,
        record_count=counts.record_count,
        active_count=counts.active_count,
        deprecated_count=counts.deprecated_count,
        dry_run=False,
        already_imported=False,
    )

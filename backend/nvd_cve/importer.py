from __future__ import annotations

import gzip
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
from pathlib import Path
from uuid import UUID

from django.db import DatabaseError, IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import NvdCpeMatch, NvdCveRecord, NvdCveSnapshot
from .snapshot import (
    CVE_ID_PATTERN,
    FEEDS_DIRECTORY,
    MANIFEST_FILENAME,
    SNAPSHOT_ID_PATTERN,
    SnapshotError,
    feed_filename,
    file_sha256,
    verify_snapshot,
)


DEFAULT_BATCH_SIZE = 1000
MIN_BATCH_SIZE = 100
MAX_BATCH_SIZE = 20000
MATCH_CRITERIA_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
VERSION_BOUNDARY_FIELDS = {
    "versionStartIncluding": "version_start_including",
    "versionStartExcluding": "version_start_excluding",
    "versionEndIncluding": "version_end_including",
    "versionEndExcluding": "version_end_excluding",
}


class NvdCveImportError(Exception):
    """A VERIFIED NVD CVE snapshot could not be imported safely."""


@dataclass(frozen=True)
class ManifestFeed:
    year: int
    filename: str
    declared_count: int


@dataclass(frozen=True)
class VerifiedNvdCveSnapshot:
    snapshot_id: str
    snapshot_path: Path
    manifest_sha256: str
    content_sha256: str
    expected_record_count: int
    feeds: tuple[ManifestFeed, ...]


@dataclass(frozen=True)
class ParsedCpeMatch:
    configuration_index: int
    node_index: int
    match_index: int
    configuration_operator: str | None
    configuration_negate: bool | None
    node_operator: str | None
    node_negate: bool | None
    vulnerable: bool
    criteria: str
    match_criteria_id: UUID
    version_start_including: str | None
    version_start_excluding: str | None
    version_end_including: str | None
    version_end_excluding: str | None


@dataclass(frozen=True)
class ParsedCveRecord:
    cve_id: str
    published_at_nvd: datetime
    last_modified_at_nvd: datetime
    vuln_status: str
    configurations: list[object] | None
    matches: tuple[ParsedCpeMatch, ...]


@dataclass
class ImportCounts:
    record_count: int = 0
    configuration_count: int = 0
    cpe_match_count: int = 0
    vulnerable_true_count: int = 0
    vulnerable_false_count: int = 0
    duplicate_cve_count: int = 0


@dataclass(frozen=True)
class ImportResult:
    snapshot_id: str
    feed_count: int
    expected_record_count: int
    record_count: int
    configuration_count: int
    cpe_match_count: int
    vulnerable_true_count: int
    vulnerable_false_count: int
    duplicate_cve_count: int
    dry_run: bool
    already_imported: bool


Reporter = Callable[[str], None]


def _silent_reporter(message: str) -> None:
    del message


def _is_nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _parse_aware_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise NvdCveImportError(
            f"{field_name} must be a non-empty datetime string"
        )
    parsed = parse_datetime(value)
    if parsed is None:
        raise NvdCveImportError(
            f"{field_name} must be a valid ISO-8601 datetime"
        )
    if timezone.is_naive(parsed):
        return parsed.replace(tzinfo=datetime_timezone.utc)
    return parsed.astimezone(datetime_timezone.utc)


def _optional_string(
    value: Mapping[str, object],
    source_name: str,
    *,
    location: str,
) -> str | None:
    if source_name not in value:
        return None
    result = value[source_name]
    if not isinstance(result, str):
        raise NvdCveImportError(
            f"{location}.{source_name} must be a string when present"
        )
    return result


def _optional_boolean(
    value: Mapping[str, object],
    source_name: str,
    *,
    location: str,
) -> bool | None:
    if source_name not in value:
        return None
    result = value[source_name]
    if type(result) is not bool:
        raise NvdCveImportError(
            f"{location}.{source_name} must be boolean when present"
        )
    return result


def verify_nvd_cve_snapshot(
    input_root: Path,
    snapshot_id: str,
) -> VerifiedNvdCveSnapshot:
    if not SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id):
        raise NvdCveImportError(
            "snapshot_id must use YYYYMMDDTHHMMSSZ format"
        )
    input_root = input_root.resolve()
    snapshot_path = input_root / snapshot_id
    manifest_path = snapshot_path / MANIFEST_FILENAME
    try:
        manifest = verify_snapshot(input_root, snapshot_id)
    except SnapshotError as error:
        raise NvdCveImportError(
            f"VERIFIED NVD CVE snapshot validation failed: {error}"
        ) from error

    if manifest.get("status") != "VERIFIED":
        raise NvdCveImportError(
            "Snapshot manifest status must be VERIFIED"
        )
    content = manifest.get("content")
    entries = manifest.get("feeds")
    feed_count = manifest.get("feed_count")
    expected_record_count = manifest.get("total_parsed_count")
    if (
        not isinstance(content, dict)
        or not isinstance(entries, list)
        or not _is_nonnegative_integer(feed_count)
        or feed_count < 1
        or feed_count != len(entries)
        or not _is_nonnegative_integer(expected_record_count)
        or expected_record_count < 1
        or manifest.get("total_declared_count")
        != expected_record_count
        or manifest.get("duplicate_cve_count") != 0
    ):
        raise NvdCveImportError(
            "Snapshot manifest feed/count validation failed"
        )
    content_sha256 = content.get("aggregate_sha256")
    if not isinstance(content_sha256, str):
        raise NvdCveImportError(
            "Snapshot manifest content SHA-256 is invalid"
        )

    feeds: list[ManifestFeed] = []
    for entry_index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise NvdCveImportError(
                f"Snapshot feed entry {entry_index} must be an object"
            )
        year = entry.get("year")
        filename = entry.get("feed_filename")
        declared_count = entry.get("parsed_count")
        if (
            type(year) is not int
            or filename != feed_filename(year)
            or not _is_nonnegative_integer(declared_count)
            or entry.get("declared_count") != declared_count
        ):
            raise NvdCveImportError(
                f"Snapshot feed entry {entry_index} is invalid"
            )
        feed_path = snapshot_path / FEEDS_DIRECTORY / filename
        if not feed_path.is_file():
            raise NvdCveImportError(
                f"Snapshot feed is missing: {filename}"
            )
        feeds.append(
            ManifestFeed(
                year=year,
                filename=filename,
                declared_count=declared_count,
            )
        )

    return VerifiedNvdCveSnapshot(
        snapshot_id=snapshot_id,
        snapshot_path=snapshot_path,
        manifest_sha256=file_sha256(manifest_path),
        content_sha256=content_sha256,
        expected_record_count=expected_record_count,
        feeds=tuple(feeds),
    )


def _parse_cpe_match(
    value: object,
    *,
    configuration_index: int,
    node_index: int,
    match_index: int,
    configuration_operator: str | None,
    configuration_negate: bool | None,
    node_operator: str | None,
    node_negate: bool | None,
    location: str,
) -> ParsedCpeMatch:
    if not isinstance(value, dict):
        raise NvdCveImportError(f"{location} must be an object")
    vulnerable = value.get("vulnerable")
    criteria = value.get("criteria")
    match_criteria_value = value.get("matchCriteriaId")
    if type(vulnerable) is not bool:
        raise NvdCveImportError(
            f"{location}.vulnerable must be boolean"
        )
    if not isinstance(criteria, str) or not criteria:
        raise NvdCveImportError(
            f"{location}.criteria must be a non-empty string"
        )
    if (
        not isinstance(match_criteria_value, str)
        or not MATCH_CRITERIA_ID_PATTERN.fullmatch(match_criteria_value)
    ):
        raise NvdCveImportError(
            f"{location}.matchCriteriaId must be a valid UUID"
        )
    try:
        match_criteria_id = UUID(match_criteria_value)
    except ValueError as error:
        raise NvdCveImportError(
            f"{location}.matchCriteriaId must be a valid UUID"
        ) from error

    boundaries = {
        target_name: _optional_string(
            value,
            source_name,
            location=location,
        )
        for source_name, target_name in VERSION_BOUNDARY_FIELDS.items()
    }
    return ParsedCpeMatch(
        configuration_index=configuration_index,
        node_index=node_index,
        match_index=match_index,
        configuration_operator=configuration_operator,
        configuration_negate=configuration_negate,
        node_operator=node_operator,
        node_negate=node_negate,
        vulnerable=vulnerable,
        criteria=criteria,
        match_criteria_id=match_criteria_id,
        **boundaries,
    )


def _parse_configurations(
    configurations: object,
    *,
    location: str,
) -> tuple[list[object], tuple[ParsedCpeMatch, ...]]:
    if not isinstance(configurations, list):
        raise NvdCveImportError(
            f"{location}.configurations must be an array when present"
        )

    matches: list[ParsedCpeMatch] = []
    for configuration_index, configuration in enumerate(configurations):
        configuration_location = (
            f"{location}.configurations[{configuration_index}]"
        )
        if not isinstance(configuration, dict):
            raise NvdCveImportError(
                f"{configuration_location} must be an object"
            )
        nodes = configuration.get("nodes")
        if not isinstance(nodes, list):
            raise NvdCveImportError(
                f"{configuration_location}.nodes must be an array"
            )
        configuration_operator = _optional_string(
            configuration,
            "operator",
            location=configuration_location,
        )
        configuration_negate = _optional_boolean(
            configuration,
            "negate",
            location=configuration_location,
        )
        for node_index, node in enumerate(nodes):
            node_location = f"{configuration_location}.nodes[{node_index}]"
            if not isinstance(node, dict):
                raise NvdCveImportError(
                    f"{node_location} must be an object"
                )
            cpe_matches = node.get("cpeMatch")
            if not isinstance(cpe_matches, list):
                raise NvdCveImportError(
                    f"{node_location}.cpeMatch must be an array"
                )
            node_operator = _optional_string(
                node,
                "operator",
                location=node_location,
            )
            node_negate = _optional_boolean(
                node,
                "negate",
                location=node_location,
            )
            for match_index, match in enumerate(cpe_matches):
                match_location = (
                    f"{node_location}.cpeMatch[{match_index}]"
                )
                matches.append(
                    _parse_cpe_match(
                        match,
                        configuration_index=configuration_index,
                        node_index=node_index,
                        match_index=match_index,
                        configuration_operator=configuration_operator,
                        configuration_negate=configuration_negate,
                        node_operator=node_operator,
                        node_negate=node_negate,
                        location=match_location,
                    )
                )
    return configurations, tuple(matches)


def _parse_cve(
    vulnerability: object,
    *,
    year: int,
    vulnerability_index: int,
) -> ParsedCveRecord:
    location = f"feed {year} vulnerability {vulnerability_index}"
    if not isinstance(vulnerability, dict):
        raise NvdCveImportError(f"{location} must be an object")
    cve = vulnerability.get("cve")
    if not isinstance(cve, dict):
        raise NvdCveImportError(f"{location}.cve must be an object")

    cve_id = cve.get("id")
    vuln_status = cve.get("vulnStatus")
    if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
        raise NvdCveImportError(f"{location}.cve.id is invalid")
    if not isinstance(vuln_status, str) or not vuln_status:
        raise NvdCveImportError(
            f"{location}.cve.vulnStatus must be a non-empty string"
        )

    if "configurations" in cve:
        configurations, matches = _parse_configurations(
            cve["configurations"],
            location=f"{location}.cve",
        )
    else:
        configurations, matches = None, ()

    return ParsedCveRecord(
        cve_id=cve_id,
        published_at_nvd=_parse_aware_datetime(
            cve.get("published"),
            f"{location}.cve.published",
        ),
        last_modified_at_nvd=_parse_aware_datetime(
            cve.get("lastModified"),
            f"{location}.cve.lastModified",
        ),
        vuln_status=vuln_status,
        configurations=configurations,
        matches=matches,
    )


def _load_feed(
    verified: VerifiedNvdCveSnapshot,
    descriptor: ManifestFeed,
) -> list[object]:
    path = verified.snapshot_path / FEEDS_DIRECTORY / descriptor.filename
    try:
        with gzip.open(path, mode="rt", encoding="utf-8") as source:
            value = json.load(source)
    except UnicodeError as error:
        raise NvdCveImportError(
            f"Feed {descriptor.year} content is not valid UTF-8"
        ) from error
    except json.JSONDecodeError as error:
        raise NvdCveImportError(
            f"Feed {descriptor.year} content is not valid JSON"
        ) from error
    except (gzip.BadGzipFile, EOFError, OSError) as error:
        raise NvdCveImportError(
            f"Feed {descriptor.year} could not be read as gzip JSON"
        ) from error

    if not isinstance(value, dict):
        raise NvdCveImportError(
            f"Feed {descriptor.year} top-level value must be an object"
        )
    vulnerabilities = value.get("vulnerabilities")
    results_per_page = value.get("resultsPerPage")
    total_results = value.get("totalResults")
    if (
        not isinstance(vulnerabilities, list)
        or not _is_nonnegative_integer(results_per_page)
        or not _is_nonnegative_integer(total_results)
        or value.get("startIndex") != 0
        or value.get("format") != "NVD_CVE"
        or value.get("version") != "2.0"
        or results_per_page != len(vulnerabilities)
        or total_results != len(vulnerabilities)
        or total_results != descriptor.declared_count
    ):
        raise NvdCveImportError(
            f"Feed {descriptor.year} pagination/count validation failed"
        )
    return vulnerabilities


def _to_cve_model(
    record: ParsedCveRecord,
    snapshot: NvdCveSnapshot,
) -> NvdCveRecord:
    return NvdCveRecord(
        snapshot=snapshot,
        cve_id=record.cve_id,
        published_at_nvd=record.published_at_nvd,
        last_modified_at_nvd=record.last_modified_at_nvd,
        vuln_status=record.vuln_status,
        configurations=record.configurations,
    )


def _to_match_model(
    match: ParsedCpeMatch,
    cve_record: NvdCveRecord,
) -> NvdCpeMatch:
    return NvdCpeMatch(
        cve_record=cve_record,
        configuration_index=match.configuration_index,
        node_index=match.node_index,
        match_index=match.match_index,
        configuration_operator=match.configuration_operator,
        configuration_negate=match.configuration_negate,
        node_operator=match.node_operator,
        node_negate=match.node_negate,
        vulnerable=match.vulnerable,
        criteria=match.criteria,
        match_criteria_id=match.match_criteria_id,
        version_start_including=match.version_start_including,
        version_start_excluding=match.version_start_excluding,
        version_end_including=match.version_end_including,
        version_end_excluding=match.version_end_excluding,
    )


def _flush_pending(
    pending: list[ParsedCveRecord],
    *,
    snapshot: NvdCveSnapshot,
    batch_size: int,
) -> None:
    cve_models = [_to_cve_model(record, snapshot) for record in pending]
    NvdCveRecord.objects.bulk_create(
        cve_models,
        batch_size=batch_size,
    )
    if any(record.pk is None for record in cve_models):
        raise NvdCveImportError(
            "Database did not return primary keys for inserted CVE records"
        )

    match_batch: list[NvdCpeMatch] = []
    for parsed, cve_model in zip(pending, cve_models, strict=True):
        for match in parsed.matches:
            match_batch.append(_to_match_model(match, cve_model))
            if len(match_batch) >= batch_size:
                NvdCpeMatch.objects.bulk_create(
                    match_batch,
                    batch_size=batch_size,
                )
                match_batch.clear()
    if match_batch:
        NvdCpeMatch.objects.bulk_create(
            match_batch,
            batch_size=batch_size,
        )


def _process_feeds(
    verified: VerifiedNvdCveSnapshot,
    *,
    batch_size: int,
    snapshot: NvdCveSnapshot | None,
    reporter: Reporter,
) -> ImportCounts:
    counts = ImportCounts()
    seen_cve_ids: set[str] = set()
    pending: list[ParsedCveRecord] = []

    for feed_index, descriptor in enumerate(verified.feeds, start=1):
        vulnerabilities = _load_feed(verified, descriptor)
        for vulnerability_index, vulnerability in enumerate(
            vulnerabilities,
            start=1,
        ):
            record = _parse_cve(
                vulnerability,
                year=descriptor.year,
                vulnerability_index=vulnerability_index,
            )
            if record.cve_id in seen_cve_ids:
                counts.duplicate_cve_count += 1
                raise NvdCveImportError(
                    f"Snapshot contains duplicate CVE ID: {record.cve_id}"
                )
            seen_cve_ids.add(record.cve_id)

            counts.record_count += 1
            counts.configuration_count += len(record.configurations or [])
            counts.cpe_match_count += len(record.matches)
            for match in record.matches:
                if match.vulnerable:
                    counts.vulnerable_true_count += 1
                else:
                    counts.vulnerable_false_count += 1

            if snapshot is not None:
                pending.append(record)
                if len(pending) >= batch_size:
                    _flush_pending(
                        pending,
                        snapshot=snapshot,
                        batch_size=batch_size,
                    )
                    pending.clear()

        reporter(
            f"Processed feed {feed_index}/{len(verified.feeds)} "
            f"(CVE-{descriptor.year}): {len(vulnerabilities)} records"
        )

    if snapshot is not None and pending:
        _flush_pending(
            pending,
            snapshot=snapshot,
            batch_size=batch_size,
        )
        pending.clear()

    if counts.record_count != verified.expected_record_count:
        raise NvdCveImportError(
            "Parsed CVE count does not match VERIFIED manifest: "
            f"parsed={counts.record_count}, "
            f"expected={verified.expected_record_count}"
        )
    if (
        counts.cpe_match_count
        != counts.vulnerable_true_count + counts.vulnerable_false_count
    ):
        raise NvdCveImportError(
            "Vulnerable true/false counts do not match CPE match count"
        )
    return counts


def _result(
    verified: VerifiedNvdCveSnapshot,
    counts: ImportCounts,
    *,
    dry_run: bool,
    already_imported: bool,
) -> ImportResult:
    return ImportResult(
        snapshot_id=verified.snapshot_id,
        feed_count=len(verified.feeds),
        expected_record_count=verified.expected_record_count,
        record_count=counts.record_count,
        configuration_count=counts.configuration_count,
        cpe_match_count=counts.cpe_match_count,
        vulnerable_true_count=counts.vulnerable_true_count,
        vulnerable_false_count=counts.vulnerable_false_count,
        duplicate_cve_count=counts.duplicate_cve_count,
        dry_run=dry_run,
        already_imported=already_imported,
    )


def _existing_import_result(
    existing: NvdCveSnapshot,
    verified: VerifiedNvdCveSnapshot,
) -> ImportResult:
    cve_count = NvdCveRecord.objects.filter(snapshot=existing).count()
    matches = NvdCpeMatch.objects.filter(cve_record__snapshot=existing)
    cpe_match_count = matches.count()
    vulnerable_true_count = matches.filter(vulnerable=True).count()
    vulnerable_false_count = matches.filter(vulnerable=False).count()
    is_consistent = (
        existing.status == NvdCveSnapshot.Status.COMPLETE
        and existing.manifest_sha256 == verified.manifest_sha256
        and existing.content_sha256 == verified.content_sha256
        and existing.feed_count == len(verified.feeds)
        and existing.record_count == verified.expected_record_count
        and existing.record_count == cve_count
        and existing.cpe_match_count == cpe_match_count
        and cpe_match_count
        == vulnerable_true_count + vulnerable_false_count
        and existing.completed_at is not None
    )
    if not is_consistent:
        raise NvdCveImportError(
            "Existing NVD CVE snapshot import is incomplete or conflicts "
            "with the VERIFIED artifact"
        )
    return _result(
        verified,
        ImportCounts(
            record_count=cve_count,
            configuration_count=existing.configuration_count,
            cpe_match_count=cpe_match_count,
            vulnerable_true_count=vulnerable_true_count,
            vulnerable_false_count=vulnerable_false_count,
        ),
        dry_run=False,
        already_imported=True,
    )


def import_nvd_cve_snapshot(
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
        raise NvdCveImportError(
            f"batch_size must be between {MIN_BATCH_SIZE} "
            f"and {MAX_BATCH_SIZE}"
        )

    verified = verify_nvd_cve_snapshot(input_root, snapshot_id)
    if dry_run:
        counts = _process_feeds(
            verified,
            batch_size=batch_size,
            snapshot=None,
            reporter=reporter,
        )
        return _result(
            verified,
            counts,
            dry_run=True,
            already_imported=False,
        )

    existing = NvdCveSnapshot.objects.filter(
        snapshot_id=snapshot_id
    ).first()
    if existing is not None:
        return _existing_import_result(existing, verified)

    try:
        with transaction.atomic():
            snapshot = NvdCveSnapshot.objects.create(
                snapshot_id=snapshot_id,
                status=NvdCveSnapshot.Status.IMPORTING,
                manifest_sha256=verified.manifest_sha256,
                content_sha256=verified.content_sha256,
                feed_count=len(verified.feeds),
                record_count=0,
                configuration_count=0,
                cpe_match_count=0,
            )
            counts = _process_feeds(
                verified,
                batch_size=batch_size,
                snapshot=snapshot,
                reporter=reporter,
            )

            db_record_count = NvdCveRecord.objects.filter(
                snapshot=snapshot
            ).count()
            db_match_count = NvdCpeMatch.objects.filter(
                cve_record__snapshot=snapshot
            ).count()
            if (
                db_record_count != counts.record_count
                or db_record_count != verified.expected_record_count
                or db_match_count != counts.cpe_match_count
            ):
                raise NvdCveImportError(
                    "Imported database counts do not match parsed counts"
                )

            snapshot.status = NvdCveSnapshot.Status.COMPLETE
            snapshot.record_count = counts.record_count
            snapshot.configuration_count = counts.configuration_count
            snapshot.cpe_match_count = counts.cpe_match_count
            snapshot.completed_at = timezone.now()
            snapshot.save(
                update_fields=[
                    "status",
                    "record_count",
                    "configuration_count",
                    "cpe_match_count",
                    "completed_at",
                ]
            )
    except (IntegrityError, DatabaseError) as error:
        raise NvdCveImportError(
            "NVD CVE uniqueness/integrity validation failed; "
            "the import was rolled back"
        ) from error

    return _result(
        verified,
        counts,
        dry_run=False,
        already_imported=False,
    )

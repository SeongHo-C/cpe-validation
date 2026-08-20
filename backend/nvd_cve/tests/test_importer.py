from __future__ import annotations

import gzip
import hashlib
import io
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import NAMESPACE_DNS, uuid5

from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import TestCase

from nvd_cve import importer as importer_module
from nvd_cve.importer import (
    NvdCveImportError,
    import_nvd_cve_snapshot,
)
from nvd_cve.models import NvdCpeMatch, NvdCveRecord, NvdCveSnapshot
from nvd_cve.snapshot import (
    FEEDS_DIRECTORY,
    MANIFEST_FILENAME,
    _feed_manifest,
    build_manifest,
    feed_filename,
    meta_filename,
    parse_metadata,
    validate_yearly_feed,
)


SNAPSHOT_ID = "20020820T105500Z"
SECOND_SNAPSHOT_ID = "20020821T105500Z"
MULTI_YEAR_SNAPSHOT_ID = "20030820T105500Z"
def make_match(
    number: int,
    *,
    vulnerable: bool = True,
    criteria: str | None = None,
) -> dict[str, object]:
    return {
        "vulnerable": vulnerable,
        "criteria": criteria
        or f"cpe:2.3:a:vendor:product:{number}:*:*:*:*:*:*:*",
        "matchCriteriaId": str(uuid5(NAMESPACE_DNS, f"match-{number}")),
        "versionStartIncluding": f"{number}.0",
        "versionStartExcluding": f"{number}.1",
        "versionEndIncluding": f"{number}.9",
        "versionEndExcluding": f"{number}.10",
    }


def make_configuration(*matches: dict[str, object]) -> dict[str, object]:
    return {
        "operator": "AND",
        "negate": False,
        "nodes": [
            {
                "operator": "OR",
                "negate": True,
                "cpeMatch": list(matches),
            }
        ],
    }


_ABSENT = object()


def make_cve(
    number: int,
    *,
    configurations: object = _ABSENT,
    cve_id: str | None = None,
) -> dict[str, object]:
    cve: dict[str, object] = {
        "id": cve_id or f"CVE-2002-{number:04d}",
        "published": "2002-01-02T03:04:05.000",
        "lastModified": "2026-08-20T11:44:10.000Z",
        "vulnStatus": "Analyzed",
    }
    if configurations is not _ABSENT:
        cve["configurations"] = configurations
    return {"cve": cve}


def make_feed(vulnerabilities: list[dict[str, object]]) -> dict[str, object]:
    return {
        "resultsPerPage": len(vulnerabilities),
        "startIndex": 0,
        "totalResults": len(vulnerabilities),
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2002-08-20T10:55:00.000",
        "vulnerabilities": vulnerabilities,
    }


def write_verified_snapshot(
    input_root: Path,
    documents: dict[int, dict[str, object]],
    *,
    snapshot_id: str = SNAPSHOT_ID,
) -> Path:
    captured_at = datetime.strptime(
        snapshot_id,
        "%Y%m%dT%H%M%SZ",
    ).replace(tzinfo=timezone.utc)
    snapshot_path = input_root / snapshot_id
    feeds_path = snapshot_path / FEEDS_DIRECTORY
    feeds_path.mkdir(parents=True)
    feed_manifests: list[dict[str, object]] = []
    aggregate = hashlib.sha256()
    aggregate_size = 0
    total_count = 0

    for year, document in sorted(documents.items()):
        content = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        compressed = gzip.compress(content, mtime=0)
        metadata_bytes = (
            "lastModifiedDate:2002-08-20T06:00:00-04:00\n"
            f"size:{len(content)}\n"
            "zipSize:0\n"
            f"gzSize:{len(compressed)}\n"
            f"sha256:{hashlib.sha256(content).hexdigest()}\n"
        ).encode("utf-8")
        metadata = parse_metadata(metadata_bytes.decode("utf-8"))
        metadata_path = feeds_path / meta_filename(year)
        feed_path = feeds_path / feed_filename(year)
        metadata_path.write_bytes(metadata_bytes)
        feed_path.write_bytes(compressed)
        validated = validate_yearly_feed(
            feed_path,
            year=year,
            metadata=metadata,
            aggregate_digest=aggregate,
        )
        feed_manifests.append(
            _feed_manifest(
                year=year,
                metadata_bytes=metadata_bytes,
                metadata=metadata,
                feed=validated,
            )
        )
        aggregate_size += len(content)
        total_count += validated.parsed_count

    manifest = build_manifest(
        snapshot_id=snapshot_id,
        base_url="https://example.test/cve/2.0",
        capture_started_at=captured_at,
        retrieved_at=captured_at,
        capture_completed_at=captured_at,
        feed_manifests=feed_manifests,
        aggregate_size=aggregate_size,
        aggregate_sha256=aggregate.hexdigest(),
        total_declared_count=total_count,
        total_parsed_count=total_count,
    )
    (snapshot_path / MANIFEST_FILENAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return snapshot_path


class NvdCveImporterTests(TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.input_root = Path(self.temporary_directory.name) / "nvd-cve"

    def _write_default(self) -> Path:
        return write_verified_snapshot(
            self.input_root,
            {
                2002: make_feed(
                    [
                        make_cve(
                            1,
                            configurations=[
                                make_configuration(
                                    make_match(1),
                                    make_match(2, vulnerable=False),
                                )
                            ],
                        ),
                        make_cve(2),
                        make_cve(3, configurations=[]),
                    ]
                )
            },
        )

    def _import(
        self,
        *,
        snapshot_id: str = SNAPSHOT_ID,
        dry_run: bool = False,
    ):
        return import_nvd_cve_snapshot(
            self.input_root,
            snapshot_id,
            batch_size=100,
            dry_run=dry_run,
        )

    def test_imports_snapshot_and_flattens_matches(self) -> None:
        self._write_default()
        result = self._import()

        snapshot = NvdCveSnapshot.objects.get(snapshot_id=SNAPSHOT_ID)
        self.assertEqual(snapshot.status, NvdCveSnapshot.Status.COMPLETE)
        self.assertEqual(snapshot.record_count, 3)
        self.assertEqual(snapshot.configuration_count, 1)
        self.assertEqual(snapshot.cpe_match_count, 2)
        self.assertIsNotNone(snapshot.completed_at)
        self.assertEqual(NvdCveRecord.objects.count(), 3)
        self.assertEqual(NvdCpeMatch.objects.count(), 2)
        self.assertEqual(result.vulnerable_true_count, 1)
        self.assertEqual(result.vulnerable_false_count, 1)

    def test_dry_run_performs_no_database_writes(self) -> None:
        self._write_default()
        result = self._import(dry_run=True)

        self.assertTrue(result.dry_run)
        self.assertEqual(result.record_count, 3)
        self.assertEqual(result.configuration_count, 1)
        self.assertEqual(result.cpe_match_count, 2)
        self.assertEqual(result.duplicate_cve_count, 0)
        self.assertEqual(NvdCveSnapshot.objects.count(), 0)
        self.assertEqual(NvdCveRecord.objects.count(), 0)
        self.assertEqual(NvdCpeMatch.objects.count(), 0)

    def test_rejects_malformed_manifest(self) -> None:
        snapshot_path = self._write_default()
        manifest_path = snapshot_path / MANIFEST_FILENAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "DOWNLOADING"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(NvdCveImportError, "validation failed"):
            self._import(dry_run=True)

    def test_rejects_manifest_hash_mismatch(self) -> None:
        snapshot_path = self._write_default()
        manifest_path = snapshot_path / MANIFEST_FILENAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["feeds"][0]["compressed_sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(NvdCveImportError, "validation failed"):
            self._import(dry_run=True)

    def test_rejects_cve_count_mismatch(self) -> None:
        snapshot_path = write_verified_snapshot(
            self.input_root,
            {2002: make_feed([make_cve(1)])},
        )
        manifest_path = snapshot_path / MANIFEST_FILENAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["total_parsed_count"] = 2
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(NvdCveImportError, "validation failed"):
            self._import(dry_run=True)

    def test_rejects_duplicate_cve_id(self) -> None:
        duplicate = make_cve(1, cve_id="CVE-2002-0001")
        write_verified_snapshot(
            self.input_root,
            {
                2002: make_feed([duplicate]),
                2003: make_feed([duplicate]),
            },
            snapshot_id=MULTI_YEAR_SNAPSHOT_ID,
        )

        with self.assertRaisesRegex(NvdCveImportError, "duplicate CVE ID"):
            self._import(
                snapshot_id=MULTI_YEAR_SNAPSHOT_ID,
                dry_run=True,
            )

    def test_rejects_malformed_cve(self) -> None:
        cve = make_cve(1)
        del cve["cve"]["vulnStatus"]
        write_verified_snapshot(self.input_root, {2002: make_feed([cve])})

        with self.assertRaisesRegex(NvdCveImportError, "vulnStatus"):
            self._import(dry_run=True)

    def test_preserves_absent_and_empty_configurations(self) -> None:
        self._write_default()
        self._import()

        absent = NvdCveRecord.objects.get(cve_id="CVE-2002-0002")
        empty = NvdCveRecord.objects.get(cve_id="CVE-2002-0003")
        self.assertIsNone(absent.configurations)
        self.assertEqual(empty.configurations, [])

    def test_rejects_null_configurations_when_present(self) -> None:
        write_verified_snapshot(
            self.input_root,
            {2002: make_feed([make_cve(1, configurations=None)])},
        )

        with self.assertRaisesRegex(NvdCveImportError, "must be an array"):
            self._import(dry_run=True)

    def test_preserves_flattened_position_boundaries_and_operators(self) -> None:
        self._write_default()
        self._import()

        match = NvdCpeMatch.objects.order_by("match_index").first()
        assert match is not None
        self.assertEqual(match.configuration_index, 0)
        self.assertEqual(match.node_index, 0)
        self.assertEqual(match.match_index, 0)
        self.assertEqual(match.configuration_operator, "AND")
        self.assertFalse(match.configuration_negate)
        self.assertEqual(match.node_operator, "OR")
        self.assertTrue(match.node_negate)
        self.assertEqual(match.version_start_including, "1.0")
        self.assertEqual(match.version_start_excluding, "1.1")
        self.assertEqual(match.version_end_including, "1.9")
        self.assertEqual(match.version_end_excluding, "1.10")

    def test_duplicate_flattened_position_is_constrained(self) -> None:
        self._write_default()
        self._import()
        match = NvdCpeMatch.objects.first()
        assert match is not None
        with self.assertRaises(IntegrityError), transaction.atomic():
            NvdCpeMatch.objects.create(
                cve_record=match.cve_record,
                configuration_index=match.configuration_index,
                node_index=match.node_index,
                match_index=match.match_index,
                vulnerable=True,
                criteria="cpe:2.3:a:other:product:*:*:*:*:*:*:*:*",
                match_criteria_id=uuid5(NAMESPACE_DNS, "duplicate"),
            )

    def test_database_failure_rolls_back_entire_import(self) -> None:
        self._write_default()
        with (
            patch.object(
                NvdCpeMatch.objects,
                "bulk_create",
                side_effect=IntegrityError("forced failure"),
            ),
            self.assertRaisesRegex(NvdCveImportError, "rolled back"),
        ):
            self._import()

        self.assertEqual(NvdCveSnapshot.objects.count(), 0)
        self.assertEqual(NvdCveRecord.objects.count(), 0)
        self.assertEqual(NvdCpeMatch.objects.count(), 0)

    def test_complete_snapshot_reimport_is_protected(self) -> None:
        self._write_default()
        first = self._import()
        second = self._import()

        self.assertFalse(first.already_imported)
        self.assertTrue(second.already_imported)
        self.assertEqual(NvdCveSnapshot.objects.count(), 1)
        self.assertEqual(NvdCveRecord.objects.count(), 3)

    def test_same_cve_is_isolated_between_snapshots(self) -> None:
        document = make_feed([make_cve(1)])
        write_verified_snapshot(self.input_root, {2002: document})
        write_verified_snapshot(
            self.input_root,
            {2002: document},
            snapshot_id=SECOND_SNAPSHOT_ID,
        )
        self._import()
        self._import(snapshot_id=SECOND_SNAPSHOT_ID)

        self.assertEqual(NvdCveSnapshot.objects.count(), 2)
        self.assertEqual(
            NvdCveRecord.objects.filter(cve_id="CVE-2002-0001").count(),
            2,
        )

    def test_database_count_mismatch_rolls_back(self) -> None:
        self._write_default()
        original_process = importer_module._process_feeds

        def process_with_wrong_count(*args, **kwargs):
            counts = original_process(*args, **kwargs)
            counts.record_count += 1
            return counts

        with (
            patch(
                "nvd_cve.importer._process_feeds",
                side_effect=process_with_wrong_count,
            ),
            self.assertRaisesRegex(NvdCveImportError, "database counts"),
        ):
            self._import()

        self.assertEqual(NvdCveSnapshot.objects.count(), 0)

    def test_management_command_dry_run_reports_zero_writes(self) -> None:
        self._write_default()
        output = io.StringIO()
        call_command(
            "import_nvd_cve_snapshot",
            snapshot_id=SNAPSHOT_ID,
            input_root=str(self.input_root),
            batch_size=100,
            dry_run=True,
            stdout=output,
        )
        rendered = output.getvalue()
        self.assertIn("Validation result: PASS", rendered)
        self.assertIn("DB writes: 0", rendered)
        self.assertEqual(NvdCveSnapshot.objects.count(), 0)

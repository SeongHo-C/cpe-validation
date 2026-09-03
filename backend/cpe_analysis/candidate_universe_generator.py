from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from django.db import connection, transaction
from django.db.models import Count, Q

from cpe.cpe23_canonical import CPE23ValueKind, parse_cpe23
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from nvd_cve.models import NvdCpeMatch, NvdCveSnapshot


DEFAULT_CPE_SNAPSHOT = "20260819T035002Z"
DEFAULT_NVD_SNAPSHOT = "20260820T110357Z"

EXPECTED_FIXED_COUNTS = {
    "dictionary_total": 1_811_261,
    "dictionary_active": 1_711_630,
    "dictionary_deprecated": 99_631,
    "nvd_distinct_criteria": 428_417,
    "nvd_occurrences": 3_170_148,
    "active_families": 149_598,
    "configuration_only_families": 31_895,
    "total_families": 181_493,
    "searchable_families": 181_484,
}

CANDIDATE_FIELDS = (
    "family_id",
    "part",
    "vendor",
    "product",
    "canonical_part",
    "canonical_vendor",
    "canonical_product",
    "source",
    "searchable",
    "searchability_class",
    "representative_raw_cpe",
    "active_cpe_entry_count",
    "distinct_version_count",
    "distinct_update_count",
    "title_count",
    "nvd_criteria_count",
    "nvd_occurrence_count",
    "has_exact_versions",
    "has_version_ranges",
    "cpe_snapshot",
    "nvd_snapshot",
)

Family = tuple[str, str, str]


class CandidateUniverseGenerationError(RuntimeError):
    """Raised when fixed input or generated output violates the contract."""


@dataclass
class ActiveFamilyStats:
    entry_count: int = 0
    versions: set[str] = field(default_factory=set)
    updates: set[str] = field(default_factory=set)
    titles: set[tuple[str, str]] = field(default_factory=set)
    representative_cpe: str = ""


@dataclass
class NvdFamilyStats:
    criteria_count: int = 0
    occurrence_count: int = 0
    criteria_versions: set[str] = field(default_factory=set)
    criteria_updates: set[str] = field(default_factory=set)
    has_exact_versions: bool = False
    has_version_ranges: bool = False
    representative_criteria: str = ""


@dataclass
class DictionaryFamilies:
    active: set[Family]
    deprecated: set[Family]
    active_stats: dict[Family, ActiveFamilyStats]
    total_rows: int
    active_rows: int
    deprecated_rows: int


@dataclass
class NvdFamilies:
    families: set[Family]
    stats: dict[Family, NvdFamilyStats]
    distinct_criteria: int
    occurrence_count: int


@dataclass(frozen=True)
class CandidateUniverseGenerationResult:
    cpe_snapshot: str
    nvd_snapshot: str
    output_directory: str
    candidate_file: str
    manifest_file: str
    dictionary_total: int
    dictionary_active: int
    dictionary_deprecated: int
    active_families: int
    deprecated_families: int
    nvd_distinct_criteria: int
    nvd_occurrences: int
    nvd_families: int
    configuration_only_families: int
    total_families: int
    searchable_families: int
    non_searchable_families: int
    candidate_file_sha256: str
    family_set_sha256: str
    transaction_read_only: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _compact_family_json(family: Family) -> str:
    return json.dumps(
        list(family),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def family_id(family: Family) -> str:
    return hashlib.sha256(
        _compact_family_json(family).encode("utf-8")
    ).hexdigest()


def family_set_sha256(families: Iterable[Family]) -> str:
    digest = hashlib.sha256()
    for family in sorted(families):
        digest.update(_compact_family_json(family).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def searchability(family: Family) -> tuple[bool, str]:
    part, vendor, product = family
    if part not in {"a", "o", "h"} or not vendor or not product:
        return False, "NON_SEARCHABLE_INVALID"
    if vendor == "*" or product == "*":
        return False, "NON_SEARCHABLE_WILDCARD"
    if vendor == "-" or product == "-":
        return False, "NON_SEARCHABLE_NA"
    return True, "SEARCHABLE"


def candidate_source_map(
    active_families: set[Family],
    deprecated_families: set[Family],
    nvd_families: set[Family],
) -> tuple[dict[Family, str], set[Family]]:
    configuration_only = nvd_families - (
        active_families | deprecated_families
    )
    sources = {
        family: "ACTIVE_DICTIONARY" for family in active_families
    }
    sources.update(
        {
            family: "NVD_CONFIGURATION_ONLY"
            for family in configuration_only
        }
    )
    if len(sources) != len(active_families) + len(configuration_only):
        raise CandidateUniverseGenerationError(
            "Candidate source sets unexpectedly overlap."
        )
    if configuration_only & deprecated_families:
        raise CandidateUniverseGenerationError(
            "Configuration-only families overlap Deprecated Dictionary."
        )
    return sources, configuration_only


def _parsed_family(raw_cpe: str, *, source: str) -> tuple[Family, object]:
    parsed = parse_cpe23(raw_cpe)
    if not parsed.is_valid or parsed.name is None:
        raise CandidateUniverseGenerationError(
            f"Invalid {source} CPE {raw_cpe!r}: {parsed.error_message}"
        )
    values = tuple(attribute.canonical for attribute in parsed.name.attributes)
    return (values[0], values[1], values[2]), parsed.name


def _scan_dictionary(snapshot: CpeDictionarySnapshot) -> DictionaryFamilies:
    active: set[Family] = set()
    deprecated: set[Family] = set()
    active_stats: dict[Family, ActiveFamilyStats] = {}
    total_rows = 0
    active_rows = 0
    deprecated_rows = 0

    rows = (
        CpeName.objects.filter(snapshot=snapshot)
        .values_list("cpe_name", "deprecated", "titles")
        .order_by("cpe_name")
        .iterator(chunk_size=10_000)
    )
    for raw_cpe, is_deprecated, titles in rows:
        total_rows += 1
        family, name = _parsed_family(raw_cpe, source="Dictionary")
        if is_deprecated:
            deprecated_rows += 1
            deprecated.add(family)
            continue

        active_rows += 1
        active.add(family)
        stats = active_stats.setdefault(family, ActiveFamilyStats())
        stats.entry_count += 1
        stats.versions.add(name.attribute("version").canonical)
        stats.updates.add(name.attribute("update").canonical)
        if not stats.representative_cpe:
            stats.representative_cpe = raw_cpe
        if not isinstance(titles, list):
            raise CandidateUniverseGenerationError(
                f"Dictionary CPE {raw_cpe!r} has non-list titles."
            )
        for title_item in titles:
            if not isinstance(title_item, dict):
                raise CandidateUniverseGenerationError(
                    f"Dictionary CPE {raw_cpe!r} has an invalid title."
                )
            title = title_item.get("title")
            language = title_item.get("lang")
            if not isinstance(title, str) or not isinstance(language, str):
                raise CandidateUniverseGenerationError(
                    f"Dictionary CPE {raw_cpe!r} has an invalid title."
                )
            stats.titles.add((title, language))

    return DictionaryFamilies(
        active=active,
        deprecated=deprecated,
        active_stats=active_stats,
        total_rows=total_rows,
        active_rows=active_rows,
        deprecated_rows=deprecated_rows,
    )


def _nvd_criteria_rows(snapshot: NvdCveSnapshot):
    has_range = (
        Q(version_start_including__isnull=False)
        | Q(version_start_excluding__isnull=False)
        | Q(version_end_including__isnull=False)
        | Q(version_end_excluding__isnull=False)
    )
    return (
        NvdCpeMatch.objects.filter(cve_record__snapshot=snapshot)
        .values("criteria")
        .annotate(
            occurrence_count=Count("id"),
            range_occurrence_count=Count("id", filter=has_range),
        )
        .order_by("criteria")
        .iterator(chunk_size=10_000)
    )


def _scan_nvd(snapshot: NvdCveSnapshot) -> NvdFamilies:
    families: set[Family] = set()
    stats: dict[Family, NvdFamilyStats] = {}
    distinct_criteria = 0
    occurrence_count = 0

    for row in _nvd_criteria_rows(snapshot):
        distinct_criteria += 1
        raw_cpe = row["criteria"]
        criteria_occurrences = int(row["occurrence_count"])
        range_occurrences = int(row["range_occurrence_count"])
        occurrence_count += criteria_occurrences
        family, name = _parsed_family(raw_cpe, source="NVD criteria")
        families.add(family)
        item = stats.setdefault(family, NvdFamilyStats())
        item.criteria_count += 1
        item.occurrence_count += criteria_occurrences
        version = name.attribute("version")
        item.criteria_versions.add(version.canonical)
        item.criteria_updates.add(name.attribute("update").canonical)
        item.has_exact_versions |= version.kind is CPE23ValueKind.STRING
        item.has_version_ranges |= range_occurrences > 0
        if not item.representative_criteria:
            item.representative_criteria = raw_cpe

    return NvdFamilies(
        families=families,
        stats=stats,
        distinct_criteria=distinct_criteria,
        occurrence_count=occurrence_count,
    )


def _candidate_row(
    family: Family,
    source: str,
    dictionary: DictionaryFamilies,
    nvd: NvdFamilies,
    *,
    cpe_snapshot: str,
    nvd_snapshot: str,
) -> dict[str, object]:
    active = dictionary.active_stats.get(family)
    nvd_item = nvd.stats.get(family)
    searchable, searchability_class = searchability(family)

    if source == "ACTIVE_DICTIONARY":
        if active is None:
            raise CandidateUniverseGenerationError(
                f"Active family {family!r} has no statistics."
            )
        representative = active.representative_cpe
        active_entries = active.entry_count
        distinct_versions = len(active.versions)
        distinct_updates = len(active.updates)
        title_count = len(active.titles)
        has_exact_versions = any(
            version not in {"*", "-"} for version in active.versions
        )
        has_version_ranges = False
    else:
        if nvd_item is None:
            raise CandidateUniverseGenerationError(
                f"NVD family {family!r} has no statistics."
            )
        representative = nvd_item.representative_criteria
        active_entries = 0
        distinct_versions = len(nvd_item.criteria_versions)
        distinct_updates = len(nvd_item.criteria_updates)
        title_count = 0
        has_exact_versions = nvd_item.has_exact_versions
        has_version_ranges = nvd_item.has_version_ranges

    return {
        "family_id": family_id(family),
        "part": family[0],
        "vendor": family[1],
        "product": family[2],
        "canonical_part": family[0],
        "canonical_vendor": family[1],
        "canonical_product": family[2],
        "source": source,
        "searchable": searchable,
        "searchability_class": searchability_class,
        "representative_raw_cpe": representative,
        "active_cpe_entry_count": active_entries,
        "distinct_version_count": distinct_versions,
        "distinct_update_count": distinct_updates,
        "title_count": title_count,
        "nvd_criteria_count": nvd_item.criteria_count if nvd_item else 0,
        "nvd_occurrence_count": (
            nvd_item.occurrence_count if nvd_item else 0
        ),
        "has_exact_versions": has_exact_versions,
        "has_version_ranges": has_version_ranges,
        "cpe_snapshot": cpe_snapshot,
        "nvd_snapshot": nvd_snapshot,
    }


def _validate_fixed_contract(
    dictionary: DictionaryFamilies,
    nvd: NvdFamilies,
    *,
    sources: dict[Family, str],
    configuration_only: set[Family],
    searchable_count: int,
    cpe_snapshot: str,
    nvd_snapshot: str,
) -> None:
    if (
        cpe_snapshot != DEFAULT_CPE_SNAPSHOT
        or nvd_snapshot != DEFAULT_NVD_SNAPSHOT
    ):
        return
    observed = {
        "dictionary_total": dictionary.total_rows,
        "dictionary_active": dictionary.active_rows,
        "dictionary_deprecated": dictionary.deprecated_rows,
        "nvd_distinct_criteria": nvd.distinct_criteria,
        "nvd_occurrences": nvd.occurrence_count,
        "active_families": len(dictionary.active),
        "configuration_only_families": len(configuration_only),
        "total_families": len(sources),
        "searchable_families": searchable_count,
    }
    failures = {
        name: {"expected": expected, "observed": observed[name]}
        for name, expected in EXPECTED_FIXED_COUNTS.items()
        if observed[name] != expected
    }
    if failures:
        raise CandidateUniverseGenerationError(
            "Fixed snapshot contract mismatch: "
            + json.dumps(failures, sort_keys=True)
        )


def generate_candidate_universe(
    output_directory: Path,
    *,
    cpe_snapshot: str = DEFAULT_CPE_SNAPSHOT,
    nvd_snapshot: str = DEFAULT_NVD_SNAPSHOT,
) -> CandidateUniverseGenerationResult:
    output_directory = Path(output_directory).resolve()
    candidate_path = output_directory / "candidate_families.csv"
    manifest_path = output_directory / "manifest.json"
    if candidate_path.exists() or manifest_path.exists():
        raise CandidateUniverseGenerationError(
            "Output candidate_families.csv or manifest.json already exists."
        )
    output_directory.mkdir(parents=True, exist_ok=True)
    temporary_candidate = output_directory / ".candidate_families.csv.tmp"
    temporary_manifest = output_directory / ".manifest.json.tmp"

    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SET TRANSACTION ISOLATION LEVEL "
                    "REPEATABLE READ, READ ONLY"
                )
                cursor.execute("SHOW transaction_read_only")
                read_only = cursor.fetchone()[0] == "on"
            if not read_only:
                raise CandidateUniverseGenerationError(
                    "Database transaction is not read-only."
                )

            dictionary_snapshot = CpeDictionarySnapshot.objects.get(
                snapshot_id=cpe_snapshot
            )
            nvd_snapshot_row = NvdCveSnapshot.objects.get(
                snapshot_id=nvd_snapshot
            )
            if dictionary_snapshot.status != "COMPLETE":
                raise CandidateUniverseGenerationError(
                    f"CPE snapshot {cpe_snapshot} is not complete."
                )
            if nvd_snapshot_row.status != "COMPLETE":
                raise CandidateUniverseGenerationError(
                    f"NVD snapshot {nvd_snapshot} is not complete."
                )

            dictionary = _scan_dictionary(dictionary_snapshot)
            nvd = _scan_nvd(nvd_snapshot_row)
            sources, configuration_only = candidate_source_map(
                dictionary.active,
                dictionary.deprecated,
                nvd.families,
            )

            searchable_count = 0
            with temporary_candidate.open(
                "w", encoding="utf-8", newline=""
            ) as stream:
                writer = csv.DictWriter(stream, fieldnames=CANDIDATE_FIELDS)
                writer.writeheader()
                for family in sorted(sources):
                    row = _candidate_row(
                        family,
                        sources[family],
                        dictionary,
                        nvd,
                        cpe_snapshot=cpe_snapshot,
                        nvd_snapshot=nvd_snapshot,
                    )
                    writer.writerow(row)
                    searchable_count += bool(row["searchable"])

            _validate_fixed_contract(
                dictionary,
                nvd,
                sources=sources,
                configuration_only=configuration_only,
                searchable_count=searchable_count,
                cpe_snapshot=cpe_snapshot,
                nvd_snapshot=nvd_snapshot,
            )
            candidate_hash = file_sha256(temporary_candidate)
            family_hash = family_set_sha256(sources)
            result = CandidateUniverseGenerationResult(
                cpe_snapshot=cpe_snapshot,
                nvd_snapshot=nvd_snapshot,
                output_directory=str(output_directory),
                candidate_file=str(candidate_path),
                manifest_file=str(manifest_path),
                dictionary_total=dictionary.total_rows,
                dictionary_active=dictionary.active_rows,
                dictionary_deprecated=dictionary.deprecated_rows,
                active_families=len(dictionary.active),
                deprecated_families=len(dictionary.deprecated),
                nvd_distinct_criteria=nvd.distinct_criteria,
                nvd_occurrences=nvd.occurrence_count,
                nvd_families=len(nvd.families),
                configuration_only_families=len(configuration_only),
                total_families=len(sources),
                searchable_families=searchable_count,
                non_searchable_families=len(sources) - searchable_count,
                candidate_file_sha256=candidate_hash,
                family_set_sha256=family_hash,
                transaction_read_only=True,
            )
            manifest = {
                "schema_version": 1,
                "purpose": "CPE product-family candidate universe",
                "family_definition": ["part", "vendor", "product"],
                "candidate_file": "candidate_families.csv",
                "search_condition": "searchable == true",
                "candidate_sources": [
                    "ACTIVE_DICTIONARY",
                    "NVD_CONFIGURATION_ONLY",
                ],
                "cpe_snapshot": cpe_snapshot,
                "nvd_snapshot": nvd_snapshot,
                "active_dictionary_families": len(dictionary.active),
                "nvd_configuration_only_families": len(
                    configuration_only
                ),
                "total_candidate_families": len(sources),
                "searchable_candidate_families": searchable_count,
                "non_searchable_candidate_families": (
                    len(sources) - searchable_count
                ),
                "deprecated_final_candidates": 0,
                "candidate_file_sha256": candidate_hash,
                "family_set_sha256": family_hash,
            }
            temporary_manifest.write_text(
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        temporary_candidate.replace(candidate_path)
        temporary_manifest.replace(manifest_path)
        return result
    finally:
        temporary_candidate.unlink(missing_ok=True)
        temporary_manifest.unlink(missing_ok=True)

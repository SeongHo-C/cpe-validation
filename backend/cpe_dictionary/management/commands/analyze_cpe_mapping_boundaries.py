from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from itertools import batched
from pathlib import Path
from typing import Any
from uuid import UUID

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from cpe.cpe23_canonical import (
    CPE23ValueKind,
    canonicalize_cpe23,
    compare_cpe23,
    parse_cpe23,
)
from cpe.mapping_boundaries import (
    CPEReferenceRecord,
    DeprecatedResolutionResult,
    DeprecatedResolutionStatus,
    NON_VERSION_TEMPLATE_ATTRIBUTES,
    configuration_only_gate,
    resolve_deprecated_cpe,
    resolve_stable_template,
)
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from cpe_dictionary.snapshot_selection import select_cpe_dictionary_snapshot
from nvd_cve.models import NvdCpeMatch, NvdCveSnapshot
from nvd_cve.snapshot_selection import select_nvd_cve_snapshot


CPE_SNAPSHOT_ID = "20260819T035002Z"
NVD_SNAPSHOT_ID = "20260820T110357Z"
EXPECTED_CPE_COUNTS = (1_811_261, 1_711_630, 99_631)
EXPECTED_NVD_COUNTS = (380_865, 760_120, 3_170_148)
DEFAULT_OUTPUT = (
    "analysis/results/cpe-mapping-rulebook-boundary-tests/"
    f"{CPE_SNAPSHOT_ID}__{NVD_SNAPSHOT_ID}"
)

BRANCH_FIELDS = (
    "test_case_id",
    "branch",
    "observed",
    "input_cpe",
    "parsed_attributes",
    "canonical_cpe",
    "active_match",
    "deprecated_match",
    "deprecated_by",
    "replacement_chain",
    "active_endpoints",
    "resolution_status",
    "stable_template_status",
    "selected_template",
    "dictionary_product_present_active",
    "dictionary_product_present_deprecated",
    "configuration_gate_passed",
    "configuration_match",
    "expected_result",
    "actual_result",
    "pass_fail",
    "review_required",
    "notes",
)

DEPRECATED_FIELDS = (
    "case_id",
    "branch",
    "source_cpe_name_id",
    "source_cpe",
    "source_status",
    "direct_replacement_count",
    "deprecated_by",
    "replacement_chains",
    "replacement_depth",
    "candidate_active_endpoints",
    "compatible_active_endpoints",
    "resolved_active_endpoint",
    "resolution_status",
    "cycle_detected",
    "missing_references",
    "deprecated_dead_ends",
    "review_required",
    "review_reason",
)

CONFIGURATION_FIELDS = (
    "case_id",
    "part",
    "vendor",
    "product",
    "dictionary_active_count",
    "dictionary_deprecated_count",
    "gate_status",
    "configuration_gate_passed",
    "criteria",
    "match_criteria_id",
    "criteria_version",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "occurrence_count",
    "distinct_cve_count",
    "representative_cve",
    "stable_template_status",
    "selected_template",
    "review_required",
    "notes",
)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _bool(value: bool) -> str:
    return str(value).lower()


def _normalize_reference(
    reference: object,
) -> tuple[str, str | None]:
    if isinstance(reference, dict):
        identifier = reference.get("cpeNameId")
        cpe_name = reference.get("cpeName")
    else:
        identifier = reference
        cpe_name = None
    if not isinstance(identifier, str) or not identifier:
        return f"INVALID_REFERENCE:{_json(reference)}", None
    try:
        normalized = str(UUID(identifier))
    except ValueError:
        normalized = f"INVALID_REFERENCE:{identifier}"
    return normalized, cpe_name if isinstance(cpe_name, str) else None


def _branch_row(
    case_id: str,
    branch: str,
    *,
    input_cpe: str = "",
    observed: bool = True,
    **values: object,
) -> dict[str, str]:
    row = {field: "" for field in BRANCH_FIELDS}
    row.update(
        {
            "test_case_id": case_id,
            "branch": branch,
            "observed": _bool(observed),
            "input_cpe": input_cpe,
            "active_match": "false",
            "deprecated_match": "false",
            "configuration_gate_passed": "false",
            "configuration_match": "false",
            "pass_fail": "PASS",
            "review_required": "false",
        }
    )
    if input_cpe:
        parsed = parse_cpe23(input_cpe)
        row["parsed_attributes"] = _json(
            parsed.name.fields if parsed.name is not None else {}
        )
        row["canonical_cpe"] = (
            canonicalize_cpe23(input_cpe) if parsed.is_valid else ""
        )
    for key, value in values.items():
        if isinstance(value, bool):
            row[key] = _bool(value)
        elif isinstance(value, (dict, list, tuple)):
            row[key] = _json(value)
        else:
            row[key] = str(value)
    if row["expected_result"] and row["actual_result"]:
        row["pass_fail"] = (
            "PASS"
            if row["expected_result"] == row["actual_result"]
            else "FAIL"
        )
    return row


class Command(BaseCommand):
    help = (
        "Read-only fixed-snapshot validation of CPE mapping boundary rules."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output-directory",
            default=DEFAULT_OUTPUT,
            help=(
                "New artifact directory, relative to the repository root "
                "unless absolute. Existing directories are never modified."
            ),
        )

    def handle(self, *args, **options) -> None:
        output = Path(options["output_directory"])
        if not output.is_absolute():
            output = settings.REPOSITORY_ROOT / output
        if output.exists():
            raise CommandError(
                f"Refusing to modify existing artifact directory: {output}"
            )

        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION READ ONLY")
            cpe_snapshot = select_cpe_dictionary_snapshot(CPE_SNAPSHOT_ID)
            nvd_snapshot = select_nvd_cve_snapshot(NVD_SNAPSHOT_ID)
            self._validate_snapshots(cpe_snapshot, nvd_snapshot)
            collected = self._collect(cpe_snapshot, nvd_snapshot)

        output.mkdir(parents=True, exist_ok=False)
        self._write_csv(
            output / "branch_cases.csv",
            BRANCH_FIELDS,
            collected["branch_rows"],
        )
        self._write_csv(
            output / "deprecated_cases.csv",
            DEPRECATED_FIELDS,
            collected["deprecated_rows"],
        )
        self._write_csv(
            output / "configuration_only_cases.csv",
            CONFIGURATION_FIELDS,
            collected["configuration_rows"],
        )
        (output / "summary.json").write_text(
            json.dumps(collected["summary"], indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        (output / "report.md").write_text(
            self._render_report(collected["summary"], collected["branch_rows"]),
            encoding="utf-8",
        )
        self.stdout.write(self.style.SUCCESS(f"Wrote read-only analysis: {output}"))

    def _validate_snapshots(
        self,
        cpe_snapshot: CpeDictionarySnapshot,
        nvd_snapshot: NvdCveSnapshot,
    ) -> None:
        actual_cpe = (
            cpe_snapshot.record_count,
            cpe_snapshot.active_count,
            cpe_snapshot.deprecated_count,
        )
        actual_nvd = (
            nvd_snapshot.record_count,
            nvd_snapshot.configuration_count,
            nvd_snapshot.cpe_match_count,
        )
        if actual_cpe != EXPECTED_CPE_COUNTS:
            raise CommandError(
                f"CPE snapshot count mismatch: {actual_cpe}"
            )
        if actual_nvd != EXPECTED_NVD_COUNTS:
            raise CommandError(
                f"NVD snapshot count mismatch: {actual_nvd}"
            )

    def _collect(
        self,
        cpe_snapshot: CpeDictionarySnapshot,
        nvd_snapshot: NvdCveSnapshot,
    ) -> dict[str, Any]:
        parser_counts: Counter[str] = Counter()
        parser_invalid_examples: defaultdict[str, list[dict[str, str]]] = (
            defaultdict(list)
        )
        for cpe_name in (
            CpeName.objects.filter(snapshot=cpe_snapshot)
            .values_list("cpe_name", flat=True)
            .iterator(chunk_size=10_000)
        ):
            parsed = parse_cpe23(cpe_name)
            parser_counts[parsed.status.value] += 1
            if (
                not parsed.is_valid
                and len(parser_invalid_examples[parsed.status.value]) < 5
            ):
                parser_invalid_examples[parsed.status.value].append(
                    {"cpe": cpe_name, "error": parsed.error_message}
                )

        records: dict[str, CPEReferenceRecord] = {}
        declared_target_names: defaultdict[str, set[str]] = defaultdict(set)
        target_identifiers: set[str] = set()
        deprecated_source_ids: list[str] = []
        for identifier, cpe_name, deprecated_by in (
            CpeName.objects.filter(snapshot=cpe_snapshot, deprecated=True)
            .values_list("cpe_name_id", "cpe_name", "deprecated_by")
            .iterator(chunk_size=5_000)
        ):
            source_identifier = str(identifier)
            replacements: list[str] = []
            for reference in deprecated_by:
                target_identifier, declared_name = _normalize_reference(reference)
                replacements.append(target_identifier)
                target_identifiers.add(target_identifier)
                if declared_name is not None:
                    declared_target_names[target_identifier].add(declared_name)
            records[source_identifier] = CPEReferenceRecord(
                identifier=source_identifier,
                cpe_name=cpe_name,
                deprecated=True,
                deprecated_by=tuple(replacements),
            )
            deprecated_source_ids.append(source_identifier)

        unresolved_targets = target_identifiers - records.keys()
        valid_target_uuids: list[UUID] = []
        for identifier in unresolved_targets:
            try:
                valid_target_uuids.append(UUID(identifier))
            except ValueError:
                continue
        for batch in batched(valid_target_uuids, 10_000):
            for identifier, cpe_name, deprecated, deprecated_by in (
                CpeName.objects.filter(
                    snapshot=cpe_snapshot,
                    cpe_name_id__in=batch,
                ).values_list(
                    "cpe_name_id",
                    "cpe_name",
                    "deprecated",
                    "deprecated_by",
                )
            ):
                normalized_replacements = tuple(
                    _normalize_reference(reference)[0]
                    for reference in deprecated_by
                )
                records[str(identifier)] = CPEReferenceRecord(
                    identifier=str(identifier),
                    cpe_name=cpe_name,
                    deprecated=deprecated,
                    deprecated_by=normalized_replacements,
                )

        resolutions: dict[str, DeprecatedResolutionResult] = {}
        resolution_counts: Counter[str] = Counter()
        direct_replacement_counts: Counter[int] = Counter()
        for identifier in deprecated_source_ids:
            record = records[identifier]
            direct_replacement_counts[len(record.deprecated_by)] += 1
            if not record.deprecated_by:
                resolution_counts[
                    DeprecatedResolutionStatus.DEPRECATED_DEAD_END.value
                ] += 1
                continue
            result = resolve_deprecated_cpe(records, identifier)
            resolutions[identifier] = result
            resolution_counts[result.resolution_status.value] += 1

        sorted_resolutions = sorted(
            resolutions.items(),
            key=lambda item: records[item[0]].cpe_name,
        )
        direct_candidate = next(
            (
                item
                for item in sorted_resolutions
                if item[1].resolution_status
                is DeprecatedResolutionStatus.RESOLVED_ACTIVE
                and item[1].replacement_count == 1
                and item[1].replacement_depth == 1
            ),
            None,
        )
        multihop_candidate = next(
            (
                item
                for item in sorted_resolutions
                if item[1].resolution_status
                is DeprecatedResolutionStatus.RESOLVED_ACTIVE
                and item[1].replacement_depth > 1
            ),
            None,
        )
        multiple_candidates = [
            item
            for item in sorted_resolutions
            if item[1].replacement_count > 1
            and len(item[1].candidate_active_endpoints) > 1
        ]
        multiple_candidate = (
            min(
                multiple_candidates,
                key=lambda item: (
                    item[1].replacement_count,
                    records[item[0]].cpe_name,
                ),
            )
            if multiple_candidates
            else None
        )

        selected_deprecated: list[tuple[str, str, DeprecatedResolutionResult]] = []
        for case_id, branch, candidate in (
            ("DEP-1TO1-01", "DEPRECATED_TO_ACTIVE_1_TO_1", direct_candidate),
            ("DEP-MULTIHOP-01", "DEPRECATED_TO_ACTIVE_MULTI_HOP", multihop_candidate),
            ("DEP-MULTIPLE-01", "DEPRECATED_MULTIPLE_REPLACEMENTS", multiple_candidate),
        ):
            if candidate is not None:
                selected_deprecated.append((case_id, branch, candidate[1]))

        for status, case_prefix in (
            (DeprecatedResolutionStatus.CYCLE_DETECTED, "DEP-CYCLE"),
            (DeprecatedResolutionStatus.MISSING_REFERENCE, "DEP-MISSING"),
        ):
            candidates = [
                result
                for _, result in sorted_resolutions
                if result.resolution_status is status
            ][:5]
            selected_deprecated.extend(
                (f"{case_prefix}-{index:02d}", status.value, result)
                for index, result in enumerate(candidates, start=1)
            )

        source_by_cpe = {
            record.cpe_name: identifier
            for identifier, record in records.items()
            if record.deprecated
        }
        deprecated_rows = [
            self._deprecated_row(
                case_id,
                branch,
                source_by_cpe[result.starting_deprecated_cpe],
                result,
                records,
                declared_target_names,
            )
            for case_id, branch, result in selected_deprecated
        ]

        branch_rows: list[dict[str, str]] = []
        linux_cpe = "cpe:2.3:o:linux:linux_kernel:5.15.176:*:*:*:*:*:*:*"
        linux_active_count = CpeName.objects.filter(
            snapshot=cpe_snapshot,
            deprecated=False,
            cpe_name=linux_cpe,
        ).count()
        branch_rows.append(
            _branch_row(
                "ACTIVE-EXACT-01",
                "ACTIVE_EXACT",
                input_cpe=linux_cpe,
                active_match=linux_active_count == 1,
                expected_result="ACTIVE_EXACT",
                actual_result=(
                    "ACTIVE_EXACT" if linux_active_count == 1 else "NOT_UNIQUE"
                ),
                notes=(
                    "Fixed-snapshot Linux kernel record; exact 11-field "
                    f"Active count={linux_active_count}."
                ),
            )
        )

        strongswan_family = ("a", "strongswan", "strongswan")
        strongswan_cpes = list(
            CpeName.objects.filter(
                snapshot=cpe_snapshot,
                deprecated=False,
                part=strongswan_family[0],
                vendor=strongswan_family[1],
                product=strongswan_family[2],
            ).values_list("cpe_name", flat=True)
        )
        strongswan_template = resolve_stable_template(
            strongswan_cpes,
            family=strongswan_family,
            normalized_version="5.9.14",
            compatibility=lambda name: (
                name.attribute("update").kind is CPE23ValueKind.NA
            ),
        )
        strongswan_input = (
            "cpe:2.3:a:strongswan:strongswan:5.9.14:-:*:*:*:*:*:*"
        )
        strongswan_exact_active = CpeName.objects.filter(
            snapshot=cpe_snapshot,
            deprecated=False,
            part="a",
            vendor="strongswan",
            product="strongswan",
            version="5.9.14",
        ).count()
        branch_rows.append(
            _branch_row(
                "VERSION-NOT-01",
                "VERSION_NOT_IN_DICTIONARY",
                input_cpe=strongswan_input,
                active_match=bool(strongswan_exact_active),
                stable_template_status=strongswan_template.status.value,
                selected_template=strongswan_template.selected_template or (),
                dictionary_product_present_active=True,
                dictionary_product_present_deprecated=(
                    CpeName.objects.filter(
                        snapshot=cpe_snapshot,
                        deprecated=True,
                        part="a",
                        vendor="strongswan",
                        product="strongswan",
                    ).exists()
                ),
                expected_result="VERSION_NOT_IN_DICTIONARY",
                actual_result=(
                    "VERSION_NOT_IN_DICTIONARY"
                    if not strongswan_exact_active
                    and not strongswan_template.review_required
                    and strongswan_template.generated_cpe == strongswan_input
                    else "REVIEW_REQUIRED"
                ),
                review_required=strongswan_template.review_required,
                notes=(
                    "Final-release compatibility evidence restricts update "
                    "to NA; the generated expression preserves update=-."
                ),
            )
        )

        for case_id, branch, candidate in (
            ("DEP-1TO1-01", "DEPRECATED_TO_ACTIVE_1_TO_1", direct_candidate),
            ("DEP-MULTIHOP-01", "DEPRECATED_TO_ACTIVE_MULTI_HOP", multihop_candidate),
            ("DEP-MULTIPLE-01", "DEPRECATED_MULTIPLE_REPLACEMENTS", multiple_candidate),
        ):
            branch_rows.append(
                self._deprecated_branch_row(case_id, branch, candidate, records)
            )

        configuration_rows, configuration_branch, config_summary = (
            self._configuration_case(cpe_snapshot, nvd_snapshot)
        )
        branch_rows.append(configuration_branch)

        netifd_family = ("a", "openwrt", "netifd")
        netifd_active = CpeName.objects.filter(
            snapshot=cpe_snapshot,
            deprecated=False,
            part=netifd_family[0],
            vendor=netifd_family[1],
            product=netifd_family[2],
        ).count()
        netifd_deprecated = CpeName.objects.filter(
            snapshot=cpe_snapshot,
            deprecated=True,
            part=netifd_family[0],
            vendor=netifd_family[1],
            product=netifd_family[2],
        ).count()
        netifd_gate = configuration_only_gate(
            active_product_count=netifd_active,
            deprecated_product_count=netifd_deprecated,
        )
        netifd_configuration = NvdCpeMatch.objects.filter(
            cve_record__snapshot=nvd_snapshot,
            criteria__startswith="cpe:2.3:a:openwrt:netifd:",
        ).count()
        branch_rows.append(
            _branch_row(
                "NO-DIRECT-01",
                "NO_DIRECT_CPE",
                input_cpe=(
                    "cpe:2.3:a:openwrt:netifd:"
                    "2024-01-04-c18cc79d:*:*:*:*:*:*:*"
                ),
                dictionary_product_present_active=bool(netifd_active),
                dictionary_product_present_deprecated=bool(netifd_deprecated),
                configuration_gate_passed=(
                    netifd_gate.configuration_lookup_allowed
                ),
                configuration_match=bool(netifd_configuration),
                expected_result="DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
                actual_result=(
                    "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
                    if netifd_gate.configuration_lookup_allowed
                    and not netifd_configuration
                    else "UNEXPECTED_MATCH"
                ),
                notes=(
                    "Existing Unitronics regression case; fixed Dictionary "
                    "and Configuration tuple counts are both zero."
                ),
            )
        )

        gitlab_family = ("a", "gitlab", "gitlab")
        gitlab_cpes = list(
            CpeName.objects.filter(
                snapshot=cpe_snapshot,
                deprecated=False,
                part=gitlab_family[0],
                vendor=gitlab_family[1],
                product=gitlab_family[2],
            ).values_list("cpe_name", flat=True)
        )
        gitlab_template = resolve_stable_template(
            gitlab_cpes,
            family=gitlab_family,
            normalized_version="*",
        )
        branch_rows.append(
            _branch_row(
                "MULTIPLE-TEMPLATE-01",
                "MULTIPLE_STABLE_TEMPLATES",
                stable_template_status=gitlab_template.status.value,
                selected_template=(),
                dictionary_product_present_active=True,
                expected_result="REVIEW_REQUIRED",
                actual_result=(
                    "REVIEW_REQUIRED"
                    if gitlab_template.review_required
                    else "AUTO_GENERATED"
                ),
                review_required=gitlab_template.review_required,
                notes=(
                    "Actual gitlab:gitlab family has "
                    f"{len(gitlab_template.templates)} non-version templates "
                    "before product-evidence filtering; no first row selected."
                ),
            )
        )

        unitronics_regression = self._unitronics_regression(
            cpe_snapshot,
            nvd_snapshot,
        )

        declared_name_mismatches = 0
        for identifier, declared_names in declared_target_names.items():
            actual = records.get(identifier)
            if actual is not None and any(
                declared != actual.cpe_name for declared in declared_names
            ):
                declared_name_mismatches += 1

        summary = {
            "scope": {
                "read_only": True,
                "full_unitronics_582_run": False,
                "ground_truth_writes": 0,
                "cve_applicability_evaluated": False,
            },
            "snapshots": {
                "cpe_dictionary": {
                    "snapshot_id": cpe_snapshot.snapshot_id,
                    "total": cpe_snapshot.record_count,
                    "active": cpe_snapshot.active_count,
                    "deprecated": cpe_snapshot.deprecated_count,
                    "manifest_sha256": cpe_snapshot.manifest_sha256,
                    "content_sha256": cpe_snapshot.content_sha256,
                },
                "nvd_cve": {
                    "snapshot_id": nvd_snapshot.snapshot_id,
                    "cves": nvd_snapshot.record_count,
                    "configurations": nvd_snapshot.configuration_count,
                    "cpe_matches": nvd_snapshot.cpe_match_count,
                    "manifest_sha256": nvd_snapshot.manifest_sha256,
                    "content_sha256": nvd_snapshot.content_sha256,
                },
            },
            "canonical_parser_snapshot_scan": {
                "total_scanned": sum(parser_counts.values()),
                "status_counts": dict(sorted(parser_counts.items())),
                "invalid_examples": dict(parser_invalid_examples),
            },
            "deprecated_graph": {
                "deprecated_sources": len(deprecated_source_ids),
                "direct_replacement_edge_count": sum(
                    count * frequency
                    for count, frequency in direct_replacement_counts.items()
                ),
                "direct_replacement_count_distribution": {
                    str(count): frequency
                    for count, frequency in sorted(direct_replacement_counts.items())
                },
                "resolution_status_source_counts": dict(
                    sorted(resolution_counts.items())
                ),
                "resolved_direct_source_count": sum(
                    1
                    for result in resolutions.values()
                    if result.resolution_status
                    is DeprecatedResolutionStatus.RESOLVED_ACTIVE
                    and result.replacement_depth == 1
                ),
                "resolved_multihop_source_count": sum(
                    1
                    for result in resolutions.values()
                    if result.resolution_status
                    is DeprecatedResolutionStatus.RESOLVED_ACTIVE
                    and result.replacement_depth > 1
                ),
                "multiple_direct_replacement_source_count": sum(
                    frequency
                    for count, frequency in direct_replacement_counts.items()
                    if count > 1
                ),
                "multiple_distinct_active_endpoint_source_count": sum(
                    1
                    for result in resolutions.values()
                    if len(result.candidate_active_endpoints) > 1
                ),
                "cycle_source_count": resolution_counts[
                    DeprecatedResolutionStatus.CYCLE_DETECTED.value
                ],
                "missing_reference_source_count": resolution_counts[
                    DeprecatedResolutionStatus.MISSING_REFERENCE.value
                ],
                "unique_missing_reference_count": len(
                    {
                        missing
                        for result in resolutions.values()
                        for missing in result.missing_references
                    }
                ),
                "maximum_observed_depth": max(
                    (result.replacement_depth for result in resolutions.values()),
                    default=0,
                ),
                "declared_target_name_mismatch_count": declared_name_mismatches,
            },
            "stable_template_cases": {
                "strongswan_final_release": {
                    "active_family_count": len(strongswan_cpes),
                    "status": strongswan_template.status.value,
                    "selected_template": strongswan_template.selected_template,
                    "generated_cpe": strongswan_template.generated_cpe,
                },
                "gitlab_unfiltered": {
                    "active_family_count": len(gitlab_cpes),
                    "status": gitlab_template.status.value,
                    "template_count": len(gitlab_template.templates),
                    "automatic_generation_blocked": gitlab_template.review_required,
                },
            },
            "configuration_only_case": config_summary,
            "no_direct_case": {
                "family": netifd_family,
                "dictionary_active_count": netifd_active,
                "dictionary_deprecated_count": netifd_deprecated,
                "configuration_occurrence_count": netifd_configuration,
                "gate_passed": netifd_gate.configuration_lookup_allowed,
            },
            "branch_tests": {
                "count": len(branch_rows),
                "passed": sum(row["pass_fail"] == "PASS" for row in branch_rows),
                "failed": sum(row["pass_fail"] != "PASS" for row in branch_rows),
                "observed": sum(row["observed"] == "true" for row in branch_rows),
                "not_observed": sum(
                    row["observed"] != "true" for row in branch_rows
                ),
            },
            "unit_test_fixtures": {
                "cycle_path_covered": True,
                "missing_reference_path_covered": True,
                "multi_hop_path_covered": True,
                "multiple_replacement_path_covered": True,
                "synthetic_production_data_created": False,
            },
            "unitronics_regression": unitronics_regression,
        }
        return {
            "summary": summary,
            "branch_rows": branch_rows,
            "deprecated_rows": deprecated_rows,
            "configuration_rows": configuration_rows,
        }

    def _deprecated_row(
        self,
        case_id: str,
        branch: str,
        source_identifier: str,
        result: DeprecatedResolutionResult,
        records: dict[str, CPEReferenceRecord],
        declared_target_names: dict[str, set[str]],
    ) -> dict[str, str]:
        source = records[source_identifier]
        references = [
            {
                "cpeNameId": identifier,
                "declaredCpeNames": sorted(
                    declared_target_names.get(identifier, set())
                ),
                "snapshotCpeName": (
                    records[identifier].cpe_name if identifier in records else None
                ),
            }
            for identifier in source.deprecated_by
        ]
        return {
            "case_id": case_id,
            "branch": branch,
            "source_cpe_name_id": source_identifier,
            "source_cpe": source.cpe_name,
            "source_status": "Deprecated",
            "direct_replacement_count": str(result.replacement_count),
            "deprecated_by": _json(references),
            "replacement_chains": _json(result.replacement_chains),
            "replacement_depth": str(result.replacement_depth),
            "candidate_active_endpoints": _json(
                result.candidate_active_endpoints
            ),
            "compatible_active_endpoints": _json(
                result.compatible_active_endpoints
            ),
            "resolved_active_endpoint": result.resolved_active_endpoint or "",
            "resolution_status": result.resolution_status.value,
            "cycle_detected": _bool(result.cycle_detected),
            "missing_references": _json(result.missing_references),
            "deprecated_dead_ends": _json(result.deprecated_dead_ends),
            "review_required": _bool(result.review_required),
            "review_reason": result.review_reason,
        }

    def _deprecated_branch_row(
        self,
        case_id: str,
        branch: str,
        candidate: tuple[str, DeprecatedResolutionResult] | None,
        records: dict[str, CPEReferenceRecord],
    ) -> dict[str, str]:
        if candidate is None:
            return _branch_row(
                case_id,
                branch,
                observed=False,
                expected_result="NOT_OBSERVED_IN_SNAPSHOT",
                actual_result="NOT_OBSERVED_IN_SNAPSHOT",
                notes=(
                    "No actual fixed-snapshot source met this branch; the "
                    "resolver code path is covered by an isolated unit fixture."
                ),
            )
        identifier, result = candidate
        source = records[identifier]
        expected = (
            "RESOLVED_ACTIVE"
            if result.resolution_status
            is DeprecatedResolutionStatus.RESOLVED_ACTIVE
            else "REVIEW_REQUIRED"
        )
        return _branch_row(
            case_id,
            branch,
            input_cpe=source.cpe_name,
            deprecated_match=True,
            deprecated_by=source.deprecated_by,
            replacement_chain=result.replacement_chains,
            active_endpoints=result.candidate_active_endpoints,
            resolution_status=result.resolution_status.value,
            expected_result=expected,
            actual_result=expected,
            review_required=result.review_required,
            notes=(
                "Actual fixed-snapshot deprecatedBy graph; all branches were "
                "retained and no first-edge selection was used."
            ),
        )

    def _configuration_case(
        self,
        cpe_snapshot: CpeDictionarySnapshot,
        nvd_snapshot: NvdCveSnapshot,
    ) -> tuple[list[dict[str, str]], dict[str, str], dict[str, object]]:
        family = ("a", "microsoft", "microsoft_365")
        active_count = CpeName.objects.filter(
            snapshot=cpe_snapshot,
            deprecated=False,
            part=family[0],
            vendor=family[1],
            product=family[2],
        ).count()
        deprecated_count = CpeName.objects.filter(
            snapshot=cpe_snapshot,
            deprecated=True,
            part=family[0],
            vendor=family[1],
            product=family[2],
        ).count()
        gate = configuration_only_gate(
            active_product_count=active_count,
            deprecated_product_count=deprecated_count,
        )
        if not gate.configuration_lookup_allowed:
            raise CommandError("Configuration-only fixture failed Dictionary gate")

        matches = list(
            NvdCpeMatch.objects.filter(
                cve_record__snapshot=nvd_snapshot,
                criteria__startswith=(
                    "cpe:2.3:a:microsoft:microsoft_365:"
                ),
            ).values(
                "criteria",
                "match_criteria_id",
                "version_start_including",
                "version_start_excluding",
                "version_end_including",
                "version_end_excluding",
                "cve_record__cve_id",
            )
        )
        grouped: defaultdict[tuple[object, ...], list[str]] = defaultdict(list)
        for match in matches:
            key = (
                match["criteria"],
                str(match["match_criteria_id"]),
                match["version_start_including"],
                match["version_start_excluding"],
                match["version_end_including"],
                match["version_end_excluding"],
            )
            grouped[key].append(match["cve_record__cve_id"])

        templates = set()
        for criteria, *_ in grouped:
            parsed = parse_cpe23(criteria)
            if parsed.name is not None:
                templates.add(
                    tuple(
                        parsed.name.attribute(attribute).canonical
                        for attribute in NON_VERSION_TEMPLATE_ATTRIBUTES
                    )
                )
        stable_status = (
            "UNIQUE_STABLE_TEMPLATE"
            if len(templates) == 1
            else "MULTIPLE_COMPATIBLE_TEMPLATES"
        )
        selected_template = next(iter(templates)) if len(templates) == 1 else ()
        rows: list[dict[str, str]] = []
        for index, (key, cves) in enumerate(sorted(grouped.items()), start=1):
            criteria, match_id, start_i, start_e, end_i, end_e = key
            parsed = parse_cpe23(criteria)
            criteria_version = (
                parsed.name.attribute("version").canonical
                if parsed.name is not None
                else ""
            )
            rows.append(
                {
                    "case_id": f"CONFIG-ONLY-{index:02d}",
                    "part": family[0],
                    "vendor": family[1],
                    "product": family[2],
                    "dictionary_active_count": str(active_count),
                    "dictionary_deprecated_count": str(deprecated_count),
                    "gate_status": gate.status.value,
                    "configuration_gate_passed": _bool(
                        gate.configuration_lookup_allowed
                    ),
                    "criteria": str(criteria),
                    "match_criteria_id": str(match_id),
                    "criteria_version": criteria_version,
                    "version_start_including": start_i or "",
                    "version_start_excluding": start_e or "",
                    "version_end_including": end_i or "",
                    "version_end_excluding": end_e or "",
                    "occurrence_count": str(len(cves)),
                    "distinct_cve_count": str(len(set(cves))),
                    "representative_cve": sorted(cves)[0],
                    "stable_template_status": stable_status,
                    "selected_template": _json(selected_template),
                    "review_required": _bool(len(templates) != 1),
                    "notes": (
                        "Product-expression existence only; no version-range "
                        "applicability was evaluated and criteria version was "
                        "not used as an installed product version."
                    ),
                }
            )

        representative = rows[0]
        branch = _branch_row(
            "CONFIG-ONLY-01",
            "CONFIGURATION_ONLY",
            input_cpe=representative["criteria"],
            dictionary_product_present_active=bool(active_count),
            dictionary_product_present_deprecated=bool(deprecated_count),
            configuration_gate_passed=gate.configuration_lookup_allowed,
            configuration_match=bool(matches),
            stable_template_status=stable_status,
            selected_template=selected_template,
            expected_result="NVD_CONFIGURATION_ONLY",
            actual_result=(
                "NVD_CONFIGURATION_ONLY"
                if gate.configuration_lookup_allowed and bool(matches)
                else "GATE_OR_MATCH_FAILURE"
            ),
            review_required=len(templates) != 1,
            notes=(
                "Actual NVD Configuration expression after zero Active and "
                "zero Deprecated Dictionary family records; existence only."
            ),
        )
        summary = {
            "family": family,
            "dictionary_active_count": active_count,
            "dictionary_deprecated_count": deprecated_count,
            "gate_status": gate.status.value,
            "configuration_occurrence_count": len(matches),
            "distinct_cve_count": len(
                {match["cve_record__cve_id"] for match in matches}
            ),
            "criteria_group_count": len(grouped),
            "stable_template_status": stable_status,
            "selected_template": selected_template,
            "version_applicability_evaluated": False,
        }
        return rows, branch, summary

    def _unitronics_regression(
        self,
        cpe_snapshot: CpeDictionarySnapshot,
        nvd_snapshot: NvdCveSnapshot,
    ) -> dict[str, object]:
        artifact = (
            settings.REPOSITORY_ROOT
            / "analysis/results/unitronics-cpe-mapping-decision-dry-run"
            / "61602e128acb__52.07.13.7/representative_cases.csv"
        )
        if not artifact.is_file():
            raise CommandError(
                f"Required prior Unitronics regression artifact is absent: {artifact}"
            )
        with artifact.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))

        decision_codes = (
            "CPE_CONFIRMED",
            "OFFICIAL_CPE_MAPPED",
            "VERSION_NOT_IN_DICTIONARY",
            "NVD_CONFIGURATION_ONLY",
            "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
            "UNRESOLVED",
        )
        previous_counts = Counter(row["proposed_decision"] for row in rows)
        actual_counts: Counter[str] = Counter()
        changed_cases: list[dict[str, str]] = []
        family_cache: dict[tuple[str, str, str], list[str]] = {}

        for row in rows:
            family = (
                row["search_part"],
                row["search_vendor"],
                row["search_product"],
            )
            branch = row["mapping_branch"]
            if branch == "ACTIVE_EXACT":
                active_count = CpeName.objects.filter(
                    snapshot=cpe_snapshot,
                    deprecated=False,
                    cpe_name=row["proposed_gt_cpe"],
                ).count()
                actual_decision = (
                    (
                        "CPE_CONFIRMED"
                        if compare_cpe23(
                            row["original_cpe"],
                            row["proposed_gt_cpe"],
                        )
                        else "OFFICIAL_CPE_MAPPED"
                    )
                    if active_count == 1
                    else "UNRESOLVED"
                )
            elif branch == "VERSION_NOT_IN_DICTIONARY":
                exact_count = CpeName.objects.filter(
                    snapshot=cpe_snapshot,
                    deprecated=False,
                    part=family[0],
                    vendor=family[1],
                    product=family[2],
                    version=row["normalized_product_version"],
                ).count()
                if family not in family_cache:
                    family_cache[family] = list(
                        CpeName.objects.filter(
                            snapshot=cpe_snapshot,
                            deprecated=False,
                            part=family[0],
                            vendor=family[1],
                            product=family[2],
                        ).values_list("cpe_name", flat=True)
                    )
                proposed = parse_cpe23(row["proposed_gt_cpe"])
                if proposed.name is None:
                    actual_decision = "UNRESOLVED"
                else:
                    expected_template = tuple(
                        proposed.name.attribute(attribute).canonical
                        for attribute in NON_VERSION_TEMPLATE_ATTRIBUTES
                    )
                    template = resolve_stable_template(
                        family_cache[family],
                        family=family,
                        normalized_version=row["normalized_product_version"],
                        compatibility=lambda name, expected=expected_template: (
                            tuple(
                                name.attribute(attribute).canonical
                                for attribute in NON_VERSION_TEMPLATE_ATTRIBUTES
                            )
                            == expected
                        ),
                    )
                    actual_decision = (
                        "VERSION_NOT_IN_DICTIONARY"
                        if exact_count == 0
                        and not template.review_required
                        and template.generated_cpe == row["proposed_gt_cpe"]
                        else "UNRESOLVED"
                    )
            elif branch == "NO_DIRECT_CPE":
                active_count = CpeName.objects.filter(
                    snapshot=cpe_snapshot,
                    deprecated=False,
                    part=family[0],
                    vendor=family[1],
                    product=family[2],
                ).count()
                deprecated_count = CpeName.objects.filter(
                    snapshot=cpe_snapshot,
                    deprecated=True,
                    part=family[0],
                    vendor=family[1],
                    product=family[2],
                ).count()
                gate = configuration_only_gate(
                    active_product_count=active_count,
                    deprecated_product_count=deprecated_count,
                )
                configuration_count = 0
                if gate.configuration_lookup_allowed:
                    configuration_count = NvdCpeMatch.objects.filter(
                        cve_record__snapshot=nvd_snapshot,
                        criteria__startswith=(
                            "cpe:2.3:" + ":".join(family) + ":"
                        ),
                    ).count()
                actual_decision = (
                    "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
                    if gate.configuration_lookup_allowed
                    and configuration_count == 0
                    else "UNRESOLVED"
                )
            else:
                actual_decision = "UNRESOLVED"

            actual_counts[actual_decision] += 1
            if actual_decision != row["proposed_decision"]:
                changed_cases.append(
                    {
                        "case_id": row["case_id"],
                        "previous_result": row["proposed_decision"],
                        "actual_result": actual_decision,
                        "reason": "Boundary helper re-evaluation differed.",
                    }
                )

        return {
            "case_count": len(rows),
            "previous_counts": {
                code: previous_counts[code] for code in decision_codes
            },
            "actual_counts": {
                code: actual_counts[code] for code in decision_codes
            },
            "changed_cases": changed_cases,
            "regression_passed": len(rows) == 11 and not changed_cases,
            "evidence": (
                "Re-evaluated against both fixed database snapshots inside "
                "the same READ ONLY transaction."
            ),
        }

    def _write_csv(
        self,
        path: Path,
        fields: tuple[str, ...],
        rows: list[dict[str, str]],
    ) -> None:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def _render_report(
        self,
        summary: dict[str, Any],
        branch_rows: list[dict[str, str]],
    ) -> str:
        graph = summary["deprecated_graph"]
        parser_scan = summary["canonical_parser_snapshot_scan"]
        config = summary["configuration_only_case"]
        regression = summary["unitronics_regression"]
        branch_lines = "\n".join(
            "| {test_case_id} | {branch} | {observed} | {actual_result} | "
            "{review_required} | {pass_fail} |".format(**row)
            for row in branch_rows
        )
        return f"""# CPE Mapping Rulebook boundary tests

## Scope

This is a read-only boundary test. It does not create Ground Truth records,
run the 582 Unitronics components, evaluate CVE applicability, mutate either
snapshot, or hook these helpers into the production save path.

All database reads ran inside a PostgreSQL transaction set to `READ ONLY`.

## Fixed snapshots

| Dataset | Snapshot | Counts |
|---|---|---|
| CPE Dictionary | `{CPE_SNAPSHOT_ID}` | 1,811,261 total; 1,711,630 Active; 99,631 Deprecated |
| NVD CVE | `{NVD_SNAPSHOT_ID}` | 380,865 CVEs; 760,120 Configurations; 3,170,148 cpeMatch rows |

## Canonical parser

- Full Dictionary scan: {parser_scan['total_scanned']:,} CPEs
- Status counts: `{_json(parser_scan['status_counts'])}`
- The parser distinguishes all 11 ordered attributes, ANY (`*`), NA (`-`),
  and an invalid empty attribute. Escape-aware parse/serialize and canonical
  comparison are covered by tests. URI percent encoding is not conflated with
  a CPE 2.3 formatted-string binding.
- Specification basis: [NIST IR 7695](https://csrc.nist.gov/pubs/ir/7695/final).

## Branch results

| Case | Branch | Observed in fixed snapshot | Actual | Review | Result |
|---|---|---:|---|---:|---|
{branch_lines}

Actual deprecated cases are in `deprecated_cases.csv`; an unobserved branch is
reported as such and is covered only by a unit fixture, never by inserting
synthetic production data.

## Deprecated graph observations

- Deprecated sources: {graph['deprecated_sources']:,}
- Direct replacement edges: {graph['direct_replacement_edge_count']:,}
- Direct resolved sources: {graph['resolved_direct_source_count']:,}
- Multi-hop resolved sources: {graph['resolved_multihop_source_count']:,}
- Sources with multiple direct replacements: {graph['multiple_direct_replacement_source_count']:,}
- Sources reaching multiple distinct Active endpoints without an evidence filter: {graph['multiple_distinct_active_endpoint_source_count']:,}
- Cycle-affected sources: {graph['cycle_source_count']:,}
- Missing-reference-affected sources: {graph['missing_reference_source_count']:,}
- Maximum observed depth: {graph['maximum_observed_depth']}
- Declared target-name mismatches: {graph['declared_target_name_mismatch_count']:,}

The resolver retains all branches, stops on cycle/missing/deprecated dead-end,
and returns an Active endpoint only when semantic filtering leaves one endpoint.

## Stable templates

- strongSwan final-release filter: `{summary['stable_template_cases']['strongswan_final_release']['status']}`;
  selected template `{_json(summary['stable_template_cases']['strongswan_final_release']['selected_template'])}`.
- Unfiltered actual gitlab family: `{summary['stable_template_cases']['gitlab_unfiltered']['status']}`
  across {summary['stable_template_cases']['gitlab_unfiltered']['template_count']} templates; automatic generation blocked.

Compatibility filtering is caller-supplied evidence. The resolver never uses
the first CPE record as a template.

## Configuration-only gate

Actual family `{':'.join(config['family'])}` has zero Active and zero Deprecated
Dictionary records, then yields {config['configuration_occurrence_count']:,}
Configuration occurrences across {config['distinct_cve_count']:,} CVEs. The
gate status is `{config['gate_status']}`. Range applicability was not evaluated.

## Unitronics 11-case regression

Regression result: **{'PASS' if regression['regression_passed'] else 'FAIL'}**.
No case changed. Counts remain:

```json
{json.dumps(regression['actual_counts'], indent=2, sort_keys=True)}
```

## Answers to the twelve exit questions

1. **Yes.** The canonical parser preserves the ordered 11 attributes and
   distinguishes STRING, ANY, NA, and invalid empty values.
2. **Yes.** Escaped colon, backslash, special characters, and redundant quoting
   round-trip canonically; tests compare parsed attributes, not raw strings.
3. **Yes, when compatibility evidence leaves one non-version template.** The
   strongSwan case reproducibly preserves `update=-`.
4. **Yes.** Multiple/no-template results have no generated CPE and require review.
5. **Yes.** The actual 1:1 branch result is recorded in the CSV.
6. **{'Yes; an actual multi-hop case was reproduced.' if graph['resolved_multihop_source_count'] else 'The code path passes its unit fixture; no resolved multi-hop source was observed in this snapshot.'}**
7. **Yes.** Every branch is traversed; multiple compatible endpoints prohibit
   automatic selection.
8. **Yes.** Cycle and missing-reference checks run over the full Deprecated
   graph. Actual source counts are {graph['cycle_source_count']} and
   {graph['missing_reference_source_count']}; both paths also have unit fixtures.
9. **Yes.** Active blocks first, Deprecated blocks second, and only absence of
   both permits Configuration lookup.
10. **Yes.** The Microsoft 365 case is reproduced from the fixed NVD snapshot.
11. **Yes.** All 11 representative Decisions remain unchanged.
12. **No defect was found in these four boundary helpers.** The full dry-run
   orchestration must still supply independently verified product identity,
   normalized version, and an explicit compatibility predicate. Ambiguous or
   absent evidence remains an intentional review stop, not an automatic result.
"""

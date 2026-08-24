from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from cpe.cpe23_canonical import (
    CPE23CanonicalizationError,
    canonicalize_cpe23,
)
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    GroundTruthDecision,
    GroundTruthResolutionOutcome,
    SBOMDocument,
)
from sboms.unitronics_duplicate_cpe_audit import (
    _effective_cpe,
    _ground_truth_fingerprint,
)
from sboms.unitronics_ground_truth_candidate_build import (
    APPROVED_DERIVED_SPLITS,
    APPROVED_REPRESENTATIVES,
    validate_representative_approvals,
)
from sboms.unitronics_ground_truth_db_application import (
    CPE_SNAPSHOT_ID,
    DATASET_KEY,
    SBOM_DOCUMENT_ID,
    _component_fingerprint,
)


CANDIDATE_RELATIVE = Path(
    "analysis/results/unitronics-ground-truth-candidate-build/"
    f"{DATASET_KEY}/components.csv"
)
FINALIZATION_OUTPUT_RELATIVE = Path(
    "analysis/results/unitronics-ground-truth-representative-finalization/"
    f"{DATASET_KEY}"
)

EXPECTED_COMPONENT_FINGERPRINT = (
    "9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e"
)
EXPECTED_INITIAL_GROUND_TRUTH_FINGERPRINT = (
    "cd40eeba9c88161d521c22d0fb6a16114dedec658efac57e82ddfa34409c9ef1"
)
EXPECTED_INITIAL_DECISION_COUNTS = {
    GroundTruthDecision.CPE_CONFIRMED: 2,
    GroundTruthDecision.OFFICIAL_CPE_MAPPED: 24,
    GroundTruthDecision.VERSION_NOT_IN_DICTIONARY: 22,
    GroundTruthDecision.NVD_CONFIGURATION_ONLY: 0,
    GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED: 529,
    GroundTruthDecision.UNRESOLVED: 5,
}
EXPECTED_FINAL_DECISION_COUNTS = {
    GroundTruthDecision.CPE_CONFIRMED: 2,
    GroundTruthDecision.OFFICIAL_CPE_MAPPED: 21,
    GroundTruthDecision.VERSION_NOT_IN_DICTIONARY: 16,
    GroundTruthDecision.NVD_CONFIGURATION_ONLY: 0,
    GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED: 538,
    GroundTruthDecision.UNRESOLVED: 5,
}
EXPECTED_REPRESENTATIVE_NAMES = frozenset(
    {
        "libcap",
        "lua",
        "ipset",
        "iptables",
        "sqlite",
        "strongswan",
        "libopenssl3",
    }
)
REGRESSION_PRODUCT_NAMES = frozenset({"curl", "libcurl4"})


class UnitronicsRepresentativeFinalizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class FinalCandidate:
    component_id: int
    name: str
    actual_product: str
    actual_product_version: str
    proposed_gt_cpe: str
    proposed_decision: str
    discrepancy_fields: str


@dataclass(frozen=True)
class FinalizationPlan:
    candidates: tuple[FinalCandidate, ...]
    candidate_sha256: str

    @property
    def by_id(self) -> dict[int, FinalCandidate]:
        return {row.component_id: row for row in self.candidates}

    @property
    def by_name(self) -> dict[str, FinalCandidate]:
        return {row.name: row for row in self.candidates}


@dataclass
class DatabaseState:
    records: list[ComponentCpeGroundTruth]
    component_count: int
    global_ground_truth_count: int
    component_fingerprint: str
    ground_truth_fingerprint: str
    decision_counts: dict[str, int]
    cpe_present_count: int
    cpe_null_count: int
    distinct_canonical_gt_cpes: int
    duplicate_canonical_gt_cpe_groups: int
    duplicate_group_component_count: int
    canonical_parse_failure_count: int
    deprecated_final_gt_count: int
    discrepancy_assignment_count: int
    correction_assignment_count: int


@dataclass(frozen=True)
class FinalizationResult:
    applied_at: str
    candidate_sha256: str
    changed_component_ids: tuple[int, ...]
    changed_component_names: tuple[str, ...]
    component_fingerprint_before: str
    component_fingerprint_after: str
    ground_truth_fingerprint_before: str
    ground_truth_fingerprint_after: str
    before_decision_counts: dict[str, int]
    after_decision_counts: dict[str, int]
    before_cpe_present_count: int
    after_cpe_present_count: int
    before_cpe_null_count: int
    after_cpe_null_count: int
    final_distinct_canonical_gt_cpes: int
    final_duplicate_canonical_gt_cpe_groups: int
    final_duplicate_group_component_count: int
    final_canonical_parse_failure_count: int
    final_deprecated_gt_count: int
    candidate_cpe_mismatch_count: int
    candidate_decision_mismatch_count: int
    component_mutation_count: int
    non_target_ground_truth_mutation_count: int
    discrepancy_assignment_count: int
    correction_assignment_count: int
    representative_states: dict[str, dict[str, str]]
    removed_states: dict[str, dict[str, str]]
    regression_states: dict[str, dict[str, str]]


def _fail(message: str) -> NoReturn:
    raise UnitronicsRepresentativeFinalizationError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except OSError as error:
        _fail(f"Cannot read candidate artifact {path}: {error}")


def _normalized_decision_counts(
    values: list[str] | tuple[str, ...],
) -> dict[str, int]:
    counts = Counter(values)
    return {
        str(decision): counts.get(str(decision), 0)
        for decision in EXPECTED_FINAL_DECISION_COUNTS
    }


def load_finalization_plan(
    repository_root: Path | None = None,
) -> FinalizationPlan:
    root = repository_root or settings.REPOSITORY_ROOT
    validate_representative_approvals(root / "analysis/results")
    candidate_path = root / CANDIDATE_RELATIVE
    rows = _read_csv(candidate_path)
    try:
        candidates = tuple(
            FinalCandidate(
                component_id=int(row["component_id"]),
                name=row["name"],
                actual_product=row["actual_product"],
                actual_product_version=row["actual_product_version"],
                proposed_gt_cpe=row["proposed_gt_cpe"],
                proposed_decision=row["proposed_decision"],
                discrepancy_fields=row["discrepancy_fields"],
            )
            for row in rows
        )
    except (KeyError, TypeError, ValueError) as error:
        _fail(f"Invalid final candidate row: {error}")
    if len(candidates) != 582:
        _fail(f"Expected 582 final candidate rows, found {len(candidates)}")
    if len({row.component_id for row in candidates}) != 582:
        _fail("Final candidate component IDs are not unique")
    if len({row.name for row in candidates}) != 582:
        _fail("Final candidate names are not unique in the fixed dataset")
    counts = _normalized_decision_counts(
        tuple(row.proposed_decision for row in candidates)
    )
    if counts != EXPECTED_FINAL_DECISION_COUNTS:
        _fail(f"Unexpected final candidate Decision distribution: {counts}")
    cpe_rows = [row for row in candidates if row.proposed_gt_cpe]
    canonical_values: list[str] = []
    for row in cpe_rows:
        try:
            canonical = canonicalize_cpe23(row.proposed_gt_cpe)
        except CPE23CanonicalizationError as error:
            _fail(f"Invalid candidate CPE for {row.name}: {error}")
        if canonical != row.proposed_gt_cpe:
            _fail(f"Non-canonical candidate CPE for {row.name}")
        canonical_values.append(canonical)
    if len(canonical_values) != 39 or len(set(canonical_values)) != 39:
        _fail("Final candidate must contain 39 distinct canonical GT CPEs")

    by_name = {row.name: row for row in candidates}
    for name, policy in APPROVED_DERIVED_SPLITS.items():
        row = by_name.get(name)
        if row is None or (
            row.component_id != int(policy.component_id)
            or row.proposed_gt_cpe
            or row.proposed_decision
            != GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
            or row.discrepancy_fields not in {"", "N/A"}
            or not row.actual_product
            or not row.actual_product_version
        ):
            _fail(f"Final derived-split candidate mismatch for {name}")
        representative = by_name.get(policy.representative)
        if (
            representative is None
            or representative.proposed_gt_cpe != policy.expected_parent_cpe
        ):
            _fail(f"Final representative candidate mismatch for {name}")
    if set(APPROVED_REPRESENTATIVES) != set(EXPECTED_REPRESENTATIVE_NAMES):
        _fail("Representative registry differs from the approved seven names")
    for name in REGRESSION_PRODUCT_NAMES:
        if not by_name[name].proposed_gt_cpe:
            _fail(f"Independent product regression: {name} lost its GT CPE")
    if (
        by_name["curl"].proposed_gt_cpe
        == by_name["libcurl4"].proposed_gt_cpe
    ):
        _fail("curl and libcurl4 must retain distinct product CPEs")
    return FinalizationPlan(
        candidates=candidates,
        candidate_sha256=_sha256(candidate_path),
    )


def _database_state(*, lock: bool = False) -> DatabaseState:
    if lock:
        SBOMDocument.objects.select_for_update().get(pk=SBOM_DOCUMENT_ID)
    components = list(
        Component.objects.filter(sbom_document_id=SBOM_DOCUMENT_ID).order_by(
            "id"
        )
    )
    records_queryset = ComponentCpeGroundTruth.objects.filter(
        component__sbom_document_id=SBOM_DOCUMENT_ID,
        snapshot__snapshot_id=CPE_SNAPSHOT_ID,
    )
    if lock:
        # ground_truth_cpe is nullable and select_related() therefore uses an
        # outer join. Lock only the Ground Truth table rows, not the nullable
        # joined CPE side.
        records_queryset = records_queryset.select_for_update(of=("self",))
    records = list(
        records_queryset.select_related(
            "component", "ground_truth_cpe"
        )
        .prefetch_related("discrepancy_types", "correction_types")
        .order_by("id")
    )
    effective = [_effective_cpe(record) for record in records]
    canonical_values: list[str] = []
    parse_failures = 0
    for value in effective:
        if not value:
            continue
        try:
            canonical = canonicalize_cpe23(value)
        except CPE23CanonicalizationError:
            parse_failures += 1
            continue
        if canonical != value:
            parse_failures += 1
            continue
        canonical_values.append(canonical)
    duplicate_counts = Counter(canonical_values)
    duplicate_groups = {
        value: count for value, count in duplicate_counts.items() if count > 1
    }
    decisions = _normalized_decision_counts(
        tuple(record.decision for record in records)
    )
    return DatabaseState(
        records=records,
        component_count=len(components),
        global_ground_truth_count=ComponentCpeGroundTruth.objects.count(),
        component_fingerprint=_component_fingerprint(components),
        ground_truth_fingerprint=_ground_truth_fingerprint(records),
        decision_counts=decisions,
        cpe_present_count=len(canonical_values),
        cpe_null_count=len(records) - len(canonical_values),
        distinct_canonical_gt_cpes=len(duplicate_counts),
        duplicate_canonical_gt_cpe_groups=len(duplicate_groups),
        duplicate_group_component_count=sum(duplicate_groups.values()),
        canonical_parse_failure_count=parse_failures,
        deprecated_final_gt_count=sum(
            bool(record.ground_truth_cpe)
            and record.ground_truth_cpe.deprecated
            for record in records
        ),
        discrepancy_assignment_count=sum(
            record.discrepancy_types.count() for record in records
        ),
        correction_assignment_count=sum(
            record.correction_types.count() for record in records
        ),
    )


def _record_fields(
    records: list[ComponentCpeGroundTruth],
) -> dict[int, dict[str, Any]]:
    return {
        record.component_id: {
            "ground_truth_cpe_id": record.ground_truth_cpe_id,
            "manual_ground_truth_cpe": record.manual_ground_truth_cpe,
            "decision": record.decision,
            "resolution_outcome": record.resolution_outcome,
            "note": record.note,
            "created_at": record.created_at.isoformat(),
            "updated_at": record.updated_at.isoformat(),
            "discrepancy_ids": sorted(
                record.discrepancy_types.values_list("id", flat=True)
            ),
            "correction_ids": sorted(
                record.correction_types.values_list("id", flat=True)
            ),
        }
        for record in records
    }


def _candidate_mismatches(
    plan: FinalizationPlan,
    state: DatabaseState,
) -> tuple[set[int], set[int]]:
    candidates = plan.by_id
    cpe_mismatches: set[int] = set()
    decision_mismatches: set[int] = set()
    for record in state.records:
        candidate = candidates.get(record.component_id)
        if candidate is None:
            _fail(
                f"DB component {record.component_id} is absent from candidates"
            )
        if _effective_cpe(record) != candidate.proposed_gt_cpe:
            cpe_mismatches.add(record.component_id)
        if record.decision != candidate.proposed_decision:
            decision_mismatches.add(record.component_id)
    return cpe_mismatches, decision_mismatches


def database_preflight(
    plan: FinalizationPlan,
    *,
    lock: bool = False,
) -> DatabaseState:
    state = _database_state(lock=lock)
    if (
        state.component_count != 582
        or state.global_ground_truth_count != 582
        or len(state.records) != 582
    ):
        _fail("Expected exactly 582 fixed Components and Ground Truth records")
    if state.component_fingerprint != EXPECTED_COMPONENT_FINGERPRINT:
        _fail("Component fingerprint differs from the approved baseline")
    if (
        state.ground_truth_fingerprint
        != EXPECTED_INITIAL_GROUND_TRUTH_FINGERPRINT
    ):
        _fail("Ground Truth fingerprint differs from the approved baseline")
    if state.decision_counts != EXPECTED_INITIAL_DECISION_COUNTS:
        _fail(
            "Initial Ground Truth Decision distribution differs from the "
            f"approved baseline: {state.decision_counts}"
        )
    if state.cpe_present_count != 48 or state.cpe_null_count != 534:
        _fail("Initial Ground Truth CPE present/null counts are not 48/534")
    records_by_name = {record.component.name: record for record in state.records}
    if len(records_by_name) != 582:
        _fail("Ground Truth component names are not unique")
    target_ids: set[int] = set()
    for name, policy in APPROVED_DERIVED_SPLITS.items():
        record = records_by_name.get(name)
        if record is None or (
            record.component_id != int(policy.component_id)
            or _effective_cpe(record) != policy.expected_parent_cpe
            or record.decision != policy.expected_current_decision
        ):
            _fail(f"Initial approved target state mismatch for {name}")
        target_ids.add(record.component_id)
    cpe_mismatches, decision_mismatches = _candidate_mismatches(plan, state)
    if cpe_mismatches != target_ids or decision_mismatches != target_ids:
        _fail(
            "Candidate-to-DB diff is not exactly the eight approved records: "
            f"cpe={sorted(cpe_mismatches)}, decision={sorted(decision_mismatches)}"
        )
    return state


def _named_states(
    state: DatabaseState,
    names: frozenset[str] | set[str],
) -> dict[str, dict[str, str]]:
    by_name = {record.component.name: record for record in state.records}
    return {
        name: {
            "component_id": str(by_name[name].component_id),
            "gt_cpe": _effective_cpe(by_name[name]),
            "decision": by_name[name].decision,
            "resolution_outcome": by_name[name].resolution_outcome,
        }
        for name in sorted(names)
    }


def verify_final_database(
    plan: FinalizationPlan,
    *,
    expected_component_fingerprint: str,
) -> tuple[DatabaseState, set[int], set[int]]:
    state = _database_state()
    if (
        state.component_count != 582
        or state.global_ground_truth_count != 582
        or len(state.records) != 582
    ):
        _fail("Final database no longer contains exactly 582 scoped records")
    if state.component_fingerprint != expected_component_fingerprint:
        _fail("Component mutation detected during representative finalization")
    if state.decision_counts != EXPECTED_FINAL_DECISION_COUNTS:
        _fail(f"Unexpected final Decision distribution: {state.decision_counts}")
    expected_scalars = {
        "cpe_present_count": 39,
        "cpe_null_count": 543,
        "distinct_canonical_gt_cpes": 39,
        "duplicate_canonical_gt_cpe_groups": 0,
        "duplicate_group_component_count": 0,
        "canonical_parse_failure_count": 0,
        "deprecated_final_gt_count": 0,
        "discrepancy_assignment_count": 0,
        "correction_assignment_count": 0,
    }
    for field, expected in expected_scalars.items():
        if getattr(state, field) != expected:
            _fail(
                f"Final database verification failed for {field}: "
                f"expected {expected}, got {getattr(state, field)}"
            )
    cpe_mismatches, decision_mismatches = _candidate_mismatches(plan, state)
    if cpe_mismatches or decision_mismatches:
        _fail(
            "Final candidate-to-DB mismatch: "
            f"cpe={sorted(cpe_mismatches)}, "
            f"decision={sorted(decision_mismatches)}"
        )
    removed = _named_states(state, set(APPROVED_DERIVED_SPLITS))
    for name, values in removed.items():
        if (
            values["gt_cpe"]
            or values["decision"]
            != GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
            or values["resolution_outcome"]
            != GroundTruthResolutionOutcome.DIRECT_OFFICIAL_NOT_CONFIRMED
        ):
            _fail(f"Removed Component final state mismatch for {name}")
    representatives = _named_states(state, set(EXPECTED_REPRESENTATIVE_NAMES))
    for name, values in representatives.items():
        if not values["gt_cpe"]:
            _fail(f"Representative Component lost its GT CPE: {name}")
    regressions = _named_states(state, set(REGRESSION_PRODUCT_NAMES))
    if (
        not regressions["curl"]["gt_cpe"]
        or not regressions["libcurl4"]["gt_cpe"]
        or regressions["curl"]["gt_cpe"]
        == regressions["libcurl4"]["gt_cpe"]
    ):
        _fail("curl/libcurl4 independent-product regression detected")
    return state, cpe_mismatches, decision_mismatches


def apply_representative_finalization(
    plan: FinalizationPlan,
) -> FinalizationResult:
    target_ids = {
        int(policy.component_id)
        for policy in APPROVED_DERIVED_SPLITS.values()
    }
    try:
        with transaction.atomic():
            before = database_preflight(plan, lock=True)
            before_fields = _record_fields(before.records)
            records_by_component = {
                record.component_id: record for record in before.records
            }
            for component_id in sorted(target_ids):
                record = records_by_component[component_id]
                record.ground_truth_cpe = None
                record.manual_ground_truth_cpe = ""
                record.decision = (
                    GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED
                )
                record.save(
                    update_fields={
                        "ground_truth_cpe",
                        "manual_ground_truth_cpe",
                        "decision",
                        "updated_at",
                    }
                )
            after, cpe_mismatches, decision_mismatches = (
                verify_final_database(
                    plan,
                    expected_component_fingerprint=(
                        before.component_fingerprint
                    ),
                )
            )
            after_fields = _record_fields(after.records)
            changed_ids = {
                component_id
                for component_id in before_fields
                if before_fields[component_id]
                != after_fields[component_id]
            }
            if changed_ids != target_ids:
                _fail(
                    "Ground Truth mutation set is not exactly the eight approved "
                    f"records: {sorted(changed_ids)}"
                )
            allowed_fields = {
                "ground_truth_cpe_id",
                "manual_ground_truth_cpe",
                "decision",
                "resolution_outcome",
                "updated_at",
            }
            for component_id in changed_ids:
                changed_fields = {
                    field
                    for field in before_fields[component_id]
                    if before_fields[component_id][field]
                    != after_fields[component_id][field]
                }
                if not changed_fields.issubset(allowed_fields):
                    _fail(
                        f"Unexpected Ground Truth fields changed for "
                        f"{component_id}: {sorted(changed_fields)}"
                    )
    except ValidationError as error:
        _fail(f"Model validation failed; transaction rolled back: {error}")

    committed, cpe_mismatches, decision_mismatches = verify_final_database(
        plan,
        expected_component_fingerprint=before.component_fingerprint,
    )
    if committed.ground_truth_fingerprint != after.ground_truth_fingerprint:
        _fail("Committed Ground Truth fingerprint differs from in-transaction state")
    changed_names = tuple(
        sorted(
            record.component.name
            for record in committed.records
            if record.component_id in target_ids
        )
    )
    return FinalizationResult(
        applied_at=timezone.now().isoformat(),
        candidate_sha256=plan.candidate_sha256,
        changed_component_ids=tuple(sorted(target_ids)),
        changed_component_names=changed_names,
        component_fingerprint_before=before.component_fingerprint,
        component_fingerprint_after=committed.component_fingerprint,
        ground_truth_fingerprint_before=before.ground_truth_fingerprint,
        ground_truth_fingerprint_after=committed.ground_truth_fingerprint,
        before_decision_counts=before.decision_counts,
        after_decision_counts=committed.decision_counts,
        before_cpe_present_count=before.cpe_present_count,
        after_cpe_present_count=committed.cpe_present_count,
        before_cpe_null_count=before.cpe_null_count,
        after_cpe_null_count=committed.cpe_null_count,
        final_distinct_canonical_gt_cpes=(
            committed.distinct_canonical_gt_cpes
        ),
        final_duplicate_canonical_gt_cpe_groups=(
            committed.duplicate_canonical_gt_cpe_groups
        ),
        final_duplicate_group_component_count=(
            committed.duplicate_group_component_count
        ),
        final_canonical_parse_failure_count=(
            committed.canonical_parse_failure_count
        ),
        final_deprecated_gt_count=committed.deprecated_final_gt_count,
        candidate_cpe_mismatch_count=len(cpe_mismatches),
        candidate_decision_mismatch_count=len(decision_mismatches),
        component_mutation_count=int(
            before.component_fingerprint != committed.component_fingerprint
        ),
        non_target_ground_truth_mutation_count=0,
        discrepancy_assignment_count=(
            committed.discrepancy_assignment_count
        ),
        correction_assignment_count=committed.correction_assignment_count,
        representative_states=_named_states(
            committed, set(EXPECTED_REPRESENTATIVE_NAMES)
        ),
        removed_states=_named_states(
            committed, set(APPROVED_DERIVED_SPLITS)
        ),
        regression_states=_named_states(
            committed, set(REGRESSION_PRODUCT_NAMES)
        ),
    )


def default_output_directory() -> Path:
    return settings.REPOSITORY_ROOT / FINALIZATION_OUTPUT_RELATIVE


def _decision_table(counts: dict[str, int]) -> str:
    return "\n".join(
        f"| `{decision}` | {count} |"
        for decision, count in counts.items()
    )


def _state_table(states: dict[str, dict[str, str]]) -> str:
    return "\n".join(
        f"| `{name}` | `{values['gt_cpe'] or 'null'}` | "
        f"`{values['decision']}` |"
        for name, values in states.items()
    )


def write_finalization_artifacts(
    result: FinalizationResult,
    *,
    cpe_audit_summary: dict[str, Any],
    cpe_audit_hashes: dict[str, str],
    output_directory: Path,
) -> list[Path]:
    if output_directory.exists():
        _fail(f"Refusing to overwrite finalization artifact: {output_directory}")
    final_status_counts = cpe_audit_summary.get(
        "final_audit_status", {}
    ).get("counts")
    if final_status_counts != {
        "ACCEPTED": 39,
        "CORRECTION_REQUIRED": 0,
        "EVIDENCE_REVIEW_REQUIRED": 0,
    }:
        _fail("Final independent CPE audit is not 39/0/0")
    output_directory.mkdir(parents=True, exist_ok=False)
    application_path = output_directory / "application_report.md"
    audit_path = output_directory / "final_audit_report.md"
    summary_path = output_directory / "summary.json"
    application_path.write_text(
        f"""# Unitronics representative Ground Truth application

## Applied scope

- Applied at: `{result.applied_at}`
- Candidate: `{CANDIDATE_RELATIVE}`
- Candidate SHA-256: `{result.candidate_sha256}`
- Approved records updated: **8**
- Transaction: `transaction.atomic()`
- Record deletion/recreation: **0**

Updated Components: `{', '.join(result.changed_component_names)}`

## Before and after

- Ground Truth records: `582 -> 582`
- CPE present: `{result.before_cpe_present_count} -> {result.after_cpe_present_count}`
- CPE null: `{result.before_cpe_null_count} -> {result.after_cpe_null_count}`
- Component fingerprint: `{result.component_fingerprint_before} -> {result.component_fingerprint_after}`
- Ground Truth fingerprint: `{result.ground_truth_fingerprint_before} -> {result.ground_truth_fingerprint_after}`

## Final Decision distribution

| Internal code | Count |
|---|---:|
{_decision_table(result.after_decision_counts)}

No reason/taxonomy field was added. Each target's dictionary FK and manual CPE
expression were cleared, and its Decision was set to
`DIRECT_OFFICIAL_CPE_NOT_CONFIRMED`. Existing notes and M2M values were not used
to store a new policy code.
""",
        encoding="utf-8",
    )
    audit_path.write_text(
        f"""# Unitronics representative Ground Truth final audit

## Final dataset

- Ground Truth records: **582**
- CPE-bearing Components: **{result.after_cpe_present_count}**
- GT CPE null: **{result.after_cpe_null_count}**
- Distinct canonical GT CPE: **{result.final_distinct_canonical_gt_cpes}**
- Duplicate canonical GT CPE groups: **{result.final_duplicate_canonical_gt_cpe_groups}**
- Components in duplicate groups: **{result.final_duplicate_group_component_count}**
- Canonical parse failures: **{result.final_canonical_parse_failure_count}**
- Deprecated final GT: **{result.final_deprecated_gt_count}**

## Removed derived splits

| Component | GT CPE | Decision |
|---|---|---|
{_state_table(result.removed_states)}

## Retained representatives

| Component | GT CPE | Decision |
|---|---|---|
{_state_table(result.representative_states)}

## Independent-product regression

| Component | GT CPE | Decision |
|---|---|---|
{_state_table(result.regression_states)}

## Independent CPE audit

- `ACCEPTED`: **39**
- `CORRECTION_REQUIRED`: **0**
- `EVIDENCE_REVIEW_REQUIRED`: **0**
- Final Deprecated GT: **0**

## Integrity

- Candidate-to-DB CPE mismatch: **{result.candidate_cpe_mismatch_count}**
- Candidate-to-DB Decision mismatch: **{result.candidate_decision_mismatch_count}**
- Component mutation: **{result.component_mutation_count}**
- Non-target Ground Truth mutation: **{result.non_target_ground_truth_mutation_count}**
- Discrepancy Type assignments: **{result.discrepancy_assignment_count}**
- Correction Type assignments: **{result.correction_assignment_count}**

The final topology audit is a rerun over the 39 current CPE-bearing records; it
does not alter the historical duplicate audit or OpenSSL representative audit.
The approved methodology is: one representative Component per upstream
product/version for distribution-specific splits, without parent-CPE inheritance
to derived splits; independently identifiable CPE products remain separate.

**Unitronics representative Ground Truth finalization: SUCCESS**
""",
        encoding="utf-8",
    )
    summary = {
        "schema_version": 1,
        "status": "SUCCESS",
        "finalization": "Unitronics representative Ground Truth finalization",
        "applied_at": result.applied_at,
        "dataset": {
            "sbom_document_id": SBOM_DOCUMENT_ID,
            "dataset_key": DATASET_KEY,
            "ground_truth_records": 582,
            "cpe_bearing_components": result.after_cpe_present_count,
            "gt_cpe_null": result.after_cpe_null_count,
            "distinct_canonical_gt_cpes": (
                result.final_distinct_canonical_gt_cpes
            ),
            "duplicate_canonical_gt_cpe_groups": (
                result.final_duplicate_canonical_gt_cpe_groups
            ),
        },
        "application": {
            "candidate_path": str(CANDIDATE_RELATIVE),
            "candidate_sha256": result.candidate_sha256,
            "removed_mapping_count": len(result.changed_component_ids),
            "changed_component_ids": list(result.changed_component_ids),
            "changed_component_names": list(result.changed_component_names),
            "record_recreation_count": 0,
            "transaction_atomic": True,
            "decision_counts_before": result.before_decision_counts,
            "decision_counts_after": result.after_decision_counts,
        },
        "independent_cpe_audit": {
            "counts": final_status_counts,
            "hashes": cpe_audit_hashes,
            "deprecated_final_gt_count": result.final_deprecated_gt_count,
        },
        "topology": {
            "distinct_canonical_gt_cpes": (
                result.final_distinct_canonical_gt_cpes
            ),
            "duplicate_groups": (
                result.final_duplicate_canonical_gt_cpe_groups
            ),
            "components_in_duplicate_groups": (
                result.final_duplicate_group_component_count
            ),
        },
        "states": {
            "removed": result.removed_states,
            "representatives": result.representative_states,
            "curl_libcurl_regression": result.regression_states,
        },
        "validation": {
            "candidate_cpe_mismatch_count": (
                result.candidate_cpe_mismatch_count
            ),
            "candidate_decision_mismatch_count": (
                result.candidate_decision_mismatch_count
            ),
            "component_mutation_count": result.component_mutation_count,
            "non_target_ground_truth_mutation_count": (
                result.non_target_ground_truth_mutation_count
            ),
            "component_fingerprint_before": (
                result.component_fingerprint_before
            ),
            "component_fingerprint_after": (
                result.component_fingerprint_after
            ),
            "ground_truth_fingerprint_before": (
                result.ground_truth_fingerprint_before
            ),
            "ground_truth_fingerprint_after": (
                result.ground_truth_fingerprint_after
            ),
            "canonical_parse_failure_count": (
                result.final_canonical_parse_failure_count
            ),
            "deprecated_final_gt_count": result.final_deprecated_gt_count,
            "migration_count": 0,
            "commit_count": 0,
            "test_results": "PENDING_FINAL_REGRESSION_RUN",
        },
        "methodology_policy": (
            "For distribution-specific splits of one upstream product/version, "
            "assign the parent CPE only to the approved representative Component; "
            "do not inherit it to derived splits. Preserve independently "
            "identifiable CPE products."
        ),
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return [application_path, audit_path, summary_path]

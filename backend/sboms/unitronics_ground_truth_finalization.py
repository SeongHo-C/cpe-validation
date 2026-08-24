from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from cpe.cpe23_canonical import CPE23CanonicalizationError, canonicalize_cpe23
from cpe_dictionary.models import CpeDictionarySnapshot
from nvd_cve.models import NvdCveSnapshot
from sboms.models import (
    ComponentCpeGroundTruth,
    GroundTruthDecision,
    GroundTruthResolutionOutcome,
    SBOMDocument,
)
from sboms.unitronics_ground_truth_candidate_build import (
    APPROVED_DERIVED_SPLITS,
    validate_product_boundary_approvals,
)
from sboms.unitronics_ground_truth_cpe_audit import (
    build_unitronics_cpe_audit,
    finalize_validation as finalize_cpe_audit_validation,
)
from sboms.unitronics_ground_truth_product_boundary_full_audit import (
    build_product_boundary_full_audit,
)
from sboms.unitronics_representative_finalization import (
    DatabaseState,
    _database_state,
)


DATASET_KEY = "61602e128acb__52.07.13.7"
SBOM_DOCUMENT_ID = 1364
CPE_SNAPSHOT_ID = "20260819T035002Z"
NVD_SNAPSHOT_ID = "20260820T110357Z"
TARGET_COMPONENT_ID = 200186
TARGET_COMPONENT_NAME = "wireguard-tools"
TARGET_OBSERVED_VERSION = "1.0.20210223-4"
TARGET_ACTUAL_PRODUCT = "wireguard-tools"
TARGET_ACTUAL_VERSION = "1.0.20210223"
OLD_GT_CPE = (
    "cpe:2.3:a:wireguard:wireguard:1.0.20210223:*:*:*:*:*:*:*"
)
OLD_DECISION = GroundTruthDecision.VERSION_NOT_IN_DICTIONARY
FINAL_DECISION = GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED

CANDIDATE_DIRECTORY = Path(
    "analysis/results/unitronics-ground-truth-candidate-build"
) / DATASET_KEY
CPE_AUDIT_DIRECTORY = Path(
    "analysis/results/unitronics-ground-truth-cpe-audit"
) / DATASET_KEY
WIREGUARD_AUDIT_SUMMARY = Path(
    "analysis/results/unitronics-wireguard-product-boundary-audit"
) / DATASET_KEY / "summary.json"
FULL_BOUNDARY_AUDIT_SUMMARY = Path(
    "analysis/results/unitronics-ground-truth-product-boundary-full-audit"
) / DATASET_KEY / "summary.json"
PRIOR_METHODOLOGY_SUMMARY = Path(
    "analysis/results/unitronics-ground-truth-methodology-final-audit"
) / DATASET_KEY / "summary.json"
OUTPUT_RELATIVE = Path(
    "analysis/results/unitronics-ground-truth-finalization"
) / DATASET_KEY

EXPECTED_APPROVAL_HASHES = {
    WIREGUARD_AUDIT_SUMMARY: (
        "cc123f6b899c7a1f5622c27700bc846b9a4eaf76ea810faec1b9ae8736c036b4"
    ),
    FULL_BOUNDARY_AUDIT_SUMMARY: (
        "0d7aa627460b3d53832c692bfe6fa9ee177f74cd147f6258491f0c043bf64010"
    ),
}
EXPECTED_CANDIDATE_HASHES = {
    CANDIDATE_DIRECTORY / "components.csv": (
        "ba750a4002ef838910d2e1edba20667cc105233644e26069d66b063e1ad18e6b"
    ),
    CANDIDATE_DIRECTORY / "summary.json": (
        "bdebf18b26c555e9073d680145d7507cf9894272956b51ce9300f03e33dc9dd4"
    ),
    CANDIDATE_DIRECTORY / "evidence_manifest.csv": (
        "c8fd1ff5b148e0d9c411ec25d8cf6ebfc5ea50baf770cfcba75783448bfb088b"
    ),
}
EXPECTED_CPE_AUDIT_HASHES = {
    CPE_AUDIT_DIRECTORY / "audit_results.csv": (
        "5a0f45ce3a62f6acee94dc55e9fe9573b780e8846e89e78c0034c22c8e871984"
    ),
    CPE_AUDIT_DIRECTORY / "summary.json": (
        "bb2740bd621845cfb486f59c6b9545892640110460f69bda0a733b53e46e78fc"
    ),
}
EXPECTED_COMPONENT_FINGERPRINT = (
    "9ffed80ba47da6bbfbb148b668930f714b8067b657506c5227854fbe82e5460e"
)
EXPECTED_INITIAL_GROUND_TRUTH_FINGERPRINT = (
    "9157dec9eaaa26f963d87a501a4d44c015e6adfef31f6d2c825b4187a35478cd"
)

EXPECTED_BEFORE_DECISIONS = {
    GroundTruthDecision.CPE_CONFIRMED: 2,
    GroundTruthDecision.OFFICIAL_CPE_MAPPED: 21,
    GroundTruthDecision.VERSION_NOT_IN_DICTIONARY: 17,
    GroundTruthDecision.NVD_CONFIGURATION_ONLY: 0,
    GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED: 537,
    GroundTruthDecision.UNRESOLVED: 5,
}
EXPECTED_FINAL_DECISIONS = {
    GroundTruthDecision.CPE_CONFIRMED: 2,
    GroundTruthDecision.OFFICIAL_CPE_MAPPED: 21,
    GroundTruthDecision.VERSION_NOT_IN_DICTIONARY: 16,
    GroundTruthDecision.NVD_CONFIGURATION_ONLY: 0,
    GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED: 538,
    GroundTruthDecision.UNRESOLVED: 5,
}
REPRESENTATIVE_NAMES = (
    "libcap",
    "lua",
    "ipset",
    "iptables",
    "sqlite",
    "strongswan",
    "libopenssl3",
)


class UnitronicsGroundTruthFinalizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CandidateRow:
    component_id: int
    name: str
    observed_version: str
    actual_product: str
    actual_product_version: str
    proposed_gt_cpe: str
    proposed_decision: str
    discrepancy_fields: str


@dataclass(frozen=True)
class FinalizationPlan:
    rows: tuple[CandidateRow, ...]
    artifact_hashes: dict[str, str]

    @property
    def by_id(self) -> dict[int, CandidateRow]:
        return {row.component_id: row for row in self.rows}

    @property
    def by_name(self) -> dict[str, CandidateRow]:
        return {row.name: row for row in self.rows}


@dataclass(frozen=True)
class FinalizationResult:
    applied_at: str
    before: dict[str, Any]
    after: dict[str, Any]
    changed_ground_truth_record_ids: tuple[int, ...]
    candidate_cpe_mismatch_count_before: int
    candidate_decision_mismatch_count_before: int
    candidate_cpe_mismatch_count_after: int
    candidate_decision_mismatch_count_after: int
    component_mutation_count: int
    wireguard_before: dict[str, Any]
    wireguard_after: dict[str, Any]
    product_boundary_summary: dict[str, Any]
    independent_cpe_summary: dict[str, Any]
    representative_regressions: dict[str, Any]
    methodology: dict[str, Any]
    artifact_hashes: dict[str, str]


def _fail(message: str) -> NoReturn:
    raise UnitronicsGroundTruthFinalizationError(message)


def default_output_directory() -> Path:
    return settings.REPOSITORY_ROOT / OUTPUT_RELATIVE


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(f"Cannot read valid JSON {path}: {error}")
    if not isinstance(value, dict):
        _fail(f"Expected a JSON object in {path}")
    return value


def _read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except OSError as error:
        _fail(f"Cannot read CSV {path}: {error}")


def _validate_hashes(
    root: Path,
    expected: dict[Path, str],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative, expected_hash in expected.items():
        path = root / relative
        if not path.is_file():
            _fail(f"Required artifact is absent: {relative}")
        actual = _sha256(path)
        if actual != expected_hash:
            _fail(
                f"Artifact hash mismatch for {relative}: expected "
                f"{expected_hash}, got {actual}"
            )
        result[str(relative)] = actual
    return result


def load_finalization_plan(
    repository_root: Path | None = None,
) -> FinalizationPlan:
    root = repository_root or settings.REPOSITORY_ROOT
    validate_product_boundary_approvals(root / "analysis/results")
    hashes = {}
    hashes.update(_validate_hashes(root, EXPECTED_APPROVAL_HASHES))
    hashes.update(_validate_hashes(root, EXPECTED_CANDIDATE_HASHES))
    hashes.update(_validate_hashes(root, EXPECTED_CPE_AUDIT_HASHES))

    rows: list[CandidateRow] = []
    for raw in _read_csv(root / CANDIDATE_DIRECTORY / "components.csv"):
        try:
            rows.append(
                CandidateRow(
                    component_id=int(raw["component_id"]),
                    name=raw["name"],
                    observed_version=raw["observed_version"],
                    actual_product=raw["actual_product"],
                    actual_product_version=raw["actual_product_version"],
                    proposed_gt_cpe=raw["proposed_gt_cpe"],
                    proposed_decision=raw["proposed_decision"],
                    discrepancy_fields=raw["discrepancy_fields"],
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            _fail(f"Invalid candidate row: {error}")
    if len(rows) != 582 or len({row.component_id for row in rows}) != 582:
        _fail("Final candidate must contain 582 unique Component IDs")
    if len({row.name for row in rows}) != 582:
        _fail("Final candidate names are not unique")
    counts = Counter(row.proposed_decision for row in rows)
    normalized_counts = {
        decision: counts[decision] for decision in EXPECTED_FINAL_DECISIONS
    }
    if normalized_counts != EXPECTED_FINAL_DECISIONS:
        _fail(f"Unexpected final candidate Decisions: {dict(counts)}")
    cpes: list[str] = []
    for row in rows:
        if not row.proposed_gt_cpe:
            continue
        try:
            canonical = canonicalize_cpe23(row.proposed_gt_cpe)
        except CPE23CanonicalizationError as error:
            _fail(f"Invalid candidate CPE for {row.name}: {error}")
        if canonical != row.proposed_gt_cpe:
            _fail(f"Non-canonical candidate CPE for {row.name}")
        cpes.append(canonical)
    if len(cpes) != 39 or len(set(cpes)) != 39:
        _fail("Final candidate must contain 39 distinct canonical GT CPEs")

    plan = FinalizationPlan(tuple(rows), hashes)
    wireguard = plan.by_name.get(TARGET_COMPONENT_NAME)
    if wireguard is None or (
        wireguard.component_id != TARGET_COMPONENT_ID
        or wireguard.observed_version != TARGET_OBSERVED_VERSION
        or wireguard.actual_product != TARGET_ACTUAL_PRODUCT
        or wireguard.actual_product_version != TARGET_ACTUAL_VERSION
        or wireguard.proposed_gt_cpe
        or wireguard.proposed_decision != FINAL_DECISION
        or wireguard.discrepancy_fields not in {"", "N/A"}
    ):
        _fail("wireguard-tools candidate does not match the approved final state")

    summary = _read_json(root / CANDIDATE_DIRECTORY / "summary.json")
    policy = summary.get("product_boundary_policy", {})
    if (
        summary.get("validation", {}).get("proposed_gt_count") != 39
        or summary.get("decisions", {}).get("counts")
        != {str(key): value for key, value in EXPECTED_FINAL_DECISIONS.items()}
        or policy.get("approved_exclusions") != [TARGET_COMPONENT_NAME]
        or policy.get("generic_semantic_matching_engine_added") is not False
    ):
        _fail("Candidate summary does not encode the approved final boundary policy")

    audit = _read_json(root / CPE_AUDIT_DIRECTORY / "summary.json")
    if (
        audit.get("final_audit_status", {}).get("counts")
        != {
            "ACCEPTED": 39,
            "CORRECTION_REQUIRED": 0,
            "EVIDENCE_REVIEW_REQUIRED": 0,
        }
        or audit.get("correction_counts")
        != {
            "circular_evidence_risks": 0,
            "discrepancy_field_corrections": 0,
            "gt_cpe_corrections": 0,
            "product_corrections": 0,
            "validation_result_corrections": 0,
            "version_corrections": 0,
        }
    ):
        _fail("Persisted independent CPE audit is not the final 39-row result")
    return plan


def _effective_cpe(record: ComponentCpeGroundTruth) -> str:
    if record.ground_truth_cpe is not None:
        return record.ground_truth_cpe.cpe_name
    return record.manual_ground_truth_cpe


def _state_summary(state: DatabaseState) -> dict[str, Any]:
    return {
        "ground_truth_records": len(state.records),
        "global_ground_truth_records": state.global_ground_truth_count,
        "component_count": state.component_count,
        "component_fingerprint": state.component_fingerprint,
        "ground_truth_fingerprint": state.ground_truth_fingerprint,
        "decision_counts": state.decision_counts,
        "cpe_bearing": state.cpe_present_count,
        "cpe_null": state.cpe_null_count,
        "distinct_canonical_gt_cpes": state.distinct_canonical_gt_cpes,
        "duplicate_canonical_gt_cpe_groups": (
            state.duplicate_canonical_gt_cpe_groups
        ),
        "canonical_parse_failure_count": state.canonical_parse_failure_count,
        "deprecated_final_gt_count": state.deprecated_final_gt_count,
        "discrepancy_assignment_count": state.discrepancy_assignment_count,
        "correction_assignment_count": state.correction_assignment_count,
    }


def _record_state(record: ComponentCpeGroundTruth) -> dict[str, Any]:
    return {
        "record_id": record.id,
        "component_id": record.component_id,
        "component_name": record.component.name,
        "component_version": record.component.version,
        "original_cpe": record.component.cpe,
        "ground_truth_cpe_id": record.ground_truth_cpe_id,
        "ground_truth_cpe": _effective_cpe(record),
        "manual_ground_truth_cpe": record.manual_ground_truth_cpe,
        "decision": record.decision,
        "resolution_outcome": record.resolution_outcome,
        "discrepancy_codes": sorted(
            item.code for item in record.discrepancy_types.all()
        ),
        "correction_codes": sorted(
            item.code for item in record.correction_types.all()
        ),
    }


def _record_signature(record: ComponentCpeGroundTruth) -> tuple[Any, ...]:
    state = _record_state(record)
    return tuple(
        json.dumps(state[key], sort_keys=True)
        for key in sorted(state)
    )


def _candidate_mismatches(
    plan: FinalizationPlan,
    state: DatabaseState,
) -> tuple[set[int], set[int]]:
    records = {record.component_id: record for record in state.records}
    if set(records) != set(plan.by_id):
        _fail("Candidate and database Component ID sets differ")
    cpe = {
        component_id
        for component_id, candidate in plan.by_id.items()
        if _effective_cpe(records[component_id]) != candidate.proposed_gt_cpe
    }
    decisions = {
        component_id
        for component_id, candidate in plan.by_id.items()
        if records[component_id].decision != candidate.proposed_decision
    }
    return cpe, decisions


def _validate_database_state(
    state: DatabaseState,
    *,
    final: bool,
) -> None:
    expected_decisions = (
        EXPECTED_FINAL_DECISIONS if final else EXPECTED_BEFORE_DECISIONS
    )
    expected_scalars = {
        "component_count": 582,
        "global_ground_truth_count": 582,
        "cpe_present_count": 39 if final else 40,
        "cpe_null_count": 543 if final else 542,
        "distinct_canonical_gt_cpes": 39 if final else 40,
        "duplicate_canonical_gt_cpe_groups": 0,
        "duplicate_group_component_count": 0,
        "canonical_parse_failure_count": 0,
        "deprecated_final_gt_count": 0,
        "discrepancy_assignment_count": 0,
        "correction_assignment_count": 0,
    }
    if len(state.records) != 582:
        _fail("Scoped Ground Truth record count is not 582")
    for field, expected in expected_scalars.items():
        if getattr(state, field) != expected:
            _fail(
                f"Unexpected {'final' if final else 'preflight'} {field}: "
                f"expected {expected}, got {getattr(state, field)}"
            )
    if state.decision_counts != expected_decisions:
        _fail(
            "Unexpected Ground Truth Decision distribution: "
            f"{state.decision_counts}"
        )
    if state.component_fingerprint != EXPECTED_COMPONENT_FINGERPRINT:
        _fail("Component fingerprint differs from the approved preflight")
    if (
        not final
        and state.ground_truth_fingerprint
        != EXPECTED_INITIAL_GROUND_TRUTH_FINGERPRINT
    ):
        _fail("Ground Truth fingerprint differs from the approved preflight")


def _validate_target(record: ComponentCpeGroundTruth, *, final: bool) -> None:
    state = _record_state(record)
    if (
        state["component_id"] != TARGET_COMPONENT_ID
        or state["component_name"] != TARGET_COMPONENT_NAME
        or state["component_version"] != TARGET_OBSERVED_VERSION
        or state["discrepancy_codes"]
        or state["correction_codes"]
    ):
        _fail("wireguard-tools target identity or relation state is unexpected")
    if final:
        if (
            state["ground_truth_cpe_id"] is not None
            or state["manual_ground_truth_cpe"]
            or state["ground_truth_cpe"]
            or state["decision"] != FINAL_DECISION
            or state["resolution_outcome"]
            != GroundTruthResolutionOutcome.DIRECT_OFFICIAL_NOT_CONFIRMED
        ):
            _fail("wireguard-tools final database state is incorrect")
    elif (
        state["ground_truth_cpe_id"] is not None
        or state["manual_ground_truth_cpe"] != OLD_GT_CPE
        or state["ground_truth_cpe"] != OLD_GT_CPE
        or state["decision"] != OLD_DECISION
        or state["resolution_outcome"]
        != GroundTruthResolutionOutcome.MANUAL_FROM_OFFICIAL_FAMILY
    ):
        _fail("wireguard-tools current database state differs from preflight")


def _representative_regressions(state: DatabaseState) -> dict[str, Any]:
    records = {record.component.name: record for record in state.records}
    representatives: dict[str, str] = {}
    for name in REPRESENTATIVE_NAMES:
        value = _effective_cpe(records[name])
        if not value:
            _fail(f"Representative Component lost its GT CPE: {name}")
        representatives[name] = value
    derived: dict[str, str | None] = {}
    for name in APPROVED_DERIVED_SPLITS:
        value = _effective_cpe(records[name])
        if value or records[name].decision != FINAL_DECISION:
            _fail(f"Approved derived split regression for {name}")
        derived[name] = None
    curl = _effective_cpe(records["curl"])
    libcurl = _effective_cpe(records["libcurl4"])
    if not curl or not libcurl or curl == libcurl:
        _fail("curl/libcurl4 independent-product regression")
    return {
        "representatives": representatives,
        "derived_splits": derived,
        "curl": curl,
        "libcurl4": libcurl,
        "curl_and_libcurl_distinct": True,
    }


def _methodology_audit(
    *,
    root: Path,
    plan: FinalizationPlan,
    state: DatabaseState,
    product_boundary: dict[str, Any],
    cpe_audit: dict[str, Any],
) -> dict[str, Any]:
    prior = _read_json(root / PRIOR_METHODOLOGY_SUMMARY)
    candidate_summary = _read_json(root / CANDIDATE_DIRECTORY / "summary.json")
    blocking: list[str] = []
    if (
        prior.get("verdict") != "READY_FOR_FINALIZATION"
        or prior.get("blocking_issue_count") != 0
    ):
        blocking.append("Prior methodology audit is not finalization-ready")
    policy = candidate_summary.get("product_boundary_policy", {})
    if (
        policy.get("status") != "APPLIED_FROM_APPROVED_AUDITS"
        or policy.get("approved_exclusions") != [TARGET_COMPONENT_NAME]
    ):
        blocking.append("Approved product-boundary policy is absent")
    if product_boundary.get("audit_status") != {
        "KEEP": 39,
        "CHANGE_CPE": 0,
        "REMOVE_CPE": 0,
        "REVIEW_REQUIRED": 0,
    }:
        blocking.append("Final product-boundary audit is not 39 KEEP")
    if cpe_audit.get("final_audit_status", {}).get("counts") != {
        "ACCEPTED": 39,
        "CORRECTION_REQUIRED": 0,
        "EVIDENCE_REVIEW_REQUIRED": 0,
    }:
        blocking.append("Final independent CPE audit is not 39 ACCEPTED")
    if state.deprecated_final_gt_count or state.canonical_parse_failure_count:
        blocking.append("Final CPE topology contains an invalid/deprecated CPE")
    verdict = "READY_FOR_FINALIZATION" if not blocking else "BLOCKED"
    return {
        "verdict": verdict,
        "blocking_issue_count": len(blocking),
        "blocking_issues": blocking,
        "ratings": {
            "methodological_consistency": (
                "PASS" if not blocking else "FAIL"
            ),
            "evidence_traceability": "PASS_WITH_LIMITATION",
            "computational_reproducibility": "PASS_WITH_LIMITATION",
        },
        "product_boundary_principle": (
            "Do not approve a mapping from similar vendor/product labels or "
            "CPE-family existence alone. Verify the official upstream product "
            "boundary against CPE title/reference/version space and, when "
            "needed, fixed-snapshot NVD usage context."
        ),
        "flow": [
            "SBOM Component",
            "Exact Firmware Evidence",
            "Actual Software Product / Version",
            "Product / Subcomponent Boundary",
            "Official Upstream Product Boundary",
            "CPE Family Product Boundary Validation",
            "Active Exact CPE",
            "Deprecated -> Active",
            "Version Not Registered",
            "NVD Configuration Only",
            "CPE Validation Result",
        ],
        "candidate_rows": len(plan.rows),
        "prior_non_blocking_limitations": prior.get(
            "non_blocking_limitations", []
        ),
    }


def finalize_unitronics_ground_truth(
    plan: FinalizationPlan,
    *,
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
    repository_root: Path | None = None,
) -> FinalizationResult:
    root = repository_root or settings.REPOSITORY_ROOT
    if (
        cpe_snapshot.snapshot_id != CPE_SNAPSHOT_ID
        or nvd_snapshot.snapshot_id != NVD_SNAPSHOT_ID
    ):
        _fail("Finalization received the wrong fixed snapshot")
    try:
        with transaction.atomic():
            SBOMDocument.objects.select_for_update().get(pk=SBOM_DOCUMENT_ID)
            before = _database_state(lock=True)
            _validate_database_state(before, final=False)
            cpe_mismatch_before, decision_mismatch_before = (
                _candidate_mismatches(plan, before)
            )
            if (
                cpe_mismatch_before != {TARGET_COMPONENT_ID}
                or decision_mismatch_before != {TARGET_COMPONENT_ID}
            ):
                _fail(
                    "Preflight candidate-to-DB differences are not exactly "
                    "wireguard-tools"
                )
            before_signatures = {
                record.id: _record_signature(record) for record in before.records
            }
            target = next(
                record
                for record in before.records
                if record.component_id == TARGET_COMPONENT_ID
            )
            _validate_target(target, final=False)
            wireguard_before = _record_state(target)

            target.ground_truth_cpe = None
            target.manual_ground_truth_cpe = ""
            target.decision = FINAL_DECISION
            target.save(
                update_fields=(
                    "ground_truth_cpe",
                    "manual_ground_truth_cpe",
                    "decision",
                    "resolution_outcome",
                    "updated_at",
                )
            )

            after = _database_state(lock=True)
            _validate_database_state(after, final=True)
            target_after = next(
                record
                for record in after.records
                if record.component_id == TARGET_COMPONENT_ID
            )
            _validate_target(target_after, final=True)
            wireguard_after = _record_state(target_after)
            after_signatures = {
                record.id: _record_signature(record) for record in after.records
            }
            changed_ids = tuple(
                sorted(
                    record_id
                    for record_id, signature in before_signatures.items()
                    if after_signatures[record_id] != signature
                )
            )
            if changed_ids != (target.id,):
                _fail(
                    "Ground Truth mutation set is not exactly the wireguard row: "
                    f"{changed_ids}"
                )
            cpe_mismatch_after, decision_mismatch_after = (
                _candidate_mismatches(plan, after)
            )
            if cpe_mismatch_after or decision_mismatch_after:
                _fail("Candidate-to-DB mismatch remains after the approved update")

            product_analysis = build_product_boundary_full_audit(
                cpe_snapshot=cpe_snapshot,
                nvd_snapshot=nvd_snapshot,
                repository_root=root,
                finalized=True,
            )
            if product_analysis.summary["audit_status"] != {
                "KEEP": 39,
                "CHANGE_CPE": 0,
                "REMOVE_CPE": 0,
                "REVIEW_REQUIRED": 0,
            }:
                _fail("Final product-boundary audit is not 39 KEEP")

            cpe_analysis = build_unitronics_cpe_audit(
                cpe_snapshot=cpe_snapshot,
                nvd_snapshot=nvd_snapshot,
            )
            finalize_cpe_audit_validation(
                cpe_analysis,
                ground_truth_count_after=ComponentCpeGroundTruth.objects.count(),
            )
            persisted_audit_rows = _read_csv(
                root / CPE_AUDIT_DIRECTORY / "audit_results.csv"
            )
            if persisted_audit_rows != cpe_analysis.rows:
                _fail("Persisted 39-row audit does not reproduce in memory")

            representative = _representative_regressions(after)
            methodology = _methodology_audit(
                root=root,
                plan=plan,
                state=after,
                product_boundary=product_analysis.summary,
                cpe_audit=cpe_analysis.summary,
            )
            if (
                methodology["verdict"] != "READY_FOR_FINALIZATION"
                or methodology["blocking_issue_count"] != 0
            ):
                _fail("Final methodology audit has a blocking issue")
    except UnitronicsGroundTruthFinalizationError:
        raise
    except Exception as error:
        raise UnitronicsGroundTruthFinalizationError(str(error)) from error

    committed = _database_state()
    _validate_database_state(committed, final=True)
    committed_cpe_mismatch, committed_decision_mismatch = (
        _candidate_mismatches(plan, committed)
    )
    if committed_cpe_mismatch or committed_decision_mismatch:
        _fail("Committed database differs from the final candidate")
    if committed.component_fingerprint != before.component_fingerprint:
        _fail("Component fingerprint changed during finalization")

    return FinalizationResult(
        applied_at=timezone.now().isoformat(),
        before=_state_summary(before),
        after=_state_summary(committed),
        changed_ground_truth_record_ids=changed_ids,
        candidate_cpe_mismatch_count_before=len(cpe_mismatch_before),
        candidate_decision_mismatch_count_before=len(decision_mismatch_before),
        candidate_cpe_mismatch_count_after=len(committed_cpe_mismatch),
        candidate_decision_mismatch_count_after=len(
            committed_decision_mismatch
        ),
        component_mutation_count=int(
            before.component_fingerprint != committed.component_fingerprint
        ),
        wireguard_before=wireguard_before,
        wireguard_after=wireguard_after,
        product_boundary_summary=product_analysis.summary,
        independent_cpe_summary=cpe_analysis.summary,
        representative_regressions=representative,
        methodology=methodology,
        artifact_hashes=plan.artifact_hashes,
    )


def _methodology_markdown(result: FinalizationResult) -> str:
    methodology = result.methodology
    flow = "\n".join(f"  -> {step}" for step in methodology["flow"])
    limitations = "\n".join(
        f"- {item}" for item in methodology["prior_non_blocking_limitations"]
    )
    return f"""# Final Ground Truth methodology

## Product-boundary rule

{methodology['product_boundary_principle']}

## Reproducible flow

```text
{flow}
```

The approved `wireguard-tools` case is encoded as a narrow audited exclusion,
not as a generic semantic matching engine. Its upstream version remains
`1.0.20210223`; only the invalid `wireguard:wireguard` family binding is removed.

## Final audit

- Methodological Consistency: `{methodology['ratings']['methodological_consistency']}`
- Evidence Traceability: `{methodology['ratings']['evidence_traceability']}`
- Computational Reproducibility: `{methodology['ratings']['computational_reproducibility']}`
- Blocking issues: `{methodology['blocking_issue_count']}`
- Verdict: `{methodology['verdict']}`

## Non-blocking limitations

{limitations}
"""


def _final_report_markdown(result: FinalizationResult) -> str:
    before = result.wireguard_before
    after = result.wireguard_after
    product = result.product_boundary_summary["audit_status"]
    cpe = result.independent_cpe_summary["final_audit_status"]["counts"]
    decisions = result.after["decision_counts"]
    return f"""# Unitronics Ground Truth finalization

## Result

**SUCCESS**

- Applied at: `{result.applied_at}`
- Transaction: `transaction.atomic()`
- Ground Truth rows changed: `{len(result.changed_ground_truth_record_ids)}`
- Component mutations: `{result.component_mutation_count}`
- Migration: `0`

## wireguard-tools

| Field | Before | After |
|---|---|---|
| GT CPE | `{before['ground_truth_cpe']}` | `null` |
| Decision | `{before['decision']}` | `{after['decision']}` |
| Resolution outcome | `{before['resolution_outcome']}` | `{after['resolution_outcome']}` |

Actual product/version: `{TARGET_ACTUAL_PRODUCT} {TARGET_ACTUAL_VERSION}`.

## Final topology

- Ground Truth records: **{result.after['ground_truth_records']}**
- CPE-bearing / null: **{result.after['cpe_bearing']} / {result.after['cpe_null']}**
- Distinct canonical CPE / duplicate groups: **{result.after['distinct_canonical_gt_cpes']} / {result.after['duplicate_canonical_gt_cpe_groups']}**
- Deprecated final GT / parse failures: **{result.after['deprecated_final_gt_count']} / {result.after['canonical_parse_failure_count']}**
- Decisions: `{json.dumps(decisions, sort_keys=True)}`
- Candidate CPE/Decision mismatches: **{result.candidate_cpe_mismatch_count_after} / {result.candidate_decision_mismatch_count_after}**

## Final audits

- Product boundary: `{json.dumps(product, sort_keys=True)}`
- Independent CPE: `{json.dumps(cpe, sort_keys=True)}`
- Version Not Registered satisfying all invariants: **{result.product_boundary_summary['validation']['version_not_registered_keep_all_invariants_count']} / 16**
- Circular evidence risks: **{result.independent_cpe_summary['correction_counts']['circular_evidence_risks']}**
- Methodology verdict / blockers: **{result.methodology['verdict']} / {result.methodology['blocking_issue_count']}**
"""


def write_finalization_artifacts(
    result: FinalizationResult,
    output_directory: Path,
) -> list[Path]:
    if output_directory.exists():
        _fail(f"Refusing to overwrite final artifact: {output_directory}")
    output_directory.mkdir(parents=True, exist_ok=False)
    report = output_directory / "final_report.md"
    methodology = output_directory / "methodology_summary.md"
    summary = output_directory / "summary.json"
    report.write_text(_final_report_markdown(result), encoding="utf-8")
    methodology.write_text(
        _methodology_markdown(result),
        encoding="utf-8",
    )
    payload = {
        "schema_version": 1,
        "status": "SUCCESS",
        "dataset": {
            "dataset_key": DATASET_KEY,
            "sbom_document_id": SBOM_DOCUMENT_ID,
            "manufacturer": "Unitronics",
            "product": "UCR-ST-B8",
            "firmware_version": "52.07.13.7",
            "component_count": 582,
        },
        "snapshots": {
            "cpe_dictionary": CPE_SNAPSHOT_ID,
            "nvd_cve_configuration": NVD_SNAPSHOT_ID,
        },
        "applied_at": result.applied_at,
        "wireguard_tools": {
            "before": result.wireguard_before,
            "after": result.wireguard_after,
        },
        "candidate_change": {
            "changed_component_count": 1,
            "changed_component_ids": [TARGET_COMPONENT_ID],
            "candidate_cpe_mismatch_count_before": (
                result.candidate_cpe_mismatch_count_before
            ),
            "candidate_decision_mismatch_count_before": (
                result.candidate_decision_mismatch_count_before
            ),
            "candidate_cpe_mismatch_count_after": (
                result.candidate_cpe_mismatch_count_after
            ),
            "candidate_decision_mismatch_count_after": (
                result.candidate_decision_mismatch_count_after
            ),
        },
        "database": {
            "before": result.before,
            "after": result.after,
            "changed_ground_truth_record_ids": list(
                result.changed_ground_truth_record_ids
            ),
            "component_mutation_count": result.component_mutation_count,
            "record_creation_count": 0,
            "record_deletion_count": 0,
        },
        "product_boundary_audit": {
            "audit_status": result.product_boundary_summary["audit_status"],
            "validation": result.product_boundary_summary["validation"],
        },
        "independent_cpe_audit": {
            "final_audit_status": result.independent_cpe_summary[
                "final_audit_status"
            ],
            "correction_counts": result.independent_cpe_summary[
                "correction_counts"
            ],
            "cpe_resolution": result.independent_cpe_summary[
                "cpe_resolution"
            ],
        },
        "representative_regressions": result.representative_regressions,
        "methodology_audit": result.methodology,
        "provenance_sha256": result.artifact_hashes,
        "safety": {
            "ground_truth_record_changes": 1,
            "component_mutations": result.component_mutation_count,
            "migration_count": 0,
            "new_taxonomy_count": 0,
            "incorrect_cpe_fields_db_changes": 0,
            "commit_count": 0,
        },
    }
    summary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return [report, methodology, summary]

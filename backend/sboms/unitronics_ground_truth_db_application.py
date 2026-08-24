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
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName
from nvd_cve.models import NvdCveSnapshot
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    GroundTruthDecision,
    SBOMDocument,
)


DATASET_KEY = "61602e128acb__52.07.13.7"
SBOM_DOCUMENT_ID = 1364
SBOM_SHA256 = (
    "61602e128acb7cdc378bdd868da489100bfb8f3dc587f0f12c5cf08cb26dd13e"
)
FIRMWARE_SHA256 = (
    "6fe59fb6e3fa2883bc96faa1488f9de56c5ecd5324f2d2c68ec5364b315ed81c"
)
CPE_SNAPSHOT_ID = "20260819T035002Z"
NVD_SNAPSHOT_ID = "20260820T110357Z"

CANDIDATE_COMPONENTS_RELATIVE = (
    "analysis/results/unitronics-ground-truth-candidate-build/"
    f"{DATASET_KEY}/components.csv"
)
CANDIDATE_SUMMARY_RELATIVE = (
    "analysis/results/unitronics-ground-truth-candidate-build/"
    f"{DATASET_KEY}/summary.json"
)
EVIDENCE_MANIFEST_RELATIVE = (
    "analysis/results/unitronics-ground-truth-candidate-build/"
    f"{DATASET_KEY}/evidence_manifest.csv"
)
AUDIT_RESULTS_RELATIVE = (
    "analysis/results/unitronics-ground-truth-cpe-audit/"
    f"{DATASET_KEY}/audit_results.csv"
)
AUDIT_SUMMARY_RELATIVE = (
    "analysis/results/unitronics-ground-truth-cpe-audit/"
    f"{DATASET_KEY}/summary.json"
)
METHODOLOGY_SUMMARY_RELATIVE = (
    "analysis/results/unitronics-ground-truth-methodology-final-audit/"
    f"{DATASET_KEY}/summary.json"
)
APPLICATION_REPORT_RELATIVE = (
    "analysis/results/unitronics-ground-truth-db-application/"
    f"{DATASET_KEY}/application_report.md"
)

EXPECTED_ARTIFACT_HASHES = {
    CANDIDATE_COMPONENTS_RELATIVE: (
        "ba750a4002ef838910d2e1edba20667cc105233644e26069d66b063e1ad18e6b"
    ),
    CANDIDATE_SUMMARY_RELATIVE: (
        "bdebf18b26c555e9073d680145d7507cf9894272956b51ce9300f03e33dc9dd4"
    ),
    EVIDENCE_MANIFEST_RELATIVE: (
        "c8fd1ff5b148e0d9c411ec25d8cf6ebfc5ea50baf770cfcba75783448bfb088b"
    ),
    AUDIT_RESULTS_RELATIVE: (
        "5a0f45ce3a62f6acee94dc55e9fe9573b780e8846e89e78c0034c22c8e871984"
    ),
    AUDIT_SUMMARY_RELATIVE: (
        "bb2740bd621845cfb486f59c6b9545892640110460f69bda0a733b53e46e78fc"
    ),
    METHODOLOGY_SUMMARY_RELATIVE: (
        "cee4b1962343685fd3d782e0f052a4525b5edd6a1ccd50cf793129ff6ee3a840"
    ),
}

EXPECTED_DECISION_COUNTS = {
    GroundTruthDecision.CPE_CONFIRMED: 2,
    GroundTruthDecision.OFFICIAL_CPE_MAPPED: 21,
    GroundTruthDecision.VERSION_NOT_IN_DICTIONARY: 16,
    GroundTruthDecision.NVD_CONFIGURATION_ONLY: 0,
    GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED: 538,
    GroundTruthDecision.UNRESOLVED: 5,
}
DICTIONARY_CPE_DECISIONS = frozenset(
    {
        GroundTruthDecision.CPE_CONFIRMED,
        GroundTruthDecision.OFFICIAL_CPE_MAPPED,
    }
)
NULL_CPE_DECISIONS = frozenset(
    {
        GroundTruthDecision.NVD_CONFIGURATION_ONLY,
        GroundTruthDecision.DIRECT_OFFICIAL_CPE_NOT_CONFIRMED,
        GroundTruthDecision.UNRESOLVED,
    }
)
WPA_CPE = "cpe:2.3:a:w1.fi:wpa_supplicant:2.11:devel:*:*:*:*:*:*"


class UnitronicsGroundTruthApplicationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CandidateRow:
    component_id: int
    name: str
    observed_version: str
    original_cpe: str
    actual_product_version: str
    proposed_gt_cpe: str
    proposed_decision: str
    cpe_resolution_path: str
    decision_reason: str


@dataclass(frozen=True)
class ApplicationPlan:
    rows: tuple[CandidateRow, ...]
    artifact_hashes: dict[str, str]

    @property
    def decision_counts(self) -> dict[str, int]:
        counts = Counter(row.proposed_decision for row in self.rows)
        return {
            decision: counts.get(decision, 0)
            for decision in EXPECTED_DECISION_COUNTS
        }

    @property
    def cpe_present_count(self) -> int:
        return sum(bool(row.proposed_gt_cpe) for row in self.rows)


@dataclass(frozen=True)
class DatabasePreflight:
    component_count: int
    ground_truth_count_before: int
    global_ground_truth_count_before: int
    component_fingerprint: str
    active_cpe_ids: dict[str, int]


@dataclass(frozen=True)
class VerificationResult:
    record_count: int
    decision_counts: dict[str, int]
    cpe_present_count: int
    cpe_null_count: int
    candidate_cpe_mismatch_count: int
    candidate_decision_mismatch_count: int
    canonical_parse_failure_count: int
    deprecated_final_gt_count: int
    discrepancy_assignment_count: int
    correction_assignment_count: int
    component_fingerprint: str
    wpa_actual_product_version: str
    wpa_ground_truth_cpe: str
    wpa_decision: str


def _fail(message: str) -> NoReturn:
    raise UnitronicsGroundTruthApplicationError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(f"Cannot read valid JSON artifact {path}: {error}")
    if not isinstance(value, dict):
        _fail(f"Expected a JSON object in {path}")
    return value


def _read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except OSError as error:
        _fail(f"Cannot read CSV artifact {path}: {error}")


def _validate_artifact_hashes(repository_root: Path) -> dict[str, str]:
    actual: dict[str, str] = {}
    for relative, expected in EXPECTED_ARTIFACT_HASHES.items():
        path = repository_root / relative
        if not path.is_file():
            _fail(f"Required artifact is missing: {relative}")
        actual[relative] = _sha256(path)
        if actual[relative] != expected:
            _fail(
                f"Artifact hash mismatch for {relative}: "
                f"expected {expected}, got {actual[relative]}"
            )
    return actual


def _validate_evidence_manifest(repository_root: Path) -> None:
    manifest_path = repository_root / EVIDENCE_MANIFEST_RELATIVE
    rows = _read_csv(manifest_path)
    evidence_ids = [row["evidence_id"] for row in rows]
    if not rows or len(evidence_ids) != len(set(evidence_ids)):
        _fail("Evidence manifest must contain unique evidence IDs")
    analysis_root = repository_root / "analysis/results"
    local_count = 0
    for row in rows:
        if row["evidence_type"] != "LOCAL_IMMUTABLE_ARTIFACT":
            continue
        local_count += 1
        evidence_path = analysis_root / row["locator"]
        if not evidence_path.is_file():
            _fail(f"Local evidence artifact is missing: {row['locator']}")
        actual_hash = _sha256(evidence_path)
        if actual_hash != row["sha256"]:
            _fail(
                f"Local evidence hash mismatch for {row['locator']}: "
                f"expected {row['sha256']}, got {actual_hash}"
            )
    if local_count != 19:
        _fail(f"Expected 19 local evidence artifacts, found {local_count}")


def _candidate_rows(repository_root: Path) -> tuple[CandidateRow, ...]:
    path = repository_root / CANDIDATE_COMPONENTS_RELATIVE
    raw_rows = _read_csv(path)
    rows: list[CandidateRow] = []
    for index, raw in enumerate(raw_rows, start=2):
        try:
            component_id = int(raw["component_id"])
            rows.append(
                CandidateRow(
                    component_id=component_id,
                    name=raw["name"],
                    observed_version=raw["observed_version"],
                    original_cpe=raw["original_cpe"],
                    actual_product_version=raw["actual_product_version"],
                    proposed_gt_cpe=raw["proposed_gt_cpe"],
                    proposed_decision=raw["proposed_decision"],
                    cpe_resolution_path=raw["cpe_resolution_path"],
                    decision_reason=raw["decision_reason"],
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            _fail(f"Invalid candidate row {index}: {error}")
    return tuple(rows)


def _validate_candidate_partition(rows: tuple[CandidateRow, ...]) -> None:
    if len(rows) != 582:
        _fail(f"Expected 582 candidate rows, found {len(rows)}")
    component_ids = [row.component_id for row in rows]
    if len(component_ids) != len(set(component_ids)):
        _fail("Candidate component IDs are not unique")
    counts = Counter(row.proposed_decision for row in rows)
    actual_counts = {
        decision: counts.get(decision, 0)
        for decision in EXPECTED_DECISION_COUNTS
    }
    unknown = set(counts) - set(EXPECTED_DECISION_COUNTS)
    if actual_counts != EXPECTED_DECISION_COUNTS or unknown:
        _fail(
            "Candidate decision partition mismatch: "
            f"expected {EXPECTED_DECISION_COUNTS}, got {dict(counts)}"
        )
    cpe_present = sum(bool(row.proposed_gt_cpe) for row in rows)
    if cpe_present != 39:
        _fail(f"Expected 39 candidate CPEs, found {cpe_present}")
    for row in rows:
        has_cpe = bool(row.proposed_gt_cpe)
        if row.proposed_decision in (
            DICTIONARY_CPE_DECISIONS
            | {GroundTruthDecision.VERSION_NOT_IN_DICTIONARY}
        ):
            if not has_cpe:
                _fail(
                    f"Component {row.component_id} requires a Ground Truth CPE"
                )
        elif row.proposed_decision in NULL_CPE_DECISIONS and has_cpe:
            _fail(
                f"Component {row.component_id} must not have a Ground Truth CPE"
            )
        if has_cpe:
            try:
                canonical = canonicalize_cpe23(row.proposed_gt_cpe)
            except CPE23CanonicalizationError as error:
                _fail(
                    f"Component {row.component_id} has invalid CPE: {error}"
                )
            if canonical != row.proposed_gt_cpe:
                _fail(
                    f"Component {row.component_id} CPE is not canonical: "
                    f"{row.proposed_gt_cpe}"
                )
        if (
            row.proposed_decision == GroundTruthDecision.CPE_CONFIRMED
            and row.proposed_gt_cpe != row.original_cpe
        ):
            _fail(
                f"CPE_CONFIRMED component {row.component_id} does not preserve "
                "the Original CPE"
            )
        if (
            row.proposed_decision == GroundTruthDecision.OFFICIAL_CPE_MAPPED
            and row.proposed_gt_cpe == row.original_cpe
        ):
            _fail(
                f"OFFICIAL_CPE_MAPPED component {row.component_id} did not "
                "change the Original CPE"
            )


def _validate_candidate_summary(repository_root: Path) -> None:
    summary = _load_json(repository_root / CANDIDATE_SUMMARY_RELATIVE)
    dataset = summary.get("dataset", {})
    snapshots = summary.get("snapshots", {})
    validation = summary.get("validation", {})
    expected_dataset_fields = {
        "component_count": 582,
        "firmware_sha256": FIRMWARE_SHA256,
        "firmware_version": "52.07.13.7",
        "manufacturer": "Unitronics",
        "product": "UCR-ST-B8",
        "sbom_document_id": SBOM_DOCUMENT_ID,
        "sbom_sha256": SBOM_SHA256,
    }
    if any(
        dataset.get(key) != value
        for key, value in expected_dataset_fields.items()
    ):
        _fail("Candidate summary dataset identity does not match the fixed target")
    decision_counts = summary.get("decisions", {}).get("counts")
    expected_counts = {
        str(key): value for key, value in EXPECTED_DECISION_COUNTS.items()
    }
    if decision_counts != expected_counts:
        _fail("Candidate summary decision partition does not match 582 rows")
    if snapshots.get("cpe_dictionary", {}).get("snapshot_id") != CPE_SNAPSHOT_ID:
        _fail("Candidate summary CPE snapshot does not match the fixed snapshot")
    if snapshots.get("nvd_cve", {}).get("snapshot_id") != NVD_SNAPSHOT_ID:
        _fail("Candidate summary NVD snapshot does not match the fixed snapshot")
    required_validation = {
        "component_rows_equal_582": True,
        "decision_partition": 582,
        "deprecated_final_gt_count": 0,
        "every_component_has_decision": True,
        "every_component_has_valid_decision": True,
        "proposed_gt_count": 39,
        "proposed_gt_parser_failure_count": 0,
    }
    if any(validation.get(key) != value for key, value in required_validation.items()):
        _fail("Candidate summary validation flags are not finalization-safe")


def _validate_audit(
    repository_root: Path,
    candidates: tuple[CandidateRow, ...],
) -> None:
    summary = _load_json(repository_root / AUDIT_SUMMARY_RELATIVE)
    status_counts = summary.get("final_audit_status", {}).get("counts")
    if status_counts != {
        "ACCEPTED": 39,
        "CORRECTION_REQUIRED": 0,
        "EVIDENCE_REVIEW_REQUIRED": 0,
    }:
        _fail("Independent CPE audit is not 39 ACCEPTED / 0 corrections")
    if summary.get("cpe_resolution", {}).get("final_deprecated_gt_count") != 0:
        _fail("Independent CPE audit contains a deprecated final CPE")
    audit_rows = _read_csv(repository_root / AUDIT_RESULTS_RELATIVE)
    if len(audit_rows) != 39:
        _fail(f"Expected 39 independent audit rows, found {len(audit_rows)}")
    audit_by_id = {int(row["component_id"]): row for row in audit_rows}
    if len(audit_by_id) != 39:
        _fail("Independent audit component IDs are not unique")
    candidates_with_cpe = {
        row.component_id: row for row in candidates if row.proposed_gt_cpe
    }
    if set(audit_by_id) != set(candidates_with_cpe):
        _fail("Independent audit scope differs from the 39 CPE-bearing candidates")
    for component_id, candidate in candidates_with_cpe.items():
        audit = audit_by_id[component_id]
        if audit["final_audit_status"] != "ACCEPTED":
            _fail(f"Component {component_id} is not ACCEPTED by the audit")
        if (
            audit["audited_gt_cpe"] != candidate.proposed_gt_cpe
            or audit["current_gt_cpe"] != candidate.proposed_gt_cpe
        ):
            _fail(f"Audit CPE mismatch for component {component_id}")
        if (
            audit["audited_validation_result"]
            != candidate.proposed_decision
            or audit["current_validation_result"]
            != candidate.proposed_decision
        ):
            _fail(f"Audit decision mismatch for component {component_id}")
        if audit["final_gt_is_deprecated"].lower() != "false":
            _fail(f"Audit retained a deprecated CPE for component {component_id}")


def _validate_methodology(repository_root: Path) -> None:
    summary = _load_json(repository_root / METHODOLOGY_SUMMARY_RELATIVE)
    if summary.get("verdict") != "READY_FOR_FINALIZATION":
        _fail("Methodology verdict is not READY_FOR_FINALIZATION")
    if summary.get("ground_truth_db_application_readiness") != "READY":
        _fail("Methodology DB application readiness is not READY")
    if summary.get("blocking_issue_count") != 0:
        _fail("Methodology final audit has blocking issues")
    if summary.get("dataset", {}).get("sbom_document_id") != SBOM_DOCUMENT_ID:
        _fail("Methodology final audit targets a different SBOMDocument")
    if summary.get("snapshots") != {
        "cpe_dictionary": CPE_SNAPSHOT_ID,
        "nvd_cve_configuration": NVD_SNAPSHOT_ID,
    }:
        _fail("Methodology final audit snapshot identity mismatch")
    invariance = summary.get("artifact_invariance", {})
    # This artifact documents the earlier 48-row methodology checkpoint. Its
    # recorded hashes remain historical and must not be rewritten after the
    # separately approved representative-policy finalization.
    expected_pairs = {
        "candidate_components_sha256_after": (
            "bf83592d1fd92c2f972a4f178f8ca01fd33cf0944d044e24aeda8b8b438c8ac9"
        ),
        "candidate_summary_sha256_after": (
            "c20ddefa98afe53b423cc1c5846ce8e2471bd3f1f41c3021ff1bee2792275a0a"
        ),
        "audit_results_sha256_after": (
            "cc75c750042489183f25c67bea379dbf3556c14c296ce91142d1c9e5d5960593"
        ),
        "audit_summary_sha256_after": (
            "50d5f37c63d545f97355bd7436106174e5386fccdd76c7a2889a86b8711d68f1"
        ),
        "existing_analysis_artifacts_unchanged": True,
    }
    if any(invariance.get(key) != value for key, value in expected_pairs.items()):
        _fail("Methodology final audit artifact invariance check failed")


def _validate_wpa(
    repository_root: Path,
    candidates: tuple[CandidateRow, ...],
) -> None:
    matches = [row for row in candidates if row.name == "wpa_supplicant"]
    if len(matches) != 1:
        _fail(f"Expected one wpa_supplicant candidate, found {len(matches)}")
    candidate = matches[0]
    if (
        candidate.actual_product_version != "2.11-devel"
        or candidate.proposed_gt_cpe != WPA_CPE
        or candidate.proposed_decision
        != GroundTruthDecision.VERSION_NOT_IN_DICTIONARY
    ):
        _fail("wpa_supplicant candidate does not contain the approved final values")
    audit_rows = _read_csv(repository_root / AUDIT_RESULTS_RELATIVE)
    audit = next(
        (row for row in audit_rows if row["name"] == "wpa_supplicant"),
        None,
    )
    if audit is None or (
        audit["observed_version"] != "2.11-devel"
        or audit["audited_product_version"] != "2.11-devel"
        or audit["audited_gt_cpe"] != WPA_CPE
        or audit["audited_validation_result"]
        != GroundTruthDecision.VERSION_NOT_IN_DICTIONARY
        or audit["final_audit_status"] != "ACCEPTED"
    ):
        _fail("wpa_supplicant independent audit values are not final")


def load_application_plan(
    repository_root: Path | None = None,
) -> ApplicationPlan:
    root = repository_root or settings.REPOSITORY_ROOT
    artifact_hashes = _validate_artifact_hashes(root)
    _validate_evidence_manifest(root)
    rows = _candidate_rows(root)
    _validate_candidate_partition(rows)
    _validate_candidate_summary(root)
    _validate_audit(root, rows)
    _validate_methodology(root)
    _validate_wpa(root, rows)
    return ApplicationPlan(rows=rows, artifact_hashes=artifact_hashes)


def _component_fingerprint(components: list[Component]) -> str:
    values = [
        {
            "id": component.id,
            "sbom_document_id": component.sbom_document_id,
            "bom_ref": component.bom_ref,
            "component_type": component.component_type,
            "group": component.group,
            "name": component.name,
            "version": component.version,
            "publisher": component.publisher,
            "purl": component.purl,
            "cpe": component.cpe,
            "properties": component.properties,
        }
        for component in sorted(components, key=lambda item: item.id)
    ]
    serialized = json.dumps(
        values,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _validate_snapshot_metadata(
    cpe_snapshot: CpeDictionarySnapshot,
    nvd_snapshot: NvdCveSnapshot,
) -> None:
    cpe_expected = {
        "status": CpeDictionarySnapshot.Status.COMPLETE,
        "manifest_sha256": (
            "d0353e020f67a19070ebf297615cba0a91b636f3f89bd580f73fd786719fddce"
        ),
        "content_sha256": (
            "9035416631831f5f50d3c723d813370532e7ceee0c5a93c8473897d5a97bfd7a"
        ),
        "record_count": 1811261,
        "active_count": 1711630,
        "deprecated_count": 99631,
    }
    nvd_expected = {
        "status": NvdCveSnapshot.Status.COMPLETE,
        "manifest_sha256": (
            "80b6107f5225923794d725b252527f575ad2b0c800765fc5ce6d0b07c18d94eb"
        ),
        "content_sha256": (
            "a8a1b6ca66a0383272a3ca035559229b1fc59535f029828b984a3998234c6eab"
        ),
        "record_count": 380865,
        "configuration_count": 760120,
        "cpe_match_count": 3170148,
    }
    if any(getattr(cpe_snapshot, key) != value for key, value in cpe_expected.items()):
        _fail("CPE Dictionary snapshot metadata does not match the fixed snapshot")
    if any(getattr(nvd_snapshot, key) != value for key, value in nvd_expected.items()):
        _fail("NVD snapshot metadata does not match the fixed snapshot")


def database_preflight(
    plan: ApplicationPlan,
    *,
    lock_sbom: bool = False,
) -> DatabasePreflight:
    sbom_queryset = SBOMDocument.objects
    if lock_sbom:
        sbom_queryset = sbom_queryset.select_for_update()
    try:
        sbom = sbom_queryset.get(pk=SBOM_DOCUMENT_ID)
        cpe_snapshot = CpeDictionarySnapshot.objects.get(
            snapshot_id=CPE_SNAPSHOT_ID
        )
        nvd_snapshot = NvdCveSnapshot.objects.get(snapshot_id=NVD_SNAPSHOT_ID)
    except (
        SBOMDocument.DoesNotExist,
        CpeDictionarySnapshot.DoesNotExist,
        NvdCveSnapshot.DoesNotExist,
    ) as error:
        _fail(f"Fixed DB target is missing: {error}")
    if (
        sbom.manufacturer != "Unitronics"
        or sbom.product_name != "UCR-ST-B8"
        or sbom.product_version != "52.07.13.7"
        or sbom.file_sha256 != SBOM_SHA256
    ):
        _fail("SBOMDocument 1364 identity does not match the fixed dataset")
    _validate_snapshot_metadata(cpe_snapshot, nvd_snapshot)

    components = list(
        Component.objects.filter(sbom_document=sbom).order_by("id")
    )
    if len(components) != len(plan.rows):
        _fail(
            f"SBOMDocument 1364 has {len(components)} components, "
            f"expected {len(plan.rows)}"
        )
    component_by_id = {component.id: component for component in components}
    candidate_by_id = {row.component_id: row for row in plan.rows}
    if set(component_by_id) != set(candidate_by_id):
        missing = sorted(set(candidate_by_id) - set(component_by_id))
        extra = sorted(set(component_by_id) - set(candidate_by_id))
        _fail(
            "Candidate/DB component ID mismatch: "
            f"missing={missing[:10]}, extra={extra[:10]}"
        )
    for component_id, candidate in candidate_by_id.items():
        component = component_by_id[component_id]
        if (
            component.name != candidate.name
            or component.version != candidate.observed_version
            or component.cpe != candidate.original_cpe
        ):
            _fail(
                f"Candidate/DB original component mismatch for {component_id}"
            )

    target_ground_truths = ComponentCpeGroundTruth.objects.filter(
        component__sbom_document=sbom
    )
    ground_truth_count_before = target_ground_truths.count()
    if ground_truth_count_before:
        _fail(
            "SBOMDocument 1364 already has Ground Truth records; "
            f"refusing to overwrite {ground_truth_count_before} records"
        )

    dictionary_values = {
        row.proposed_gt_cpe
        for row in plan.rows
        if row.proposed_decision in DICTIONARY_CPE_DECISIONS
    }
    dictionary_rows = list(
        CpeName.objects.filter(
            snapshot=cpe_snapshot,
            cpe_name__in=dictionary_values,
        )
    )
    if len(dictionary_rows) != len(dictionary_values):
        found = {row.cpe_name for row in dictionary_rows}
        _fail(
            "Active Dictionary CPE lookup is incomplete: "
            f"missing={sorted(dictionary_values - found)}"
        )
    deprecated_values = sorted(
        row.cpe_name for row in dictionary_rows if row.deprecated
    )
    if deprecated_values:
        _fail(f"Final Dictionary Ground Truth contains Deprecated CPEs: {deprecated_values}")

    version_expressions = {
        row.proposed_gt_cpe
        for row in plan.rows
        if row.proposed_decision == GroundTruthDecision.VERSION_NOT_IN_DICTIONARY
    }
    registered_versions = list(
        CpeName.objects.filter(
            snapshot=cpe_snapshot,
            cpe_name__in=version_expressions,
        ).values_list("cpe_name", flat=True)
    )
    if registered_versions:
        _fail(
            "VERSION_NOT_IN_DICTIONARY expressions unexpectedly exist in the "
            f"fixed Dictionary snapshot: {sorted(registered_versions)}"
        )
    return DatabasePreflight(
        component_count=len(components),
        ground_truth_count_before=ground_truth_count_before,
        global_ground_truth_count_before=ComponentCpeGroundTruth.objects.count(),
        component_fingerprint=_component_fingerprint(components),
        active_cpe_ids={row.cpe_name: row.id for row in dictionary_rows},
    )


def _provenance_note(component_id: int) -> str:
    candidate_hash = EXPECTED_ARTIFACT_HASHES[CANDIDATE_COMPONENTS_RELATIVE]
    return (
        "Verified Unitronics Ground Truth candidate; "
        f"artifact={CANDIDATE_COMPONENTS_RELATIVE}; "
        f"sha256={candidate_hash}; candidate_component_id={component_id}"
    )


def verify_database_application(
    plan: ApplicationPlan,
    *,
    expected_component_fingerprint: str,
) -> VerificationResult:
    records = list(
        ComponentCpeGroundTruth.objects.filter(
            component__sbom_document_id=SBOM_DOCUMENT_ID,
            snapshot__snapshot_id=CPE_SNAPSHOT_ID,
        )
        .select_related("component", "ground_truth_cpe")
        .prefetch_related("discrepancy_types", "correction_types")
        .order_by("component_id")
    )
    candidate_by_id = {row.component_id: row for row in plan.rows}
    record_by_id = {record.component_id: record for record in records}
    if set(record_by_id) != set(candidate_by_id):
        _fail("Post-write Ground Truth component partition does not match candidates")

    decision_counts = Counter(record.decision for record in records)
    normalized_counts = {
        decision: decision_counts.get(decision, 0)
        for decision in EXPECTED_DECISION_COUNTS
    }
    candidate_cpe_mismatch_count = 0
    candidate_decision_mismatch_count = 0
    parse_failure_count = 0
    deprecated_count = 0
    present_count = 0
    discrepancy_assignment_count = 0
    correction_assignment_count = 0
    for component_id, candidate in candidate_by_id.items():
        record = record_by_id[component_id]
        effective_cpe = (
            record.ground_truth_cpe.cpe_name
            if record.ground_truth_cpe is not None
            else record.manual_ground_truth_cpe
        )
        if effective_cpe:
            present_count += 1
            try:
                if canonicalize_cpe23(effective_cpe) != effective_cpe:
                    parse_failure_count += 1
            except CPE23CanonicalizationError:
                parse_failure_count += 1
        if record.ground_truth_cpe is not None and record.ground_truth_cpe.deprecated:
            deprecated_count += 1
        if effective_cpe != candidate.proposed_gt_cpe:
            candidate_cpe_mismatch_count += 1
        if record.decision != candidate.proposed_decision:
            candidate_decision_mismatch_count += 1
        discrepancy_assignment_count += record.discrepancy_types.count()
        correction_assignment_count += record.correction_types.count()

    components = list(
        Component.objects.filter(sbom_document_id=SBOM_DOCUMENT_ID).order_by("id")
    )
    component_fingerprint = _component_fingerprint(components)
    wpa_candidate = next(row for row in plan.rows if row.name == "wpa_supplicant")
    wpa_record = record_by_id[wpa_candidate.component_id]
    wpa_cpe = (
        wpa_record.ground_truth_cpe.cpe_name
        if wpa_record.ground_truth_cpe is not None
        else wpa_record.manual_ground_truth_cpe
    )
    result = VerificationResult(
        record_count=len(records),
        decision_counts=normalized_counts,
        cpe_present_count=present_count,
        cpe_null_count=len(records) - present_count,
        candidate_cpe_mismatch_count=candidate_cpe_mismatch_count,
        candidate_decision_mismatch_count=candidate_decision_mismatch_count,
        canonical_parse_failure_count=parse_failure_count,
        deprecated_final_gt_count=deprecated_count,
        discrepancy_assignment_count=discrepancy_assignment_count,
        correction_assignment_count=correction_assignment_count,
        component_fingerprint=component_fingerprint,
        wpa_actual_product_version=wpa_candidate.actual_product_version,
        wpa_ground_truth_cpe=wpa_cpe,
        wpa_decision=wpa_record.decision,
    )
    expected = {
        "record_count": len(plan.rows),
        "decision_counts": plan.decision_counts,
        "cpe_present_count": plan.cpe_present_count,
        "cpe_null_count": len(plan.rows) - plan.cpe_present_count,
        "candidate_cpe_mismatch_count": 0,
        "candidate_decision_mismatch_count": 0,
        "canonical_parse_failure_count": 0,
        "deprecated_final_gt_count": 0,
        "discrepancy_assignment_count": 0,
        "correction_assignment_count": 0,
        "component_fingerprint": expected_component_fingerprint,
        "wpa_actual_product_version": "2.11-devel",
        "wpa_ground_truth_cpe": WPA_CPE,
        "wpa_decision": GroundTruthDecision.VERSION_NOT_IN_DICTIONARY,
    }
    for field, value in expected.items():
        if getattr(result, field) != value:
            _fail(
                f"Post-write verification failed for {field}: "
                f"expected {value}, got {getattr(result, field)}"
            )
    null_decisions_with_cpe = sum(
        1
        for record in records
        if record.decision in NULL_CPE_DECISIONS
        and (record.ground_truth_cpe_id or record.manual_ground_truth_cpe)
    )
    if null_decisions_with_cpe:
        _fail(
            f"Found {null_decisions_with_cpe} null-CPE decisions with a CPE value"
        )
    return result


def apply_application_plan(
    plan: ApplicationPlan,
) -> tuple[DatabasePreflight, VerificationResult]:
    try:
        with transaction.atomic():
            preflight = database_preflight(plan, lock_sbom=True)
            rows_by_id = {
                row.id: row
                for row in CpeName.objects.filter(
                    id__in=preflight.active_cpe_ids.values()
                )
            }
            snapshot_pk = CpeDictionarySnapshot.objects.only("id").get(
                snapshot_id=CPE_SNAPSHOT_ID
            ).id
            for candidate in sorted(plan.rows, key=lambda row: row.component_id):
                dictionary_cpe = None
                manual_cpe = ""
                if candidate.proposed_decision in DICTIONARY_CPE_DECISIONS:
                    dictionary_cpe = rows_by_id[
                        preflight.active_cpe_ids[candidate.proposed_gt_cpe]
                    ]
                elif (
                    candidate.proposed_decision
                    == GroundTruthDecision.VERSION_NOT_IN_DICTIONARY
                ):
                    manual_cpe = candidate.proposed_gt_cpe
                record = ComponentCpeGroundTruth(
                    component_id=candidate.component_id,
                    snapshot_id=snapshot_pk,
                    ground_truth_cpe=dictionary_cpe,
                    manual_ground_truth_cpe=manual_cpe,
                    decision=candidate.proposed_decision,
                    note=_provenance_note(candidate.component_id),
                )
                record.save()
            result = verify_database_application(
                plan,
                expected_component_fingerprint=preflight.component_fingerprint,
            )
    except ValidationError as error:
        _fail(f"Ground Truth model validation failed; transaction rolled back: {error}")

    committed_result = verify_database_application(
        plan,
        expected_component_fingerprint=preflight.component_fingerprint,
    )
    return preflight, committed_result


def default_application_report_path() -> Path:
    return settings.REPOSITORY_ROOT / APPLICATION_REPORT_RELATIVE


def write_application_report(
    plan: ApplicationPlan,
    preflight: DatabasePreflight,
    result: VerificationResult,
    output_path: Path,
) -> Path:
    if output_path.exists():
        _fail(f"Refusing to overwrite existing application report: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    counts = "\n".join(
        f"| `{decision}` | {result.decision_counts[decision]} |"
        for decision in EXPECTED_DECISION_COUNTS
    )
    hashes = "\n".join(
        f"- `{relative}`: `{digest}`"
        for relative, digest in plan.artifact_hashes.items()
    )
    content = f"""# Unitronics Ground Truth DB Application Report

## Application identity

- Applied at: `{timezone.now().isoformat()}`
- SBOMDocument: `{SBOM_DOCUMENT_ID}`
- Manufacturer/Product/Firmware: `Unitronics / UCR-ST-B8 / 52.07.13.7`
- Firmware SHA-256: `{FIRMWARE_SHA256}`
- SBOM SHA-256: `{SBOM_SHA256}`
- CPE Dictionary snapshot: `{CPE_SNAPSHOT_ID}`
- NVD snapshot: `{NVD_SNAPSHOT_ID}`

## Verified source artifacts

{hashes}

## Preflight

- Components: `{preflight.component_count}`
- Target Ground Truth records before apply: `{preflight.ground_truth_count_before}`
- Global Ground Truth records before apply: `{preflight.global_ground_truth_count_before}`
- Original Component fingerprint: `{preflight.component_fingerprint}`
- Candidate rows and unique Component IDs: `582 / 582`
- Independent CPE audit: `39 ACCEPTED / 0 CORRECTION_REQUIRED / 0 EVIDENCE_REVIEW_REQUIRED`
- Methodology verdict/readiness/blockers: `READY_FOR_FINALIZATION / READY / 0`

## Applied CPE Validation Results

| Internal code | DB count |
|---|---:|
{counts}

## Post-write verification

- Ground Truth records: `{result.record_count}`
- GT CPE present/null: `{result.cpe_present_count} / {result.cpe_null_count}`
- Candidate-to-DB CPE mismatch: `{result.candidate_cpe_mismatch_count}`
- Candidate-to-DB result mismatch: `{result.candidate_decision_mismatch_count}`
- Canonical parse failures: `{result.canonical_parse_failure_count}`
- Deprecated final GT CPEs: `{result.deprecated_final_gt_count}`
- Discrepancy Type assignments: `{result.discrepancy_assignment_count}`
- Correction Type assignments: `{result.correction_assignment_count}`
- Post-write Component fingerprint: `{result.component_fingerprint}`
- Original Component mutation: `0`

## wpa_supplicant

- Actual candidate version: `{result.wpa_actual_product_version}`
- Ground Truth CPE: `{result.wpa_ground_truth_cpe}`
- CPE Validation Result: `{result.wpa_decision}`

## Safety and final status

- Application used `transaction.atomic()` and an SBOM row lock.
- Any in-transaction validation failure rolls back all Ground Truth inserts.
- Existing Ground Truth records are never overwritten, updated, or deleted.
- Incorrect CPE Fields and Correction Types were intentionally left empty.
- Original Components and fixed snapshot data were not modified.
- Final status: `SUCCESS`
"""
    try:
        with output_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    except OSError as error:
        _fail(f"Could not write application report {output_path}: {error}")
    return output_path

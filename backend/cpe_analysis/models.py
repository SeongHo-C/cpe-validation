from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from sboms.models import Component


class CPEAnalysisRunStatus(models.TextChoices):
    RUNNING = "RUNNING", "Running"
    COMPLETED = "COMPLETED", "Completed"
    FAILED = "FAILED", "Failed"


class CPEAnalysisOutcome(models.TextChoices):
    UNIQUE_CORRECT = "UNIQUE_CORRECT", "Unique correct"
    CORRECT_BUT_AMBIGUOUS = (
        "CORRECT_BUT_AMBIGUOUS",
        "Correct but ambiguous",
    )
    NOT_TOP_GROUP = "NOT_TOP_GROUP", "Not top group"


class CPEAnalysisRun(models.Model):
    algorithm_id = models.CharField(max_length=64)
    status = models.CharField(
        max_length=16,
        choices=CPEAnalysisRunStatus.choices,
    )
    parameters = models.JSONField(default=dict, blank=True)
    query_count = models.PositiveIntegerField()
    candidate_family_count = models.PositiveIntegerField()
    top1_accuracy = models.FloatField(null=True, blank=True)
    recall_at_5 = models.FloatField(null=True, blank=True)
    recall_at_10 = models.FloatField(null=True, blank=True)
    mrr = models.FloatField(null=True, blank=True)
    unique_correct_count = models.PositiveIntegerField(
        null=True,
        blank=True,
    )
    ambiguous_count = models.PositiveIntegerField(
        null=True,
        blank=True,
    )
    not_top_group_count = models.PositiveIntegerField(
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at", "-id")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    status__in=CPEAnalysisRunStatus.values,
                ),
                name="cpe_analysis_run_status_valid",
            ),
        ]
        indexes = [
            models.Index(
                fields=["algorithm_id", "status", "-created_at"],
                name="cpe_run_alg_status_idx",
            ),
        ]

    def clean(self) -> None:
        super().clean()
        if not isinstance(self.parameters, dict):
            raise ValidationError(
                {"parameters": "Parameters must be a JSON object."}
            )

    def __str__(self) -> str:
        return f"{self.algorithm_id} ({self.status})"


class CPEAnalysisQueryResult(models.Model):
    run = models.ForeignKey(
        CPEAnalysisRun,
        on_delete=models.CASCADE,
        related_name="query_results",
    )
    component = models.ForeignKey(
        Component,
        on_delete=models.CASCADE,
        related_name="cpe_analysis_results",
    )
    target_score = models.FloatField()
    better_count = models.PositiveIntegerField()
    tie_size = models.PositiveIntegerField()
    best_rank = models.PositiveIntegerField()
    worst_rank = models.PositiveIntegerField()
    outcome = models.CharField(
        max_length=32,
        choices=CPEAnalysisOutcome.choices,
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["run", "component"],
                name="unique_cpe_run_component",
            ),
            models.CheckConstraint(
                condition=models.Q(tie_size__gte=1),
                name="cpe_result_tie_size_gte_1",
            ),
            models.CheckConstraint(
                condition=models.Q(best_rank__gte=1),
                name="cpe_result_best_rank_gte_1",
            ),
            models.CheckConstraint(
                condition=models.Q(worst_rank__gte=1),
                name="cpe_result_worst_rank_gte_1",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    best_rank__lte=models.F("worst_rank"),
                ),
                name="cpe_result_rank_order_valid",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        outcome=CPEAnalysisOutcome.UNIQUE_CORRECT,
                        best_rank=1,
                        worst_rank=1,
                    )
                    | models.Q(
                        outcome=(
                            CPEAnalysisOutcome.CORRECT_BUT_AMBIGUOUS
                        ),
                        best_rank=1,
                        worst_rank__gt=1,
                    )
                    | models.Q(
                        outcome=CPEAnalysisOutcome.NOT_TOP_GROUP,
                        best_rank__gt=1,
                    )
                ),
                name="cpe_result_outcome_consistent",
            ),
        ]

    @property
    def top_group_hit(self) -> bool:
        return self.best_rank == 1

    @property
    def top1_success(self) -> bool:
        return self.worst_rank == 1

    @property
    def recall_at_5_success(self) -> bool:
        return self.worst_rank <= 5

    @property
    def recall_at_10_success(self) -> bool:
        return self.worst_rank <= 10

    @property
    def reciprocal_rank(self) -> float:
        return 1 / self.worst_rank

    def clean(self) -> None:
        super().clean()
        if self.best_rank is None or self.worst_rank is None:
            return

        errors: dict[str, str] = {}
        if self.best_rank > self.worst_rank:
            errors["worst_rank"] = (
                "Worst rank must be greater than or equal to best rank."
            )
        if self.outcome == CPEAnalysisOutcome.UNIQUE_CORRECT and not (
            self.best_rank == 1 and self.worst_rank == 1
        ):
            errors["outcome"] = (
                "UNIQUE_CORRECT requires best_rank=1 and worst_rank=1."
            )
        elif (
            self.outcome == CPEAnalysisOutcome.CORRECT_BUT_AMBIGUOUS
            and not (self.best_rank == 1 and self.worst_rank > 1)
        ):
            errors["outcome"] = (
                "CORRECT_BUT_AMBIGUOUS requires best_rank=1 and "
                "worst_rank>1."
            )
        elif (
            self.outcome == CPEAnalysisOutcome.NOT_TOP_GROUP
            and self.best_rank <= 1
        ):
            errors["outcome"] = "NOT_TOP_GROUP requires best_rank>1."
        if errors:
            raise ValidationError(errors)

    def __str__(self) -> str:
        return (
            f"{self.run.algorithm_id}: component {self.component_id} "
            f"({self.outcome})"
        )

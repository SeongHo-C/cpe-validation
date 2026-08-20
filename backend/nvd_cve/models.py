from django.db import models


class NvdCveSnapshot(models.Model):
    class Status(models.TextChoices):
        IMPORTING = "IMPORTING", "Importing"
        COMPLETE = "COMPLETE", "Complete"

    snapshot_id = models.CharField(max_length=32, unique=True)
    status = models.CharField(max_length=16, choices=Status.choices)
    manifest_sha256 = models.CharField(max_length=64)
    content_sha256 = models.CharField(max_length=64)
    feed_count = models.PositiveIntegerField()
    record_count = models.BigIntegerField()
    configuration_count = models.BigIntegerField()
    cpe_match_count = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.snapshot_id} ({self.status})"


class NvdCveRecord(models.Model):
    snapshot = models.ForeignKey(
        NvdCveSnapshot,
        on_delete=models.PROTECT,
        related_name="cve_records",
    )
    cve_id = models.CharField(max_length=32)
    published_at_nvd = models.DateTimeField()
    last_modified_at_nvd = models.DateTimeField()
    vuln_status = models.TextField()
    configurations = models.JSONField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["snapshot", "cve_id"],
                name="unique_nvd_cve_per_snapshot",
            ),
        ]

    def __str__(self) -> str:
        return self.cve_id


class NvdCpeMatch(models.Model):
    cve_record = models.ForeignKey(
        NvdCveRecord,
        on_delete=models.CASCADE,
        related_name="cpe_matches",
    )
    configuration_index = models.PositiveIntegerField()
    node_index = models.PositiveIntegerField()
    match_index = models.PositiveIntegerField()

    configuration_operator = models.TextField(null=True)
    configuration_negate = models.BooleanField(null=True)
    node_operator = models.TextField(null=True)
    node_negate = models.BooleanField(null=True)

    vulnerable = models.BooleanField()
    criteria = models.TextField()
    match_criteria_id = models.UUIDField()
    version_start_including = models.TextField(null=True)
    version_start_excluding = models.TextField(null=True)
    version_end_including = models.TextField(null=True)
    version_end_excluding = models.TextField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "cve_record",
                    "configuration_index",
                    "node_index",
                    "match_index",
                ],
                name="unique_nvd_cpe_match_position",
            ),
        ]
        indexes = [
            models.Index(
                fields=["criteria"],
                name="nvd_match_criteria_idx",
            ),
            models.Index(
                fields=["match_criteria_id"],
                name="nvd_match_id_idx",
            ),
            models.Index(
                fields=["vulnerable"],
                name="nvd_match_vuln_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.cve_record.cve_id}: {self.criteria}"

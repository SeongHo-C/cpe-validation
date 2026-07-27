from django.db import models


class CpeDictionarySnapshot(models.Model):
    class Status(models.TextChoices):
        IMPORTING = "IMPORTING", "Importing"
        COMPLETE = "COMPLETE", "Complete"

    snapshot_id = models.CharField(max_length=32, unique=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
    )
    feed_last_modified = models.DateTimeField()
    manifest_sha256 = models.CharField(max_length=64)
    archive_sha256 = models.CharField(max_length=64)
    content_sha256 = models.CharField(max_length=64)
    member_count = models.PositiveIntegerField()
    expected_record_count = models.BigIntegerField()
    record_count = models.BigIntegerField()
    active_count = models.BigIntegerField()
    deprecated_count = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.snapshot_id} ({self.status})"


class CpeName(models.Model):
    snapshot = models.ForeignKey(
        CpeDictionarySnapshot,
        on_delete=models.PROTECT,
        related_name="cpe_names",
    )
    cpe_name_id = models.UUIDField()
    cpe_name = models.TextField()
    deprecated = models.BooleanField()
    created_at_nvd = models.DateTimeField()
    last_modified_at_nvd = models.DateTimeField()

    part = models.TextField()
    vendor = models.TextField()
    product = models.TextField()
    version = models.TextField()
    update = models.TextField()
    edition = models.TextField()
    language = models.TextField()
    sw_edition = models.TextField()
    target_sw = models.TextField()
    target_hw = models.TextField()
    other = models.TextField()

    titles = models.JSONField(default=list)
    references = models.JSONField(default=list)
    deprecated_by = models.JSONField(default=list)
    deprecates = models.JSONField(default=list)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["snapshot", "cpe_name_id"],
                name="unique_cpe_id_per_snapshot",
            ),
            models.UniqueConstraint(
                fields=["snapshot", "cpe_name"],
                name="unique_cpe_name_per_snapshot",
            ),
        ]
        indexes = [
            models.Index(
                fields=["snapshot", "deprecated"],
                name="cpe_snap_deprecated_idx",
            ),
        ]

    def __str__(self) -> str:
        return self.cpe_name

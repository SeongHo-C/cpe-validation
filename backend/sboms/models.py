from django.core.exceptions import ValidationError
from django.db import models

from cpe_dictionary.models import CpeDictionarySnapshot, CpeName


class DockerImage(models.Model):
    repository = models.CharField(max_length=255)
    tag = models.CharField(max_length=128)
    platform = models.CharField(
        max_length=64,
        default="linux/amd64",
    )
    manifest_digest = models.CharField(
        max_length=71,
        unique=True,
    )
    pinned_reference = models.CharField(
        max_length=512,
        unique=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["repository", "tag"]

    def __str__(self) -> str:
        return f"{self.repository}:{self.tag} ({self.platform})"


class SBOMDocument(models.Model):
    class Format(models.TextChoices):
        CYCLONEDX_JSON = "CYCLONEDX_JSON", "CycloneDX JSON"

    docker_image = models.ForeignKey(
        DockerImage,
        on_delete=models.PROTECT,
        related_name="sbom_documents",
    )
    source_path = models.CharField(max_length=512)
    file_sha256 = models.CharField(
        max_length=64,
        unique=True,
    )
    format = models.CharField(
        max_length=32,
        choices=Format.choices,
        default=Format.CYCLONEDX_JSON,
    )
    spec_version = models.CharField(max_length=32)
    serial_number = models.CharField(
        max_length=255,
        blank=True,
    )
    document_version = models.PositiveIntegerField(default=1)
    generator_name = models.CharField(max_length=128)
    generator_version = models.CharField(max_length=64)
    source_type = models.CharField(
        max_length=32,
        default="registry",
    )
    scope = models.CharField(
        max_length=32,
        default="squashed",
    )
    generated_at = models.DateTimeField(
        null=True,
        blank=True,
    )
    imported_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = [
            "docker_image__repository",
            "docker_image__tag",
        ]
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "docker_image",
                    "generator_name",
                    "generator_version",
                    "format",
                    "file_sha256",
                ],
                name="unique_sbom_document_import",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"{self.docker_image.repository}:"
            f"{self.docker_image.tag} - "
            f"{self.generator_name} {self.generator_version}"
        )


class Component(models.Model):
    sbom_document = models.ForeignKey(
        SBOMDocument,
        on_delete=models.CASCADE,
        related_name="components",
    )
    bom_ref = models.CharField(max_length=1024)
    component_type = models.CharField(max_length=64)
    group = models.CharField(
        max_length=255,
        blank=True,
    )
    name = models.CharField(max_length=255)
    version = models.CharField(
        max_length=255,
        blank=True,
    )
    publisher = models.CharField(
        max_length=255,
        blank=True,
    )
    purl = models.TextField(blank=True)
    cpe = models.TextField(blank=True)
    properties = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name", "version"]
        constraints = [
            models.UniqueConstraint(
                fields=["sbom_document", "bom_ref"],
                name="unique_component_bom_ref_per_sbom",
            ),
        ]
        indexes = [
            models.Index(
                fields=["sbom_document", "name"],
                name="component_sbom_name_idx",
            ),
        ]

    def __str__(self) -> str:
        if self.version:
            return f"{self.name} {self.version}"
        return self.name


class ComponentCpeGroundTruth(models.Model):
    component = models.ForeignKey(
        Component,
        on_delete=models.PROTECT,
        related_name="cpe_ground_truths",
    )
    snapshot = models.ForeignKey(
        CpeDictionarySnapshot,
        on_delete=models.PROTECT,
        related_name="component_ground_truths",
    )
    ground_truth_cpe = models.ForeignKey(
        CpeName,
        on_delete=models.PROTECT,
        related_name="component_ground_truths",
        null=True,
        blank=True,
    )
    decision_type = models.CharField(max_length=255)
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["component", "snapshot"],
                name="unique_component_ground_truth_per_snapshot",
            ),
        ]

    def clean(self) -> None:
        super().clean()
        self.decision_type = (
            self.decision_type.strip()
            if isinstance(self.decision_type, str)
            else ""
        )
        if not self.decision_type:
            raise ValidationError(
                {
                    "decision_type": (
                        "Decision type must not be blank."
                    )
                }
            )
        if (
            self.ground_truth_cpe_id is not None
            and self.snapshot_id is not None
        ):
            cpe_snapshot_id = (
                CpeName.objects.filter(
                    pk=self.ground_truth_cpe_id
                )
                .values_list("snapshot_id", flat=True)
                .first()
            )
            if (
                cpe_snapshot_id is not None
                and cpe_snapshot_id != self.snapshot_id
            ):
                raise ValidationError(
                    {
                        "ground_truth_cpe": (
                            "Ground Truth CPE must belong to the "
                            "selected Dictionary snapshot."
                        )
                    }
                )

    def save(self, *args, **kwargs) -> None:
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return (
            f"Component {self.component_id} Ground Truth "
            f"({self.snapshot.snapshot_id})"
        )

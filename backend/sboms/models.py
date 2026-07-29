import re

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower

from cpe.cpe23 import parse_cpe23_formatted_string
from cpe_dictionary.models import CpeDictionarySnapshot, CpeName


HANGUL_PATTERN = re.compile(
    "[\u1100-\u11ff\u3130-\u318f"
    "\ua960-\ua97f\uac00-\ud7ff\uffa0-\uffdc]"
)
CORRECTION_TYPE_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


def contains_hangul(value: str) -> bool:
    return bool(HANGUL_PATTERN.search(value))


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


class GroundTruthResolutionOutcome(models.TextChoices):
    ORIGINAL_OFFICIAL_CONFIRMED = (
        "ORIGINAL_OFFICIAL_CONFIRMED",
        "Original CPE confirmed",
    )
    CORRECTED_TO_DICTIONARY = (
        "CORRECTED_TO_DICTIONARY",
        "Corrected to official CPE",
    )
    MANUAL_FROM_OFFICIAL_FAMILY = (
        "MANUAL_FROM_OFFICIAL_FAMILY",
        "Manual CPE from official family",
    )
    DIRECT_OFFICIAL_NOT_CONFIRMED = (
        "DIRECT_OFFICIAL_NOT_CONFIRMED",
        "Direct official CPE not confirmed",
    )


def derive_resolution_outcome(
    *,
    original_cpe: str,
    dictionary_cpe: str | None,
    manual_cpe: str,
) -> str:
    if dictionary_cpe is not None:
        if dictionary_cpe == original_cpe:
            return (
                GroundTruthResolutionOutcome
                .ORIGINAL_OFFICIAL_CONFIRMED
            )
        return GroundTruthResolutionOutcome.CORRECTED_TO_DICTIONARY
    if manual_cpe:
        return (
            GroundTruthResolutionOutcome
            .MANUAL_FROM_OFFICIAL_FAMILY
        )
    return (
        GroundTruthResolutionOutcome
        .DIRECT_OFFICIAL_NOT_CONFIRMED
    )


class GroundTruthCorrectionType(models.Model):
    code = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "id")
        constraints = [
            models.UniqueConstraint(
                Lower("name"),
                name="unique_ground_truth_correction_type_name_ci",
            ),
        ]

    def clean(self) -> None:
        super().clean()
        self.code = (
            self.code.strip().lower()
            if isinstance(self.code, str)
            else ""
        )
        self.name = self.name.strip() if isinstance(self.name, str) else ""
        self.description = (
            self.description.strip()
            if isinstance(self.description, str)
            else ""
        )
        if not self.code:
            raise ValidationError(
                {"code": "Correction Type code must not be blank."}
            )
        if not CORRECTION_TYPE_CODE_PATTERN.fullmatch(self.code):
            raise ValidationError(
                {
                    "code": (
                        "Correction Type code must start with a "
                        "lowercase letter and contain only lowercase "
                        "letters, digits, and underscores."
                    )
                }
            )
        if not self.name:
            raise ValidationError(
                {"name": "Correction Type name must not be blank."}
            )
        if contains_hangul(self.name):
            raise ValidationError(
                {
                    "name": (
                        "Correction Type names must be written in "
                        "English."
                    )
                }
            )
        if contains_hangul(self.description):
            raise ValidationError(
                {
                    "description": (
                        "Correction Type descriptions must be written "
                        "in English."
                    )
                }
            )

    def save(self, *args, **kwargs) -> None:
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
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
    manual_ground_truth_cpe = models.TextField(
        blank=True,
        default="",
    )
    resolution_outcome = models.CharField(
        max_length=64,
        choices=GroundTruthResolutionOutcome.choices,
        editable=False,
    )
    correction_types = models.ManyToManyField(
        GroundTruthCorrectionType,
        blank=True,
        related_name="ground_truth_records",
    )
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["component", "snapshot"],
                name="unique_component_ground_truth_per_snapshot",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(ground_truth_cpe__isnull=True)
                    | models.Q(manual_ground_truth_cpe="")
                ),
                name="ground_truth_has_one_cpe_source",
            ),
        ]

    def clean(self) -> None:
        super().clean()
        self.manual_ground_truth_cpe = (
            self.manual_ground_truth_cpe.strip()
            if isinstance(self.manual_ground_truth_cpe, str)
            else ""
        )
        if (
            self.ground_truth_cpe_id is not None
            and self.manual_ground_truth_cpe
        ):
            raise ValidationError(
                {
                    "manual_ground_truth_cpe": (
                        "Dictionary and manual Ground Truth CPEs "
                        "cannot both be set."
                    )
                }
            )
        if self.manual_ground_truth_cpe:
            parse_result = parse_cpe23_formatted_string(
                self.manual_ground_truth_cpe
            )
            if not parse_result.is_structurally_valid:
                raise ValidationError(
                    {
                        "manual_ground_truth_cpe": (
                            parse_result.error_message
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
        original_cpe = (
            Component.objects.filter(pk=self.component_id)
            .values_list("cpe", flat=True)
            .first()
            or ""
            if self.component_id is not None
            else ""
        )
        dictionary_cpe = (
            CpeName.objects.filter(pk=self.ground_truth_cpe_id)
            .values_list("cpe_name", flat=True)
            .first()
            if self.ground_truth_cpe_id is not None
            else None
        )
        self.resolution_outcome = derive_resolution_outcome(
            original_cpe=original_cpe,
            dictionary_cpe=dictionary_cpe,
            manual_cpe=(
                self.manual_ground_truth_cpe.strip()
                if isinstance(
                    self.manual_ground_truth_cpe,
                    str,
                )
                else ""
            ),
        )
        self.full_clean()
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            kwargs["update_fields"] = {
                *update_fields,
                "resolution_outcome",
            }
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return (
            f"Component {self.component_id} Ground Truth "
            f"({self.snapshot.snapshot_id})"
        )

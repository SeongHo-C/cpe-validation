from __future__ import annotations

from typing import Any

from rest_framework import serializers

from cpe.cpe23 import parse_cpe23_formatted_string
from cpe_dictionary.models import CpeName
from sboms.exact_matching import match_cpe
from sboms.models import (
    Component,
    ComponentCpeGroundTruth,
    DockerImage,
    GroundTruthCorrectionType,
    GroundTruthResolutionOutcome,
    SBOMDocument,
    CORRECTION_TYPE_CODE_PATTERN,
    contains_hangul,
    derive_resolution_outcome,
)


class ImageReferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = DockerImage
        fields = ("id", "repository", "tag")


class SBOMDocumentSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = SBOMDocument
        fields = (
            "id",
            "source_path",
            "file_sha256",
            "format",
            "spec_version",
            "serial_number",
            "document_version",
            "generator_name",
            "generator_version",
            "source_type",
            "scope",
            "generated_at",
            "imported_at",
        )


class ComponentSBOMDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SBOMDocument
        fields = (
            "id",
            "source_path",
            "spec_version",
            "generator_name",
            "generator_version",
            "source_type",
            "scope",
        )


class DockerImageListSerializer(serializers.ModelSerializer):
    sbom_count = serializers.IntegerField(read_only=True)
    total_components = serializers.IntegerField(read_only=True)
    components_with_primary_cpe = serializers.IntegerField(
        read_only=True
    )
    components_without_primary_cpe = serializers.SerializerMethodField()
    primary_cpe_ratio = serializers.SerializerMethodField()
    unique_primary_cpes = serializers.IntegerField(read_only=True)

    class Meta:
        model = DockerImage
        fields = (
            "id",
            "repository",
            "tag",
            "platform",
            "manifest_digest",
            "pinned_reference",
            "sbom_count",
            "total_components",
            "components_with_primary_cpe",
            "components_without_primary_cpe",
            "primary_cpe_ratio",
            "unique_primary_cpes",
        )

    def get_components_without_primary_cpe(
        self,
        instance: DockerImage,
    ) -> int:
        return (
            instance.total_components
            - instance.components_with_primary_cpe
        )

    def get_primary_cpe_ratio(
        self,
        instance: DockerImage,
    ) -> float:
        if instance.total_components == 0:
            return 0.0
        return (
            instance.components_with_primary_cpe
            / instance.total_components
        )


class DockerImageDetailSerializer(DockerImageListSerializer):
    sbom_documents = SBOMDocumentSummarySerializer(
        many=True,
        read_only=True,
    )

    class Meta(DockerImageListSerializer.Meta):
        fields = (
            *DockerImageListSerializer.Meta.fields,
            "sbom_documents",
        )


class _ComponentCPESerializerMixin:
    include_detail_fields = False

    def to_representation(
        self,
        instance: Component,
    ) -> dict[str, Any]:
        representation = super().to_representation(instance)
        if not instance.cpe:
            representation["structural_status"] = "NOT_PRESENT"
            representation["cpe_fields"] = None
            structural_error_message = None
        else:
            parse_result = parse_cpe23_formatted_string(instance.cpe)
            representation[
                "structural_status"
            ] = parse_result.status.value
            representation["cpe_fields"] = (
                dict(parse_result.fields)
                if parse_result.is_structurally_valid
                else None
            )
            structural_error_message = (
                parse_result.error_message or None
            )

        if self.include_detail_fields:
            representation[
                "structural_error_message"
            ] = structural_error_message
            match_result = match_cpe(
                instance.cpe,
                self.context["cpe_dictionary_snapshot"],
            )
            representation[
                "dictionary_status"
            ] = match_result.status.value
            representation["dictionary_match"] = {
                "snapshot_id": match_result.snapshot_id,
                "cpe_name_id": (
                    match_result.matched_cpe_name_id
                ),
                "matched_cpe_name": (
                    match_result.matched_cpe_name
                ),
                "deprecated": match_result.deprecated,
            }
        else:
            match_result = self.context[
                "cpe_dictionary_matches"
            ][instance.cpe]
            representation[
                "dictionary_status"
            ] = match_result.status.value
        return representation


class ComponentListSerializer(
    _ComponentCPESerializerMixin,
    serializers.Serializer,
):
    id = serializers.IntegerField(read_only=True)
    image = ImageReferenceSerializer(
        source="sbom_document.docker_image",
        read_only=True,
    )
    sbom_document_id = serializers.IntegerField(read_only=True)
    component_type = serializers.CharField(read_only=True)
    group = serializers.CharField(read_only=True)
    name = serializers.CharField(read_only=True)
    version = serializers.CharField(read_only=True)
    publisher = serializers.CharField(read_only=True)
    purl = serializers.CharField(read_only=True)
    cpe = serializers.CharField(read_only=True)


class ComponentDetailSerializer(ComponentListSerializer):
    include_detail_fields = True

    bom_ref = serializers.CharField(read_only=True)
    properties = serializers.JSONField(read_only=True)
    sbom_document = ComponentSBOMDocumentSerializer(read_only=True)


class GroundTruthCpeSerializer(serializers.ModelSerializer):
    cpe_uuid = serializers.UUIDField(
        source="cpe_name_id",
        read_only=True,
    )

    class Meta:
        model = CpeName
        fields = (
            "id",
            "cpe_name",
            "cpe_uuid",
            "deprecated",
            "part",
            "vendor",
            "product",
            "version",
        )


class GroundTruthCorrectionTypeSerializer(
    serializers.ModelSerializer
):
    usage_count = serializers.IntegerField(
        read_only=True,
        required=False,
    )

    class Meta:
        model = GroundTruthCorrectionType
        fields = (
            "id",
            "code",
            "name",
            "description",
            "is_active",
            "usage_count",
        )


class GroundTruthCorrectionTypeCreateSerializer(
    serializers.ModelSerializer
):
    class Meta:
        model = GroundTruthCorrectionType
        fields = ("code", "name", "description")

    def validate_code(self, value: str) -> str:
        normalized_code = value.strip().lower()
        if not CORRECTION_TYPE_CODE_PATTERN.fullmatch(
            normalized_code
        ):
            raise serializers.ValidationError(
                (
                    "Correction Type code must start with a lowercase "
                    "letter and contain only lowercase letters, "
                    "digits, and underscores."
                )
            )
        if GroundTruthCorrectionType.objects.filter(
            code=normalized_code
        ).exists():
            raise serializers.ValidationError(
                "A Correction Type with this code already exists."
            )
        return normalized_code

    def validate_name(self, value: str) -> str:
        normalized_name = value.strip()
        if not normalized_name:
            raise serializers.ValidationError(
                "Correction Type name must not be blank."
            )
        if GroundTruthCorrectionType.objects.filter(
            name__iexact=normalized_name
        ).exists():
            raise serializers.ValidationError(
                "A Correction Type with this name already exists."
            )
        if contains_hangul(normalized_name):
            raise serializers.ValidationError(
                "Correction Type names must be written in English."
            )
        return normalized_name

    def validate_description(self, value: str) -> str:
        normalized_description = value.strip()
        if contains_hangul(normalized_description):
            raise serializers.ValidationError(
                (
                    "Correction Type descriptions must be written "
                    "in English."
                )
            )
        return normalized_description


class GroundTruthCorrectionTypeUpdateSerializer(
    serializers.ModelSerializer
):
    class Meta:
        model = GroundTruthCorrectionType
        fields = ("description", "is_active")

    def validate_description(self, value: str) -> str:
        normalized_description = value.strip()
        if contains_hangul(normalized_description):
            raise serializers.ValidationError(
                (
                    "Correction Type descriptions must be written "
                    "in English."
                )
            )
        return normalized_description

    def validate(self, attributes: dict) -> dict:
        immutable_fields = {
            field
            for field in ("code", "name")
            if field in self.initial_data
        }
        if immutable_fields:
            raise serializers.ValidationError(
                {
                    field: (
                        f"Correction Type {field} cannot be changed."
                    )
                    for field in immutable_fields
                }
            )
        return attributes


class ComponentCpeGroundTruthSerializer(
    serializers.ModelSerializer
):
    source = serializers.SerializerMethodField()
    dictionary_cpe = GroundTruthCpeSerializer(
        source="ground_truth_cpe",
        read_only=True,
    )
    ground_truth_cpe = GroundTruthCpeSerializer(read_only=True)
    manual_cpe = serializers.SerializerMethodField()
    resolution_outcome = serializers.SerializerMethodField()
    correction_types = GroundTruthCorrectionTypeSerializer(
        many=True,
        read_only=True,
    )

    class Meta:
        model = ComponentCpeGroundTruth
        fields = (
            "id",
            "source",
            "dictionary_cpe",
            "ground_truth_cpe",
            "manual_cpe",
            "resolution_outcome",
            "correction_types",
            "note",
            "created_at",
            "updated_at",
        )

    def get_source(
        self,
        instance: ComponentCpeGroundTruth,
    ) -> str:
        if instance.ground_truth_cpe_id is not None:
            return "DICTIONARY"
        if instance.manual_ground_truth_cpe:
            return "MANUAL"
        return "NONE"

    def get_manual_cpe(
        self,
        instance: ComponentCpeGroundTruth,
    ) -> str | None:
        return instance.manual_ground_truth_cpe or None

    def get_resolution_outcome(
        self,
        instance: ComponentCpeGroundTruth,
    ) -> dict[str, str]:
        outcome = GroundTruthResolutionOutcome(
            instance.resolution_outcome
        )
        return {
            "code": outcome.value,
            "label": outcome.label,
        }


class ComponentCpeGroundTruthWriteSerializer(
    serializers.Serializer
):
    dictionary_cpe_id = serializers.PrimaryKeyRelatedField(
        source="dictionary_cpe_input",
        queryset=CpeName.objects.all(),
        allow_null=True,
        required=False,
    )
    ground_truth_cpe_id = serializers.PrimaryKeyRelatedField(
        source="legacy_dictionary_cpe_input",
        queryset=CpeName.objects.all(),
        allow_null=True,
        required=False,
        write_only=True,
    )
    manual_cpe = serializers.CharField(
        allow_blank=True,
        allow_null=True,
        required=False,
        default=None,
        trim_whitespace=True,
    )
    correction_type_ids = serializers.PrimaryKeyRelatedField(
        source="correction_types",
        queryset=GroundTruthCorrectionType.objects.all(),
        many=True,
        required=False,
        default=list,
    )
    note = serializers.CharField(
        allow_blank=True,
        required=False,
        default="",
        trim_whitespace=False,
    )

    def validate(self, attributes: dict) -> dict:
        if "resolution_outcome" in self.initial_data:
            raise serializers.ValidationError(
                {
                    "resolution_outcome": (
                        "Resolution Outcome is calculated by the "
                        "server."
                    )
                }
            )
        if "snapshot_id" in self.initial_data:
            raise serializers.ValidationError(
                {
                    "snapshot_id": (
                        "Dictionary snapshot is selected by the server."
                    )
                }
            )
        raw_correction_type_ids = self.initial_data.get(
            "correction_type_ids",
            [],
        )
        if (
            isinstance(raw_correction_type_ids, list)
            and len(raw_correction_type_ids)
            != len(set(map(str, raw_correction_type_ids)))
        ):
            raise serializers.ValidationError(
                {
                    "correction_type_ids": (
                        "A Correction Type may be selected only once."
                    )
                }
            )
        correction_types = attributes["correction_types"]
        current_ground_truth = self.context.get(
            "current_ground_truth"
        )
        existing_correction_type_ids = (
            set(
                current_ground_truth.correction_types.values_list(
                    "id",
                    flat=True,
                )
            )
            if current_ground_truth is not None
            else set()
        )
        newly_selected_inactive = [
            correction_type
            for correction_type in correction_types
            if (
                not correction_type.is_active
                and correction_type.id
                not in existing_correction_type_ids
            )
        ]
        if newly_selected_inactive:
            raise serializers.ValidationError(
                {
                    "correction_type_ids": (
                        "Inactive Correction Types cannot be newly "
                        "selected."
                    )
                }
            )
        dictionary_cpe = attributes.pop(
            "dictionary_cpe_input",
            serializers.empty,
        )
        legacy_dictionary_cpe = attributes.pop(
            "legacy_dictionary_cpe_input",
            serializers.empty,
        )
        if (
            dictionary_cpe is not serializers.empty
            and legacy_dictionary_cpe is not serializers.empty
            and dictionary_cpe != legacy_dictionary_cpe
        ):
            raise serializers.ValidationError(
                {
                    "dictionary_cpe_id": (
                        "Only one Dictionary Ground Truth CPE "
                        "may be provided."
                    )
                }
            )
        ground_truth_cpe = (
            dictionary_cpe
            if dictionary_cpe is not serializers.empty
            else (
                legacy_dictionary_cpe
                if legacy_dictionary_cpe is not serializers.empty
                else None
            )
        )
        manual_cpe = attributes.pop("manual_cpe", None)
        normalized_manual_cpe = (
            manual_cpe.strip()
            if isinstance(manual_cpe, str)
            else ""
        )
        if (
            ground_truth_cpe is not None
            and normalized_manual_cpe
        ):
            raise serializers.ValidationError(
                {
                    "manual_cpe": (
                        "Dictionary and manual Ground Truth CPEs "
                        "cannot both be set."
                    )
                }
            )
        if normalized_manual_cpe:
            parse_result = parse_cpe23_formatted_string(
                normalized_manual_cpe
            )
            if not parse_result.is_structurally_valid:
                raise serializers.ValidationError(
                    {
                        "manual_cpe": parse_result.error_message
                    }
                )
        snapshot = self.context["snapshot"]
        if (
            ground_truth_cpe is not None
            and ground_truth_cpe.snapshot_id != snapshot.id
        ):
            raise serializers.ValidationError(
                {
                    "dictionary_cpe_id": (
                        "Ground Truth CPE must belong to the current "
                        "Dictionary snapshot."
                    )
                }
            )
        attributes["ground_truth_cpe"] = ground_truth_cpe
        attributes[
            "manual_ground_truth_cpe"
        ] = normalized_manual_cpe
        outcome = derive_resolution_outcome(
            original_cpe=self.context["component"].cpe,
            dictionary_cpe=(
                ground_truth_cpe.cpe_name
                if ground_truth_cpe is not None
                else None
            ),
            manual_cpe=normalized_manual_cpe,
        )
        if (
            outcome
            in {
                (
                    GroundTruthResolutionOutcome
                    .ORIGINAL_OFFICIAL_CONFIRMED
                ),
                (
                    GroundTruthResolutionOutcome
                    .DIRECT_OFFICIAL_NOT_CONFIRMED
                ),
            }
            and correction_types
        ):
            raise serializers.ValidationError(
                {
                    "correction_type_ids": (
                        "Correction Types must be empty for this "
                        "Resolution Outcome."
                    )
                }
            )
        attributes["resolution_outcome"] = outcome
        return attributes


class GroundTruthComponentListSerializer(
    ComponentListSerializer
):
    ground_truth_status = serializers.SerializerMethodField()
    ground_truth = serializers.SerializerMethodField()
    resolution_outcome = serializers.SerializerMethodField()
    correction_types = serializers.SerializerMethodField()

    def _ground_truth(
        self,
        instance: Component,
    ) -> ComponentCpeGroundTruth | None:
        return self.context["ground_truth_records"].get(instance.id)

    def get_ground_truth_status(
        self,
        instance: Component,
    ) -> str:
        return (
            "COMPLETED"
            if self._ground_truth(instance) is not None
            else "UNREVIEWED"
        )

    def get_ground_truth(
        self,
        instance: Component,
    ) -> dict | None:
        ground_truth = self._ground_truth(instance)
        if ground_truth is None:
            return None
        return ComponentCpeGroundTruthSerializer(
            ground_truth
        ).data

    def get_resolution_outcome(
        self,
        instance: Component,
    ) -> dict | None:
        ground_truth = self._ground_truth(instance)
        if ground_truth is None:
            return None
        outcome = GroundTruthResolutionOutcome(
            ground_truth.resolution_outcome
        )
        return {
            "code": outcome.value,
            "label": outcome.label,
        }

    def get_correction_types(
        self,
        instance: Component,
    ) -> list[dict]:
        ground_truth = self._ground_truth(instance)
        if ground_truth is None:
            return []
        return GroundTruthCorrectionTypeSerializer(
            ground_truth.correction_types.all(),
            many=True,
        ).data

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
    SBOMDocument,
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

    class Meta:
        model = ComponentCpeGroundTruth
        fields = (
            "id",
            "source",
            "dictionary_cpe",
            "ground_truth_cpe",
            "manual_cpe",
            "decision_type",
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
    decision_type = serializers.CharField(
        max_length=255,
        allow_blank=False,
        trim_whitespace=True,
    )
    note = serializers.CharField(
        allow_blank=True,
        required=False,
        default="",
        trim_whitespace=False,
    )

    def validate(self, attributes: dict) -> dict:
        if "snapshot_id" in self.initial_data:
            raise serializers.ValidationError(
                {
                    "snapshot_id": (
                        "Dictionary snapshot is selected by the server."
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
        return attributes


class GroundTruthComponentListSerializer(
    ComponentListSerializer
):
    ground_truth_status = serializers.SerializerMethodField()
    ground_truth = serializers.SerializerMethodField()
    decision_type = serializers.SerializerMethodField()

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

    def get_decision_type(
        self,
        instance: Component,
    ) -> str | None:
        ground_truth = self._ground_truth(instance)
        return (
            ground_truth.decision_type
            if ground_truth is not None
            else None
        )

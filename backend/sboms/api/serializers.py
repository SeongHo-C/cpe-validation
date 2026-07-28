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
    ground_truth_cpe = GroundTruthCpeSerializer(read_only=True)

    class Meta:
        model = ComponentCpeGroundTruth
        fields = (
            "id",
            "ground_truth_cpe",
            "decision_type",
            "note",
            "created_at",
            "updated_at",
        )


class ComponentCpeGroundTruthWriteSerializer(
    serializers.Serializer
):
    ground_truth_cpe_id = serializers.PrimaryKeyRelatedField(
        source="ground_truth_cpe",
        queryset=CpeName.objects.all(),
        allow_null=True,
        required=False,
        default=None,
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
        ground_truth_cpe = attributes["ground_truth_cpe"]
        snapshot = self.context["snapshot"]
        if (
            ground_truth_cpe is not None
            and ground_truth_cpe.snapshot_id != snapshot.id
        ):
            raise serializers.ValidationError(
                {
                    "ground_truth_cpe_id": (
                        "Ground Truth CPE must belong to the current "
                        "Dictionary snapshot."
                    )
                }
            )
        return attributes

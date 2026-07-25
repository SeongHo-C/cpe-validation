from __future__ import annotations

from typing import Any

from rest_framework import serializers

from sboms.cpe23 import parse_cpe23_formatted_string
from sboms.models import Component, DockerImage, SBOMDocument


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
            representation["dictionary_status"] = "UNVALIDATED"
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

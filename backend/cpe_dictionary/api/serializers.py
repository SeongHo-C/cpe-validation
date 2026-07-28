from __future__ import annotations

from rest_framework import serializers

from cpe_dictionary.models import CpeName


def representative_title(titles: object) -> str:
    if not isinstance(titles, list):
        return ""
    first_title = ""
    for item in titles:
        if not isinstance(item, dict):
            continue
        title = item.get("title")
        if not isinstance(title, str):
            continue
        if not first_title:
            first_title = title
        language = item.get("lang")
        if (
            isinstance(language, str)
            and language.lower().startswith("en")
        ):
            return title
    return first_title


class CpeNameListSerializer(serializers.ModelSerializer):
    title = serializers.SerializerMethodField()
    snapshot_id = serializers.SerializerMethodField()

    class Meta:
        model = CpeName
        fields = (
            "id",
            "cpe_name_id",
            "cpe_name",
            "part",
            "vendor",
            "product",
            "version",
            "update",
            "edition",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other",
            "deprecated",
            "title",
            "snapshot_id",
        )

    def get_title(self, instance: CpeName) -> str:
        return representative_title(instance.titles)

    def get_snapshot_id(self, instance: CpeName) -> str:
        return self.context["snapshot_id"]


class CpeNameDetailSerializer(serializers.ModelSerializer):
    snapshot_id = serializers.CharField(
        source="snapshot.snapshot_id",
        read_only=True,
    )
    snapshot_manifest_sha256 = serializers.CharField(
        source="snapshot.manifest_sha256",
        read_only=True,
    )
    references = serializers.SerializerMethodField()

    class Meta:
        model = CpeName
        fields = (
            "id",
            "cpe_name_id",
            "cpe_name",
            "snapshot_id",
            "snapshot_manifest_sha256",
            "deprecated",
            "deprecated_by",
            "deprecates",
            "created_at_nvd",
            "last_modified_at_nvd",
            "part",
            "vendor",
            "product",
            "version",
            "update",
            "edition",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other",
            "titles",
            "references",
        )

    def get_references(
        self,
        instance: CpeName,
    ) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []
        if not isinstance(instance.references, list):
            return normalized
        for item in instance.references:
            if not isinstance(item, dict):
                continue
            raw_url = item.get("url", item.get("ref", ""))
            raw_type = item.get("type", "")
            normalized.append(
                {
                    "url": raw_url if isinstance(raw_url, str) else "",
                    "type": raw_type if isinstance(raw_type, str) else "",
                }
            )
        return normalized

#!/usr/bin/env python3
"""Resolve platform-specific image manifest digests with Docker Buildx."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import yaml


DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_FORMAT = "{{json .Manifest}}"
PILOT_OS = "linux"
PILOT_ARCHITECTURE = "amd64"


class ResolutionError(Exception):
    """Base class for expected digest-resolution failures."""

    error_type = "resolution_error"


class InvalidArgumentsError(ResolutionError):
    error_type = "invalid_arguments"


class InvalidInputError(ResolutionError):
    error_type = "invalid_input"


class OutputExistsError(ResolutionError):
    error_type = "output_exists"


class DockerNotFoundError(ResolutionError):
    error_type = "docker_not_found"


class DockerCommandError(ResolutionError):
    error_type = "docker_command_failed"


class InvalidJsonError(ResolutionError):
    error_type = "invalid_json"


class InvalidManifestSchemaError(ResolutionError):
    error_type = "invalid_manifest_schema"


class UnsupportedMediaTypeError(ResolutionError):
    error_type = "unsupported_top_level_media_type"


class InvalidDigestError(ResolutionError):
    error_type = "invalid_digest"


class NoMatchingManifestError(ResolutionError):
    error_type = "no_matching_manifest"


class MultipleMatchingManifestsError(ResolutionError):
    error_type = "multiple_matching_manifests"


def utc_now() -> str:
    """Return an ISO 8601 timestamp in UTC."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def validate_digest(value: Any, label: str) -> str:
    """Validate and return a sha256 digest."""

    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        raise InvalidDigestError(
            f"{label} must match sha256 followed by 64 lowercase hexadecimal "
            f"characters; received {value!r}"
        )
    return value


def parse_image_reference(reference: str) -> dict[str, str]:
    """Parse and normalize a tagged container image reference."""

    value = reference.strip()
    if not value or any(character.isspace() for character in value):
        raise InvalidArgumentsError(
            "image reference must be non-empty and contain no whitespace"
        )
    if "://" in value:
        raise InvalidArgumentsError("image reference must not include a URL scheme")
    if "@" in value:
        raise InvalidArgumentsError(
            "digest-based input references are not supported; provide a tag"
        )

    last_component = value.rsplit("/", 1)[-1]
    if ":" in last_component:
        repository_part, tag = value.rsplit(":", 1)
    else:
        repository_part, tag = value, "latest"

    if not repository_part or not tag:
        raise InvalidArgumentsError(
            "image reference must contain a repository and tag"
        )

    components = repository_part.split("/")
    if any(not component for component in components):
        raise InvalidArgumentsError(
            "image repository contains an empty path component"
        )

    first_component = components[0]
    has_explicit_registry = (
        "." in first_component
        or ":" in first_component
        or first_component == "localhost"
    )

    if has_explicit_registry:
        registry = first_component.lower()
        repository_components = components[1:]
        if not repository_components:
            raise InvalidArgumentsError("image repository path is missing")
    else:
        registry = "docker.io"
        repository_components = components

    if registry in {"index.docker.io", "registry-1.docker.io"}:
        registry = "docker.io"
    if registry == "docker.io" and len(repository_components) == 1:
        repository_components.insert(0, "library")

    normalized_repository = "/".join([registry, *repository_components])
    return {
        "input_reference": value,
        "normalized_repository": normalized_repository,
        "normalized_reference": f"{normalized_repository}:{tag}",
        "input_tag": tag,
        "repository_name": repository_components[-1],
    }


def required_string(
    mapping: dict[str, Any], key: str, context: str
) -> str:
    """Read one required scalar string from a parsed YAML mapping."""

    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InvalidInputError(f"{context}.{key} must be a non-empty string")
    if any(character.isspace() for character in value):
        raise InvalidInputError(f"{context}.{key} must not contain whitespace")
    return value


def build_image_reference(
    registry: str,
    namespace: str,
    repository: str,
    tag: str,
) -> str:
    """Build the canonical input reference required by the pilot."""

    values = {
        "registry": registry,
        "namespace": namespace,
        "repository": repository,
        "tag": tag,
    }
    for label, value in values.items():
        if not isinstance(value, str) or not value:
            raise InvalidInputError(f"{label} must be a non-empty string")
        if any(character.isspace() for character in value):
            raise InvalidInputError(f"{label} must not contain whitespace")

    registry_value = registry.rstrip("/")
    namespace_value = namespace.strip("/")
    repository_value = repository.strip("/")
    if not registry_value or not namespace_value or not repository_value:
        raise InvalidInputError(
            "registry, namespace, and repository must contain path components"
        )
    return (
        f"{registry_value}/{namespace_value}/{repository_value}:{tag}"
    )


def safe_filename_component(value: str, label: str) -> str:
    """Return a conservative filename component."""

    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    if not sanitized or sanitized in {".", ".."}:
        raise InvalidArgumentsError(
            f"{label} cannot be represented safely in a filename"
        )
    return sanitized


def raw_output_filename(repository: str, tag: str) -> str:
    """Build the single raw manifest filename for an input image."""

    repository_name = safe_filename_component(repository, "repository name")
    tag_value = safe_filename_component(tag, "tag")
    return f"{repository_name}-{tag_value}.json"


def load_input_configuration(input_path: Path) -> dict[str, Any]:
    """Load and validate the ordered image list from a YAML file."""

    try:
        with input_path.open("r", encoding="utf-8") as input_file:
            document = yaml.load(input_file, Loader=yaml.BaseLoader)
    except OSError as error:
        raise InvalidInputError(
            f"cannot read input file {input_path}: {error}"
        ) from error
    except yaml.YAMLError as error:
        raise InvalidInputError(
            f"input file {input_path} is not valid YAML: {error}"
        ) from error

    if not isinstance(document, dict):
        raise InvalidInputError("input YAML root must be a mapping")

    selection_date = required_string(document, "selection_date", "input")
    registry = required_string(document, "registry", "input")
    namespace = required_string(document, "namespace", "input")

    platform_value = document.get("platform")
    if not isinstance(platform_value, dict):
        raise InvalidInputError("input.platform must be a mapping")
    target_os = required_string(platform_value, "os", "input.platform")
    target_architecture = required_string(
        platform_value,
        "architecture",
        "input.platform",
    )
    if (
        target_os != PILOT_OS
        or target_architecture != PILOT_ARCHITECTURE
    ):
        raise InvalidInputError(
            "pilot platform must be linux/amd64; "
            f"received {target_os}/{target_architecture}"
        )

    image_values = document.get("images")
    if not isinstance(image_values, list) or not image_values:
        raise InvalidInputError("input.images must be a non-empty array")

    images = []
    for index, image_value in enumerate(image_values):
        if not isinstance(image_value, dict):
            raise InvalidInputError(
                f"input.images[{index}] must be a mapping"
            )
        repository = required_string(
            image_value,
            "repository",
            f"input.images[{index}]",
        )
        tag = required_string(
            image_value,
            "tag",
            f"input.images[{index}]",
        )
        images.append(
            {
                "repository": repository,
                "tag": tag,
                "reference": build_image_reference(
                    registry,
                    namespace,
                    repository,
                    tag,
                ),
            }
        )

    return {
        "selection_date": selection_date,
        "registry": registry,
        "namespace": namespace,
        "platform": {
            "os": target_os,
            "architecture": target_architecture,
        },
        "images": images,
    }


def validate_index_manifest(
    document: Any,
) -> tuple[str, str, list[dict[str, Any]]]:
    """Validate the index/list envelope and all descriptor digests."""

    if not isinstance(document, dict):
        raise InvalidManifestSchemaError(
            "manifest document must be a JSON object"
        )

    media_type = document.get("mediaType")
    if media_type not in INDEX_MEDIA_TYPES:
        raise UnsupportedMediaTypeError(
            "top-level mediaType must be an OCI index or Docker manifest "
            f"list; received {media_type!r}"
        )

    top_level_digest = validate_digest(
        document.get("digest"),
        "top-level manifest digest",
    )
    manifests = document.get("manifests")
    if not isinstance(manifests, list):
        raise InvalidManifestSchemaError(
            "manifest document 'manifests' must be an array"
        )

    validated_manifests: list[dict[str, Any]] = []
    for index, descriptor in enumerate(manifests):
        if not isinstance(descriptor, dict):
            raise InvalidManifestSchemaError(
                f"manifest descriptor at index {index} must be a JSON object"
            )
        validate_digest(
            descriptor.get("digest"),
            f"manifest descriptor {index} digest",
        )
        validated_manifests.append(descriptor)

    return media_type, top_level_digest, validated_manifests


def select_platform_manifest(
    manifests: Sequence[dict[str, Any]],
    target_os: str,
    target_architecture: str,
) -> dict[str, Any]:
    """Select exactly one descriptor matching the requested platform."""

    matches = []
    for descriptor in manifests:
        descriptor_platform = descriptor.get("platform")
        if not isinstance(descriptor_platform, dict):
            continue
        if (
            descriptor_platform.get("os") == target_os
            and descriptor_platform.get("architecture")
            == target_architecture
        ):
            matches.append(descriptor)

    target = f"{target_os}/{target_architecture}"
    if not matches:
        raise NoMatchingManifestError(
            f"no manifest matched target platform {target}"
        )
    if len(matches) > 1:
        raise MultipleMatchingManifestsError(
            f"{len(matches)} manifests matched target platform {target}"
        )

    selected = matches[0]
    selected_media_type = selected.get("mediaType")
    if not isinstance(selected_media_type, str) or not selected_media_type:
        raise InvalidManifestSchemaError(
            f"manifest selected for {target} has no valid mediaType"
        )
    validate_digest(
        selected.get("digest"),
        f"{target} manifest digest",
    )
    return selected


def extract_manifest_metadata(
    document: Any,
    target_os: str,
    target_architecture: str,
) -> dict[str, str]:
    """Extract validated top-level and platform-specific metadata."""

    media_type, top_level_digest, manifests = validate_index_manifest(
        document
    )
    selected = select_platform_manifest(
        manifests,
        target_os,
        target_architecture,
    )
    return {
        "top_level_media_type": media_type,
        "top_level_digest": top_level_digest,
        "platform_manifest_media_type": selected["mediaType"],
        "platform_manifest_digest": selected["digest"],
    }


def parse_json_bytes(data: bytes, label: str) -> Any:
    """Parse a UTF-8 JSON response without altering its saved bytes."""

    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvalidJsonError(
            f"{label} is not valid UTF-8 JSON: {error}"
        ) from error


def write_bytes_exclusive(path: Path, data: bytes) -> None:
    """Create a file without replacing any existing path."""

    try:
        with path.open("xb") as output:
            output.write(data)
    except FileExistsError as error:
        raise OutputExistsError(
            f"refusing to overwrite existing file: {path}"
        ) from error


def write_json_exclusive(path: Path, payload: dict[str, Any]) -> None:
    """Create a formatted JSON file without replacing an existing path."""

    encoded = (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    ).encode("utf-8")
    write_bytes_exclusive(path, encoded)


def report_progress(message: str) -> None:
    """Report progress without mixing it into JSON written to stdout."""

    print(message, file=sys.stderr)


def run_docker_command(command: Sequence[str]) -> bytes:
    """Run one Docker command and report its status on standard error."""

    display_command = shlex.join(command)
    report_progress(f"docker_command={display_command}")
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        report_progress(
            "docker_command_error=docker executable not found"
        )
        raise DockerNotFoundError(
            "docker executable was not found in PATH"
        ) from error

    stdout_text = completed.stdout.decode("utf-8", errors="replace")
    stderr_text = completed.stderr.decode("utf-8", errors="replace")
    report_progress(f"docker_return_code={completed.returncode}")
    report_progress(
        f"docker_stderr={json.dumps(stderr_text, ensure_ascii=False)}"
    )
    report_progress(f"docker_stdout_bytes={len(completed.stdout)}")

    if completed.returncode != 0:
        report_progress(
            "docker_stdout_on_error="
            f"{json.dumps(stdout_text, ensure_ascii=False)}"
        )
        message = (
            f"Docker command exited with status {completed.returncode}: "
            f"{display_command}"
        )
        if stderr_text.strip():
            message = f"{message}; stderr: {stderr_text.strip()}"
        if stdout_text.strip():
            message = f"{message}; stdout: {stdout_text.strip()}"
        raise DockerCommandError(message)
    return completed.stdout


def build_image_result(
    image: dict[str, str],
    target_os: str,
    target_architecture: str,
) -> dict[str, Any]:
    """Build the stable per-image success/failure result schema."""

    return {
        "status": "failed",
        "input_reference": image["input_reference"],
        "normalized_repository": image["normalized_repository"],
        "input_tag": image["input_tag"],
        "target_os": target_os,
        "target_architecture": target_architecture,
        "top_level_media_type": None,
        "top_level_digest": None,
        "platform_manifest_media_type": None,
        "platform_manifest_digest": None,
        "pinned_reference": None,
        "verified_at_utc": None,
        "raw_output": None,
        "error": None,
    }


def error_details(error: Exception) -> dict[str, str]:
    """Convert an exception into the public per-image error schema."""

    if isinstance(error, ResolutionError):
        error_type = error.error_type
    elif isinstance(error, OSError):
        error_type = "filesystem_error"
    else:
        error_type = "unexpected_error"
    return {
        "type": error_type,
        "message": str(error),
    }


def resolve_image_digest(
    reference: str,
    target_os: str,
    target_architecture: str,
    project_root: Path,
) -> tuple[dict[str, Any], int]:
    """Resolve one image and save its unmodified formatted manifest JSON."""

    for value, label in (
        (target_os, "os"),
        (target_architecture, "architecture"),
    ):
        if not value or any(character.isspace() for character in value):
            raise InvalidArgumentsError(
                f"target {label} must be non-empty and contain no whitespace"
            )

    image = parse_image_reference(reference)
    raw_directory = project_root / "results" / "raw"
    raw_directory.mkdir(parents=True, exist_ok=True)
    raw_filename = raw_output_filename(
        image["repository_name"],
        image["input_tag"],
    )
    raw_path = raw_directory / raw_filename
    result = build_image_result(
        image,
        target_os,
        target_architecture,
    )

    report_progress(
        f"start reference={image['input_reference']} "
        f"target={target_os}/{target_architecture} "
        f"python={platform.python_version()} "
        f"host_platform={platform.platform()}"
    )

    try:
        if raw_path.exists():
            raise OutputExistsError(
                f"refusing to overwrite existing file: {raw_path}"
            )

        command = [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            image["input_reference"],
            "--format",
            MANIFEST_FORMAT,
        ]
        manifest_bytes = run_docker_command(command)
        write_bytes_exclusive(raw_path, manifest_bytes)
        result["raw_output"] = str(
            raw_path.relative_to(project_root)
        )

        manifest_document = parse_json_bytes(
            manifest_bytes,
            "structured manifest response",
        )
        manifest_metadata = extract_manifest_metadata(
            manifest_document,
            target_os,
            target_architecture,
        )
        result.update(manifest_metadata)

        selected_digest = manifest_metadata[
            "platform_manifest_digest"
        ]
        result["pinned_reference"] = (
            f"{image['normalized_repository']}@{selected_digest}"
        )
        result["status"] = "success"
        result["verified_at_utc"] = utc_now()
        result["error"] = None
        report_progress(
            f"success reference={image['input_reference']} "
            f"top_level_digest={result['top_level_digest']} "
            f"platform_manifest_digest="
            f"{result['platform_manifest_digest']}"
        )
        return result, 0
    except Exception as error:
        result["status"] = "failed"
        result["verified_at_utc"] = utc_now()
        result["error"] = error_details(error)
        report_progress(
            f"failure reference={image['input_reference']} "
            f"type={result['error']['type']} "
            f"message={result['error']['message']}"
        )
        return result, 1


def build_integrated_result(
    configuration: dict[str, Any],
    images: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the aggregate result document."""

    success_count = sum(
        image["status"] == "success" for image in images
    )
    total_images = len(images)
    return {
        "schema_version": 1,
        "selection_date": configuration["selection_date"],
        "platform": {
            "os": configuration["platform"]["os"],
            "architecture": configuration["platform"][
                "architecture"
            ],
        },
        "total_images": total_images,
        "success_count": success_count,
        "failure_count": total_images - success_count,
        "images": images,
    }


def resolve_images_from_file(
    input_path: Path,
    project_root: Path,
) -> tuple[dict[str, Any], int]:
    """Resolve every input image in order and write one aggregate JSON."""

    configuration = load_input_configuration(input_path)
    result_path = project_root / "results" / "image-digests.json"
    if result_path.exists():
        raise OutputExistsError(
            f"refusing to overwrite existing file: {result_path}"
        )

    target_os = configuration["platform"]["os"]
    target_architecture = configuration["platform"]["architecture"]
    image_results = []
    for image in configuration["images"]:
        image_result, _ = resolve_image_digest(
            image["reference"],
            target_os,
            target_architecture,
            project_root,
        )
        image_results.append(image_result)

    integrated_result = build_integrated_result(
        configuration,
        image_results,
    )
    result_path.parent.mkdir(parents=True, exist_ok=True)
    write_json_exclusive(result_path, integrated_result)
    report_progress(
        f"completed total_images={integrated_result['total_images']} "
        f"success_count={integrated_result['success_count']} "
        f"failure_count={integrated_result['failure_count']} "
        f"result={result_path}"
    )
    return integrated_result, 0


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Resolve platform manifest digests using "
            "'docker buildx imagetools inspect'."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--reference",
        help="Tagged image reference for single-image mode",
    )
    mode.add_argument(
        "--input",
        type=Path,
        help="YAML image list for ordered batch mode",
    )
    parser.add_argument(
        "--os",
        dest="target_os",
        help="Target OS for single-image mode",
    )
    parser.add_argument(
        "--architecture",
        dest="target_architecture",
        help="Target architecture for single-image mode",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    project_root = Path(__file__).resolve().parent.parent

    if arguments.input is not None and (
        arguments.target_os is not None
        or arguments.target_architecture is not None
    ):
        parser.error(
            "--os and --architecture are only valid with --reference"
        )
    if arguments.reference is not None and (
        arguments.target_os is None
        or arguments.target_architecture is None
    ):
        parser.error(
            "--reference requires --os and --architecture"
        )

    try:
        if arguments.input is not None:
            result, exit_code = resolve_images_from_file(
                arguments.input,
                project_root,
            )
        else:
            assert arguments.reference is not None
            assert arguments.target_os is not None
            assert arguments.target_architecture is not None
            result, exit_code = resolve_image_digest(
                arguments.reference,
                arguments.target_os,
                arguments.target_architecture,
                project_root,
            )
    except Exception as error:
        payload = {
            "status": "failed",
            "error": error_details(error),
        }
        print(
            json.dumps(payload, ensure_ascii=False, indent=2),
            file=sys.stderr,
        )
        return 1

    stream = sys.stdout if exit_code == 0 else sys.stderr
    print(
        json.dumps(result, ensure_ascii=False, indent=2),
        file=stream,
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

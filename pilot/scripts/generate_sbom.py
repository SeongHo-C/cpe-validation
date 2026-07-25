#!/usr/bin/env python3
"""Generate validated CycloneDX SBOMs from digest-pinned image references."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


EXPECTED_SYFT_VERSION = "1.49.0"
PILOT_OS = "linux"
PILOT_ARCHITECTURE = "amd64"
PILOT_PLATFORM = f"{PILOT_OS}/{PILOT_ARCHITECTURE}"
DEFAULT_INPUT_PATH = Path("results/image-digests.json")
DEFAULT_OUTPUT_DIRECTORY = Path("results/sboms")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
FILENAME_COMPONENT_PATTERN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")


class SbomGenerationError(Exception):
    """Base class for expected SBOM generation failures."""


class InputValidationError(SbomGenerationError):
    """Raised when the digest input is missing or invalid."""


class RepositoryNotFoundError(InputValidationError):
    """Raised when a requested repository is absent from the input."""


class SyftNotFoundError(SbomGenerationError):
    """Raised when the Syft executable cannot be found."""


class SyftVersionError(SbomGenerationError):
    """Raised when the installed Syft version cannot be accepted."""


class SyftCommandError(SbomGenerationError):
    """Raised when a Syft scan exits unsuccessfully."""


class OutputExistsError(SbomGenerationError):
    """Raised when a final SBOM already exists without --overwrite."""


class CycloneDxValidationError(SbomGenerationError):
    """Raised when a generated file is not a basic CycloneDX document."""


Runner = Callable[..., subprocess.CompletedProcess[Any]]


@dataclass(frozen=True)
class RunSummary:
    """Counts from one ordered SBOM generation run."""

    total: int
    success: int
    failed: int


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Generate Syft CycloneDX JSON SBOMs from digest-pinned "
            "linux/amd64 image references."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=(
            "digest result JSON "
            f"(default: {DEFAULT_INPUT_PATH.as_posix()})"
        ),
    )
    parser.add_argument(
        "--repository",
        help="process only the named repository from the input",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
        help=(
            "SBOM output directory "
            f"(default: {DEFAULT_OUTPUT_DIRECTORY.as_posix()})"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="atomically replace an existing SBOM only after validation",
    )
    return parser


def validate_digest(value: Any) -> str:
    """Validate and return a lowercase sha256 digest."""

    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        raise InputValidationError(
            "platform_manifest_digest must match sha256 followed by "
            f"64 lowercase hexadecimal characters; received {value!r}"
        )
    return value


def required_string(
    mapping: dict[str, Any],
    key: str,
    context: str,
) -> str:
    """Read one required, non-empty string."""

    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise InputValidationError(
            f"{context}.{key} must be a non-empty string"
        )
    if value != value.strip() or any(
        character.isspace() for character in value
    ):
        raise InputValidationError(
            f"{context}.{key} must not contain whitespace"
        )
    return value


def validate_top_level(document: Any) -> dict[str, Any]:
    """Validate the stable envelope of image-digests.json."""

    if not isinstance(document, dict):
        raise InputValidationError("input JSON root must be an object")
    if (
        not isinstance(document.get("schema_version"), int)
        or isinstance(document.get("schema_version"), bool)
        or document["schema_version"] != 1
    ):
        raise InputValidationError("input.schema_version must be 1")

    platform = document.get("platform")
    if not isinstance(platform, dict):
        raise InputValidationError("input.platform must be an object")
    if (
        platform.get("os") != PILOT_OS
        or platform.get("architecture") != PILOT_ARCHITECTURE
    ):
        raise InputValidationError(
            "input platform must be linux/amd64; received "
            f"{platform.get('os')}/{platform.get('architecture')}"
        )

    images = document.get("images")
    if not isinstance(images, list):
        raise InputValidationError("input.images must be an array")
    return document


def load_digest_input(input_path: Path) -> dict[str, Any]:
    """Load JSON input and validate its top-level structure."""

    try:
        with input_path.open("r", encoding="utf-8") as input_file:
            document = json.load(input_file)
    except FileNotFoundError as error:
        raise InputValidationError(
            f"input file does not exist: {input_path}"
        ) from error
    except OSError as error:
        raise InputValidationError(
            f"cannot read input file {input_path}: {error}"
        ) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InputValidationError(
            f"input file is not valid UTF-8 JSON: {input_path}: {error}"
        ) from error
    return validate_top_level(document)


def repository_name(normalized_repository: Any) -> str:
    """Extract the last path element from a normalized repository."""

    if (
        not isinstance(normalized_repository, str)
        or not normalized_repository
        or normalized_repository != normalized_repository.strip()
        or any(
            character.isspace()
            for character in normalized_repository
        )
        or normalized_repository.startswith("/")
        or normalized_repository.endswith("/")
        or "@" in normalized_repository
    ):
        raise InputValidationError(
            "normalized_repository must be a non-empty repository path"
        )
    name = normalized_repository.rsplit("/", 1)[-1]
    if not name:
        raise InputValidationError(
            "normalized_repository has no repository name"
        )
    return name


def validate_filename_component(value: str, label: str) -> str:
    """Reject path syntax while preserving the input component exactly."""

    if FILENAME_COMPONENT_PATTERN.fullmatch(value) is None:
        raise InputValidationError(
            f"{label} cannot be used safely in an SBOM filename: {value!r}"
        )
    return value


def sbom_output_filename(
    normalized_repository: str,
    input_tag: str,
) -> str:
    """Build <repository>-<tag>.cdx.json without changing either value."""

    name = validate_filename_component(
        repository_name(normalized_repository),
        "repository name",
    )
    tag = validate_filename_component(input_tag, "input tag")
    return f"{name}-{tag}.cdx.json"


def validate_image_entry(
    image: Any,
    index: int | None = None,
) -> dict[str, str]:
    """Validate one successful digest result before it reaches Syft."""

    context = (
        f"input.images[{index}]" if index is not None else "image"
    )
    if not isinstance(image, dict):
        raise InputValidationError(f"{context} must be an object")
    if image.get("status") != "success":
        raise InputValidationError(
            f"{context}.status must be 'success'"
        )
    if image.get("target_os") != PILOT_OS:
        raise InputValidationError(
            f"{context}.target_os must be 'linux'"
        )
    if image.get("target_architecture") != PILOT_ARCHITECTURE:
        raise InputValidationError(
            f"{context}.target_architecture must be 'amd64'"
        )

    normalized_repository = required_string(
        image,
        "normalized_repository",
        context,
    )
    input_tag = required_string(image, "input_tag", context)
    digest = validate_digest(image.get("platform_manifest_digest"))
    pinned_reference = required_string(
        image,
        "pinned_reference",
        context,
    )
    pinned_repository, separator, pinned_digest = (
        pinned_reference.rpartition("@")
    )
    if (
        separator != "@"
        or pinned_repository != normalized_repository
        or pinned_digest != digest
    ):
        raise InputValidationError(
            f"{context}.pinned_reference must equal "
            f"{normalized_repository}@{digest}"
        )

    sbom_output_filename(normalized_repository, input_tag)
    return {
        "normalized_repository": normalized_repository,
        "input_tag": input_tag,
        "platform_manifest_digest": digest,
        "pinned_reference": pinned_reference,
        "repository": repository_name(normalized_repository),
    }


def select_repository(
    images: Sequence[Any],
    requested_repository: str | None,
) -> list[Any]:
    """Select one repository without changing input order."""

    if requested_repository is None:
        return list(images)
    if (
        not requested_repository
        or requested_repository != requested_repository.strip()
        or any(
            character.isspace() for character in requested_repository
        )
        or "/" in requested_repository
    ):
        raise RepositoryNotFoundError(
            f"invalid repository selector: {requested_repository!r}"
        )

    matches = []
    for image in images:
        if not isinstance(image, dict):
            continue
        try:
            name = repository_name(image.get("normalized_repository"))
        except InputValidationError:
            continue
        if name == requested_repository:
            matches.append(image)

    if not matches:
        raise RepositoryNotFoundError(
            f"repository not found in input: {requested_repository}"
        )
    if len(matches) > 1:
        raise InputValidationError(
            f"repository is not unique in input: {requested_repository}"
        )
    return matches


def build_syft_environment(
    base_environment: dict[str, str] | None = None,
) -> dict[str, str]:
    """Preserve the environment and set the fixed offline-safe options."""

    environment = dict(
        os.environ if base_environment is None else base_environment
    )
    environment["SYFT_FORMAT_CYCLONEDX_JSON_PRETTY"] = "true"
    environment["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    return environment


def completed_output(value: Any) -> str:
    """Convert a subprocess output value to displayable text."""

    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def check_syft_version(
    runner: Runner | None = None,
) -> str:
    """Require exactly Syft 1.49.0 before any image processing."""

    command = ["syft", "version", "-o", "json"]
    run = subprocess.run if runner is None else runner
    try:
        completed = run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            env=build_syft_environment(),
        )
    except FileNotFoundError as error:
        raise SyftNotFoundError(
            "Syft executable was not found in PATH"
        ) from error
    except OSError as error:
        raise SyftVersionError(
            f"cannot execute Syft version command: {error}"
        ) from error

    stderr = completed_output(completed.stderr).strip()
    if completed.returncode != 0:
        message = (
            "Syft version command failed with exit status "
            f"{completed.returncode}"
        )
        if stderr:
            message = f"{message}: {stderr}"
        raise SyftVersionError(message)

    stdout = completed_output(completed.stdout)
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise SyftVersionError(
            f"Syft version output is not valid JSON: {error}"
        ) from error
    if not isinstance(document, dict):
        raise SyftVersionError(
            "Syft version output must be a JSON object"
        )
    version = document.get("version")
    if not isinstance(version, str) or not version:
        raise SyftVersionError(
            "Syft version output has no non-empty 'version' string"
        )
    normalized_version = (
        version[1:] if version.startswith("v") else version
    )
    if normalized_version != EXPECTED_SYFT_VERSION:
        raise SyftVersionError(
            "Syft version mismatch: expected "
            f"{EXPECTED_SYFT_VERSION}, found {version}"
        )
    return normalized_version


def build_syft_command(
    pinned_reference: str,
    temporary_output_path: Path,
) -> list[str]:
    """Build the fixed registry-based, squashed CycloneDX scan command."""

    return [
        "syft",
        "scan",
        pinned_reference,
        "--from",
        "registry",
        "--platform",
        PILOT_PLATFORM,
        "--scope",
        "squashed",
        "--output",
        f"cyclonedx-json={temporary_output_path}",
    ]


def validate_cyclonedx_output(output_path: Path) -> dict[str, Any]:
    """Validate the required basic structure of a generated SBOM."""

    try:
        if not output_path.is_file():
            raise CycloneDxValidationError(
                f"Syft did not create an output file: {output_path}"
            )
        if output_path.stat().st_size == 0:
            raise CycloneDxValidationError(
                f"Syft output file is empty: {output_path}"
            )
        with output_path.open("r", encoding="utf-8") as output_file:
            document = json.load(output_file)
    except CycloneDxValidationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CycloneDxValidationError(
            f"Syft output is not valid UTF-8 JSON: {output_path}: {error}"
        ) from error

    if not isinstance(document, dict):
        raise CycloneDxValidationError(
            "CycloneDX output root must be a JSON object"
        )
    if document.get("bomFormat") != "CycloneDX":
        raise CycloneDxValidationError(
            "CycloneDX output bomFormat must be 'CycloneDX'"
        )
    spec_version = document.get("specVersion")
    if not isinstance(spec_version, str) or not spec_version:
        raise CycloneDxValidationError(
            "CycloneDX output specVersion must be non-empty"
        )
    if not isinstance(document.get("components"), list):
        raise CycloneDxValidationError(
            "CycloneDX output components must be an array"
        )
    return document


def publish_temporary_output(
    temporary_path: Path,
    final_path: Path,
    overwrite: bool,
) -> None:
    """Publish a validated file atomically without unintended replacement."""

    if overwrite:
        os.replace(temporary_path, final_path)
        return
    try:
        os.link(temporary_path, final_path)
    except FileExistsError as error:
        raise OutputExistsError(
            f"refusing to overwrite existing SBOM: {final_path}"
        ) from error
    temporary_path.unlink()


def generate_single_sbom(
    image: Any,
    output_directory: Path,
    overwrite: bool = False,
    runner: Runner | None = None,
    index: int | None = None,
) -> Path:
    """Generate, validate, and atomically publish one image SBOM."""

    validated = validate_image_entry(image, index=index)
    final_path = output_directory / sbom_output_filename(
        validated["normalized_repository"],
        validated["input_tag"],
    )
    if final_path.exists() and not overwrite:
        raise OutputExistsError(
            f"refusing to overwrite existing SBOM: {final_path}"
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=output_directory,
        prefix=f".{final_path.name}.",
        suffix=".tmp",
    )
    os.close(file_descriptor)
    temporary_path = Path(temporary_name)
    run = subprocess.run if runner is None else runner

    try:
        command = build_syft_command(
            validated["pinned_reference"],
            temporary_path,
        )
        try:
            completed = run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                env=build_syft_environment(),
            )
        except FileNotFoundError as error:
            raise SyftNotFoundError(
                "Syft executable was not found in PATH"
            ) from error
        except OSError as error:
            raise SyftCommandError(
                f"cannot execute Syft scan command: {error}"
            ) from error

        if completed.returncode != 0:
            stderr = completed_output(completed.stderr).strip()
            message = (
                "Syft command failed with exit status "
                f"{completed.returncode}"
            )
            if stderr:
                message = f"{message}: {stderr}"
            raise SyftCommandError(message)

        validate_cyclonedx_output(temporary_path)
        if final_path.exists() and not overwrite:
            raise OutputExistsError(
                f"refusing to overwrite existing SBOM: {final_path}"
            )
        publish_temporary_output(
            temporary_path,
            final_path,
            overwrite,
        )
        return final_path
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def image_display_name(image: Any, index: int) -> str:
    """Build a best-effort terminal label without validating the item."""

    if isinstance(image, dict):
        repository = image.get("normalized_repository")
        tag = image.get("input_tag")
        try:
            name = repository_name(repository)
        except InputValidationError:
            name = f"images[{index}]"
        if isinstance(tag, str) and tag:
            return f"{name}:{tag}"
        return name
    return f"images[{index}]"


def process_images(
    images: Sequence[Any],
    output_directory: Path,
    overwrite: bool = False,
    runner: Runner | None = None,
) -> RunSummary:
    """Process every selected image in order and continue after failures."""

    success_count = 0
    failure_count = 0
    for index, image in enumerate(images):
        label = image_display_name(image, index)
        try:
            output_path = generate_single_sbom(
                image,
                output_directory,
                overwrite=overwrite,
                runner=runner,
                index=index,
            )
        except Exception as error:
            failure_count += 1
            print(f"[failed] {label} -> {error}", file=sys.stderr)
            continue
        success_count += 1
        print(f"[success] {label} -> {output_path}")

    return RunSummary(
        total=len(images),
        success=success_count,
        failed=failure_count,
    )


def print_summary(summary: RunSummary) -> None:
    """Print the stable terminal summary."""

    print(f"total: {summary.total}")
    print(f"success: {summary.success}")
    print(f"failed: {summary.failed}")


def exit_code_for_summary(summary: RunSummary) -> int:
    """Return success only when every selected image succeeded."""

    return 0 if summary.failed == 0 else 1


def main(argv: Sequence[str] | None = None) -> int:
    """Coordinate CLI validation, version checking, and ordered scans."""

    arguments = build_parser().parse_args(argv)
    try:
        document = load_digest_input(arguments.input)
        selected_images = select_repository(
            document["images"],
            arguments.repository,
        )
        check_syft_version()
    except SbomGenerationError as error:
        print(f"[error] {error}", file=sys.stderr)
        return 2

    summary = process_images(
        selected_images,
        arguments.output_dir,
        overwrite=arguments.overwrite,
    )
    print_summary(summary)
    return exit_code_for_summary(summary)


if __name__ == "__main__":
    raise SystemExit(main())

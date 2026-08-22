#!/usr/bin/env python3
"""Render the NVD Configuration/CPE Dictionary coverage paper figure.

The script is intentionally independent of Django and reads only the supplied
summary JSON. All plotted widths and displayed values are derived from raw
counts in that file.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from typing import Any, Mapping, Sequence
import xml.etree.ElementTree as ET


# Keep Matplotlib's cache in a writable location and remove time-based PDF
# metadata at the backend level before importing Matplotlib.
os.environ.setdefault(
    "MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "cpe-validation-matplotlib")
)
os.environ["SOURCE_DATE_EPOCH"] = "0"

import matplotlib  # noqa: E402

matplotlib.use("Agg")

from matplotlib import pyplot as plt  # noqa: E402
from matplotlib.artist import Artist  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402
from matplotlib.text import Text  # noqa: E402


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parents[1]
STYLE_PATH = SCRIPT_DIR / "paper.mplstyle"
DEFAULT_SUMMARY = (
    REPOSITORY_ROOT
    / "analysis/results/nvd-cpe-dictionary-coverage"
    / "20260820T110357Z__20260819T035002Z/summary.json"
)
DEFAULT_OUTPUT_DIR = (
    SCRIPT_DIR
    / "generated/nvd-cpe-dictionary-coverage"
    / "20260820T110357Z__20260819T035002Z"
)

FIGURE_SIZE_INCHES = (7.0, 2.05)
PNG_DPI = 600
SVG_HASHSALT = "nvd-cpe-dictionary-coverage-v1"
OUTPUT_BASENAME = "nvd_cpe_dictionary_coverage"

CATEGORY_KEYS = (
    "EXACT_PRESENT",
    "EXACT_ABSENT_SAME_PRODUCT_TUPLE_PRESENT",
    "EXACT_ABSENT_SAME_PRODUCT_TUPLE_ABSENT",
)
CATEGORY_LABELS = (
    "Exact match",
    "Same product only",
    "No matching product",
)

# These values are validation guards supplied with the figure specification.
# Figure geometry and text are always computed from the loaded raw counts.
EXPECTED_INPUT = {
    "expression_total": 428_417,
    "expression_counts": (269_267, 83_194, 75_956),
    "occurrence_total": 3_170_148,
    "occurrence_counts": (2_413_552, 599_022, 157_574),
    "absent_product_tuple_count": 31_895,
    "expression_percentages": (62.85, 19.42, 17.73),
    "occurrence_percentages": (76.13, 18.90, 4.97),
}

COLOR_FILLS = ("#0072B2", "#E69F00", "#D55E00")
COLOR_TEXT = ("#FFFFFF", "#171717", "#FFFFFF")
MONO_FILLS = ("#4A4A4A", "#B5B5B5", "#E4E4E4")
MONO_TEXT = ("#FFFFFF", "#171717", "#171717")
MONO_HATCHES = ("", "////", "xx")
NEUTRAL_TEXT = "#5F6368"
LEADER_COLOR = "#72777D"
BAR_HEIGHT = 0.35


class FigureInputError(ValueError):
    """Raised when the source summary does not match the documented schema."""


@dataclass(frozen=True)
class BarData:
    """Raw counts and derived percentages for one 100% stacked bar."""

    label: str
    total: int
    counts: tuple[int, int, int]

    @property
    def percentages(self) -> tuple[float, float, float]:
        return tuple(count / self.total * 100.0 for count in self.counts)  # type: ignore[return-value]


@dataclass(frozen=True)
class CoverageData:
    """Validated values needed to render the figure and caption."""

    expressions: BarData
    occurrences: BarData
    absent_product_tuple_count: int
    nvd_snapshot: str
    cpe_snapshot: str


@dataclass(frozen=True)
class PngMetadata:
    """PNG dimensions and physical resolution parsed from PNG chunks."""

    width: int
    height: int
    dpi_x: float
    dpi_y: float


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate publication outputs for NVD CPE Dictionary coverage "
            "from a precomputed summary.json."
        )
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=DEFAULT_SUMMARY,
        help=f"Input coverage summary JSON (default: {DEFAULT_SUMMARY})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory for generated outputs (default: {DEFAULT_OUTPUT_DIR})",
    )
    return parser.parse_args(argv)


def load_summary(path: Path) -> Mapping[str, Any]:
    """Load the summary JSON after checking that it is a regular file."""

    if not path.exists():
        raise FigureInputError(f"Input summary does not exist: {path}")
    if not path.is_file():
        raise FigureInputError(f"Input summary is not a regular file: {path}")
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FigureInputError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise FigureInputError("Input summary root must be a JSON object")
    return loaded


def require_mapping(parent: Mapping[str, Any], key: str, context: str) -> Mapping[str, Any]:
    if key not in parent:
        raise FigureInputError(f"Missing JSON key: {context}.{key}")
    value = parent[key]
    if not isinstance(value, dict):
        raise FigureInputError(f"Expected object at {context}.{key}, got {type(value).__name__}")
    return value


def require_int(parent: Mapping[str, Any], key: str, context: str) -> int:
    if key not in parent:
        raise FigureInputError(f"Missing JSON key: {context}.{key}")
    value = parent[key]
    if type(value) is not int:  # Reject booleans, which are int subclasses in Python.
        raise FigureInputError(f"Expected integer at {context}.{key}, got {type(value).__name__}")
    if value < 0:
        raise FigureInputError(f"Expected non-negative count at {context}.{key}, got {value}")
    return value


def require_number(parent: Mapping[str, Any], key: str, context: str) -> float:
    if key not in parent:
        raise FigureInputError(f"Missing JSON key: {context}.{key}")
    value = parent[key]
    if type(value) not in (int, float):
        raise FigureInputError(f"Expected number at {context}.{key}, got {type(value).__name__}")
    return float(value)


def require_string(parent: Mapping[str, Any], key: str, context: str) -> str:
    if key not in parent:
        raise FigureInputError(f"Missing JSON key: {context}.{key}")
    value = parent[key]
    if not isinstance(value, str) or not value:
        raise FigureInputError(f"Expected non-empty string at {context}.{key}")
    return value


def extract_coverage_counts(summary: Mapping[str, Any]) -> CoverageData:
    """Map the documented summary schema to the values used by the figure."""

    overall = require_mapping(summary, "overall_coverage", "root")
    total = require_mapping(overall, "total", "root.overall_coverage")
    classes = require_mapping(overall, "coverage_classes", "root.overall_coverage")
    dataset = require_mapping(summary, "dataset", "root")
    absent_tuples = require_mapping(
        summary, "configuration_only_product_tuples", "root"
    )

    expression_counts: list[int] = []
    occurrence_counts: list[int] = []
    stored_expression_percentages: list[float] = []
    stored_occurrence_percentages: list[float] = []
    for class_key in CATEGORY_KEYS:
        item = require_mapping(
            classes, class_key, "root.overall_coverage.coverage_classes"
        )
        expression_counts.append(
            require_int(
                item,
                "distinct_criteria_expression_count",
                f"root.overall_coverage.coverage_classes.{class_key}",
            )
        )
        occurrence_counts.append(
            require_int(
                item,
                "occurrence_count",
                f"root.overall_coverage.coverage_classes.{class_key}",
            )
        )

        # Validate the summary's stored percentages, but never use them for
        # geometry or labels.
        stored_expression_percentage = require_number(
            item,
            "expression_percent_within_group",
            f"root.overall_coverage.coverage_classes.{class_key}",
        )
        stored_occurrence_percentage = require_number(
            item,
            "occurrence_percent_within_group",
            f"root.overall_coverage.coverage_classes.{class_key}",
        )
        if not math.isfinite(stored_expression_percentage) or not math.isfinite(
            stored_occurrence_percentage
        ):
            raise FigureInputError(f"Non-finite percentage stored for {class_key}")
        stored_expression_percentages.append(stored_expression_percentage)
        stored_occurrence_percentages.append(stored_occurrence_percentage)

    expressions = BarData(
        label="Unique CPE expressions",
        total=require_int(
            total,
            "distinct_criteria_expression_count",
            "root.overall_coverage.total",
        ),
        counts=tuple(expression_counts),  # type: ignore[arg-type]
    )
    occurrences = BarData(
        label="CPE expression occurrences",
        total=require_int(total, "occurrence_count", "root.overall_coverage.total"),
        counts=tuple(occurrence_counts),  # type: ignore[arg-type]
    )
    data = CoverageData(
        expressions=expressions,
        occurrences=occurrences,
        absent_product_tuple_count=require_int(
            absent_tuples,
            "distinct_product_tuple_count",
            "root.configuration_only_product_tuples",
        ),
        nvd_snapshot=require_string(dataset, "nvd_snapshot_id", "root.dataset"),
        cpe_snapshot=require_string(
            dataset, "cpe_dictionary_snapshot_id", "root.dataset"
        ),
    )

    dataset_expression_total = require_int(
        dataset, "distinct_configuration_criteria_expression_count", "root.dataset"
    )
    dataset_occurrence_total = require_int(
        dataset, "cpe_match_occurrence_count", "root.dataset"
    )
    if dataset_expression_total != data.expressions.total:
        raise FigureInputError(
            "Dataset and overall expression totals differ: "
            f"{dataset_expression_total:,} != {data.expressions.total:,}"
        )
    if dataset_occurrence_total != data.occurrences.total:
        raise FigureInputError(
            "Dataset and overall occurrence totals differ: "
            f"{dataset_occurrence_total:,} != {data.occurrences.total:,}"
        )

    stored_absent_expression_count = require_int(
        absent_tuples,
        "criteria_expressions_with_parseable_tuple",
        "root.configuration_only_product_tuples",
    )
    if stored_absent_expression_count != data.expressions.counts[2]:
        raise FigureInputError(
            "Product-tuple-absent expression counts differ across summary sections: "
            f"{stored_absent_expression_count:,} != {data.expressions.counts[2]:,}"
        )

    for index, class_key in enumerate(CATEGORY_KEYS):
        percentage_pairs = (
            (
                "expression",
                stored_expression_percentages[index],
                data.expressions.percentages[index],
            ),
            (
                "occurrence",
                stored_occurrence_percentages[index],
                data.occurrences.percentages[index],
            ),
        )
        for measure, stored, calculated in percentage_pairs:
            if not math.isclose(stored, calculated, rel_tol=0.0, abs_tol=1e-7):
                raise FigureInputError(
                    f"Stored {measure} percentage for {class_key} does not match "
                    f"its raw counts: {stored:.8f} != {calculated:.8f}"
                )
    return data


def validate_counts(data: CoverageData) -> None:
    """Check count invariants, displayed percentages, and expected input values."""

    differences: list[str] = []

    for bar in (data.expressions, data.occurrences):
        category_sum = sum(bar.counts)
        if category_sum != bar.total:
            differences.append(
                f"{bar.label}: category sum {category_sum:,} != total {bar.total:,}"
            )
        percentage_sum = sum(bar.percentages)
        if not math.isclose(percentage_sum, 100.0, rel_tol=0.0, abs_tol=1e-10):
            differences.append(
                f"{bar.label}: raw-count percentages sum to {percentage_sum:.12f}%"
            )

    expected_pairs = (
        (
            "expression total",
            data.expressions.total,
            EXPECTED_INPUT["expression_total"],
        ),
        (
            "expression category counts",
            data.expressions.counts,
            EXPECTED_INPUT["expression_counts"],
        ),
        (
            "occurrence total",
            data.occurrences.total,
            EXPECTED_INPUT["occurrence_total"],
        ),
        (
            "occurrence category counts",
            data.occurrences.counts,
            EXPECTED_INPUT["occurrence_counts"],
        ),
        (
            "distinct absent product tuples",
            data.absent_product_tuple_count,
            EXPECTED_INPUT["absent_product_tuple_count"],
        ),
        (
            "expression displayed percentages",
            tuple(round(value, 2) for value in data.expressions.percentages),
            EXPECTED_INPUT["expression_percentages"],
        ),
        (
            "occurrence displayed percentages",
            tuple(round(value, 2) for value in data.occurrences.percentages),
            EXPECTED_INPUT["occurrence_percentages"],
        ),
    )
    for name, actual, expected in expected_pairs:
        if actual != expected:
            differences.append(f"{name}: expected {expected!r}, found {actual!r}")

    if differences:
        detail = "\n  - ".join(differences)
        raise FigureInputError(
            "Input summary does not match the validated figure specification:\n"
            f"  - {detail}"
        )


def build_color_figure(data: CoverageData) -> Figure:
    return build_figure(data, monochrome=False)


def build_monochrome_figure(data: CoverageData) -> Figure:
    return build_figure(data, monochrome=True)


def build_figure(data: CoverageData, *, monochrome: bool) -> Figure:
    """Build one aligned two-row 100% stacked-bar figure."""

    fills = MONO_FILLS if monochrome else COLOR_FILLS
    text_colors = MONO_TEXT if monochrome else COLOR_TEXT
    hatches = MONO_HATCHES if monochrome else ("", "", "")

    with plt.style.context(STYLE_PATH):
        matplotlib.rcParams["svg.hashsalt"] = SVG_HASHSALT
        figure = plt.figure(figsize=FIGURE_SIZE_INCHES, constrained_layout=False)
        axes = figure.add_axes((0.055, 0.06, 0.91, 0.76))

        bars = (data.expressions, data.occurrences)
        y_positions = (0.68, -0.10)

        for row_index, (bar, y_position) in enumerate(zip(bars, y_positions)):
            left = 0.0
            for category_index, (percentage, count) in enumerate(
                zip(bar.percentages, bar.counts)
            ):
                edge_color = "#555555" if monochrome else "#FFFFFF"
                axes.barh(
                    y_position,
                    percentage,
                    left=left,
                    height=BAR_HEIGHT,
                    color=fills[category_index],
                    edgecolor=edge_color,
                    linewidth=0.7 if monochrome else 1.0,
                    hatch=hatches[category_index],
                    zorder=2,
                )

                is_external_label = row_index == 1 and category_index == 2
                if not is_external_label:
                    center = left + percentage / 2.0
                    axes.text(
                        center,
                        y_position + 0.048,
                        f"{percentage:.2f}%",
                        color=text_colors[category_index],
                        fontsize=8.2,
                        fontweight="bold",
                        ha="center",
                        va="center",
                        zorder=6,
                    )
                    axes.text(
                        center,
                        y_position - 0.079,
                        f"{count:,}",
                        color=text_colors[category_index],
                        fontsize=7.1,
                        ha="center",
                        va="center",
                        zorder=6,
                    )
                left += percentage

            # Make monochrome segment boundaries unmistakable without relying
            # on fill shade or hatch alone.
            if monochrome:
                boundaries = (
                    bar.percentages[0],
                    bar.percentages[0] + bar.percentages[1],
                )
                axes.vlines(
                    boundaries,
                    y_position - BAR_HEIGHT / 2,
                    y_position + BAR_HEIGHT / 2,
                    colors="#FFFFFF",
                    linewidth=1.15,
                    zorder=5,
                )

            axes.text(
                -40.0,
                y_position + 0.035,
                bar.label,
                color="#202124",
                fontsize=7.7,
                fontweight="semibold",
                ha="left",
                va="bottom",
            )
            axes.text(
                -40.0,
                y_position - 0.045,
                f"n = {bar.total:,}",
                color=NEUTRAL_TEXT,
                fontsize=7.05,
                ha="left",
                va="top",
            )

        external_percentage = data.occurrences.percentages[2]
        external_count = data.occurrences.counts[2]
        external_y = y_positions[1]
        axes.plot(
            (99.0, 100.2, 101.3),
            (
                external_y + BAR_HEIGHT * 0.25,
                external_y + BAR_HEIGHT * 0.25,
                external_y + 0.095,
            ),
            color=LEADER_COLOR,
            linewidth=0.65,
            solid_capstyle="round",
            zorder=7,
        )
        axes.text(
            102.1,
            external_y + 0.052,
            f"{external_percentage:.2f}%",
            color="#202124",
            fontsize=8.1,
            fontweight="bold",
            ha="left",
            va="center",
            zorder=7,
        )
        axes.text(
            102.1,
            external_y - 0.076,
            f"{external_count:,}",
            color=NEUTRAL_TEXT,
            fontsize=7.05,
            ha="left",
            va="center",
            zorder=7,
        )

        legend_handles = [
            Patch(
                facecolor=fills[index],
                edgecolor="#555555" if monochrome else "#FFFFFF",
                linewidth=0.7,
                hatch=hatches[index],
                label=label,
            )
            for index, label in enumerate(CATEGORY_LABELS)
        ]
        figure.legend(
            handles=legend_handles,
            loc="upper center",
            bbox_to_anchor=(0.61, 0.92),
            ncol=3,
            borderaxespad=0.0,
            handlelength=1.25,
            handleheight=0.72,
            handletextpad=0.38,
            columnspacing=1.25,
            frameon=False,
        )

        axes.set_xlim(-34.5, 112.0)
        axes.set_ylim(-0.50, 1.06)
        axes.set_xticks([])
        axes.set_yticks([])
        axes.grid(False)
        for spine in axes.spines.values():
            spine.set_visible(False)

        figure.canvas.draw()
        validate_artist_bounds(figure)
        return figure


def validate_artist_bounds(figure: Figure) -> None:
    """Fail if any visible text or legend extends beyond the figure canvas."""

    renderer = figure.canvas.get_renderer()
    canvas = figure.bbox
    tolerance_pixels = 0.75
    outside: list[str] = []

    candidates: list[Artist] = list(figure.findobj(match=Text))
    if figure.legends:
        candidates.extend(figure.legends)
    for artist in candidates:
        if not artist.get_visible():
            continue
        if isinstance(artist, Text) and not artist.get_text():
            continue
        extent = artist.get_window_extent(renderer)
        if (
            extent.x0 < canvas.x0 - tolerance_pixels
            or extent.y0 < canvas.y0 - tolerance_pixels
            or extent.x1 > canvas.x1 + tolerance_pixels
            or extent.y1 > canvas.y1 + tolerance_pixels
        ):
            label = artist.get_text() if isinstance(artist, Text) else "legend"
            outside.append(label)

    if outside:
        raise RuntimeError(
            "Figure layout validation found clipped artists: " + ", ".join(outside)
        )


def build_caption(data: CoverageData) -> str:
    """Create a concise paper caption using only values extracted from JSON."""

    return (
        "**Figure. Coverage of NVD Configuration CPE expressions by the CPE "
        "Dictionary.** "
        "“Unique CPE expressions” denotes distinct CPE 2.3 criteria strings "
        "observed in NVD CVE Configurations, while “CPE expression occurrences” "
        "counts all `cpeMatch` occurrences. “Exact match” requires an identical "
        "CPE name in the Dictionary. “Same product only” denotes no exact match "
        "but at least one Dictionary entry with the same `(part, vendor, product)` "
        "tuple; “No matching product” means that tuple is also absent. The "
        f"{data.expressions.counts[2]:,} expressions in the latter class correspond "
        f"to {data.absent_product_tuple_count:,} distinct product tuples.\n"
    )


def save_figure(figure: Figure, path: Path) -> None:
    suffix = path.suffix.lower()
    common: dict[str, Any] = {"transparent": False}
    if suffix == ".pdf":
        common["metadata"] = {
            "Title": "NVD CPE Dictionary coverage",
            "Author": "",
            "Subject": "Coverage of NVD Configuration CPE expressions",
            "Keywords": "",
            "Creator": "Matplotlib",
            "Producer": "Matplotlib",
            "CreationDate": None,
            "ModDate": None,
        }
    elif suffix == ".svg":
        common["metadata"] = {"Date": None, "Creator": "Matplotlib"}
    elif suffix == ".png":
        common["dpi"] = PNG_DPI
        common["metadata"] = {"Software": "Matplotlib"}
    else:
        raise RuntimeError(f"Unsupported output format: {path}")
    # Saving occurs after build_figure() returns, so re-enter the shared style
    # context here to retain vector-font, bounding-box, and deterministic SVG
    # settings in every backend.
    with plt.style.context(STYLE_PATH):
        matplotlib.rcParams["svg.hashsalt"] = SVG_HASHSALT
        figure.savefig(path, **common)


def save_outputs(data: CoverageData, output_dir: Path) -> Mapping[str, Path]:
    """Render, validate, and atomically publish all required outputs."""

    output_dir.mkdir(parents=True, exist_ok=True)
    temporary_dir = Path(
        tempfile.mkdtemp(prefix=".nvd-cpe-figure-", dir=output_dir.parent)
    )
    paths = {
        "pdf": output_dir / f"{OUTPUT_BASENAME}.pdf",
        "svg": output_dir / f"{OUTPUT_BASENAME}.svg",
        "png": output_dir / f"{OUTPUT_BASENAME}.png",
        "monochrome_pdf": output_dir / f"{OUTPUT_BASENAME}_monochrome.pdf",
        "monochrome_png": output_dir / f"{OUTPUT_BASENAME}_monochrome.png",
        "caption": output_dir / "caption.md",
    }
    staged = {name: temporary_dir / path.name for name, path in paths.items()}

    color_figure: Figure | None = None
    monochrome_figure: Figure | None = None
    try:
        color_figure = build_color_figure(data)
        save_figure(color_figure, staged["pdf"])
        save_figure(color_figure, staged["svg"])
        save_figure(color_figure, staged["png"])

        monochrome_figure = build_monochrome_figure(data)
        save_figure(monochrome_figure, staged["monochrome_pdf"])
        save_figure(monochrome_figure, staged["monochrome_png"])
        staged["caption"].write_text(build_caption(data), encoding="utf-8")

        validate_output_files(staged)
        for name, final_path in paths.items():
            os.replace(staged[name], final_path)
        return paths
    finally:
        if color_figure is not None:
            plt.close(color_figure)
        if monochrome_figure is not None:
            plt.close(monochrome_figure)
        shutil.rmtree(temporary_dir, ignore_errors=True)


def validate_output_files(paths: Mapping[str, Path]) -> None:
    for name, path in paths.items():
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f"Missing or empty staged output ({name}): {path}")

    for key in ("pdf", "monochrome_pdf"):
        content = paths[key].read_bytes()
        if not content.startswith(b"%PDF-") or b"%%EOF" not in content[-1024:]:
            raise RuntimeError(f"Invalid PDF structure: {paths[key]}")

    try:
        svg_root = ET.parse(paths["svg"]).getroot()
    except ET.ParseError as exc:
        raise RuntimeError(f"SVG XML parse failed: {paths['svg']}: {exc}") from exc
    if svg_root.tag.rsplit("}", 1)[-1] != "svg":
        raise RuntimeError(f"SVG document has unexpected root element: {svg_root.tag}")

    for key in ("png", "monochrome_png"):
        metadata = read_png_metadata(paths[key])
        if not math.isclose(metadata.dpi_x, PNG_DPI, abs_tol=0.5) or not math.isclose(
            metadata.dpi_y, PNG_DPI, abs_tol=0.5
        ):
            raise RuntimeError(
                f"PNG resolution is not {PNG_DPI} DPI: {paths[key]} "
                f"({metadata.dpi_x:.2f} x {metadata.dpi_y:.2f})"
            )
        expected_width = round(FIGURE_SIZE_INCHES[0] * PNG_DPI)
        expected_height = round(FIGURE_SIZE_INCHES[1] * PNG_DPI)
        if metadata.width != expected_width or metadata.height != expected_height:
            raise RuntimeError(
                f"PNG dimensions do not match the configured figure size: {paths[key]} "
                f"({metadata.width} x {metadata.height}, expected "
                f"{expected_width} x {expected_height})"
            )


def read_png_metadata(path: Path) -> PngMetadata:
    """Read IHDR and pHYs chunks without requiring Pillow."""

    width: int | None = None
    height: int | None = None
    pixels_per_meter_x: int | None = None
    pixels_per_meter_y: int | None = None
    unit: int | None = None

    with path.open("rb") as stream:
        if stream.read(8) != b"\x89PNG\r\n\x1a\n":
            raise RuntimeError(f"Invalid PNG signature: {path}")
        while True:
            length_bytes = stream.read(4)
            if len(length_bytes) != 4:
                break
            length = struct.unpack(">I", length_bytes)[0]
            chunk_type = stream.read(4)
            payload = stream.read(length)
            crc = stream.read(4)
            if len(payload) != length or len(crc) != 4:
                raise RuntimeError(f"Truncated PNG chunk in {path}")
            if chunk_type == b"IHDR":
                width, height = struct.unpack(">II", payload[:8])
            elif chunk_type == b"pHYs":
                pixels_per_meter_x, pixels_per_meter_y, unit = struct.unpack(">IIB", payload)
            elif chunk_type == b"IEND":
                break

    if width is None or height is None:
        raise RuntimeError(f"PNG has no IHDR chunk: {path}")
    if pixels_per_meter_x is None or pixels_per_meter_y is None or unit != 1:
        raise RuntimeError(f"PNG has no physical-resolution metadata: {path}")
    meters_per_inch = 0.0254
    return PngMetadata(
        width=width,
        height=height,
        dpi_x=pixels_per_meter_x * meters_per_inch,
        dpi_y=pixels_per_meter_y * meters_per_inch,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    summary_path = args.summary.resolve()
    output_dir = args.output_dir.resolve()

    try:
        summary = load_summary(summary_path)
        data = extract_coverage_counts(summary)
        validate_counts(data)
        outputs = save_outputs(data, output_dir)
    except (FigureInputError, OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Input summary: {summary_path}")
    print(f"Input SHA-256: {sha256_file(summary_path)}")
    print(f"Distinct expressions: {data.expressions.total:,}")
    print(f"Total occurrences: {data.occurrences.total:,}")
    print(f"Output PDF: {outputs['pdf']}")
    print(f"Output SVG: {outputs['svg']}")
    print(f"Output PNG: {outputs['png']}")
    print(f"Monochrome PDF: {outputs['monochrome_pdf']}")
    print(f"Monochrome PNG: {outputs['monochrome_png']}")
    print(f"Caption: {outputs['caption']}")
    print("Validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

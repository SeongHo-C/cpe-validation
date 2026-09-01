#!/usr/bin/env python3
"""Generate the RQ2 candidate-space composition paper figure.

Provenance:
  CPE Dictionary snapshot: 20260819T035002Z
  NVD Configuration snapshot: 20260820T110357Z

The verified counts are frozen so normal regeneration is offline and does
not query Django, a database, or the network. Family identity is the
canonical CPE 2.3 (part, vendor, product) tuple used by the candidate-space
analysis. NVD Configuration occurrences count every NvdCpeMatch row.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import tempfile


os.environ.setdefault(
    "MPLCONFIGDIR",
    str(Path(tempfile.gettempdir()) / "cpe-validation-matplotlib"),
)
os.environ["SOURCE_DATE_EPOCH"] = "0"

import matplotlib  # noqa: E402

matplotlib.use("Agg")

from matplotlib import font_manager, pyplot as plt  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
from matplotlib.text import Annotation, Text  # noqa: E402


SCRIPT_DIR = Path(__file__).resolve().parent
STYLE_PATH = SCRIPT_DIR / "paper.mplstyle"
OUTPUT_DIRECTORY = SCRIPT_DIR / "output"
OUTPUT_STEM = "cpe_candidate_space_composition"
OUTPUT_FORMATS = ("pdf", "png", "svg")

FIGURE_SIZE = (3.5, 0.85)
PNG_DPI = 600
BAR_HEIGHT = 0.42
Y_POSITIONS = (0.45, -0.35)
Y_LIMITS = (-0.75, 0.85)
AXES_BOUNDS = (0.030, 0.08, 0.940, 0.84)

FONT_SERIF_FALLBACKS = (
    "Times New Roman",
    "Times",
    "STIXGeneral",
    "DejaVu Serif",
)

ACTIVE_COLOR = "#557A9E"
CONFIGURATION_ONLY_COLOR = "#D9A24E"
OTHER_COLOR = "#CDD2D7"
COLORS = (
    ACTIVE_COLOR,
    CONFIGURATION_ONLY_COLOR,
    OTHER_COLOR,
)


@dataclass(frozen=True)
class CompositionBar:
    label: str
    total: int
    counts: tuple[int, int, int]

    @property
    def percentages(self) -> tuple[float, float, float]:
        return tuple(
            count / self.total * 100.0 for count in self.counts
        )  # type: ignore[return-value]


CANDIDATE_SPACE = CompositionBar(
    label="Candidate Space",
    total=181_493,
    counts=(149_598, 31_895, 0),
)
NVD_CONFIGURATION_OCCURRENCES = CompositionBar(
    label="NVD Configuration Occurrences",
    total=3_170_148,
    counts=(2_996_232, 157_574, 16_342),
)
COMPOSITION_BARS = (
    CANDIDATE_SPACE,
    NVD_CONFIGURATION_OCCURRENCES,
)
EXPECTED_PERCENTAGES = (
    (82.43, 17.57, 0.00),
    (94.51, 4.97, 0.52),
)


def select_serif_font_family() -> str:
    """Use Times New Roman when installed, with a quiet paper-serif fallback."""

    for family in FONT_SERIF_FALLBACKS:
        try:
            font_manager.findfont(
                font_manager.FontProperties(family=family),
                fallback_to_default=False,
            )
        except ValueError:
            continue
        return family
    raise RuntimeError("No supported serif font is available")


SELECTED_FONT_FAMILY = select_serif_font_family()


def relative_luminance(hex_color: str) -> float:
    channels: list[float] = []
    for start in (1, 3, 5):
        value = int(hex_color[start : start + 2], 16) / 255.0
        channels.append(
            value / 12.92
            if value <= 0.04045
            else ((value + 0.055) / 1.055) ** 2.4
        )
    red, green, blue = channels
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def validate_frozen_data() -> None:
    for bar, expected in zip(COMPOSITION_BARS, EXPECTED_PERCENTAGES):
        if sum(bar.counts) != bar.total:
            raise ValueError(
                f"{bar.label}: category sum {sum(bar.counts):,} "
                f"!= {bar.total:,}"
            )
        rounded = tuple(round(value, 2) for value in bar.percentages)
        if rounded != expected:
            raise ValueError(
                f"{bar.label}: percentages {rounded!r} != {expected!r}"
            )
        if not math.isclose(
            sum(bar.percentages),
            100.0,
            abs_tol=1e-10,
        ):
            raise ValueError(f"{bar.label}: percentages do not sum to 100%")

    luminances = [relative_luminance(color) for color in COLORS]
    minimum_separation = min(
        abs(left - right)
        for index, left in enumerate(luminances)
        for right in luminances[index + 1 :]
    )
    if minimum_separation < 0.20:
        raise ValueError("Category colors are too similar in grayscale")


def draw_stacked_bars(axes: object) -> None:
    for bar, y_position in zip(COMPOSITION_BARS, Y_POSITIONS):
        left = 0.0
        for category_index, (count, percentage) in enumerate(
            zip(bar.counts, bar.percentages)
        ):
            if count == 0:
                continue
            axes.barh(
                y_position,
                percentage,
                left=left,
                height=BAR_HEIGHT,
                color=COLORS[category_index],
                edgecolor="#FFFFFF",
                linewidth=0.25,
                zorder=3,
            )
            left += percentage


def style_axes(axes: object) -> None:
    axes.set_xlim(0.0, 100.0)
    axes.set_ylim(*Y_LIMITS)
    axes.set_xticks(())
    axes.set_yticks(())
    axes.grid(False)
    for spine in axes.spines.values():
        spine.set_visible(False)
    axes.set_axis_off()


def build_figure() -> Figure:
    validate_frozen_data()
    with plt.style.context(STYLE_PATH):
        matplotlib.rcParams.update(
            {
                "font.family": SELECTED_FONT_FAMILY,
                "font.size": 8.0,
                "font.weight": "normal",
                "axes.labelsize": 8.0,
                "xtick.labelsize": 8.0,
                "ytick.labelsize": 8.0,
                "legend.fontsize": 8.0,
                "pdf.fonttype": 42,
                "ps.fonttype": 42,
                "svg.fonttype": "none",
                "svg.hashsalt": "cpe-candidate-space-composition-v1",
            }
        )
        figure = plt.figure(figsize=FIGURE_SIZE, constrained_layout=False)
        axes = figure.add_axes(AXES_BOUNDS)
        draw_stacked_bars(axes)
        style_axes(axes)
        figure.canvas.draw()
        validate_figure(figure)
        return figure


def validate_figure(figure: Figure) -> None:
    if tuple(figure.get_size_inches()) != FIGURE_SIZE:
        raise RuntimeError("Figure dimensions differ from the IEEE target")
    if len(figure.axes) != 1:
        raise RuntimeError("The final figure must contain exactly one axis")

    axes = figure.axes[0]
    if axes.get_title():
        raise RuntimeError("The final figure must not contain an internal title")
    if tuple(axes.get_xlim()) != (0.0, 100.0):
        raise RuntimeError("The x-axis must span exactly 0 to 100 percent")
    if axes.axison:
        raise RuntimeError("The final figure axis must be disabled")
    if len(axes.get_xticks()) or len(axes.get_yticks()):
        raise RuntimeError("The final figure must not contain axis ticks")
    if any(spine.get_visible() for spine in axes.spines.values()):
        raise RuntimeError("The final figure must not contain visible spines")
    if any(
        line.get_visible()
        for line in (*axes.get_xgridlines(), *axes.get_ygridlines())
    ):
        raise RuntimeError("The final figure must not contain gridlines")

    expected_widths = (
        CANDIDATE_SPACE.percentages[0],
        CANDIDATE_SPACE.percentages[1],
        NVD_CONFIGURATION_OCCURRENCES.percentages[0],
        NVD_CONFIGURATION_OCCURRENCES.percentages[1],
        NVD_CONFIGURATION_OCCURRENCES.percentages[2],
    )
    patches = list(axes.patches)
    if len(patches) != len(expected_widths):
        raise RuntimeError(
            f"Expected {len(expected_widths)} positive segments, "
            f"found {len(patches)}"
        )
    if any(
        not math.isclose(patch.get_width(), expected, abs_tol=1e-10)
        for patch, expected in zip(patches, expected_widths)
    ):
        raise RuntimeError("A stacked segment differs from the frozen counts")

    visible_texts = [
        text
        for text in figure.findobj(match=Text)
        if text.get_visible() and text.get_text()
    ]
    if visible_texts:
        raise RuntimeError("The bar-only figure must not contain any text")
    if figure.legends:
        raise RuntimeError("The bar-only figure must not contain a legend")

    annotations = [
        text
        for text in figure.findobj(match=Annotation)
        if text.get_visible()
    ]
    if annotations:
        raise RuntimeError("The bar-only figure must not contain annotations")
    if any(line.get_visible() for line in axes.lines):
        raise RuntimeError("The bar-only figure must not contain guide lines")


def output_metadata(extension: str) -> dict[str, object]:
    if extension == "pdf":
        return {
            "Title": "CPE candidate space composition",
            "Author": "CPE Validation Research",
            "Subject": "RQ2 candidate source composition",
            "Creator": "Matplotlib",
            "Producer": "Matplotlib",
            "CreationDate": datetime(1970, 1, 1, tzinfo=timezone.utc),
            "ModDate": datetime(1970, 1, 1, tzinfo=timezone.utc),
        }
    if extension == "svg":
        return {
            "Title": "CPE candidate space composition",
            "Description": "RQ2 candidate source composition",
            "Creator": "Matplotlib",
            "Date": "1970-01-01T00:00:00Z",
        }
    return {"Software": "Matplotlib"}


def main() -> int:
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    figure = build_figure()
    output_paths: list[Path] = []
    try:
        with matplotlib.rc_context(
            {
                "pdf.fonttype": 42,
                "svg.fonttype": "none",
                "svg.hashsalt": "cpe-candidate-space-composition-v1",
            }
        ):
            for extension in OUTPUT_FORMATS:
                output_path = OUTPUT_DIRECTORY / f"{OUTPUT_STEM}.{extension}"
                figure.savefig(
                    output_path,
                    dpi=PNG_DPI if extension == "png" else None,
                    transparent=False,
                    metadata=output_metadata(extension),
                )
                output_paths.append(output_path)
    finally:
        plt.close(figure)

    selected_font = font_manager.findfont(
        font_manager.FontProperties(family=SELECTED_FONT_FAMILY),
        fallback_to_default=False,
    )
    print(f"font_family={SELECTED_FONT_FAMILY}")
    print(f"font_path={selected_font}")
    for path in output_paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate the NVD Configuration/CPE Dictionary coverage paper PNG.

Provenance:
  NVD CVE snapshot: 20260820T110357Z
  CPE Dictionary snapshot: 20260819T035002Z
  Coverage analysis: 428,417 distinct Configuration criteria strings and
  3,170,148 cpeMatch occurrences.

The Dictionary comparison includes both Active and Deprecated CPE names.
"Exact match" is a case-sensitive raw criteria/CPE-name equality. "Same
product in dictionary" means no exact match but at least one raw parsed
(part, vendor, product) tuple match. "Product not in dictionary" means neither
is present. The verified counts are frozen here so regeneration is offline
and does not query Django, a database, or the network.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import tempfile


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
STYLE_PATH = SCRIPT_DIR / "paper.mplstyle"
OUTPUT_PATH = SCRIPT_DIR / "output" / "nvd_cpe_dictionary_coverage.png"

FIGURE_SIZE = (7.0, 2.05)
PNG_DPI = 600
COLOR_FILLS = ("#0072B2", "#E69F00", "#D55E00")
COLOR_TEXT = ("#FFFFFF", "#171717", "#FFFFFF")
CATEGORY_LABELS = (
    "Exact match",
    "Same product in dictionary",
    "Product not in dictionary",
)
NEUTRAL_TEXT = "#5F6368"
LEADER_COLOR = "#72777D"
BAR_HEIGHT = 0.35


@dataclass(frozen=True)
class CoverageBar:
    label: str
    total: int
    counts: tuple[int, int, int]

    @property
    def percentages(self) -> tuple[float, float, float]:
        return tuple(count / self.total * 100.0 for count in self.counts)  # type: ignore[return-value]


UNIQUE_EXPRESSIONS = CoverageBar(
    label="Unique CPE expressions",
    total=428_417,
    counts=(269_267, 83_194, 75_956),
)
ALL_OCCURRENCES = CoverageBar(
    label="CPE expression occurrences",
    total=3_170_148,
    counts=(2_413_552, 599_022, 157_574),
)
COVERAGE_BARS = (UNIQUE_EXPRESSIONS, ALL_OCCURRENCES)
EXPECTED_PERCENTAGES = (
    (62.85, 19.42, 17.73),
    (76.13, 18.90, 4.97),
)


def validate_frozen_data() -> None:
    for bar, expected in zip(COVERAGE_BARS, EXPECTED_PERCENTAGES):
        if sum(bar.counts) != bar.total:
            raise ValueError(
                f"{bar.label}: category sum {sum(bar.counts):,} != {bar.total:,}"
            )
        percentages = tuple(round(value, 2) for value in bar.percentages)
        if percentages != expected:
            raise ValueError(
                f"{bar.label}: percentages {percentages!r} != {expected!r}"
            )
        if not math.isclose(sum(bar.percentages), 100.0, abs_tol=1e-10):
            raise ValueError(f"{bar.label}: percentages do not sum to 100%")


def build_figure() -> Figure:
    validate_frozen_data()
    with plt.style.context(STYLE_PATH):
        figure = plt.figure(figsize=FIGURE_SIZE, constrained_layout=False)
        axes = figure.add_axes((0.055, 0.06, 0.91, 0.76))
        y_positions = (0.68, -0.10)

        for row_index, (bar, y_position) in enumerate(
            zip(COVERAGE_BARS, y_positions)
        ):
            left = 0.0
            for category_index, (percentage, count) in enumerate(
                zip(bar.percentages, bar.counts)
            ):
                axes.barh(
                    y_position,
                    percentage,
                    left=left,
                    height=BAR_HEIGHT,
                    color=COLOR_FILLS[category_index],
                    edgecolor="#FFFFFF",
                    linewidth=1.0,
                    zorder=2,
                )

                external_label = row_index == 1 and category_index == 2
                if not external_label:
                    center = left + percentage / 2.0
                    axes.text(
                        center,
                        y_position + 0.048,
                        f"{percentage:.2f}%",
                        color=COLOR_TEXT[category_index],
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
                        color=COLOR_TEXT[category_index],
                        fontsize=7.1,
                        ha="center",
                        va="center",
                        zorder=6,
                    )
                left += percentage

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

        external_percentage = ALL_OCCURRENCES.percentages[2]
        external_count = ALL_OCCURRENCES.counts[2]
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
                facecolor=COLOR_FILLS[index],
                edgecolor="#FFFFFF",
                linewidth=0.7,
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
        validate_figure(figure)
        return figure


def validate_figure(figure: Figure) -> None:
    axes = figure.axes[0]
    patches = list(axes.patches)
    expected_widths = [
        percentage
        for bar in COVERAGE_BARS
        for percentage in bar.percentages
    ]
    if len(patches) != 6:
        raise RuntimeError(f"Expected six stacked segments, found {len(patches)}")
    if any(
        not math.isclose(patch.get_width(), expected, abs_tol=1e-10)
        for patch, expected in zip(patches, expected_widths)
    ):
        raise RuntimeError("A stacked segment differs from the frozen raw counts")

    renderer = figure.canvas.get_renderer()
    canvas = figure.bbox
    candidates: list[Artist] = list(figure.findobj(match=Text))
    candidates.extend(figure.legends)
    for artist in candidates:
        if not artist.get_visible():
            continue
        if isinstance(artist, Text) and not artist.get_text():
            continue
        extent = artist.get_window_extent(renderer)
        if (
            extent.x0 < canvas.x0 - 0.75
            or extent.y0 < canvas.y0 - 0.75
            or extent.x1 > canvas.x1 + 0.75
            or extent.y1 > canvas.y1 + 0.75
        ):
            label = artist.get_text() if isinstance(artist, Text) else "legend"
            raise RuntimeError(f"Clipped figure artist: {label!r}")


def main() -> int:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    figure = build_figure()
    try:
        with plt.style.context(STYLE_PATH):
            figure.savefig(
                OUTPUT_PATH,
                dpi=PNG_DPI,
                transparent=False,
                metadata={"Software": "Matplotlib"},
            )
    finally:
        plt.close(figure)
    print(OUTPUT_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

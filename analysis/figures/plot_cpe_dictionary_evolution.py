#!/usr/bin/env python3
"""Generate the publication PNG for annual CPE Dictionary activity.

Source: https://nvd.nist.gov/products/cpe/statistics
Statistics retrieved: 2026-08-22
The 2026 values are partial-year sums through August, as available at that
retrieval. They are neither annualized nor projected.

The verified annual values are frozen in this file so normal regeneration is
offline and does not depend on mutable web content.
"""

from __future__ import annotations

from dataclasses import dataclass
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
from matplotlib.text import Text  # noqa: E402
from matplotlib.ticker import FuncFormatter, MaxNLocator  # noqa: E402


SCRIPT_DIR = Path(__file__).resolve().parent
STYLE_PATH = SCRIPT_DIR / "paper.mplstyle"
OUTPUT_PATH = SCRIPT_DIR / "output" / "cpe_dictionary_evolution.png"

FIGURE_SIZE = (7.16, 3.55)
PNG_DPI = 600
NEW_COLOR = "#0072B2"
MODIFIED_COLOR = "#E69F00"
DEPRECATED_COLOR = "#D55E00"
BAR_EDGE_COLOR = "#4A4A4A"
GRID_COLOR = "#E3E3E3"
PARTIAL_HATCH = "//"


@dataclass(frozen=True)
class AnnualStat:
    year: int
    new: int
    modified: int
    deprecated: int
    months_observed: int = 12


ANNUAL_STATS: tuple[AnnualStat, ...] = (
    AnnualStat(2009, 5_786, 3_079, 37),
    AnnualStat(2010, 11_094, 8_959, 548),
    AnnualStat(2011, 9_263, 6_961, 657),
    AnnualStat(2012, 23_235, 29_088, 453),
    AnnualStat(2013, 15_671, 14_622, 103),
    AnnualStat(2014, 16_714, 15_305, 196),
    AnnualStat(2015, 6_503, 6_681, 63),
    AnnualStat(2016, 11_074, 7_571, 298),
    AnnualStat(2017, 18_650, 8_964, 88),
    AnnualStat(2018, 56_509, 39_162, 868),
    AnnualStat(2019, 272_322, 236_740, 8_928),
    AnnualStat(2020, 171_681, 161_178, 11_263),
    AnnualStat(2021, 189_563, 232_583, 13_803),
    AnnualStat(2022, 175_776, 171_851, 11_484),
    AnnualStat(2023, 222_949, 234_053, 11_730),
    AnnualStat(2024, 130_099, 136_651, 12_179),
    AnnualStat(2025, 193_433, 206_702, 16_659),
    AnnualStat(2026, 276_999, 293_719, 10_901, months_observed=8),
)


def validate_frozen_data() -> None:
    years = tuple(row.year for row in ANNUAL_STATS)
    if years != tuple(range(2009, 2027)):
        raise ValueError("Annual statistics must cover every year from 2009 through 2026")
    if any(row.months_observed != 12 for row in ANNUAL_STATS[:-1]):
        raise ValueError("Every complete year must contain twelve observed months")
    if ANNUAL_STATS[-1].months_observed != 8:
        raise ValueError("The frozen 2026 observation must remain an eight-month partial year")
    if ANNUAL_STATS[-2] != AnnualStat(2025, 193_433, 206_702, 16_659):
        raise ValueError("The independently verified 2025 totals changed")
    if ANNUAL_STATS[-1] != AnnualStat(2026, 276_999, 293_719, 10_901, 8):
        raise ValueError("The independently verified 2026 partial totals changed")
    recent = ANNUAL_STATS[-6:-1]
    means = tuple(sum(getattr(row, field) for row in recent) / 5 for field in ("new", "modified", "deprecated"))
    if means != (182_364.0, 196_368.0, 13_171.0):
        raise ValueError(f"The 2021–2025 validation means changed: {means}")


def format_thousands(value: float, _position: object = None) -> str:
    if value == 0:
        return "0"
    if abs(value) >= 1_000:
        return f"{value / 1_000:g}k"
    return f"{value:g}"


def style_axis(axis: object, *, show_x: bool) -> None:
    axis.set_axisbelow(True)
    axis.grid(axis="y", color=GRID_COLOR, linewidth=0.45)
    axis.grid(axis="x", visible=False)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.spines["left"].set_color("#777777")
    axis.spines["bottom"].set_color("#777777")
    axis.spines["left"].set_linewidth(0.65)
    axis.spines["bottom"].set_linewidth(0.65)
    axis.tick_params(axis="both", width=0.65, length=2.6, color="#777777")
    axis.yaxis.set_major_locator(MaxNLocator(nbins=5, integer=True, prune="upper"))
    axis.yaxis.set_major_formatter(FuncFormatter(format_thousands))
    if show_x:
        positions = (0, 3, 6, 9, 12, 15, 17)
        labels = ("2009", "2012", "2015", "2018", "2021", "2024", "2026*")
        axis.set_xticks(positions, labels)
    else:
        axis.tick_params(axis="x", labelbottom=False)
    axis.set_xlim(-0.65, len(ANNUAL_STATS) - 0.35)


def draw_bars(
    axis: object,
    x_values: list[float],
    values: list[int],
    *,
    width: float,
    color: str,
    label: str,
) -> None:
    bars = axis.bar(
        x_values,
        values,
        width=width,
        color=color,
        edgecolor=BAR_EDGE_COLOR,
        linewidth=0.62,
        label=label,
        zorder=3,
    )
    partial = bars[-1]
    partial.set_facecolor("#FBFBFB")
    partial.set_edgecolor(color)
    partial.set_linewidth(1.0)
    partial.set_hatch(PARTIAL_HATCH)


def validate_layout(figure: object) -> None:
    top, bottom = figure.axes
    if top.get_ylabel() or bottom.get_ylabel():
        raise RuntimeError("The final panels must not have y-axis titles")
    if top.get_position().y0 - bottom.get_position().y1 < 0.08:
        raise RuntimeError("The two panels are not sufficiently separated")
    ratio = top.get_position().height / bottom.get_position().height
    if not 1.3 <= ratio <= 1.5:
        raise RuntimeError(f"Unexpected panel height ratio: {ratio:.3f}")
    bars = list(top.patches) + list(bottom.patches)
    expected_heights = [row.new for row in ANNUAL_STATS]
    expected_heights.extend(row.modified for row in ANNUAL_STATS)
    expected_heights.extend(row.deprecated for row in ANNUAL_STATS)
    if len(bars) != len(expected_heights):
        raise RuntimeError("The final figure must contain exactly three annual bar series")
    if any(bar.get_height() != expected for bar, expected in zip(bars, expected_heights)):
        raise RuntimeError("A plotted bar differs from the frozen annual statistics")
    partial_indices = {17, 35, 53}
    for index, bar in enumerate(bars):
        hatch = bar.get_hatch() or ""
        if index in partial_indices and hatch != PARTIAL_HATCH:
            raise RuntimeError("Every 2026 bar must use the common partial-year hatch")
        if index not in partial_indices and hatch:
            raise RuntimeError("Complete-year bars must use solid fill")
    texts = [
        text.get_text()
        for text in figure.findobj(match=Text)
        if text.get_visible() and text.get_text()
    ]
    forbidden = ("YTD", "Peak", "retrieval", "Number of CPE entries", "CPE entries per year")
    if any(term in text for term in forbidden for text in texts):
        raise RuntimeError("The final figure contains a forbidden internal annotation")
    if "Year" in texts or "2026*" not in texts:
        raise RuntimeError("The final x-axis labeling is incomplete")
    if top.get_title(loc="left") != "(a) New and modified entries":
        raise RuntimeError("Unexpected top-panel title")
    if bottom.get_title(loc="left") != "(b) Deprecated entries":
        raise RuntimeError("Unexpected bottom-panel title")
    if top.get_legend() is None or bottom.get_legend() is not None:
        raise RuntimeError("Only the top panel may contain a legend")
    renderer = figure.canvas.get_renderer()
    canvas = figure.bbox
    for text in figure.findobj(match=Text):
        if not text.get_visible() or not text.get_text():
            continue
        extent = text.get_window_extent(renderer)
        if extent.x0 < canvas.x0 - 0.75 or extent.y0 < canvas.y0 - 0.75 or extent.x1 > canvas.x1 + 0.75 or extent.y1 > canvas.y1 + 0.75:
            raise RuntimeError(f"Clipped figure text: {text.get_text()!r}")


def build_figure() -> object:
    validate_frozen_data()
    with plt.style.context(STYLE_PATH):
        matplotlib.rcParams.update(
            {
                "font.size": 9.0,
                "axes.labelsize": 9.0,
                "axes.titlesize": 9.0,
                "xtick.labelsize": 9.0,
                "ytick.labelsize": 9.0,
                "legend.fontsize": 8.0,
            }
        )
        figure, (top, bottom) = plt.subplots(
            2,
            1,
            figsize=FIGURE_SIZE,
            sharex=True,
            gridspec_kw={"height_ratios": (1.4, 1), "hspace": 0.42},
        )
        x = list(range(len(ANNUAL_STATS)))
        width = 0.36
        draw_bars(top, [value - width / 2 for value in x], [row.new for row in ANNUAL_STATS], width=width, color=NEW_COLOR, label="New entries")
        draw_bars(top, [value + width / 2 for value in x], [row.modified for row in ANNUAL_STATS], width=width, color=MODIFIED_COLOR, label="Modified entries")
        draw_bars(bottom, x, [row.deprecated for row in ANNUAL_STATS], width=0.58, color=DEPRECATED_COLOR, label="_nolegend_")

        top.set_title("(a) New and modified entries", loc="left", pad=4)
        bottom.set_title("(b) Deprecated entries", loc="left", pad=4)
        style_axis(top, show_x=False)
        style_axis(bottom, show_x=True)
        top.set_ylim(0, max(max(row.new, row.modified) for row in ANNUAL_STATS) * 1.16)
        bottom.set_ylim(0, max(row.deprecated for row in ANNUAL_STATS) * 1.22)
        top.legend(loc="upper left", ncol=2, handlelength=1.45, columnspacing=1.2, frameon=False)
        figure.subplots_adjust(left=0.065, right=0.992, top=0.95, bottom=0.135)
        figure.canvas.draw()
        validate_layout(figure)
        return figure


def main() -> int:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    figure = build_figure()
    try:
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

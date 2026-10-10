#!/usr/bin/env python3
"""Draw the README's load-ratio chart from committed measurements.

Reads docs/assets/perf/load-ratios.json and writes a light and a dark SVG beside it. The chart
plots the *ratio* of gcm_decrypt LIKE to AES_DECRYPT LIKE per run, never milliseconds: each CI run
lands on its own hosted machine, so absolute times rank the runners, while the ratio is measured
within one session and is what the regression gate judges (docs/perf.md).

Internal documentation tooling (stack-python): it encrypts nothing, reads no database, and its
only input is the JSON file. `--check` redraws into a temporary directory and fails if the
committed SVGs differ, so a figure can never drift from its data.

Output: the paths written on stdout, problems on stderr, the check result via the exit code.
"""

from __future__ import annotations

import argparse
import filecmp
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402 - the backend must be chosen first

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "assets" / "perf" / "load-ratios.json"
OUT_DIR = DATA.parent

# The first three categorical slots of the reference palette, validated all-pairs in both modes
# (dataviz validate_palette.js). Light aqua sits at 2.74:1 on the surface, so every suite also
# has its own marker shape and the legend names it: identity never rests on colour alone.
THEMES: dict[str, dict[str, Any]] = {
    "light": {
        "surface": "#fcfcfb",
        "text": "#0b0b0b",
        "muted": "#52514e",
        "grid": "#e4e3df",
        "series": {"aes256": "#2a78d6", "aes192": "#eb6834", "aes128": "#1baf7a"},
    },
    "dark": {
        "surface": "#1a1a19",
        "text": "#ffffff",
        "muted": "#c3c2b7",
        "grid": "#383835",
        "series": {"aes256": "#3987e5", "aes192": "#d95926", "aes128": "#199e70"},
    },
}
MARKERS = {"aes256": "o", "aes192": "s", "aes128": "^"}
# A triangle at the same size reads smaller than a circle or a square; this evens the visual area.
MARKER_SIZE = {"aes256": 9, "aes192": 8.5, "aes128": 10.5}
SUITE_OFFSET = {"aes256": -0.24, "aes192": 0.0, "aes128": 0.24}
RUN_OFFSET = (-0.06, 0.0, 0.06)


def load() -> dict[str, Any]:
    with DATA.open(encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
    return data


def draw(data: dict[str, Any], theme_name: str, path: Path) -> None:
    theme = THEMES[theme_name]
    plt.rcParams.update(
        {
            # Deterministic output on every machine: no timestamp, a fixed id salt, and text drawn
            # as outlines from DejaVu Sans, the font matplotlib bundles. Text left as text would be
            # laid out with whatever font the host has (Helvetica on macOS, something else on the
            # CI runner), so the committed SVG and a CI redraw would never be byte-identical, and
            # every viewer would see a different face.
            "svg.hashsalt": "mysql-gcm-perf",
            "svg.fonttype": "path",
            "font.family": "sans-serif",
            "font.sans-serif": ["DejaVu Sans"],
            "font.size": 11,
        }
    )
    fig, ax = plt.subplots(figsize=(8.8, 4.6), dpi=100)
    fig.patch.set_facecolor(theme["surface"])
    ax.set_facecolor(theme["surface"])

    sessions: list[int] = data["sessions"]
    xs = list(range(len(sessions)))

    # Reference lines first, so the marks sit on top of them.
    ax.axhline(1.0, color=theme["muted"], linewidth=1.5, zorder=1)
    ax.axhline(data["gate"], color=theme["muted"], linewidth=1.0, linestyle=(0, (4, 3)), zorder=1)
    right = len(sessions) - 0.5
    ax.text(
        right,
        1.0 + 0.006,
        "same speed as AES_DECRYPT",
        ha="right",
        va="bottom",
        color=theme["muted"],
        fontsize=10,
    )
    ax.text(
        right,
        data["gate"] + 0.006,
        f"regression gate {data['gate']:.2f}",
        ha="right",
        va="bottom",
        color=theme["muted"],
        fontsize=10,
    )

    for suite, spec in data["suites"].items():
        colour = theme["series"][suite]
        for x, s in zip(xs, sessions, strict=True):
            for offset, ratio in zip(RUN_OFFSET, spec["ratios"][str(s)], strict=True):
                ax.plot(
                    x + SUITE_OFFSET[suite] + offset,
                    ratio,
                    marker=MARKERS[suite],
                    markersize=MARKER_SIZE[suite],
                    color=colour,
                    markeredgecolor=theme["surface"],
                    markeredgewidth=2,
                    linestyle="none",
                    zorder=3,
                )
        # One invisible-data handle per suite for the legend.
        ax.plot(
            [],
            [],
            marker=MARKERS[suite],
            markersize=MARKER_SIZE[suite],
            color=colour,
            markeredgecolor=theme["surface"],
            markeredgewidth=2,
            linestyle="none",
            label=spec["label"],
        )

    ax.set_xlim(-0.5, len(sessions) - 0.5)
    ax.set_ylim(0.70, 1.16)
    ax.set_xticks(xs, [f"{s} session" + ("" if s == 1 else "s") for s in sessions])
    ax.set_yticks([0.7, 0.8, 0.9, 1.0, 1.1])
    ax.set_ylabel("p95 ratio, lower is faster", color=theme["muted"])
    ax.grid(axis="y", color=theme["grid"], linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(theme["grid"])
    ax.tick_params(colors=theme["muted"], length=0)

    # Title, subtitle and legend share one left edge: the figure's, not the axes'.
    left = 0.02
    fig.text(
        left,
        0.955,
        "gcm_decrypt(col) LIKE vs AES_DECRYPT(col) LIKE",
        ha="left",
        va="top",
        color=theme["text"],
        fontsize=14,
        fontweight="bold",
    )
    fig.text(
        left,
        0.885,
        f"p95 ratio, {data['rows']:,} encrypted rows, {data['server']}. "
        "Nine CI runs, three per suite, each on its own hosted runner.",
        ha="left",
        va="top",
        color=theme["muted"],
        fontsize=10,
    )
    legend = fig.legend(
        loc="upper left",
        bbox_to_anchor=(left - 0.008, 0.835),
        ncol=3,
        frameon=False,
        handletextpad=0.3,
        columnspacing=1.4,
    )
    for text in legend.get_texts():
        text.set_color(theme["text"])

    fig.subplots_adjust(left=0.09, right=0.98, top=0.74, bottom=0.10)
    # The suffix picks the format, so a PNG can be drawn to look at; only SVGs are committed.
    meta = {"Date": None} if path.suffix == ".svg" else {}
    fig.savefig(path, format=path.suffix[1:], facecolor=theme["surface"], metadata=meta)
    plt.close(fig)


def render(out_dir: Path) -> list[Path]:
    data = load()
    written = []
    for theme_name in THEMES:
        path = out_dir / f"load-ratio-{theme_name}.svg"
        draw(data, theme_name, path)
        written.append(path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed SVGs are stale")
    args = parser.parse_args()

    if not args.check:
        for path in render(OUT_DIR):
            print(path.relative_to(ROOT))
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        stale = [
            fresh.name
            for fresh in render(Path(tmp))
            if not (OUT_DIR / fresh.name).exists()
            or not filecmp.cmp(fresh, OUT_DIR / fresh.name, shallow=False)
        ]
    for name in stale:
        print(f"{name} is stale: run scripts/plot-perf.py and commit the result", file=sys.stderr)
    if not stale:
        print("perf charts up to date")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())

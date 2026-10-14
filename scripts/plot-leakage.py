#!/usr/bin/env python3
"""Draw the A17 leakage charts from the committed experiment JSON.

Reads docs/assets/leakage/results.json and writes light and dark SVGs beside it:

- `leakage-utility-*.svg` — every variant as a point: leakage (token recovery) against
  utility (the candidate fraction a token query still returns). Down and left is better.
- `naming-attacks-*.svg` — attacks 1-3 on V0, so the attack choices compare.

Internal documentation tooling (stack-python, amendment A17): it encrypts nothing, reads no
database, and its only input is the JSON file. `--check` redraws into a temporary directory
and fails if the committed SVGs differ, so a figure can never drift from its data.

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
DATA = ROOT / "docs" / "assets" / "leakage" / "results.json"
OUT_DIR = DATA.parent

THEMES: dict[str, dict[str, Any]] = {
    "light": {
        "surface": "#fcfcfb",
        "text": "#0b0b0b",
        "muted": "#52514e",
        "grid": "#e4e3df",
        "series": {"ko": "#2a78d6", "latin": "#eb6834"},
    },
    "dark": {
        "surface": "#1a1a19",
        "text": "#ffffff",
        "muted": "#c3c2b7",
        "grid": "#383835",
        "series": {"ko": "#3987e5", "latin": "#d95926"},
    },
}
MARKERS = {"ko": "o", "latin": "^"}
VARIANT_ORDER = ("V0", "V1", "V2", "V3-8", "V3-12", "V3-16", "V7")


def load() -> dict[str, Any]:
    with DATA.open(encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
    return data


def _configure(theme: dict[str, Any]) -> None:
    plt.rcParams.update(
        {
            # Deterministic output on every machine: no timestamp, a fixed id salt, and text drawn
            # as outlines from DejaVu Sans, the font matplotlib bundles (see scripts/plot-perf.py).
            "svg.hashsalt": "mysql-gcm-leakage",
            "svg.fonttype": "path",
            "font.family": "sans-serif",
            "font.sans-serif": ["DejaVu Sans"],
            "font.size": 11,
        }
    )


def _frame(fig: Any, ax: Any, theme: dict[str, Any], title: str, subtitle: str) -> None:
    ax.grid(color=theme["grid"], linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("bottom", "left"):
        ax.spines[side].set_color(theme["grid"])
    ax.tick_params(colors=theme["muted"], length=0)
    fig.text(
        0.02, 0.955, title, ha="left", va="top", color=theme["text"], fontsize=14, fontweight="bold"
    )
    fig.text(0.02, 0.885, subtitle, ha="left", va="top", color=theme["muted"], fontsize=10)


def draw_leakage_utility(data: dict[str, Any], theme_name: str, path: Path) -> None:
    theme = THEMES[theme_name]
    _configure(theme)
    fig, ax = plt.subplots(figsize=(8.8, 4.8), dpi=100)
    fig.patch.set_facecolor(theme["surface"])
    ax.set_facecolor(theme["surface"])
    results = data["results"]
    for language in ("ko", "latin"):
        for variant in VARIANT_ORDER:
            record = results.get(f"{language}:{variant}:3")
            if record is None:
                continue
            x = record["utility"]["mean_candidate_fraction"]["mean"]
            y = record["leakage"]["token_recovery_weighted"]["mean"]
            ax.plot(
                x,
                y,
                marker=MARKERS[language],
                markersize=9,
                color=theme["series"][language],
                markeredgecolor=theme["surface"],
                markeredgewidth=1.5,
                linestyle="none",
                zorder=3,
            )
            ax.annotate(
                variant,
                (x, y),
                textcoords="offset points",
                xytext=(6, 4),
                color=theme["muted"],
                fontsize=9,
            )
    for language in ("ko", "latin"):
        ax.plot(
            [],
            [],
            marker=MARKERS[language],
            markersize=9,
            color=theme["series"][language],
            linestyle="none",
            label=language,
        )
    ax.set_xlabel("utility: mean candidate fraction a token query returns", color=theme["muted"])
    ax.set_ylabel("leakage: occurrence-weighted token recovery", color=theme["muted"])
    ax.legend(frameon=False, loc="upper right", labelcolor=theme["text"])
    _frame(
        fig,
        ax,
        theme,
        "Token-index leakage against utility (attack 3, N = 300k)",
        "Left and down is better. Attack 3 (known-row seeding) on each variant, 20 seeds.",
    )
    fig.subplots_adjust(left=0.10, right=0.98, top=0.76, bottom=0.12)
    meta = {"Date": None} if path.suffix == ".svg" else {}
    fig.savefig(path, format=path.suffix[1:], facecolor=theme["surface"], metadata=meta)
    plt.close(fig)


def draw_naming_attacks(data: dict[str, Any], theme_name: str, path: Path) -> None:
    theme = THEMES[theme_name]
    _configure(theme)
    fig, ax = plt.subplots(figsize=(8.8, 4.4), dpi=100)
    fig.patch.set_facecolor(theme["surface"])
    ax.set_facecolor(theme["surface"])
    results = data["results"]
    attacks = data["config"]["attacks"]
    width = 0.38
    for offset, language in zip((-width / 2, width / 2), ("ko", "latin"), strict=True):
        heights = [
            results[f"{language}:V0:{attack}"]["leakage"]["token_recovery_weighted"]["mean"]
            for attack in attacks
        ]
        positions = [index + offset for index in range(len(attacks))]
        ax.bar(
            positions,
            heights,
            width=width,
            color=theme["series"][language],
            label=language,
            zorder=3,
        )
    ax.set_xticks(range(len(attacks)), [f"attack {a}" for a in attacks])
    ax.set_ylabel("occurrence-weighted token recovery", color=theme["muted"])
    ax.legend(frameon=False, loc="upper left", labelcolor=theme["text"])
    _frame(
        fig,
        ax,
        theme,
        "Naming attacks on V0 (N = 300k)",
        "Attacks 1-3, 20 seeds each. Attack 3 seeds from known rows.",
    )
    fig.subplots_adjust(left=0.10, right=0.98, top=0.76, bottom=0.12)
    meta = {"Date": None} if path.suffix == ".svg" else {}
    fig.savefig(path, format=path.suffix[1:], facecolor=theme["surface"], metadata=meta)
    plt.close(fig)


def render(out_dir: Path) -> list[Path]:
    data = load()
    written: list[Path] = []
    for theme_name in THEMES:
        for name, draw in (
            ("leakage-utility", draw_leakage_utility),
            ("naming-attacks", draw_naming_attacks),
        ):
            path = out_dir / f"{name}-{theme_name}.svg"
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
        print(
            f"{name} is stale: run scripts/plot-leakage.py and commit the result", file=sys.stderr
        )
    if not stale:
        print("leakage charts up to date")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())

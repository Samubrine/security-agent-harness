"""WCAG 2.1 contrast check for the design tokens in design.md (section 11).

Run: python3 docs/design/contrast_check.py
Exit code 1 if any pair falls below its required ratio.
"""

import sys

# (foreground, background, required ratio, what it is)
PAIRS = [
    ("#ececec", "#080808", 4.5, "text-strong on bg"),
    ("#a3a3a3", "#080808", 4.5, "text on bg"),
    ("#a3a3a3", "#1c1c1c", 4.5, "text on surface-2"),
    ("#868686", "#080808", 4.5, "text-muted on bg"),
    ("#868686", "#121212", 4.5, "text-muted on surface-1"),
    ("#868686", "#1c1c1c", 4.5, "text-muted on surface-2"),
    ("#27916b", "#080808", 4.5, "accent (eyebrow) on bg"),
    ("#34b386", "#080808", 4.5, "accent-text on bg"),
    ("#34b386", "#121212", 4.5, "accent-text on surface-1"),
    ("#ffffff", "#1f7a59", 4.5, "status bar text on accent-bar"),
    ("#080808", "#e8f4f0", 4.5, "text-on-mint on mint (primary button)"),
    ("#ff6b6b", "#080808", 4.5, "critical text on bg"),
    ("#e0943a", "#080808", 4.5, "high text on bg"),
    ("#e0943a", "#121212", 4.5, "high text on surface-1"),
    ("#d4c15a", "#080808", 4.5, "medium text on bg"),
    ("#7fb39f", "#080808", 4.5, "low text on bg"),
    ("#d00020", "#080808", 3.0, "critical dot on bg (non-text)"),
    ("#666666", "#121212", 3.0, "line-input on surface-1 (field border)"),
    ("#666666", "#080808", 3.0, "line-input on bg (field border)"),
]


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    channels = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def ratio(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def main() -> int:
    failed = 0
    for fg, bg, need, label in PAIRS:
        r = ratio(fg, bg)
        ok = r >= need
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {r:5.2f}:1  (needs {need})  {label}  {fg} on {bg}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

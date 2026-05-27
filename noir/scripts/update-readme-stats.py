#!/usr/bin/env python3
"""Regenerate the Noir benchmark table in README.md from noir/stats_noir.csv.

Run from anywhere in the repo:

    python noir/scripts/update-readme-stats.py
"""
import csv
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = REPO_ROOT / "noir" / "stats_noir.csv"
README_PATH = REPO_ROOT / "README.md"
START = "<!-- NOIR_STATS_START -->"
END = "<!-- NOIR_STATS_END -->"
HINT = "<!-- regenerate with: python noir/scripts/update-readme-stats.py -->"

# (csv column, markdown header)
COLUMNS = [
    ("test", "Noir test"),
    ("acir", "acir"),
    ("circuit", "circuit"),
    ("create_vk", "create_vk [s]"),
    ("create_proof", "create_proof [s]"),
    ("verify", "verify [s]"),
    ("proof_size", "proof_size [B]"),
]


def main() -> None:
    with CSV_PATH.open(newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("test")]

    headers = [label for _, label in COLUMNS]
    values = [[row[key] for key, _ in COLUMNS] for row in rows]

    widths = [len(h) for h in headers]
    for row in values:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(cells: list[str]) -> str:
        return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, widths)) + " |"

    sep = "|" + "|".join("-" * (w + 2) for w in widths) + "|"
    table = "\n".join([fmt(headers), sep, *(fmt(r) for r in values)])

    readme = README_PATH.read_text()
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(readme):
        raise SystemExit(
            f"markers {START} ... {END} not found in {README_PATH}; "
            "add them around the table you want to regenerate"
        )

    updated = pattern.sub(f"{START}\n{HINT}\n{table}\n{END}", readme)
    README_PATH.write_text(updated)
    print(f"updated {README_PATH.relative_to(REPO_ROOT)} "
          f"with {len(values)} rows from {CSV_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()

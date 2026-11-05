#!/usr/bin/env python3
"""Record the Go base being merged into the working branch; do not commit."""

import json
from pathlib import Path
import subprocess


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def main():
    root = Path(git(Path(__file__).resolve().parent, "rev-parse", "--show-toplevel"))
    base = git(root, "rev-parse", "refs/heads/base")
    merged = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", base, "HEAD"]
    ).returncode == 0
    pending = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "MERGE_HEAD"],
        capture_output=True, text=True,
    )
    if not merged and pending.stdout.strip() != base:
        raise SystemExit("Merge base into the working branch before recording it.")
    message = git(root, "log", "base", "-1", "--grep=^Projected-commit:", "--format=%B")
    fields = {}
    for line in message.splitlines():
        key, separator, value = line.partition(": ")
        if separator:
            fields[key] = value
    if not all(key in fields for key in ("Go-tag", "Go-commit", "Projected-commit")):
        raise SystemExit("No importer update record found on base.")
    projected = fields["Projected-commit"]
    subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", projected, base], check=True
    )
    if git(root, "rev-parse", base + "^{tree}") != git(root, "rev-parse", projected + "^{tree}"):
        raise SystemExit("Base differs from the pristine Go projection; inspect it before continuing.")
    path = root / "UPSTREAM.json"
    metadata = json.loads(path.read_text())
    metadata.update(
        go_tag=fields["Go-tag"], go_commit=fields["Go-commit"],
        projected_commit=projected, base_branch="base", base_commit=base,
    )
    metadata.pop("baseline_tag", None)
    path.write_text(json.dumps(metadata, indent=2) + "\n")
    print("Updated UPSTREAM.json for " + fields["Go-tag"] + ". Nothing committed.")


if __name__ == "__main__":
    main()

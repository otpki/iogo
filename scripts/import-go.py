#!/usr/bin/env python3
"""Prepare an upstream Go update branch for a merge into base."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile


FILTER_REPO_SHA256 = "67447413e273fc76809289111748870b6f6072f08b17efe94863a92d810b7d94"
PATHS = [
    "LICENSE",
    "PATENTS",
    "src/pkg/crypto/x509/",
    "src/crypto/x509/",
    "src/pkg/crypto/crypto.go",
    "src/crypto/crypto.go",
]
RENAMES = [
    "src/pkg/crypto/x509/:crypto/x509/",
    "src/crypto/x509/:crypto/x509/",
    "src/pkg/crypto/crypto.go:crypto/crypto.go",
    "src/crypto/crypto.go:crypto/crypto.go",
]


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True
    ).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-repo", required=True, type=Path,
                        help="Full local clone of the upstream Go repository")
    parser.add_argument("--go-ref", required=True,
                        help="Upstream Go tag or commit to project")
    parser.add_argument("--branch", required=True,
                        help="New local branch for a pull request into base")
    parser.add_argument("--base-branch", default="base",
                        help="Local pristine upstream branch (default: base)")
    parser.add_argument("--filter-repo", required=True, type=Path,
                        help="Path to the unmodified git-filter-repo v2.47.0 script")
    args = parser.parse_args()

    root = Path(git(Path(__file__).resolve().parent, "rev-parse", "--show-toplevel"))
    source = args.go_repo.resolve()
    tool = args.filter_repo.resolve()
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    if digest != FILTER_REPO_SHA256:
        parser.error("Use the pinned, unmodified git-filter-repo v2.47.0 script; checksum mismatch")
    if source == root:
        parser.error("The Go source repository must be separate from this repository")
    if git(source, "rev-parse", "--is-shallow-repository") != "false":
        parser.error("A full Go clone is required for reproducible history")
    git(root, "check-ref-format", "refs/heads/" + args.branch)
    git(root, "check-ref-format", "refs/heads/" + args.base_branch)
    existing = subprocess.run(
        ["git", "-C", str(root), "show-ref", "--verify", "--quiet",
         "refs/heads/" + args.branch]
    )
    if existing.returncode == 0:
        parser.error("The update branch already exists; choose a new branch name")
    base_commit = git(root, "rev-parse", "--verify",
                      "refs/heads/" + args.base_branch + "^{commit}")
    author_name = git(root, "config", "user.name")
    author_email = git(root, "config", "user.email")
    source_commit = git(source, "rev-parse", "--verify", "--end-of-options",
                        args.go_ref + "^{commit}")

    with tempfile.TemporaryDirectory(prefix="iogo-go-projection-") as temp:
        subprocess.run(["git", "init", "--quiet", "-b", "projection", temp], check=True)
        command = [sys.executable, str(tool), "--source", str(source), "--target", temp]
        for path in PATHS:
            command += ["--path", path]
        for rename in RENAMES:
            command += ["--path-rename", rename]
        command += [
            "--prune-empty", "always", "--prune-degenerate", "always",
            "--preserve-commit-hashes",
            "--commit-callback",
            'commit.message = commit.message.rstrip() + b"\\n\\nGo-commit: " + commit.original_id + b"\\n"',
            "--refname-callback", 'return b"refs/heads/upstream-go"',
            "--refs", source_commit,
        ]
        subprocess.run(command, check=True)
        projected_commit = git(temp, "rev-parse", "refs/heads/upstream-go")
        subprocess.run([
            "git", "-C", temp, "fetch", "--no-tags", str(root),
            "refs/heads/" + args.base_branch + ":refs/heads/current-base",
        ], check=True)
        # Refuse a raced local base update; the PR must start from the base
        # revision inspected above.
        if git(temp, "rev-parse", "current-base") != base_commit:
            parser.error("Base changed during the import; retry from the updated base")
        projected_tree = git(temp, "rev-parse", "upstream-go^{tree}")
        if git(temp, "rev-parse", "current-base^{tree}") == projected_tree:
            print("No changes to the selected Go source files; no update branch created.")
            return
        subprocess.run(["git", "-C", temp, "config", "user.name", author_name], check=True)
        subprocess.run(["git", "-C", temp, "config", "user.email", author_email], check=True)
        subprocess.run(["git", "-C", temp, "switch", "-c", "base-update", "current-base"], check=True)
        subprocess.run(["git", "-C", temp, "merge", "--no-ff", "--no-commit", "upstream-go"], check=True)
        if git(temp, "write-tree") != projected_tree:
            parser.error("Base contains changes outside pristine upstream Go; no branch created")
        message = (
            "Update upstream Go base to " + args.go_ref + "\n\n"
            "Go-tag: " + args.go_ref + "\n"
            "Go-commit: " + source_commit + "\n"
            "Projected-commit: " + projected_commit + "\n"
        )
        subprocess.run(["git", "-C", temp, "commit", "-m", message], check=True)
        subprocess.run([
            "git", "-C", str(root), "fetch", "--no-tags", temp,
            "refs/heads/base-update:refs/heads/" + args.branch,
        ], check=True)

    print("Original Go commit:", source_commit)
    print("Projected commit:", projected_commit)
    print("Update branch:", args.branch)
    print("Base used:", base_commit)
    print("Open a PR from " + args.branch + " into " + args.base_branch + ". Use a merge commit.")
    print("Then merge base into main through a second PR. See UPSTREAM.md.")
    print("No working files, existing branches, or remote repositories were changed.")


if __name__ == "__main__":
    main()

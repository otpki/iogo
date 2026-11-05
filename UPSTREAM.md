# Updating from upstream Go

We keep two long-lived branches:

- **base** contains pristine Go source and its history.
- **main** contains the working IOGO library and our changes.

Updates use two pull requests, both merged with **Create a merge commit**.
Do not squash or rebase either PR: the shared ancestry is what makes later
updates work. Both branches can require PR reviews. Main also requires library
CI; base is upstream source, not a standalone module, so library build checks
do not apply there. Allow merge commits rather than requiring linear history.

Publish the initial base branch once with `git push -u origin base` before
starting the first update.

## 1. Prepare an upstream update

This example updates Go 1.27.0 to 1.27.3. For a later update, replace the target
version with a newer published release. Run from the library repository with a
clean working tree and the full Go clone at `../go-upstream.git`.

```sh
git switch base
git pull --ff-only origin base
git switch main
git pull --ff-only origin main
git -C ../go-upstream.git fetch origin --tags

curl -fsSL https://raw.githubusercontent.com/newren/git-filter-repo/v2.47.0/git-filter-repo \
  -o /tmp/iogo-git-filter-repo.py

python3 scripts/import-go.py \
  --go-repo ../go-upstream.git \
  --go-ref go1.27.3 \
  --branch base-go1.27.3 \
  --filter-repo /tmp/iogo-git-filter-repo.py

git push -u origin base-go1.27.3
```

The script prepares a branch descended from base, retaining the new Go history.
It does not change base, main, or your working files. If no relevant source files
changed, it reports that and creates no branch; no library update is needed.

On GitHub, open a PR **from `base-go1.27.3` into `base`**. Review the upstream
changes, then use **Create a merge commit**. Delete the PR branch afterward.

## 2. Merge base into our working library

```sh
git switch base
git pull --ff-only origin base
git switch main
git pull --ff-only origin main
git switch -c merge-go1.27.3
git merge --no-ff --no-commit base
```

If Git reports conflicts, resolve them and stage the resolved files with
`git add`. Preserve our library adaptations and the upstream fixes. To cancel,
run `git merge --abort`.

Record the Go version automatically, then review and test:

```sh
python3 scripts/record-base.py
git add UPSTREAM.json
git diff --cached
go build ./...
go vet ./...
go test -timeout 5m ./...
git commit -m "Merge Go 1.27.3 base into IOGO"
git push -u origin merge-go1.27.3
```

On GitHub, open a PR **from `merge-go1.27.3` into `main`**. Wait for review and
all platform checks, then use **Create a merge commit**. Delete that PR branch
afterward. No history is rewritten and no force push is required.

After merging, update local main with `git switch main` followed by
`git pull --ff-only origin main`.

## Seeing our changes

After base has been merged into main and both local branches are up to date:

```sh
git diff base main -- crypto/
```

This shows the crypto changes IOGO makes to the current upstream Go source.
For the complete difference, including tooling and documentation, use
`git diff base main`.

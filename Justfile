set dotenv-load := false

# ------------------------------------------------------------------
# Paths / Config
# ------------------------------------------------------------------

root := justfile_directory()
tool_path := root / ".tool/bin"

export PATH := tool_path + ":" + env_var("PATH")
export AQUA_ROOT_DIR := root + "/.tool"
export AQUA_DISABLE_POLICY := "true"

default:
    @just --list

shell:
    exec "${SHELL:-/bin/sh}" -i

# -----------------------------
# aqua bootstrap + tool install
# -----------------------------

# install aqua itself into .tool/bin — no global install needed
aqua:
    mkdir -p "{{ tool_path }}"
    test -x "{{ tool_path }}/aqua" || curl -sSfL https://raw.githubusercontent.com/aquaproj/aqua-installer/v4.1.1/aqua-installer | bash

# install every tool pinned in .aqua.yaml (or a tag subset: just tools lint)
tools *tags: aqua
    aqua install {{ if tags == "" { "" } else { "-t " + replace(tags, " ", " -t ") } }}

# -----------------------------
# Build / check recipes
# -----------------------------

# gofmt -w over the tree (upstream Go style, no gofumpt)
format:
    gofmt -w .

alias fmt := format

# empty gofmt -l output means formatted
format-check:
    test -z "$(gofmt -l .)"

# plain vet — the upstream Go tree is not golangci-clean
lint:
    go vet ./...

tidy:
    go mod tidy

test:
    go test -timeout 5m ./...

test-ci:
    go test -timeout 5m -short ./...

vulncheck:
    govulncheck ./...

# bump all module dependencies, then tidy
update:
    go get -u all
    just tidy

# Same checks CI runs: formatting, lint, short tests, tidy, and a clean
# working tree — fails on tracked diffs and untracked leftovers alike.
check: tools
    just format-check
    just lint
    just test-ci
    just tidy
    @if [ -n "$(git status --porcelain)" ]; then \
        echo "Generation, tidy, or formatting left changes:"; \
        git status --porcelain; \
        git diff --stat; \
        exit 1; \
    fi

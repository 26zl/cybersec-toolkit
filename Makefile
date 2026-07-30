# Cybersec toolkit — developer & contributor shortcuts.
# Run `make` or `make help` for the list. Targets cover the core local checks;
# GitHub also runs security, CodeQL, and integration workflows.

SHELL := bash
SH_FILES := install.sh lib/*.sh modules/*.sh scripts/*.sh
# Pinned so a local `make lint-md` matches CI, which uses the SHA-pinned
# DavidAnson/markdownlint-cli2-action. Bump both together.
MARKDOWNLINT_VERSION := 0.23.2
# Paths the CI markdown-lint job skips; applied to tracked and untracked *.md files.
MD_EXCLUDE :=^tests/bats/|^tests/test_helper/|^mcp_server/\.venv/|^\.claude/skills/|^\.agents/skills/

.DEFAULT_GOAL := help
.PHONY: help setup lint lint-sh lint-py lint-md format test test-bats test-py validate-packages check-links test-distros \
	validate check-pins check-skills sync-skills curate check mcp docker clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## One-time dev setup: submodules, MCP deps, skill mirror (Codex-ready)
	git submodule update --init --recursive
	cd mcp_server && uv sync --group dev
	scripts/sync-skills.sh

lint: lint-sh lint-py lint-md ## Run all linters

lint-sh: ## shellcheck + bash syntax on all shell scripts
	shellcheck --severity=warning $(SH_FILES)
	bash -n $(SH_FILES)

lint-py: ## ruff check on the MCP server and repo-root scripts
	cd mcp_server && uv run --group dev ruff check . && uv run --group dev ruff format --check . \
		&& uv run --group dev ruff check ../scripts/

lint-md: ## markdownlint on tracked and untracked docs (mirrors the CI job)
	git ls-files --cached --others --exclude-standard '*.md' | grep -vE '$(MD_EXCLUDE)' | xargs npx --yes markdownlint-cli2@$(MARKDOWNLINT_VERSION)

format: ## Auto-format the MCP server with ruff
	cd mcp_server && uv run --group dev ruff format .

test: test-bats test-py ## Run all tests

test-bats: ## Bash unit tests (bats)
	./tests/bats/bin/bats tests/*.bats

test-py: ## MCP server tests (pytest)
	cd mcp_server && uv run --group dev pytest tests/ -q

validate: ## Run every data-consistency validator (tools, MCP sync, distros, skills, profiles, version, agent docs)
	python3 scripts/validate_tools_config.py
	python3 scripts/validate_mcp_sync.py
	python3 scripts/validate_distro_compat.py
	python3 scripts/validate_claude_skills.py
	python3 scripts/audit_skill_dependencies.py --check-declared
	bash scripts/update-skills.sh --check-pins
	python3 scripts/validate_agent_docs.py
	bash scripts/validate_profiles.sh
	bash scripts/validate_version.sh

validate-packages: ## Check every mapped package name exists in this distro's repos (needs network)
	bash scripts/validate_distro_packages.sh

check-links: ## Report dead external links in tracked Markdown (needs network)
	python3 scripts/check_doc_links.py

test-distros: ## Smoke-test install across apt/dnf/pacman/zypper in containers (needs podman/docker)
	bash scripts/test-distros.sh

check-pins: ## Assert vendored-skill upstream pins agree across all sources (offline)
	bash scripts/update-skills.sh --check-pins

check-skills: ## Report vendored-skill drift against upstream (clones sources)
	bash scripts/update-skills.sh

sync-skills: ## Mirror .claude/skills/ -> .agents/skills/ (for Codex and AGENTS.md tools)
	scripts/sync-skills.sh

curate: ## Regenerate skill curation + requirements (run after adding/removing a skill)
	python3 scripts/curate_claude_skills.py --write
	python3 scripts/audit_skill_dependencies.py --write-requirements

check: lint validate test ## Run the core local checks before pushing

mcp: ## Launch the MCP server inspector (web UI)
	cd mcp_server && uv run fastmcp dev server.py

docker: ## Build the Docker image
	docker build -t cybersec-toolkit .

clean: ## Remove Python caches and test artifacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf mcp_server/.ruff_cache 2>/dev/null || true

# Cybersec toolkit — developer & contributor shortcuts.
# Run `make` or `make help` for the list. Targets mirror the CI/validation commands
# in CLAUDE.md so a green `make check` locally means a green pipeline.

SHELL := bash
SH_FILES := install.sh lib/*.sh modules/*.sh scripts/*.sh
# Same globs as the markdown-lint CI job (skips vendored skills and submodules).
MD_GLOBS := **/*.md !docs/TOOL_ANALYSIS.md !tests/bats/**/*.md !tests/test_helper/**/*.md \
	!mcp_server/.venv/**/*.md !.claude/skills/**/*.md !.agents/skills/**/*.md

.DEFAULT_GOAL := help
.PHONY: help setup lint lint-sh lint-py lint-md format test test-bats test-py \
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

lint-md: ## markdownlint on tracked docs (CI globs)
	npx --yes markdownlint-cli2 $(MD_GLOBS)

format: ## Auto-format the MCP server with ruff
	cd mcp_server && uv run --group dev ruff format .

test: test-bats test-py ## Run all tests

test-bats: ## Bash unit tests (bats)
	./tests/bats/bin/bats tests/*.bats

test-py: ## MCP server tests (pytest)
	cd mcp_server && uv run --group dev pytest tests/ -q

validate: ## Run every data-consistency validator (tools, MCP sync, distros, skills, profiles)
	python3 scripts/validate_tools_config.py
	python3 scripts/validate_mcp_sync.py
	python3 scripts/validate_distro_compat.py
	python3 scripts/validate_claude_skills.py
	python3 scripts/audit_skill_dependencies.py --check-declared
	bash scripts/update-skills.sh --check-pins

check-pins: ## Assert vendored-skill upstream pins agree across all sources (offline)
	bash scripts/update-skills.sh --check-pins

check-skills: ## Report vendored-skill drift against upstream (clones sources)
	bash scripts/update-skills.sh

sync-skills: ## Mirror .claude/skills/ -> .agents/skills/ (for Codex and AGENTS.md tools)
	scripts/sync-skills.sh

curate: ## Regenerate skill curation + requirements (run after adding/removing a skill)
	python3 scripts/curate_claude_skills.py --write
	python3 scripts/audit_skill_dependencies.py --write-requirements

check: lint validate test ## Everything CI runs — go/no-go before pushing

mcp: ## Launch the MCP server inspector (web UI)
	cd mcp_server && uv run fastmcp dev server.py

docker: ## Build the Docker image
	docker build -t cybersec-toolkit .

clean: ## Remove Python caches and test artifacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf mcp_server/.ruff_cache 2>/dev/null || true

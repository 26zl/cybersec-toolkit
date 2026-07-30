## Summary

What changed and why?

## Type

- [ ] Bug fix
- [ ] Tool addition/update
- [ ] Installer/MCP change
- [ ] Documentation
- [ ] Other

## Validation

- [ ] `python3 scripts/validate_tools_config.py`
- [ ] `python3 scripts/validate_mcp_sync.py` if MCP-shared data changed
- [ ] `python3 scripts/validate_distro_compat.py` if distro mappings changed
- [ ] `bash scripts/validate_profiles.sh` if profiles changed
- [ ] `bash scripts/validate_version.sh` if version metadata changed
- [ ] `python3 scripts/validate_agent_docs.py` if agent documentation changed
- [ ] `python3 scripts/validate_claude_skills.py` if skills changed
- [ ] `python3 scripts/audit_skill_dependencies.py --check-declared` if skill helper scripts changed
- [ ] `bash scripts/update-skills.sh --check-pins` if vendored skills or source pins changed
- [ ] `shellcheck --severity=warning install.sh lib/*.sh modules/*.sh scripts/*.sh`
- [ ] `bash -n install.sh lib/*.sh modules/*.sh scripts/*.sh`
- [ ] `./tests/bats/bin/bats tests/*.bats`
- [ ] `cd mcp_server && uv run --group dev ruff check . && uv run --group dev ruff format --check . && uv run --group dev ruff check ../scripts/ && uv run --group dev pytest tests/ -q`

## Notes

Anything reviewers should know?

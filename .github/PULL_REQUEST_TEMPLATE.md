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
- [ ] `python3 scripts/validate_claude_skills.py` if skills changed
- [ ] `shellcheck --severity=warning install.sh lib/*.sh modules/*.sh scripts/*.sh`
- [ ] `bash -n install.sh lib/*.sh modules/*.sh scripts/*.sh`
- [ ] `./tests/bats/bin/bats tests/*.bats`
- [ ] `cd mcp_server && uv run --group dev ruff check . && uv run --group dev ruff format --check . && uv run --group dev pytest tests/ -q`

## Notes

Anything reviewers should know?

#!/usr/bin/env python3
"""Regression tests for the repository's Python tooling.

Run with: python3 -m unittest discover -s scripts -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import _bash_arrays  # noqa: E402
import _skill_text  # noqa: E402
import bump_version  # noqa: E402
import check_model_tools  # noqa: E402
import scan_skills  # noqa: E402
import validate_agent_docs  # noqa: E402
import validate_claude_skills  # noqa: E402
import validate_client_configs  # noqa: E402
import validate_findings  # noqa: E402
import validate_mcp_sync  # noqa: E402
import validate_tools_config  # noqa: E402
import verify_audit_chain  # noqa: E402

GRANT_VARIANTS = {
    "bare": "---\nname: a\nallowed-tools: Bash\n---\nbody\n",
    "double-quoted key": '---\nname: a\n"allowed-tools": Bash\n---\nbody\n',
    "single-quoted key": "---\nname: a\n'allowed-tools': Bash\n---\nbody\n",
    "space before colon": "---\nname: a\nallowed-tools : Bash\n---\nbody\n",
    "underscore spelling": "---\nname: a\nallowed_tools: Bash\n---\nbody\n",
    "byte-order mark": "\ufeff---\nname: a\nallowed-tools: Bash\n---\nbody\n",
    "flow mapping": "---\n{name: a, allowed-tools: Bash}\n---\nbody\n",
    "duplicate key": "---\nname: a\nallowed-tools: Read\nallowed-tools: Bash\n---\nbody\n",
    "escaped quoted key": '---\nname: a\n"allowed\\u002Dtools": Bash\n---\nbody\n',
    "hex escaped key": '---\nname: a\n"allowed\\x2Dtools": Bash\n---\nbody\n',
    "long escaped key": '---\nname: a\n"allowed\\U0000002Dtools": Bash\n---\nbody\n',
    "explicit key": "---\nname: a\n? allowed-tools\n: Bash\n---\nbody\n",
    "explicit escaped key": '---\nname: a\n? "allowed\\u002Dtools"\n: Bash\n---\nbody\n',
    "folded escaped key": '---\nname: a\n"allowed\\\n  -tools": Bash\n---\nbody\n',
    "alias key": "---\nname: a\nkey: &key allowed-tools\n*key: Bash\n---\nbody\n",
}


class SecurityWorkflowTests(unittest.TestCase):
    def test_eval_scan_distinguishes_commands_from_parser_data(self):
        workflow = (SCRIPTS.parent / ".github/workflows/security.yml").read_text()
        scan = next(line for line in workflow.splitlines() if "done < <(grep -nP" in line and "?eval" in line)
        pattern = re.compile(scan.split("grep -nP '", 1)[1].split('\' "$f"', 1)[0])
        for command in (
            'eval "$cmd"',
            '    eval "$cmd"',
            'if true; then eval "$cmd"; fi',
            'true && command eval "$cmd"',
            'builtin eval "$cmd"',
            'value=1 eval "$cmd"',
            "'eval' \"$cmd\"",
            'result=$(eval "$cmd")',
        ):
            with self.subTest(command=command):
                self.assertIsNotNone(pattern.search(command))
        for data in (
            '# eval "$cmd"',
            "if|then|eval|builtin) continue ;;",
            '    "builtin", "eval",',
            '    if wrapper == "eval" and not tok.startswith("-"):',
            'echo "eval is prohibited"',
        ):
            with self.subTest(data=data):
                self.assertIsNone(pattern.search(data))


class SkillUpdateConfigurationTests(unittest.TestCase):
    def _read_limits(self, minimum: str, maximum: str) -> subprocess.CompletedProcess:
        script = (SCRIPTS / "update-skills.sh").read_text().split("# name|git-url|pinned-commit", 1)[0]
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "limits.sh"
            path.write_text(script + '\nprintf "%s %s\\n" "$MIN_AGE_DAYS" "$MAX_STALE_DAYS"\n')
            return subprocess.run(
                ["bash", str(path)],
                env={**os.environ, "MIN_AGE_DAYS": minimum, "MAX_STALE_DAYS": maximum},
                capture_output=True,
                text=True,
            )

    def test_leading_zero_limits_are_decimal(self):
        result = self._read_limits("008", "0009")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "8 9")
        self.assertEqual(self._read_limits("000", "000").stdout.strip(), "0 0")

    def test_limits_cannot_overflow_seconds_arithmetic(self):
        for minimum, maximum in (("106751991167301", "1"), ("1", "999999999999999999999")):
            with self.subTest(minimum=minimum, maximum=maximum):
                self.assertEqual(self._read_limits(minimum, maximum).returncode, 2)


class SkillTextTests(unittest.TestCase):
    def test_every_grant_spelling_is_seen(self):
        for label, text in GRANT_VARIANTS.items():
            with self.subTest(label):
                tools = _skill_text.granted_tools(text)
                self.assertTrue(tools, "grant not detected")
                self.assertTrue(set(tools) - _skill_text.PROMPT_FREE_TOOLS)

    def test_duplicate_grants_are_all_dropped(self):
        cleaned = _skill_text.drop_tool_grant(GRANT_VARIANTS["duplicate key"])
        self.assertIsNone(_skill_text.granted_tools(cleaned))
        self.assertIn("name: a", cleaned)

    def test_quoted_and_bom_grants_are_dropped(self):
        for label in ("double-quoted key", "single-quoted key", "space before colon", "byte-order mark"):
            with self.subTest(label):
                self.assertIsNone(_skill_text.granted_tools(_skill_text.drop_tool_grant(GRANT_VARIANTS[label])))

    def test_flow_mapping_is_flagged_as_unparsed(self):
        self.assertTrue(_skill_text.has_unparsed_grant(GRANT_VARIANTS["flow mapping"]))
        self.assertFalse(_skill_text.has_unparsed_grant(GRANT_VARIANTS["bare"]))

    def test_complex_yaml_keys_fail_closed(self):
        for variant in (
            "escaped quoted key",
            "hex escaped key",
            "long escaped key",
            "explicit key",
            "explicit escaped key",
            "folded escaped key",
            "alias key",
        ):
            with self.subTest(variant=variant):
                self.assertTrue(_skill_text.has_unparsed_grant(GRANT_VARIANTS[variant]))
                self.assertIn(_skill_text.UNPARSED_GRANT, _skill_text.granted_tools(GRANT_VARIANTS[variant]))

    def test_read_only_grant_and_prose_mentions_pass(self):
        self.assertEqual(_skill_text.granted_tools("---\nname: a\nallowed-tools: Read, Grep\n---\n"), ["Read", "Grep"])
        prose = "---\nname: a\ndescription: the allowed-tools entry is legacy\n---\nallowed-tools: Bash\n"
        self.assertIsNone(_skill_text.granted_tools(prose))

    def test_block_list_grant_keeps_continuation_lines(self):
        text = "---\nname: a\nallowed-tools:\n  - Read\n  - Bash\ndescription: x\n---\n"
        self.assertEqual(_skill_text.granted_tools(text), ["Read", "Bash"])
        self.assertNotIn("Bash", _skill_text.drop_tool_grant(text))

    def test_invisible_ranges(self):
        for code in (0xE0001, 0xE0100, 0xE01EF, 0x61C, 0x180B, 0x180E, 0x2065, 0x206A, 0x206F, 0x200B, 0x2062):
            with self.subTest(hex(code)):
                self.assertIsNotNone(_skill_text.find_invisible("a" + chr(code) + "b"))
        for code in (0x200C, 0x200D, 0xFE0F):
            with self.subTest(hex(code)):
                self.assertIsNone(_skill_text.find_invisible("a" + chr(code) + "b"))


class SkillValidatorTests(unittest.TestCase):
    def test_symlink_inside_a_skill_is_an_error(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            skill = root / "demo"
            skill.mkdir()
            (skill / "SKILL.md").write_text("---\nname: demo\n---\n")
            (skill / "link.md").symlink_to("/etc/hosts")
            errors: list[str] = []
            with mock.patch.object(validate_claude_skills, "ROOT", root):
                validate_claude_skills._validate_no_links([skill], errors)
            self.assertEqual(len(errors), 1)
            self.assertIn("symbolic link", errors[0])

    def test_invalid_utf8_file_cannot_hide_tag_characters(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            skill = root / "demo"
            skill.mkdir()
            (skill / "SKILL.md").write_bytes(b"hello \xff \xf3\xa0\x81\x81 end\n")
            errors: list[str] = []
            with mock.patch.object(validate_claude_skills, "ROOT", root):
                validate_claude_skills._validate_visible_text([skill], errors)
            self.assertEqual(len(errors), 1)
            self.assertIn("invisible characters", errors[0])

    def test_unparseable_grant_is_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            skill = root / "demo"
            skill.mkdir()
            (skill / "SKILL.md").write_text(GRANT_VARIANTS["flow mapping"])
            errors: list[str] = []
            with mock.patch.object(validate_claude_skills, "ROOT", root):
                validate_claude_skills._validate_tool_grants([skill], errors)
            self.assertEqual(len(errors), 1)


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}  # fmt: skip
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env).stdout.decode()


class RevendorTests(unittest.TestCase):
    def _run(self, target_files: dict[str, bytes]) -> tuple[subprocess.CompletedProcess, Path, str]:
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(scratch, ignore_errors=True))
        upstream, skills = scratch / "up", scratch / "skills"
        (upstream / "demo").mkdir(parents=True)
        _git(upstream, "init", "-q")
        base = b"---\nname: demo\ndescription: d\n---\nhello\n"
        (upstream / "demo" / "SKILL.md").write_bytes(base)
        _git(upstream, "add", "-A")
        _git(upstream, "commit", "-qm", "base")
        pin = _git(upstream, "rev-parse", "HEAD").strip()
        (skills / "demo").mkdir(parents=True)
        (skills / "demo" / "SKILL.md").write_bytes(base)
        for rel, data in target_files.items():
            (upstream / "demo" / rel).write_bytes(data)
        _git(upstream, "add", "-A")
        _git(upstream, "commit", "-qm", "target")
        target = _git(upstream, "rev-parse", "HEAD").strip()
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "revendor_skills.py"), "--clone", str(upstream), "--pin", pin,
             "--target", target, "--skills-dir", str(skills)],
            capture_output=True,
            text=True,
        )  # fmt: skip
        return proc, skills / "demo", target

    def test_quoted_key_grant_is_removed(self):
        incoming = b'---\nname: demo\n"allowed-tools": Bash\ndescription: d\n---\nhello\n'
        proc, skill, _ = self._run({"SKILL.md": incoming})
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIsNone(_skill_text.granted_tools((skill / "SKILL.md").read_text()))

    def test_flow_mapping_grant_blocks_the_skill(self):
        incoming = b"---\n{name: demo, allowed-tools: Bash}\n---\nhello\n"
        proc, skill, _ = self._run({"SKILL.md": incoming})
        self.assertEqual(proc.returncode, 3, proc.stderr + proc.stdout)
        self.assertIn("BLOCKED", proc.stdout)
        self.assertNotIn("Bash", (skill / "SKILL.md").read_text())

    def test_non_utf8_text_is_sanitised_and_does_not_crash(self):
        incoming = b"---\nname: demo\ndescription: d\n---\nhello \xff \xf3\xa0\x81\x81\n"
        proc, skill, _ = self._run({"SKILL.md": incoming})
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        written = (skill / "SKILL.md").read_bytes()
        self.assertNotIn(b"\xf3\xa0\x81\x81", written)
        self.assertIn(b"<U+E0041>", written)
        self.assertIn(b"\xff", written)

    def test_non_utf8_path_is_not_a_traceback(self):
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(scratch, ignore_errors=True))
        upstream = scratch / "up"
        upstream.mkdir()
        _git(upstream, "init", "-q")
        (upstream / "keep").write_text("x")
        _git(upstream, "add", "-A")
        _git(upstream, "commit", "-qm", "one")
        pin = _git(upstream, "rev-parse", "HEAD").strip()
        blob = _git(upstream, "rev-parse", "HEAD:keep").strip()
        tree_in = f"100644 blob {blob}\t".encode() + b"\xffbad\0"
        env = {**os.environ, "GIT_DIR": str(upstream / ".git")}
        tree = subprocess.run(["git", "mktree", "-z"], input=tree_in, capture_output=True, env=env, check=True)
        commit = _git(upstream, "commit-tree", tree.stdout.decode().strip(), "-p", pin, "-m", "two").strip()
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "revendor_skills.py"), "--clone", str(upstream), "--pin", pin,
             "--target", commit, "--skills-dir", str(scratch / "none")],
            capture_output=True,
            text=True,
        )  # fmt: skip
        self.assertNotIn("Traceback", proc.stderr)


class AuditChainTests(unittest.TestCase):
    def test_non_object_lines_are_problems(self):
        for line in ("[1]", "123", '"x"', "null"):
            with self.subTest(line):
                self.assertTrue(verify_audit_chain.verify([line])[0])

    def test_boolean_seq_is_rejected(self):
        record = {"chain": "c" * 32, "seq": True, "prev": verify_audit_chain.CHAIN_GENESIS}
        self.assertTrue(verify_audit_chain.verify([json.dumps(record)])[0])

    def test_partial_or_malformed_chain_is_not_accepted_as_legacy(self):
        complete = {"chain": "c" * 32, "seq": 1, "prev": verify_audit_chain.CHAIN_GENESIS}
        for field in complete:
            for malformed in (
                {key: value for key, value in complete.items() if key != field},
                {**complete, field: None},
            ):
                with self.subTest(record=malformed):
                    self.assertTrue(verify_audit_chain.verify([json.dumps(malformed)])[0])
        self.assertFalse(verify_audit_chain.verify(['{"event":"legacy"}'])[0])


class ScanSkillsTests(unittest.TestCase):
    def test_skill_missing_from_report_is_an_error(self):
        report = {"multi_skill": True, "skills": [{"name": "one", "issues": []}]}
        skills = [Path("/x/one"), Path("/x/two")]
        with mock.patch.object(scan_skills, "scan_batch", return_value=report):
            with self.assertRaises(RuntimeError) as ctx:
                scan_skills.run_scan(skills, 1)
        self.assertIn("two", str(ctx.exception))

    def test_duplicate_and_unexpected_names_cannot_hide_missing_skills(self):
        for names in (("one", "one"), ("one", "unexpected"), ("one", "two", "extra")):
            report = {"multi_skill": True, "skills": [{"name": name, "issues": []} for name in names]}
            with self.subTest(names=names), mock.patch.object(scan_skills, "scan_batch", return_value=report):
                with self.assertRaises(RuntimeError):
                    scan_skills.run_scan([Path("/x/one"), Path("/x/two")], 1)

    def test_complete_report_counts_reported_skills(self):
        report = {"multi_skill": True, "skills": [{"name": "one", "issues": []}, {"name": "two", "issues": []}]}
        with mock.patch.object(scan_skills, "scan_batch", return_value=report):
            result = scan_skills.run_scan([Path("/x/one"), Path("/x/two")], 1)
        self.assertEqual(result["skills"], 2)

    def test_nameless_entry_is_incomplete(self):
        _, incomplete, reported = scan_skills.collect({"multi_skill": True, "skills": [{"issues": []}]})
        self.assertEqual(len(incomplete), 1)
        self.assertEqual(len(reported), 1)


class BumpVersionTests(unittest.TestCase):
    def _fake_root(self, scratch: Path, drop: str | None = None) -> None:
        files = {
            "mcp_server/pyproject.toml": 'version = "1.0.0"\n',
            ".claude-plugin/plugin.json": '{"version": "1.0.0"}\n',
            ".claude-plugin/marketplace.json": '{"version": "1.0.0"}\n',
            "CITATION.cff": 'version: "1.0.0"\n',
            "server.json": '{"version": "1.0.0", "image": "cybersec-toolkit:1.0.0"}\n',
            "README.md": "git clone --branch v1.0.0 x\n",
            "VERSION": "1.0.0\n",
        }
        for rel, text in files.items():
            if rel == drop:
                text = "nothing here\n"
            (scratch / rel).parent.mkdir(parents=True, exist_ok=True)
            (scratch / rel).write_text(text)

    def _bump(self, scratch: Path, version: str) -> int:
        with mock.patch.object(bump_version, "ROOT", scratch), mock.patch.object(sys, "argv", ["bump", version]):
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    bump_version.main()
            except SystemExit as exc:
                return 1 if isinstance(exc.code, str) else int(exc.code or 0)
        return 0

    def test_failed_bump_changes_nothing(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self._fake_root(root, drop="README.md")
            before = {p: p.read_text() for p in root.rglob("*") if p.is_file()}
            self.assertEqual(self._bump(root, "2.0.0"), 1)
            self.assertEqual(before, {p: p.read_text() for p in root.rglob("*") if p.is_file()})

    def test_successful_bump_updates_every_surface(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self._fake_root(root)
            self.assertEqual(self._bump(root, "2.0.0"), 0)
            self.assertEqual((root / "VERSION").read_text(), "2.0.0\n")
            self.assertIn("cybersec-toolkit:2.0.0", (root / "server.json").read_text())

    def test_trailing_newline_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self._fake_root(root)
            self.assertEqual(self._bump(root, "2.0.0\n"), 1)
            self.assertEqual((root / "VERSION").read_text(), "1.0.0\n")

    SURFACES = (
        "VERSION",
        "mcp_server/pyproject.toml",
        ".claude-plugin/plugin.json",
        ".claude-plugin/marketplace.json",
        "CITATION.cff",
        "server.json",
        "README.md",
    )

    def _real_copy(self, root: Path) -> None:
        repo = SCRIPTS.parent
        for rel in self.SURFACES:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes((repo / rel).read_bytes())

    def _run(self, script: str, root: Path, *args: str) -> subprocess.CompletedProcess:
        interpreter = ["bash"] if script.endswith(".sh") else [sys.executable]
        return subprocess.run(
            [*interpreter, str(SCRIPTS / script), *args],
            env={**os.environ, "BUMP_VERSION_ROOT": str(root)},
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_real_surfaces_bump_to_a_version_validate_version_accepts(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self._real_copy(root)
            bumped = self._run("bump_version.py", root, "9.9.9")
            self.assertEqual(bumped.returncode, 0, bumped.stderr)
            checked = self._run("validate_version.sh", root)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertIn("9.9.9", checked.stdout)

    def test_unpatchable_real_surface_leaves_every_file_unchanged(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self._real_copy(root)
            readme = root / "README.md"
            readme.write_text(readme.read_text().replace("--branch v", "--branch "))
            before = {rel: (root / rel).read_bytes() for rel in self.SURFACES}
            bumped = self._run("bump_version.py", root, "9.9.9")
            self.assertNotEqual(bumped.returncode, 0)
            self.assertEqual(before, {rel: (root / rel).read_bytes() for rel in self.SURFACES})
            self.assertNotEqual(self._run("validate_version.sh", root).returncode, 0)


class ClientConfigTests(unittest.TestCase):
    def test_rejected_config_does_not_echo_environment_values_or_arguments(self):
        value = "synthetic-private-config-value"
        text = json.dumps({"mcpServers": {"cybersec-tools": {"command": value, "args": [], "env": {"API_KEY": value}}}})
        errors = validate_client_configs.check(".mcp.json", text)
        self.assertTrue(errors)
        self.assertNotIn(value, " ".join(errors))

    def test_selftest_passes_on_the_tracked_configs(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(validate_client_configs.selftest(), 0)

    def test_widened_environment_is_rejected(self):
        text = (SCRIPTS.parent / ".mcp.json").read_text()
        widened = text.replace('"CYBERSEC_MCP_ALLOW_EXTERNAL": "0"', '"CYBERSEC_MCP_ALLOW_EXTERNAL": "1"')
        self.assertNotEqual(widened, text)
        self.assertTrue(validate_client_configs.check(".mcp.json", widened))


class AgentDocsTests(unittest.TestCase):
    def test_selftest_passes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(validate_agent_docs.selftest(), 0)


class GitExecutionSyncTests(unittest.TestCase):
    def _check(self, *, extra_tool=False, installer_text=None):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            tools = json.loads((SCRIPTS.parent / "tools_config.json").read_text())
            if extra_tool:
                tools.append({"name": "synthetic-cli", "method": "git", "module": "misc", "url": ""})
            (root / "tools_config.json").write_text(json.dumps(tools))
            (root / "lib").mkdir()
            text = installer_text if installer_text is not None else (SCRIPTS.parent / "lib/installers.sh").read_text()
            (root / "lib/installers.sh").write_text(text)
            with mock.patch.object(validate_mcp_sync, "ROOT", root), mock.patch.object(validate_mcp_sync, "errors", []):
                with contextlib.redirect_stdout(io.StringIO()):
                    validate_mcp_sync.check_git_execution_metadata()
                return list(validate_mcp_sync.errors)

    def test_current_git_execution_metadata_matches_installers(self):
        self.assertEqual(self._check(), [])

    def test_new_git_tool_requires_an_explicit_execution_disposition(self):
        self.assertTrue(any("synthetic-cli' lacks" in error for error in self._check(extra_tool=True)))

    def test_build_commands_must_have_matching_artifact_metadata(self):
        text = (SCRIPTS.parent / "lib/installers.sh").read_text()
        modified = text.replace('[bettercap]="bettercap"', '[synthetic-cli]="bettercap"')
        self.assertNotEqual(text, modified)
        self.assertTrue(any("different tool keys" in error for error in self._check(installer_text=modified)))


class BashArrayTests(unittest.TestCase):
    def body(self, text: str) -> str | None:
        return _bash_arrays.balanced_array_body(text, text.index("("))

    def test_escaped_paren_does_not_close_the_array(self):
        self.assertEqual(self.body("A=( a\\)b c )"), " a\\)b c ")

    def test_escaped_quote_does_not_flip_quote_state(self):
        self.assertEqual(self.body('A=( "x\\"" y )\nB=( z )'), ' "x\\"" y ')

    def test_apostrophe_in_comment_is_ignored(self):
        self.assertEqual(self.body('A=( "p" # it\'s (x)\n "q" )'), ' "p" # it\'s (x)\n "q" ')

    def test_unterminated_array_is_none(self):
        self.assertIsNone(self.body("A=(\n a\n b\n"))

    def test_unquoted_parser_survives_paren_in_comment(self):
        self.assertEqual(validate_mcp_sync.parse_bash_unquoted_array("X=( a # (old)\n b c )", "X"), ["a", "b", "c"])

    def test_sync_parser_reads_source_companions_in_ansi_quoted_values(self):
        text = "declare -gA BUILD_BINS=([tool]=$'build/tool|tool\\nbuild/helper|helper')"
        self.assertEqual(
            validate_mcp_sync.parse_bash_assoc_array(text, "BUILD_BINS"),
            {"tool": "build/tool|tool\nbuild/helper|helper"},
        )

    def test_unclosed_array_is_recorded_for_validation(self):
        validate_tools_config.UNCLOSED_ARRAYS.clear()
        validate_tools_config.parse_arrays("WEB_PACKAGES=(\n  nmap\n  curl\n")
        self.assertEqual(validate_tools_config.UNCLOSED_ARRAYS, {"WEB_PACKAGES"})
        validate_tools_config.UNCLOSED_ARRAYS.clear()


class FindingsTests(unittest.TestCase):
    def _check(self, content: str) -> list[str]:
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "findings.json"
            path.write_text(content)
            return validate_findings.check_file(path)[1]

    def test_empty_file_is_refused(self):
        self.assertTrue(any("holds no findings" in p for p in self._check("")))
        self.assertTrue(any("holds no findings" in p for p in self._check("[]")))

    def test_list_valued_fields_are_problems_not_crashes(self):
        bad = [{"id": "a", "title": "t", "target": "x", "kind": [], "status": [], "severity": {},
                "evidence": [{"source": []}]}]  # fmt: skip
        problems = self._check(json.dumps(bad))
        self.assertTrue(any("'kind'" in p for p in problems))
        self.assertTrue(any("'status'" in p for p in problems))


class CheckModelToolsTests(unittest.TestCase):
    def test_base_url_rules(self):
        ok = [
            "http://localhost:11434/v1",
            "http://127.0.0.1:8080/v1",
            "http://[::1]:1234/v1",
            "https://api.example.com/v1",
        ]
        bad = [
            "http://example.com/v1",
            "file:///etc/passwd",
            "ftp://example.com/v1",
            "http://10.0.0.5/v1",
            "example.com",
            "",
        ]
        for url in ok:
            self.assertIsNone(check_model_tools.validate_base_url(url), url)
        for url in bad:
            self.assertIsNotNone(check_model_tools.validate_base_url(url), url)

    def test_main_refuses_cleartext_remote_endpoint_before_any_request(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"K": "secret"}), contextlib.redirect_stderr(err):
            code = check_model_tools.main(["--base-url", "http://example.com/v1", "--model", "m", "--api-key-env", "K"])
        self.assertEqual(code, 2)
        self.assertNotIn("secret", err.getvalue())

    def test_keyed_requests_do_not_follow_redirects(self):
        handler = check_model_tools._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "http://evil.example/"))


class SourceHashTests(unittest.TestCase):
    def _hash(self):
        return subprocess.run(["bash", str(SCRIPTS / "sandbox-source-hash.sh")], capture_output=True, text=True)

    def test_editor_and_os_files_do_not_change_the_hash(self):
        before = self._hash()
        if before.returncode != 0:
            self.skipTest("sandbox-source-hash.sh needs bash 4 and sha256sum")
        stray = [SCRIPTS / ".DS_Store", SCRIPTS / "notes.swp", SCRIPTS / "x.py~", SCRIPTS / "x.py.orig"]
        try:
            for path in stray:
                path.write_text("junk")
            self.assertEqual(self._hash().stdout, before.stdout)
        finally:
            for path in stray:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

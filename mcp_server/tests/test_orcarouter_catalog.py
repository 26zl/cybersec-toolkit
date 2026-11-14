"""Tests for the OrcaRouter Cyber Inference helper in scripts/.

Covers the catalog capability filters, the verified fallback seed, the credential
seam (API key vs OAuth 2.0 + PKCE returning the same result type), PKCE
verifier/state handling against a local fake auth server, and the exact generation
rule for 401 recovery. All credentials here are fake.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import io
import json
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import evaluate_orcarouter_catalog as orca  # noqa: E402
import orcarouter_model_filter as model_filter  # noqa: E402

FAKE_KEY = "sk-orca-test-0000000000000000"
FAKE_OAUTH_KEY = "sk-orca-test-1111111111111111"
FAKE_CODE = "fake-code-abc123"


# --------------------------------------------------------------------------- fixtures


def _record(model_id, endpoint_types, modalities=None, context=None, params=None):
    record = {"id": model_id, "object": "model", "supported_endpoint_types": endpoint_types}
    if modalities is not None:
        record["architecture"] = {"modality": "x", "input_modalities": modalities}
    if context is not None:
        record["context_length"] = context
    if params is not None:
        record["supported_parameters"] = params
    return record


MIXED_CATALOG = {
    "object": "list",
    "data": [
        _record("openai/gpt-5.5", ["openai", "openai-response"], ["file", "image", "text"], params=["reasoning"]),
        _record("anthropic/claude-opus-4.8", ["openai", "anthropic", "openai-response"], ["text", "image", "file"]),
        _record("google/gemini-3.5-flash", ["openai", "gemini"], ["text", "image", "video", "audio"]),
        _record("deepseek/deepseek-v4-pro", ["openai", "openai-response"], ["text"]),
        _record("orcarouter/auto", ["openai", "openai-response", "anthropic", "gemini"]),
        _record("orcarouter/fusion", ["openai", "openai-response", "anthropic", "gemini"], context=1000000),
        _record("google/gemini-embedding-001", ["embeddings"], ["text"]),
        _record("google/imagen-4.0-generate-001", ["image-generation"]),
        _record("kling/kling-v2-5-turbo", ["openai-video"]),
        _record("jina-ai/jina-reranker-v3", ["jina-rerank"]),
        _record("tencent/hy3-free", []),
        {"id": "broken-shape", "supported_endpoint_types": "openai"},
        {"id": 123},
        _record("chat-no-modalities", ["openai"]),
        "not-a-record",
    ],
}


@pytest.fixture()
def catalog():
    return orca.build_catalog(MIXED_CATALOG)


class _FakeAuth(http.server.BaseHTTPRequestHandler):
    state: dict = {}

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        self.state["paths"].append(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        self.state["body"] = body
        status, payload = self.state["respond"](body)
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture()
def fake_auth():
    _FakeAuth.state = {
        "paths": [],
        "body": None,
        "respond": lambda body: (200, {"key": FAKE_OAUTH_KEY, "scope": "api"}),
    }
    server = http.server.HTTPServer(("127.0.0.1", 0), _FakeAuth)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", _FakeAuth.state
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- catalog


def test_catalog_is_bounded_and_drops_malformed_records(catalog):
    ids = [m["id"] for m in catalog]
    assert "broken-shape" in ids  # chat-shaped record still normalizable
    assert "tencent/hy3-free" in ids
    assert "not-a-record" not in ids
    assert len(catalog) == len(set(ids))
    record = next(m for m in catalog if m["id"] == "tencent/hy3-free")
    assert record["input_modalities"] == []
    assert record["context_length"] is None


def test_text_picker_keeps_only_chat_models(catalog):
    text = {m["id"] for m in orca.select(catalog)}
    assert {"openai/gpt-5.5", "anthropic/claude-opus-4.8", "deepseek/deepseek-v4-pro", "orcarouter/auto"} <= text
    assert not text & {
        "google/gemini-embedding-001",
        "google/imagen-4.0-generate-001",
        "kling/kling-v2-5-turbo",
        "jina-ai/jina-reranker-v3",
        "tencent/hy3-free",
    }


def test_multimodal_picker_excludes_text_only_and_undeclared_models(catalog):
    multimodal = {m["id"] for m in orca.select(catalog, "image")}
    assert {"openai/gpt-5.5", "anthropic/claude-opus-4.8", "google/gemini-3.5-flash"} <= multimodal
    assert not multimodal & {"deepseek/deepseek-v4-pro", "chat-no-modalities", "orcarouter/auto", "tencent/hy3-free"}


def test_reasoning_metadata_is_preserved(catalog):
    gpt = next(m for m in catalog if m["id"] == "openai/gpt-5.5")
    assert gpt["reasoning_efforts"] == ["low", "medium", "high", "xhigh"]


def test_filter_drops_kept_records_without_a_chat_endpoint(catalog):
    target = {
        "id": "deepseek/deepseek-v4-pro",
        "supported_endpoint_types": ["embeddings"],
        "input_modalities": ["text"],
    }
    assert model_filter.is_chat(target) is False
    assert model_filter.select([target]) == []
    kept = model_filter.select(catalog)
    assert kept
    assert all(model_filter.is_chat(m) for m in kept), kept
    assert orca.select(catalog) == kept


def test_seed_is_used_only_when_discovery_fails(monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setenv(orca.API_KEY_ENV, FAKE_KEY)
    monkeypatch.setattr(orca, "fetch_catalog", boom)
    assert orca.main([]) == 0
    assert "catalog: seed" in capsys.readouterr().out
    resolved = orca.backup_seed()
    assert resolved["source"] == "seed"
    ids = {m["id"] for m in resolved["catalog"]}
    assert {"orcarouter/auto", "orcarouter/fusion", "openai/gpt-5.5"} <= ids
    gpt = next(m for m in resolved["catalog"] if m["id"] == "openai/gpt-5.5")
    assert gpt["reasoning_efforts"] == ["low", "medium", "high", "xhigh"]
    assert "image" in gpt["input_modalities"]

    # A live catalog is authoritative: no seed entries are mixed in.
    monkeypatch.setattr(
        orca, "fetch_catalog", lambda *a, **k: orca.build_catalog({"data": [_record("x/y", ["openai"])]})
    )
    assert orca.main(["--json"]) == 0
    live = json.loads(capsys.readouterr().out)
    assert live["source"] == "live"
    assert live["text"] == ["x/y"]


def test_non_https_remote_origin_is_refused():
    with pytest.raises(ValueError):
        orca.fetch_catalog("http://api.example.com/v1")
    url, _ = orca._catalog_request("http://127.0.0.1:8000/v1", None)
    assert url == "http://127.0.0.1:8000/v1/models"


def test_catalog_file_source(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(MIXED_CATALOG))
    resolved = orca.read_catalog(str(path))
    assert resolved["source"] == "file"
    assert orca.select(resolved["catalog"])

def test_cli_prints_config_and_filtered_pickers(tmp_path, capsys):
    assert orca.main(["--show-config"]) == 0
    config = json.loads(capsys.readouterr().out)
    assert config["model_providers.orcarouter"]["base_url"] == "https://api.orcarouter.ai/v1"
    assert config["model_providers.orcarouter"]["name"] == "OrcaRouter Cyber Inference"
    assert config["model"] == "orcarouter/auto"

    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(MIXED_CATALOG))
    assert orca.main(["--input", str(path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["source"] == "file"
    assert "google/imagen-4.0-generate-001" not in report["text"]
    assert "deepseek/deepseek-v4-pro" not in report["multimodal"]


# --------------------------------------------------------------------------- credential seam


def test_both_adapters_return_the_same_credential_result(fake_auth):
    auth_base, state = fake_auth
    store = orca.CredentialStore()
    api_result = store.from_api_key(FAKE_KEY)
    oauth_result = store.from_oauth(auth_base, FAKE_CODE, "fake-verifier")

    assert isinstance(api_result, orca.CredentialResult)
    assert isinstance(oauth_result, orca.CredentialResult)
    assert api_result.credential.source == "api-key"
    assert oauth_result.credential.source == "orcarouter-oauth"
    assert oauth_result.scope == "api"

    # Downstream (catalog discovery and inference) reads only .key, never the source.
    assert store.credential is oauth_result.credential
    url, headers = orca._catalog_request(orca.DEFAULT_API_BASE, store.credential.key)
    assert url == "https://api.orcarouter.ai/v1/models"
    assert headers["Authorization"] == "Bearer " + FAKE_OAUTH_KEY

    # Exchange hits the auth origin's /api/v1/auth/keys, never the relay's /v1/auth/keys.
    assert state["paths"] == ["/api/v1/auth/keys"]
    assert state["body"] == {"code": FAKE_CODE, "code_verifier": "fake-verifier", "code_challenge_method": "S256"}


def test_api_key_adapter_rejects_non_orcarouter_keys():
    store = orca.CredentialStore()
    with pytest.raises(orca.AuthorizationError) as exc:
        store.from_api_key("sk-other-123")
    assert "sk-orca-" in str(exc.value)
    assert "sk-other-123" not in str(exc.value)


def test_credential_repr_never_contains_the_key():
    store = orca.CredentialStore()
    credential = store.from_api_key(FAKE_KEY).credential
    assert FAKE_KEY not in repr(credential)


@pytest.mark.parametrize(
    ("status", "payload"),
    [(403, {"error": "invalid_grant"}), (400, {"error": "invalid_request"}), (429, {"error": "too_many"})],
)
def test_exchange_errors_are_terminal_and_secret_free(fake_auth, status, payload):
    auth_base, state = fake_auth
    state["respond"] = lambda body: (status, payload)
    store = orca.CredentialStore()
    with pytest.raises(orca.AuthorizationError) as exc:
        store.from_oauth(auth_base, FAKE_CODE, "fake-verifier")
    message = str(exc.value)
    assert "fake-verifier" not in message and FAKE_CODE not in message
    assert store.credential is None


def test_scope_downgrade_is_rejected(fake_auth):
    auth_base, state = fake_auth
    state["respond"] = lambda body: (200, {"key": FAKE_OAUTH_KEY, "scope": "connector"})
    store = orca.CredentialStore()
    with pytest.raises(orca.AuthorizationError, match="does not cover"):
        store.from_oauth(auth_base, FAKE_CODE, "fake-verifier")


def test_missing_key_in_response_is_terminal(fake_auth):
    auth_base, state = fake_auth
    state["respond"] = lambda body: (200, {"scope": "api"})
    with pytest.raises(orca.AuthorizationError):
        orca.CredentialStore().from_oauth(auth_base, FAKE_CODE, "fake-verifier")


# --------------------------------------------------------------------------- PKCE


def test_pkce_pair_is_fresh_high_entropy_and_s256():
    verifier_a, challenge_a = orca.pkce_pair()
    verifier_b, challenge_b = orca.pkce_pair()
    assert verifier_a != verifier_b
    assert len(verifier_a) >= 43
    assert "=" not in challenge_a and "=" not in verifier_a
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier_a.encode()).digest()).decode().rstrip("=")
    assert challenge_a == expected


def test_authorize_url_uses_auth_origin_and_s256():
    url = orca.authorize_url(orca.DEFAULT_AUTH_BASE, "http://127.0.0.1:9/cb", "CHAL", "STATE")
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parts.query)
    assert (parts.scheme, parts.netloc, parts.path) == ("https", "www.orcarouter.ai", "/auth")
    assert query["callback_url"] == ["http://127.0.0.1:9/cb"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == ["CHAL"]
    assert query["state"] == ["STATE"]
    assert query["scope"] == ["api"]


def test_loopback_connect_delivers_code_and_exchanges(fake_auth):
    auth_base, state = fake_auth
    captured: dict = {}
    real_print = sys.stderr

    class Capture(io.StringIO):
        def write(self, text: str) -> int:
            captured.setdefault("url", text)
            return len(text)

    sys.stderr = Capture()
    try:
        def approve():
            while "url" not in captured:
                pass
            line = captured["url"].splitlines()[1].strip()
            callback = urllib.parse.parse_qs(urllib.parse.urlsplit(line).query)["callback_url"][0]
            query = urllib.parse.urlencode({"code": FAKE_CODE, "state": "wrong"})
            urllib.request.urlopen(callback + "?" + query, timeout=10).read()

        thread = threading.Thread(target=approve, daemon=True)
        thread.start()
        with pytest.raises(orca.AuthorizationError, match="state mismatch"):
            orca.connect_loopback(auth_base, timeout=10)
        assert state["paths"] == []  # a mismatched state never reaches exchange
    finally:
        sys.stderr = real_print


def test_loopback_connect_success(fake_auth):
    auth_base, state = fake_auth
    captured: dict = {}

    class Capture(io.StringIO):
        def write(self, text: str) -> int:
            captured.setdefault("url", text)
            return len(text)

    real_print = sys.stderr
    sys.stderr = Capture()
    try:
        def approve():
            while "url" not in captured:
                pass
            auth_url = captured["url"].splitlines()[1].strip()
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(auth_url).query)
            callback = query["callback_url"][0]
            urllib.request.urlopen(
                callback + "?" + urllib.parse.urlencode({"code": FAKE_CODE, "state": query["state"][0]}),
                timeout=10,
            ).read()

        thread = threading.Thread(target=approve, daemon=True)
        thread.start()
        result = orca.connect_loopback(auth_base, timeout=10)
    finally:
        sys.stderr = real_print
    assert result.credential.key == FAKE_OAUTH_KEY
    assert state["paths"] == ["/api/v1/auth/keys"]
    challenge_sent = urllib.parse.parse_qs(urllib.parse.urlsplit(captured["url"].splitlines()[1].strip()).query)
    verifier = state["body"]["code_verifier"]
    derived = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert challenge_sent["code_challenge"] == [derived]  # verifier itself never travelled to the authorize URL


# --------------------------------------------------------------------------- 401 recovery


def test_unauthorized_marks_only_the_rejected_generation():
    store = orca.CredentialStore()
    old = store.from_api_key(FAKE_KEY).credential
    new = store.from_api_key(FAKE_OAUTH_KEY).credential
    assert old.generation != new.generation
    assert store.mark_unauthorized(old.generation) is False
    assert new.needs_reauth is False
    assert store.mark_unauthorized(new.generation) is True
    assert new.needs_reauth is True


def test_live_check_requires_a_credential(monkeypatch):
    monkeypatch.delenv("ORCAROUTER_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        orca.main(["--live", "orcarouter/auto"])


def test_script_runs_as_module_cli(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(MIXED_CATALOG))
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(REPO_ROOT / "scripts" / "evaluate_orcarouter_catalog.py"),
            "--input",
            str(path),
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["source"] == "file"

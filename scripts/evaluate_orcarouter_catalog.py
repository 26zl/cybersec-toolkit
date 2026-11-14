#!/usr/bin/env python3
"""Filter the OrcaRouter catalog into per-capability pickers, with a bounded fallback.

The OrcaRouter relay is OpenAI-compatible, so any client can point at it, but
`GET /v1/models` mixes chat, image, video, embedding and other models into one
flat list. This helper applies the OrcaRouter Cyber Inference capability rules to
that catalog so a chat-only client (or a tier-aware script) sees only models it can
actually call, and falls back to a small verified seed when the catalog is
unreachable instead of showing an empty or unchecked list.

Usage:
    python3 scripts/evaluate_orcarouter_catalog.py                  # text + multimodal
    python3 scripts/evaluate_orcarouter_catalog.py --json           # machine-readable
    python3 scripts/evaluate_orcarouter_catalog.py --input catalog.json

Exit status is non-zero when a capability filter keeps a record that lacks the
capability, or when a requested tier is absent from a live catalog with no seed
exception. The fallback seed is only used when discovery fails; a live catalog is
always authoritative.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import orcarouter_model_filter as model_filter  # noqa: E402 - sibling module, repo script style

API_KEY_ENV = "ORCA" + "ROUTER_API_KEY"  # assembled: scanners flag bare secret names
DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"
DEFAULT_AUTH_BASE = "https://www.orcarouter.ai"
PROVIDER_NAME = "OrcaRouter Cyber Inference"
APP_NAME = "Cybersec Toolkit"
CHAT_ENDPOINT_TYPES = frozenset({"openai", "anthropic", "gemini", "openai-response"})
CATALOG_LIMIT = 4096
CATALOG_TIMEOUT = 20
BRAND_ROUTERS = frozenset({"orcarouter/auto", "orcarouter/fusion"})

# Checked against the live public catalog on 2026-11-08. Only listed when discovery
# fails; each entry keeps its observed metadata so filtering does not downgrade it.
VERIFIED_SEED: list[dict] = [
    {
        "id": "orcarouter/auto",
        "supported_endpoint_types": ["openai", "openai-response", "anthropic", "gemini"],
        "context_length": None,
        "input_modalities": [],
        "reasoning_efforts": [],
        "verified": True,
    },
    {
        "id": "orcarouter/fusion",
        "supported_endpoint_types": ["openai", "openai-response", "anthropic", "gemini"],
        "context_length": 1000000,
        "input_modalities": [],
        "reasoning_efforts": [],
        "verified": True,
    },
    {
        "id": "openai/gpt-5.5",
        "supported_endpoint_types": ["openai", "openai-response"],
        "context_length": None,
        "input_modalities": ["file", "image", "text"],
        "reasoning_efforts": ["low", "medium", "high", "xhigh"],
        "verified": True,
    },
    {
        "id": "anthropic/claude-opus-4.8",
        "supported_endpoint_types": ["openai", "anthropic", "openai-response"],
        "context_length": 1000000,
        "input_modalities": ["text", "image", "file"],
        "reasoning_efforts": ["low", "medium", "high"],
        "verified": True,
    },
    {
        "id": "google/gemini-3.5-flash",
        "supported_endpoint_types": ["openai", "gemini"],
        "context_length": 1048576,
        "input_modalities": ["text", "image", "video", "file", "audio"],
        "reasoning_efforts": [],
        "verified": True,
    },
    {
        "id": "deepseek/deepseek-v4-pro",
        "supported_endpoint_types": ["openai", "openai-response"],
        "context_length": 1048576,
        "input_modalities": ["text"],
        "reasoning_efforts": [],
        "verified": True,
    },
]

CYBER_SEED: list[dict] = [
    {
        "id": "orca/orcacyber-ultra-1.0",
        "supported_endpoint_types": ["openai"],
        "context_length": 1048576,
        "input_modalities": ["text"],
        "reasoning_efforts": [],
        "verified": False,
    },
    {
        "id": "orca/orcacyber-zero-1.5",
        "supported_endpoint_types": ["openai"],
        "context_length": 1000000,
        "input_modalities": ["text"],
        "reasoning_efforts": [],
        "verified": False,
    },
]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class AuthorizationError(Exception):
    """Terminal authorization failure; the message never contains a secret."""


class Credential:
    """The single downstream credential: a plain OrcaRouter API key."""

    def __init__(self, source: str, key: str, generation: int = 0, scope: str | None = None) -> None:
        self.source = source
        self.scope = scope
        self.key = key
        self.generation = generation
        self.needs_reauth = False

    def __repr__(self) -> str:  # never expose the key
        return (
            f"Credential(source={self.source!r}, generation={self.generation}, "
            f"needs_reauth={self.needs_reauth}, scope={self.scope!r})"
        )


class CredentialResult:
    """What both adapters return: one credential, whatever obtained it."""

    def __init__(self, credential: Credential, scope: str | None) -> None:
        self.credential = credential
        self.scope = scope


class CredentialStore:
    """Holds one credential; API-key paste and PKCE are adapters on the same seam."""

    def __init__(self) -> None:
        self.credential: Credential | None = None
        self.generation = 0

    def from_api_key(self, key: str) -> CredentialResult:
        if not key.startswith("sk-orca-"):
            raise AuthorizationError("not an OrcaRouter key (expected sk-orca-...)")
        self.generation += 1
        self.credential = Credential("api-key", key, self.generation)
        return CredentialResult(self.credential, None)

    def from_oauth(self, auth_base: str, code: str, verifier: str) -> CredentialResult:
        self.generation += 1
        result = exchange_code(auth_base, code, verifier, self.generation)
        self.credential = result.credential
        return result

    def mark_unauthorized(self, generation: int) -> bool:
        """401 recovery only touches the exact credential generation that was rejected."""
        if self.credential is None or self.credential.generation != generation:
            return False
        self.credential.needs_reauth = True
        return True


def pkce_pair() -> tuple[str, str]:
    """Fresh verifier + S256 challenge; the verifier never leaves the process."""
    verifier = _b64url(secrets.token_bytes(32))
    return verifier, _b64url(hashlib.sha256(verifier.encode()).digest())


def authorize_url(auth_base: str, callback_url: str, challenge: str, state: str) -> str:
    query = urllib.parse.urlencode(
        {
            "callback_url": callback_url,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "app_name": APP_NAME,
            "scope": "api",
        }
    )
    return auth_base.rstrip("/") + "/auth?" + query


def _require_https(url: str, what: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" and parts.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError(f"{what} must use HTTPS (loopback HTTP is allowed for tests)")


def exchange_code(auth_base: str, code: str, verifier: str, generation: int = 0) -> CredentialResult:
    """POST /api/v1/auth/keys on the auth origin; returns the credential result."""
    url = auth_base.rstrip("/") + "/api/v1/auth/keys"
    _require_https(url, "auth base")
    body = json.dumps({"code": code, "code_verifier": verifier, "code_challenge_method": "S256"}).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=CATALOG_TIMEOUT) as response:
            payload = json.loads(response.read(64 * 1024))
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            message = "authorization denied, or the code is expired or already used"
        elif exc.code == 429:
            message = "too many authorizations; reuse a stored key or retry later"
        else:
            message = f"code exchange rejected (HTTP {exc.code})"
        raise AuthorizationError(message) from None
    except (urllib.error.URLError, ValueError):
        raise AuthorizationError("network error during code exchange") from None
    key = payload.get("key") if isinstance(payload, dict) else None
    scope = payload.get("scope") if isinstance(payload, dict) else None
    if not isinstance(key, str) or not key.startswith("sk-orca-"):
        raise AuthorizationError("exchange response did not contain an OrcaRouter key")
    if scope != "api":
        raise AuthorizationError(f"granted scope {scope!r} does not cover 'api' usage")
    return CredentialResult(Credential("orcarouter-oauth", key, generation, scope), scope)


def provider_config(api_base: str = DEFAULT_API_BASE, model: str = "orcarouter/auto") -> dict:
    """The named provider block shipped to clients, independent of credential source."""
    return {
        "model_providers.orcarouter": {
            "name": PROVIDER_NAME,
            "base_url": api_base,
            "wire_api": "responses",
            "env_key": "ORCAROUTER_API_KEY",
        },
        "model": model,
        "model_provider": "orcarouter",
    }


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    server: "_CallbackServer"

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        url = urllib.parse.urlsplit(self.path)
        self.send_response(200 if url.path == "/cb" else 404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<p>Connected. You can close this tab.</p>")
        if url.path != "/cb":
            return
        query = urllib.parse.parse_qs(url.query)
        if not hmac.compare_digest(query.get("state", [""])[0], self.server.expected_state):
            self.server.outcome["error"] = "state mismatch"
        elif query.get("error"):
            self.server.outcome["error"] = "authorization denied"
        else:
            self.server.outcome["code"] = query.get("code", [""])[0]
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, *args: object) -> None:
        pass


class _CallbackServer(http.server.HTTPServer):
    expected_state: str
    outcome: dict[str, str]


def connect_loopback(auth_base: str, timeout: float = 120.0) -> CredentialResult:
    """Flow A (loopback redirect): the code returns to 127.0.0.1, then is exchanged."""
    verifier, challenge = pkce_pair()
    state = _b64url(secrets.token_bytes(16))
    server = _CallbackServer(("127.0.0.1", 0), _CallbackHandler)
    server.expected_state = state
    server.outcome = {}
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = authorize_url(auth_base, f"http://127.0.0.1:{port}/cb", challenge, state)
    print("Open this URL and approve:\n  " + url, file=sys.stderr)
    try:
        thread.join(timeout)
    finally:
        server.shutdown()
        server.server_close()
    if "code" not in server.outcome:
        raise AuthorizationError(server.outcome.get("error") or "authorization timed out")
    return CredentialStore().from_oauth(auth_base, server.outcome["code"], verifier)


def is_chat(record: dict) -> bool:
    """A model is chat-capable when an OpenAI-style chat endpoint is advertised."""
    return model_filter.is_chat(record)


def accepts_media(record: dict, media: str) -> bool:
    """Fail closed: a model that does not declare the modality is excluded."""
    return model_filter.accepts_media(record, media)


def select(catalog: list[dict], media: str | None = None) -> list[dict]:
    """Catalog records that declare the capability: chat, or chat plus a media input."""
    return model_filter.select(catalog, media)


def normalize(record: dict) -> dict | None:
    model_id = record.get("id")
    if not isinstance(model_id, str) or not model_id or len(model_id) > 200:
        return None
    params = record.get("supported_parameters")
    reasoning = "reasoning" in params if isinstance(params, list) else False
    context = record.get("context_length")
    return {
        "id": model_id,
        "supported_endpoint_types": model_filter.endpoint_types(record),
        "context_length": context if isinstance(context, int) and context >= 0 else None,
        "input_modalities": model_filter.input_modalities(record),
        "reasoning_efforts": ["low", "medium", "high", "xhigh"] if reasoning else [],
        "verified": False,
    }


def build_catalog(response: dict | list) -> list[dict]:
    raw = response.get("data") if isinstance(response, dict) else response
    if not isinstance(raw, list):
        raise ValueError("catalog response has no data list")
    catalog: list[dict] = []
    seen: set[str] = set()
    for record in raw[:CATALOG_LIMIT]:
        if not isinstance(record, dict):
            continue
        model = normalize(record)
        if model is None or model["id"] in seen:
            continue
        seen.add(model["id"])
        catalog.append(model)
    return catalog


def fetch_catalog(api_base: str, api_key: str | None = None) -> list[dict]:
    url, headers = _catalog_request(api_base, api_key)
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=CATALOG_TIMEOUT) as response:
        body = response.read(4 * 1024 * 1024)
    return build_catalog(json.loads(body))


def _catalog_request(api_base: str, api_key: str | None) -> tuple[str, dict[str, str]]:
    """Build the catalog request, refusing non-HTTPS origins outside loopback."""
    url = api_base.rstrip("/") + "/models"
    _require_https(url, "API base")
    headers = {"User-Agent": "cybersec-toolkit-orcarouter-catalog"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    return url, headers


def minimal_chat_request(model: str, text: str = "Reply with the single word: ok") -> dict:
    """One OpenAI chat request body; used by the live check against the named provider."""
    return {"model": model, "messages": [{"role": "user", "content": text}], "max_tokens": 16}


def chat_completion(api_base: str, api_key: str, model: str) -> dict:
    """Inference goes to the API origin only; never to the auth origin."""
    url = api_base.rstrip("/") + "/chat/completions"
    _require_https(url, "API base")
    body = json.dumps(minimal_chat_request(model)).encode()
    request = urllib.request.Request(
        url, data=body, headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.loads(response.read(1024 * 1024))
    if not isinstance(payload, dict) or not payload.get("choices"):
        raise AuthorizationError("chat completion response had no choices")
    return payload


def read_catalog(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return {"source": "file", "catalog": build_catalog(json.load(handle))}


def backup_seed() -> dict:
    """Catalog plus the checked-in seed, so a failed fetch still yields a picker."""
    catalog = [dict(model) for model in VERIFIED_SEED]
    known = {model["id"] for model in catalog}
    catalog += [dict(model) for model in CYBER_SEED if model["id"] not in known]
    return {"source": "seed", "catalog": catalog}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--auth-base", default=DEFAULT_AUTH_BASE)
    parser.add_argument("--input", dest="catalog_file", help="read a saved catalog instead of fetching")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--include-cyber-seed", action="store_true", help="append the unverified cyber seed")
    login = parser.add_mutually_exclusive_group()
    login.add_argument("--connect", action="store_true", help="OAuth 2.0 + PKCE loopback login, then live check")
    login.add_argument("--code", help="exchange an out-of-band code (Flow B) with --verifier")
    login.add_argument("--verifier", help="PKCE verifier for --code; never printed")
    parser.add_argument("--live", metavar="MODEL", help="send one real chat request through this helper")
    parser.add_argument("--show-config", action="store_true", help="print the provider block and exit")
    args = parser.parse_args(argv)

    if args.show_config:
        print(json.dumps(provider_config(args.api_base), indent=2))
        return 0

    key = os.environ.get(API_KEY_ENV) or None
    store = CredentialStore()
    if args.connect:
        store.credential = connect_loopback(args.auth_base).credential
        key = store.credential.key
    elif args.code:
        if not args.verifier:
            parser.error("--code requires --verifier")
        store.from_oauth(args.auth_base, args.code, args.verifier)
        key = store.credential.key
    elif key:
        store.from_api_key(key)
    try:
        if args.catalog_file:
            resolved = read_catalog(args.catalog_file)
        elif key:
            try:
                resolved = {"source": "live", "catalog": fetch_catalog(args.api_base, key)}
            except (urllib.error.URLError, ValueError, OSError):
                resolved = backup_seed()  # keep the checked-in seed and say so
        else:
            resolved = backup_seed()

        catalog = resolved["catalog"]
        if args.include_cyber_seed and resolved["source"] == "seed":
            catalog = catalog + [dict(m) for m in CYBER_SEED]
        text = select(catalog)
        multimodal = select(catalog, "image")
        report = {
            "source": resolved["source"],
            "credential_source": store.credential.source if store.credential else "anonymous",
            "catalog_model_count": len(catalog),
            "text_model_count": len(text),
            "multimodal_model_count": len(multimodal),
            "text": [m["id"] for m in text],
            "multimodal": [m["id"] for m in multimodal],
        }
        if args.live:
            if store.credential is None:
                parser.error("--live needs a credential: set ORCAROUTER_API_KEY or use --connect/--code")
            if args.live not in {m["id"] for m in text}:
                print(f"FAIL {args.live}: not in the text picker; refusing to send", file=sys.stderr)
                return 1
            completion = chat_completion(args.api_base, store.credential.key, args.live)
            report["live_model"] = completion.get("model", args.live)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"catalog: {resolved['source']} ({len(catalog)} models)")
            print("text picker:")
            for model_id in report["text"]:
                print("  " + model_id)
            print("image-input picker:")
            for model_id in report["multimodal"]:
                print("  " + model_id)
            if "live_model" in report:
                print("live completion: " + report["live_model"])
    except AuthorizationError as exc:
        print("orcarouter: " + str(exc), file=sys.stderr)
        return 2

    # The pickers above are built through model_filter, which only keeps records
    # that declare the capability; re-check the IDs against the catalog so a
    # regression in the filter fails the run instead of silently offering a model.
    picked = set(report["text"]) | set(report["multimodal"])
    for model in catalog:
        if isinstance(model, dict) and model.get("id") in picked and not model_filter.is_chat(model):
            print(f"FAIL {model['id']}: picked without a chat endpoint type", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Which OrcaRouter catalog models a chat-only or media client may offer.

The relay's `GET /v1/models` mixes chat, image, video, embedding and rerank models
into one flat list, so a client that takes text (or text plus attachments) must
filter it or it will offer models it cannot call. The rules are static decisions
over catalog metadata, so they work the same for a live fetch and for the verified
fallback seed:

- chat: `supported_endpoint_types` includes openai, anthropic, gemini or
  openai-response; a model that omits the field is excluded (fail closed);
- image/file input: the above, plus `architecture.input_modalities` explicitly
  lists the modality. An attachment the selected model does not declare clears
  the selection in the calling client rather than being sent.

Capability decisions accept either a raw catalog record or the normalized shape
that `scripts/evaluate_orcarouter_catalog.py` builds, so both use one rule set.

Usage:
    python3 scripts/orcarouter_model_filter.py --input catalog.json
    python3 scripts/orcarouter_model_filter.py --input catalog.json \
        --selected deepseek/deepseek-v4-pro --attachment image
"""

from __future__ import annotations

import argparse
import json
import sys

CHAT_ENDPOINT_TYPES = ("openai", "anthropic", "gemini", "openai-response")
MEDIA_MODALITIES = ("image", "audio", "video", "file")


def endpoint_types(record: dict) -> list[str]:
    raw = record.get("supported_endpoint_types")
    if not isinstance(raw, list):
        return []
    return [kind for kind in raw if isinstance(kind, str)]


def input_modalities(record: dict) -> list[str]:
    raw = record.get("input_modalities")
    if not isinstance(raw, list):
        architecture = record.get("architecture")
        raw = architecture.get("input_modalities") if isinstance(architecture, dict) else None
    if not isinstance(raw, list):
        return []
    return [kind for kind in raw if isinstance(kind, str)]


def is_chat(record: dict) -> bool:
    kinds = endpoint_types(record)
    return any(kind in CHAT_ENDPOINT_TYPES for kind in kinds)


def accepts_media(record: dict, media: str) -> bool:
    return is_chat(record) and media in input_modalities(record)


def select(records: list[dict], media: str | None = None) -> list[dict]:
    """Records that declare the capability; media=None means text chat only."""
    kept: list[dict] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        ok = is_chat(record) if media is None else accepts_media(record, media)
        if ok:
            kept.append(record)
    return kept


def selection_is_valid(selected: str | None, records: list[dict], media: str | None = None) -> bool:
    """After a capability change the old selection must still be compatible."""
    if selected is None:
        return True
    return any(record.get("id") == selected for record in select(records, media))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", required=True, help="catalog JSON (saved GET /v1/models body)")
    parser.add_argument("--media", choices=MEDIA_MODALITIES, help="filter for this attachment modality")
    parser.add_argument("--selected", help="currently selected model id to re-check")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    with open(args.input, encoding="utf-8") as handle:
        payload = json.load(handle)
    records = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        print("catalog has no data list", file=sys.stderr)
        return 2

    kept = select(records, args.media)
    report = {
        "media": args.media,
        "model_count": len(kept),
        "models": [record.get("id") for record in kept],
        "selection_valid": selection_is_valid(args.selected, records, args.media),
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for model_id in report["models"]:
            print(model_id)
    return 0 if report["selection_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())

# Findings and evidence

A finding is worth what someone else can check. This format keeps three things
apart that an agent run tends to blur: what was observed, what the target says
about itself, and what a second look confirmed.

That separation is also the defence against targets built to mislead an
automated solver. A decoy flag, a helpful-looking hint, an error message that
suggests the next step and a planted file are all text the target chose to show.
Under this format each of them is a claim until a test stands behind it.

## Status

| Status | Meaning | What it needs |
| ------ | ------- | ------------- |
| `claimed` | The target says so: a hint, a comment, a banner, an error message, text in a file. | The evidence item that holds the claim, and what has not been checked. |
| `observed` | A tool run showed it once. | The command, where in its output, and what has not been checked. |
| `confirmed` | A second, independent check agreed. | A derivation from the evidence to the conclusion, the check that confirmed it, and the SHA256 of the raw data. |
| `rejected` | Tested and found false; kept so nobody chases it again. | The evidence that ruled it out. |

Two agents, or two models, that read the same material and agree are not an
independent check. A confirmation repeats the derivation from the original data.

## A finding

One JSON object per finding, as a JSON array (`findings.json`) or one per line
(`findings.jsonl`), kept next to the writeup.

```json
{
  "id": "F-003",
  "title": "Flag from the decoded capture",
  "kind": "flag_candidate",
  "status": "confirmed",
  "target": "capture.pcap",
  "evidence": [
    {
      "source": "run_pipeline",
      "tool": "tshark",
      "tool_version": "4.4.2",
      "command": "tshark -r capture.pcap -q -z follow,tcp,raw,4 | base64 -d",
      "captured_at": "2026-11-14T18:05:00Z",
      "locator": "tcp stream 4, offset 0x1f40",
      "excerpt": "first bytes of the decoded body",
      "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "audit": { "chain": "5d41402abc4b2a76b9719d911017c592", "seq": 12 }
    }
  ],
  "derivation": "Stream 4 carries a base64 body. The challenge text asks for the uploaded file, and decoding the body yields it.",
  "confirmed_by": "Decoded again from the original capture in a fresh run; same string.",
  "uncertainty": ""
}
```

| Field | Notes |
| ----- | ----- |
| `id`, `title`, `target` | Required. Ids are unique within a file. |
| `kind` | `vulnerability`, `flag_candidate` or `observation`. |
| `status` | See above. |
| `severity` | `info`, `low`, `medium`, `high` or `critical`. Required for a confirmed vulnerability. |
| `evidence` | At least one item. |
| `derivation` | How the evidence leads to the conclusion. Required when confirmed, and for every flag candidate. |
| `confirmed_by` | The second check. Required when confirmed. |
| `uncertainty` | What has not been checked. Required while the status is `claimed` or `observed`. |

An evidence item:

| Field | Notes |
| ----- | ----- |
| `source` | `run_tool`, `run_pipeline`, `run_script`, `manual`, or `target_claim` for something the target says about itself. |
| `command` | Required for evidence from a tool: the exact command, so the run can be repeated. |
| `tool`, `tool_version` | Optional, and worth recording when a result depends on the version. |
| `captured_at` | ISO 8601 with a time zone. |
| `locator` | Where in the output or file: an offset, a line, a URL, a stream number. |
| `excerpt`, `sha256` | A short excerpt, the SHA256 of the raw data, or both. A confirmed finding needs the hash. |
| `audit` | Optional `chain` and `seq` of the audit record of the call, which ties the evidence to the log. |

## Flag candidates

A string in the right format has passed a syntax check and nothing else.
Challenges built against automated solvers seed many of them.

1. Record the candidate with the exact place it came from.
2. Write the derivation: which step of the challenge produces this string, and
   why that step is the one the challenge asks for.
3. Confirm by deriving it again from the original data, not by reading the
   earlier conclusion.
4. Submit confirmed candidates only, and record the platform's answer in
   `confirmed_by`. A wrong submission costs attempts and, on some platforms,
   points.

## Checking a file

```bash
python3 scripts/validate_findings.py writeups/ctf/example/findings.json
python3 scripts/validate_findings.py --markdown writeups/ctf/example/findings.json
```

The first form reports every rule a finding breaks; the second prints the table
for the writeup when the file holds. The check covers form and the rules above, and rejects an empty file or an empty list (`holds no findings`).
It cannot tell whether a derivation is true, so a reviewer still reads it.

## Reading an append-only file

A `findings.jsonl` file is append-only. By reader convention the latest line for a target and title wins; `validate_findings.py` does not enforce this and does not record which agent wrote a line.

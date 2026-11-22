"""Auto-detection routes a target to the advisor category its content calls for."""

from __future__ import annotations

import os
import struct
import time
import zipfile
from unittest.mock import patch

import pytest

from mcp_server.guided_assessment import _SNIFF_BYTES, _ZIP_MAX_MEMBERS, _infer_workflow_type


def _zip(path, names):
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, b"synthetic")
    return path


CONTENT_CASES = [
    ("capture", struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1), "forensics"),
    ("chal", b"\x7fELF\x02\x01\x01" + b"\x00" * 57, "pwn"),
    ("firmware.bin", b"hsqs" + b"\x00" * 60, "reversing"),
    ("sample.dat", b"MZ\x90\x00" + b"\x00" * 60, "reversing"),
    ("picture.dat", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, "stego"),
    ("sound", b"RIFF\x24\x00\x00\x00WAVEfmt ", "stego"),
    ("evidence", b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 16, "forensics"),
    ("macro.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16, "forensics"),
    ("rsa.txt", b"n = 3233\ne = 17\nc = 2790\n", "crypto"),
    ("key.txt", b"-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQAD\n-----END PUBLIC KEY-----\n", "crypto"),
    ("hashes.txt", b"5f4dcc3b5aa765d61d8327deb882cf99\n$6$salt$abcdefghijklmnop\n", "crypto"),
    ("token.txt", b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl\n", "web"),
    ("mail.txt", b"Received: from mx\nFrom: a@example.invalid\nSubject: x\n\nbody\n", "forensics"),
    ("auth.txt", b"Nov 21 10:00:01 host sshd[1]: Failed password\n" * 3, "forensics"),
    ("deploy.yaml", b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n", "cloud"),
    ("Dockerfile", b"FROM ubuntu:26.04\nRUN apt-get update\n", "cloud"),
    ("main.txt", b'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n', "cloud"),
    ("contract.txt", b"// SPDX\npragma solidity ^0.8.0;\ncontract C {}\n", "blockchain"),
    ("notes.txt", b"nothing to see here\n", "misc"),
]


@pytest.mark.parametrize(("name", "content", "category"), CONTENT_CASES)
def test_file_content_selects_the_category(name, content, category, tmp_path):
    path = tmp_path / name
    path.write_bytes(content)
    assert _infer_workflow_type(str(path), "file") == ("ctf", category)


@pytest.mark.parametrize(
    ("name", "names", "category"),
    [
        ("app.zip", ["AndroidManifest.xml", "classes.dex"], "mobile"),
        ("invoice.docx", ["[Content_Types].xml", "word/vbaProject.bin"], "forensics"),
        ("tool.zip", ["META-INF/MANIFEST.MF", "a/B.class"], "reversing"),
        ("bundle.apk", ["readme.txt"], "forensics"),
    ],
)
def test_zip_members_select_the_category(name, names, category, tmp_path):
    path = _zip(tmp_path / name, names)
    assert _infer_workflow_type(str(path), "file") == ("ctf", category)


def test_missing_file_keeps_the_extension_route():
    assert _infer_workflow_type("./does-not-exist.pcap", "file") == ("ctf", "forensics")


def test_fifo_is_not_read_and_falls_back_to_the_extension(tmp_path):
    fifo = tmp_path / "pipe.bin"
    os.mkfifo(fifo)
    assert _infer_workflow_type(str(fifo), "file") == ("ctf", "pwn")


def test_multibyte_character_at_the_read_boundary_still_reads_as_text(tmp_path):
    path = tmp_path / "rsa.txt"
    prefix = b"n = 3233\ne = 17\n"
    filler = b"a" * (_SNIFF_BYTES - len(prefix) - 1)
    path.write_bytes(prefix + filler + "æ".encode())
    assert _infer_workflow_type(str(path), "file") == ("ctf", "crypto")


def test_cloud_file_under_bounty_maps_to_the_cloud_target_type(tmp_path):
    path = tmp_path / "deploy.yaml"
    path.write_bytes(b"apiVersion: v1\nkind: Pod\n")
    assert _infer_workflow_type(str(path), "file", "bounty") == ("bounty", "cloud")


@pytest.mark.parametrize(
    ("url", "workflow", "expected"),
    [
        ("http://10.0.0.5/v1/chat/completions", None, ("bounty", "llm")),
        ("http://10.0.0.5/api/generate", None, ("bounty", "llm")),
        ("https://10.0.0.5/v1/messages", "ctf", ("ctf", "llm")),
        ("http://10.0.0.5/api/users", None, ("bounty", "api")),
        ("http://10.0.0.5/chat/completions-archive", None, ("bounty", "web_app")),
    ],
)
def test_llm_endpoints_route_to_llm(url, workflow, expected):
    assert _infer_workflow_type(url, "url", workflow) == expected


@pytest.mark.parametrize(
    "content", [b"\n" * _SNIFF_BYTES, b" \n" * (_SNIFF_BYTES // 2), b"\t\t\t\n" * (_SNIFF_BYTES // 4)]
)
def test_whitespace_only_files_are_classified_quickly(content, tmp_path):
    path = tmp_path / "whitespace.txt"
    path.write_bytes(content)
    started = time.monotonic()
    assert _infer_workflow_type(str(path), "file") == ("ctf", "misc")
    assert time.monotonic() - started < 1.0


def test_a_zip_python_cannot_read_falls_back_to_the_extension(tmp_path):
    path = _zip(tmp_path / "odd.apk", ["AndroidManifest.xml"])
    data = bytearray(path.read_bytes())
    data[data.rfind(b"PK\x01\x02") + 6] = 255
    path.write_bytes(bytes(data))
    assert _infer_workflow_type(str(path), "file") == ("ctf", "mobile")


def test_a_large_central_directory_is_not_read(tmp_path):
    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for index in range(_ZIP_MAX_MEMBERS + 1):
            archive.writestr(f"f{index}", b"")
    with patch("mcp_server.guided_assessment.zipfile.ZipFile") as zip_reader:
        assert _infer_workflow_type(str(path), "file") == ("ctf", "forensics")
    zip_reader.assert_not_called()


def test_device_files_are_not_opened():
    with patch("mcp_server.guided_assessment.os.open", side_effect=AssertionError("opened a device")):
        assert _infer_workflow_type("/dev/null", "file") == ("ctf", "misc")


def test_gemini_generate_content_routes_to_llm():
    assert _infer_workflow_type("https://10.0.0.5/v1beta/models/m:generateContent", "url") == ("bounty", "llm")

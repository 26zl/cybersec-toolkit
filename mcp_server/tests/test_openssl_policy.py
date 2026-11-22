"""openssl's offline commands run under the default policy; its network and code-loading paths do not."""

from __future__ import annotations

import shlex

import pytest

from mcp_server.security import check_policy

OFFLINE = [
    "genrsa 2048",
    "ec -in /tmp/k.pem -noout -text",
    "ecparam -name prime256v1 -genkey",
    "ciphers -v",
    "errstr 0x1",
    "sha256 /tmp/f",
    "sha3-256 /tmp/f",
    "aes-256-cbc -d -in /tmp/f -k pw",
    "des3 -d -in /tmp/f",
    "req -new -newkey rsa:2048 -nodes -keyout /tmp/k -out /tmp/csr -subj /CN=x",
    "enc -d -aes-128-ecb -in /tmp/f -k secret -pbkdf2",
    "dgst -sha256 -hmac key /tmp/f",
    "genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048",
    "passwd -6 -salt abc password",
    "pkcs12 -in /tmp/x.p12 -nokeys -passin pass:secret",
    "x509 -in /tmp/c.pem -noout -text -nameopt RFC2253",
    "x509 -in http://10.0.0.5/c.pem -noout",
    "ocsp -url http://10.0.0.5/ -issuer /tmp/i.pem -cert /tmp/c.pem",
    "s_client -connect 10.0.0.1:443",
    "s_client -connect 10.0.0.1:443 -groups X25519:P-256 -servername lab.internal",
    "req -new -key /tmp/k -subj /CN=x -addext crlDistributionPoints=URI:http://127.0.0.1/crl.pem -out /tmp/csr",
    "req -new -key /tmp/k -subj /CN=x -addext crlDistributionPoints=URI:http://10.0.0.1/a,URI:http://10.0.0.2/b",
]

REFUSED = [
    "x509 -in http://8.8.8.8/c.pem -noout",
    "x509 -in=http://8.8.8.8/c.pem",
    "verify -crl_download -CAfile /tmp/ca.pem /tmp/c.pem",
    "s_client -connect 8.8.8.8:443",
    "ocsp -url http://8.8.8.8/ -issuer /tmp/i.pem -cert /tmp/c.pem",
    "s_time -connect evil.example:443",
    "storeutl http://8.8.8.8/c.pem",
    "engine -t dynamic",
    "aes-256-cbc -in /tmp/f -out /etc/x",
    # openssl resolves a command by hash and first eight characters: these run s_client/s_server.
    "s_clientEz3dDm -connect 8.8.8.8:443",
    "s_serverL0Zh2j -accept 4433 -proxy 8.8.8.8:3128",
    "list -providers -provider-path=/tmp -provider=evil",
    "list --provider-path /tmp/p --provider evil",
    "fipsinstall -module /tmp/evil.so -out /tmp/f.cnf",
    "x509 -in /tmp/c.pem -engine=/tmp/e.so",
    "req -config=/tmp/c.cnf -new",
    "s_client -connect seed",
    "s_time -connect kdf",
    "req -new -key /tmp/k -subj /CN=x -addext crlDistributionPoints=URI:http://8.8.8.8/crl.pem -out /tmp/csr",
    # User information and list separators must not move the host a parser fetches from.
    "x509 -in http://10.0.0.5,@8.8.8.8/c.pem -noout",
    "x509 -in http://10.0.0.5;@8.8.8.8/c.pem -noout",
    "x509 -in http://user@10.0.0.5/c.pem -noout",
    "req -new -key /tmp/k -subj /CN=x -addext crlDistributionPoints=URI:http://10.0.0.1/a,URI:http://8.8.8.8/b",
]


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")


@pytest.mark.parametrize("args", OFFLINE)
def test_offline_and_private_openssl_commands_pass(offline, args):
    check_policy("openssl", shlex.split(args), "openssl")


@pytest.mark.parametrize("args", REFUSED)
def test_external_and_code_loading_openssl_commands_are_refused(offline, args):
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy("openssl", shlex.split(args), "openssl")


def test_crl_download_is_allowed_once_external_access_is(monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    check_policy("openssl", shlex.split("verify -crl_download -CAfile /tmp/ca.pem /tmp/c.pem"), "openssl")

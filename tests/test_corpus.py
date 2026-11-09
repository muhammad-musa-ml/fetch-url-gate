import ipaddress
import socket

import pytest

from fetch_url_gate.baseline import text_rule_allows
from fetch_url_gate.classify import _embedded_v4, check_url
from fetch_url_gate.corpus import TARGETS, benign_cases, hostile_cases, ipv4_spellings, resolver
from fetch_url_gate.hostparse import parse_host

PORT = 8080


def test_gate_denies_every_hostile_case():
    allowed = [c.url for c in hostile_cases(PORT) if check_url(c.url, resolver=resolver).allow]
    assert allowed == []


def test_gate_allows_every_benign_case():
    denied = [(c.url, check_url(c.url, resolver=resolver).reason) for c in benign_cases() if not check_url(c.url, resolver=resolver).allow]
    assert denied == []


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_every_spelling_parses_to_the_address_it_was_built_from(target):
    ip = ipaddress.IPv4Address(TARGETS[target])
    for group, host in ipv4_spellings(TARGETS[target]):
        parsed = parse_host(host)
        if isinstance(parsed, ipaddress.IPv6Address):
            parsed = _embedded_v4(parsed)
        assert parsed == ip, (group, host)


NUMERIC_GROUPS = {
    "dotted", "two-part", "three-part", "decimal", "hex-single", "hex-parts",
    "octal-parts", "octal-single", "mixed-radix",
}


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_parser_agrees_with_the_os_on_numeric_spellings(target):
    for group, host in ipv4_spellings(TARGETS[target]):
        if group not in NUMERIC_GROUPS:
            continue
        os_view = ipaddress.IPv4Address(socket.inet_aton(host))
        assert parse_host(host) == os_view, (group, host)


def test_text_rule_catches_only_the_literals():
    denied = ["file:///etc/passwd", "http://localhost/", "http://127.0.0.1/", "http://[::1]/", "http://0.0.0.0/"]
    assert not any(text_rule_allows(u) for u in denied)
    missed = [
        "http://127.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://169.254.169.254/",
        "http://rebind.example/",
        "http://[::ffff:7f00:1]/",
        "http://10.0.0.5/",
    ]
    assert all(text_rule_allows(u) for u in missed)
    # The literal inside an IPv6 form is still caught, because the rule matches text.
    assert not text_rule_allows("http://[::ffff:127.0.0.1]/")


def test_text_rule_blocks_innocent_urls_the_gate_allows():
    innocent = [c.url for c in benign_cases() if not text_rule_allows(c.url)]
    assert "https://en.wikipedia.org/wiki/Localhost" in innocent
    assert "https://127.0.0.1.example.com/" in innocent


def test_corpus_size_is_pinned():
    # 4 targets x (21 spellings + 12 URL shapes), 5 IPv6 literals, 8 ignored
    # code points, 6 reserved suffixes, 3 special addresses, 2 curl globs, 3
    # leading-zero hosts, 5 localhost names, 3 internal names, 3 single-label
    # names, 7 DNS names, 7 other schemes.
    assert len(hostile_cases(PORT)) == 4 * (21 + 12) + 5 + 8 + 6 + 3 + 2 + 3 + 5 + 3 + 3 + 7 + 7
    assert len(benign_cases()) == 27

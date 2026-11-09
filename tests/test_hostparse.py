import ipaddress

import pytest

from fetch_url_gate.hostparse import HostError, parse_host

LOOPBACK = ipaddress.IPv4Address("127.0.0.1")

# Every spelling here names 127.0.0.1 to a browser or to the OS resolver.
LOOPBACK_SPELLINGS = [
    "127.0.0.1",
    "127.1",
    "127.0.1",
    "2130706433",
    "0x7f000001",
    "0X7F000001",
    "0x7f.0x0.0x0.0x1",
    "0x7f.1",
    "0177.0.0.1",
    "0177.0.0.01",
    "017700000001",
    "127.000.000.001",
    "127.0.0.1.",
    "127。0。0。1",
    "127．0．0．1",
    "１２７．０．０．１",
    "%31%32%37.0.0.1",
    "127.0.0.0x1",
]


@pytest.mark.parametrize("spelling", LOOPBACK_SPELLINGS)
def test_every_loopback_spelling_parses_to_the_same_address(spelling):
    assert parse_host(spelling) == LOOPBACK


@pytest.mark.parametrize(
    "spelling, expected",
    [
        ("169.254.169.254", "169.254.169.254"),
        ("2852039166", "169.254.169.254"),
        ("0xa9fea9fe", "169.254.169.254"),
        ("169.16689662", "169.254.169.254"),
        ("010.0.0.5", "8.0.0.5"),  # a leading zero means octal
        ("0", "0.0.0.0"),
        ("0x", "0.0.0.0"),
        ("4294967295", "255.255.255.255"),
    ],
)
def test_other_numeric_spellings(spelling, expected):
    assert parse_host(spelling) == ipaddress.IPv4Address(expected)


@pytest.mark.parametrize(
    "bad",
    [
        "256.0.0.1",
        "1.2.3.4.5",
        "4294967296",
        "08.1.1.1",
        "0x1g.0.0.1",
        "1..1",
        "",
        "ex ample.com",
        "exa/mple.com",
        "a%00b.com",
        "%ff.com",
        "[::1",
        "[::1%eth0]",
        "[:::1]",
        "a" * 64 + ".com",
    ],
)
def test_unreadable_hosts_raise(bad):
    with pytest.raises(HostError):
        parse_host(bad)


@pytest.mark.parametrize(
    "domain",
    ["example.com", "EXAMPLE.com", "www.python.org.", "127.0.0.1.example.com", "1e3.com", "a1.b2"],
)
def test_domains_stay_domains(domain):
    assert parse_host(domain) == domain.lower()


def test_idna_domain_becomes_ascii():
    assert parse_host("münchen.de") == "xn--mnchen-3ya.de"


@pytest.mark.parametrize(
    "literal, expected",
    [
        ("[::1]", "::1"),
        ("[0:0:0:0:0:0:0:1]", "::1"),
        ("[::ffff:127.0.0.1]", "::ffff:7f00:1"),
        ("[2606:4700:4700::1111]", "2606:4700:4700::1111"),
    ],
)
def test_ipv6_literals(literal, expected):
    assert parse_host(literal) == ipaddress.IPv6Address(expected)

"""Hostile and benign URLs for the comparison.

Hostile means: the URL reaches a loopback, metadata, private or unspecified
address, or a scheme that is not http(s), by a route that a fetcher may follow.
Every hostile case is built from a rule, not copied from a list, so the counts
in the results come from this file.
"""

from __future__ import annotations

from dataclasses import dataclass

TARGETS = {
    "loopback": "127.0.0.1",
    "metadata": "169.254.169.254",
    "private": "10.0.0.5",
    "unspecified": "0.0.0.0",
}

# What the evaluation's fixed resolver returns. Names not listed resolve to a
# public address, so a benign name is never blocked by the resolver.
DNS_TABLE = {
    "localtest.example": ["127.0.0.1"],
    "rebind.example": ["127.0.0.1"],
    "localhost.localdomain": ["127.0.0.1"],
    "meta-alias.example": ["169.254.169.254"],
    "split.example": ["93.184.216.34", "10.0.0.5"],
    "v6-private.example": ["fd00::5"],
    "mapped.example": ["::ffff:127.0.0.1"],
}
PUBLIC_ADDRESS = "93.184.216.34"

_FULLWIDTH = str.maketrans("0123456789", "０１２３４５６７８９")


@dataclass(frozen=True)
class Case:
    group: str
    target: str
    url: str
    expect_allow: bool


def resolver(name: str) -> list[str]:
    return DNS_TABLE.get(name, [PUBLIC_ADDRESS])


def _octal(n: int) -> str:
    return "0" + format(n, "o") if n else "0"


def ipv4_spellings(ip: str) -> list[tuple[str, str]]:
    """Every host spelling of one IPv4 address that the standard reads as that address."""
    a, b, c, d = (int(x) for x in ip.split("."))
    v = (a << 24) | (b << 16) | (c << 8) | d
    dotted = f"{a}.{b}.{c}.{d}"
    hi, lo = (a << 8) | b, (c << 8) | d
    return [
        ("dotted", dotted),
        ("two-part", f"{a}.{(b << 16) | (c << 8) | d}"),
        ("three-part", f"{a}.{b}.{(c << 8) | d}"),
        ("decimal", str(v)),
        ("hex-single", f"0x{v:x}"),
        ("hex-single-upper", f"0X{v:X}"),
        ("hex-parts", ".".join(f"0x{n:x}" for n in (a, b, c, d))),
        ("octal-parts", ".".join(_octal(n) for n in (a, b, c, d))),
        ("octal-single", "0" + format(v, "o")),
        ("mixed-radix", f"0x{a:x}.{b}.{_octal(c)}.{d}"),
        ("trailing-dot", dotted + "."),
        ("fullwidth-digits", dotted.translate(_FULLWIDTH)),
        ("ideographic-dots", dotted.replace(".", "。")),
        ("fullwidth-dots", dotted.replace(".", "．")),
        ("fullwidth-all", dotted.translate(_FULLWIDTH).replace(".", "．")),
        ("percent-encoded", "".join(f"%{ord(ch):02X}" for ch in dotted)),
        ("mapped-ipv6", f"[::ffff:{dotted}]"),
        ("mapped-ipv6-hex", f"[::ffff:{hi:x}:{lo:x}]"),
        ("mapped-ipv6-long", f"[0:0:0:0:0:ffff:{dotted}]"),
        ("6to4-ipv6", f"[2002:{hi:04x}:{lo:04x}::]"),
        ("nat64-ipv6", f"[64:ff9b::{hi:x}:{lo:x}]"),
    ]


def _wrapped(dotted: str, port: int) -> list[tuple[str, str]]:
    host = f"{dotted}:{port}"
    return [
        ("userinfo", f"http://evil.example@{host}/"),
        ("userinfo-port-lookalike", f"http://example.com:80@{host}/"),
        ("credentials", f"http://u:p@{host}/"),
        ("upper-scheme", f"HTTP://{host}/"),
        ("no-slashes", f"http:{host}/"),
        ("extra-slashes", f"http:////{host}/"),
        ("backslashes", f"http:\\\\{host}\\x"),
        ("tab-inside", "http://" + dotted.replace(".", "\t.", 1) + f":{port}/"),
        ("newline-inside", "http://" + dotted.replace(".", ".\n", 1) + f":{port}/"),
        ("leading-space", f"  http://{host}/"),
        ("fragment-trick", f"http://{host}#@example.com/"),
        ("query-trick", f"http://{host}?@example.com/"),
    ]


def hostile_cases(port: int) -> list[Case]:
    cases: list[Case] = []
    for target, ip in TARGETS.items():
        for group, host in ipv4_spellings(ip):
            cases.append(Case(group, target, f"http://{host}:{port}/", False))
        for group, url in _wrapped(ip, port):
            cases.append(Case(group, target, url, False))
    extra_hosts = [
        ("loopback", "ipv6-literal", "[::1]"),
        ("loopback", "ipv6-literal", "[0:0:0:0:0:0:0:1]"),
        ("loopback", "ipv6-literal", "[0000:0000:0000:0000:0000:0000:0000:0001]"),
        ("unspecified", "ipv6-literal", "[::]"),
        ("metadata", "ipv6-literal", "[fd00:ec2::254]"),
    ]
    for target, group, host in extra_hosts:
        cases.append(Case(group, target, f"http://{host}:{port}/", False))
    for name in ["localhost", "LOCALHOST", "localhost.", "app.localhost", "x.y.localhost"]:
        cases.append(Case("localhost-name", "loopback", f"http://{name}:{port}/", False))
    for name in ["metadata.google.internal", "ip-10-0-0-5.ec2.internal", "metadata"]:
        cases.append(Case("internal-name", "metadata", f"http://{name}:{port}/", False))
    for name in ["intranet", "router", "printer"]:
        cases.append(Case("single-label", "private", f"http://{name}:{port}/", False))
    for name in DNS_TABLE:
        cases.append(Case("dns-name", "dns", f"http://{name}:{port}/", False))
    for url in [
        "file:///etc/passwd",
        "FILE:///C:/Windows/win.ini",
        f"ftp://127.0.0.1:{port}/",
        f"gopher://127.0.0.1:{port}/_x",
        f"dict://127.0.0.1:{port}/info",
        "javascript:alert(1)",
        "data:text/html,x",
    ]:
        cases.append(Case("other-scheme", "scheme", url, False))
    return cases


def benign_cases() -> list[Case]:
    urls = [
        ("public-name", "https://example.com/"),
        ("public-name", "https://www.python.org/downloads/"),
        ("public-name", "https://docs.python.org/3/library/ipaddress.html"),
        ("public-name", "https://sub.domain.example.co.uk/a/b?c=d#e"),
        ("public-name", "https://example.com:8443/path"),
        ("public-name", "http://example.com:80/"),
        ("public-name", "https://EXAMPLE.COM/"),
        ("public-name", "https://example.com./"),
        ("public-name", "https://user@example.com/"),
        ("public-name", "https://m\u00fcnchen.de/"),
        ("public-name", "https://xn--mnchen-3ya.de/"),
        ("public-address", "http://93.184.216.34/"),
        ("public-address", "http://8.8.8.8/"),
        ("public-address", "http://1.1.1.1/"),
        ("public-address", "http://134744072/"),
        ("public-address", "http://0x08080808/"),
        ("public-address", "https://[2606:4700:4700::1111]/"),
        ("public-address", "http://[2001:4860:4860::8888]/"),
        ("risky-text", "https://en.wikipedia.org/wiki/Localhost"),
        ("risky-text", "https://example.com/?next=http://127.0.0.1"),
        ("risky-text", "https://example.com/docs/0.0.0.0-explained"),
        ("risky-text", "https://127.0.0.1.example.com/"),
        ("risky-text", "https://localhost.example.com/"),
        ("risky-text", "https://notlocalhost.example.org/"),
    ]
    return [Case(group, "public", url, True) for group, url in urls]

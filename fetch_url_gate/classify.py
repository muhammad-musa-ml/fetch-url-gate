"""Decide whether a URL may be fetched on behalf of a tool call.

The rule is on the address, not on the text: the URL is split the way the
standard splits it, the host is turned into the address it names, and only
globally routable addresses pass. Anything that cannot be read is denied.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from .hostparse import HostError, parse_host

Resolver = Callable[[str], Iterable[str]]

ALLOWED_SCHEMES = ("http", "https")
METADATA = ipaddress.IPv4Address("169.254.169.254")
_NAT64 = bytes.fromhex("0064ff9b" + "00" * 8)
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")
_STRIP = "".join(chr(c) for c in range(0x21))
_DROP = dict.fromkeys(map(ord, "\t\n\r"))


@dataclass(frozen=True)
class Verdict:
    allow: bool
    reason: str
    host: str | None = None
    ip: str | None = None
    # What to hand to the fetcher: the URL rebuilt from the parts that were
    # checked, so the fetcher cannot read the original text differently.
    fetch_url: str | None = None


def _deny(reason: str, host: str | None = None, ip: str | None = None) -> Verdict:
    return Verdict(False, reason, host, ip)


def _split(url: str) -> tuple[str, str, str, str]:
    text = url.strip(_STRIP).translate(_DROP)
    match = _SCHEME.match(text)
    if not match:
        raise HostError("no scheme")
    scheme = match.group(1).lower()
    if scheme not in ALLOWED_SCHEMES:
        raise HostError(f"scheme {scheme!r} is not allowed")
    rest = text[match.end():].lstrip("/\\")
    end = next((i for i, ch in enumerate(rest) if ch in "/\\?#"), len(rest))
    authority, remainder = rest[:end], rest[end:]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            raise HostError("unterminated IPv6 literal")
        host, after = authority[: close + 1], authority[close + 1:]
        if after and not after.startswith(":"):
            raise HostError("text after the IPv6 literal")
        port = after[1:]
    else:
        host, _, port = authority.partition(":")
    if port and not (port.isascii() and port.isdigit() and int(port) <= 65535):
        raise HostError("bad port")
    return scheme, host, port, remainder


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    packed = ip.packed
    if packed[:2] == b"\x20\x02":  # 6to4
        return ipaddress.IPv4Address(packed[2:6])
    if packed[:12] == _NAT64:
        return ipaddress.IPv4Address(packed[12:])
    return None


def _kind(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_link_local:
        return "link-local (cloud metadata address)" if ip == METADATA else "link-local"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    return "not globally routable"


def _check_ip(ip, host: str) -> Verdict | None:
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_v4(ip)
        if inner is not None:
            ip = inner
    # is_global alone lets multicast through, so it is checked on its own.
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        return _deny(f"{ip} is {_kind(ip)}", host, str(ip))
    return None


def _check_name(name: str, resolver: Resolver | None, allow_single_label: bool) -> Verdict | None:
    bare = name.rstrip(".")
    if bare == "localhost" or bare.endswith(".localhost"):
        return _deny("localhost name", name)
    if bare.endswith(".internal") or bare == "metadata":
        return _deny("internal name", name)
    if "." not in bare and not allow_single_label:
        return _deny("single-label name", name)
    if resolver is not None:
        addresses = list(resolver(bare))
        if not addresses:
            return _deny("name does not resolve", name)
        for text in addresses:
            try:
                ip = ipaddress.ip_address(text)
            except ValueError:
                return _deny(f"resolver returned {text!r}, not an address", name)
            blocked = _check_ip(ip, name)
            if blocked is not None:
                return _deny(f"{name} resolves to {blocked.reason}", name, blocked.ip)
    return None


def check_url(
    url: str,
    resolver: Resolver | None = None,
    allow_single_label: bool = False,
) -> Verdict:
    """Return a Verdict. Never raises on bad input; unreadable URLs are denied."""
    try:
        scheme, raw_host, port, remainder = _split(url)
        host = parse_host(raw_host)
    except HostError as exc:
        return _deny(str(exc))
    if isinstance(host, str):
        blocked = _check_name(host, resolver, allow_single_label)
        shown = host.rstrip(".")
        ip_text = None
    else:
        blocked = _check_ip(host, str(host))
        shown = f"[{host}]" if isinstance(host, ipaddress.IPv6Address) else str(host)
        ip_text = str(host)
    if blocked is not None:
        return blocked
    tail = remainder.replace("\\", "/")
    if tail == "" or tail[0] in "?#":
        tail = "/" + tail
    fetch_url = f"{scheme}://{shown}{':' + str(int(port)) if port else ''}{tail}"
    return Verdict(True, "global address" if ip_text else "public name", shown, ip_text, fetch_url)

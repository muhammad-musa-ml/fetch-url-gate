"""Host parsing that follows the WHATWG URL Standard.

A browser, or any client that hands the host to the OS resolver, reads
"127.1", "0x7f000001", "2130706433" and "0177.0.0.1" as addresses. This module
turns every such spelling into the address it names, so a check can look at
the address and not at the text.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote_to_bytes


class HostError(ValueError):
    """The host cannot be read as a valid host. Callers should deny."""


# Forbidden host code points from the standard, plus all controls and "%".
_FORBIDDEN = set("\x00\t\n\r #/:<>?@[\\]^|%\x7f") | {chr(c) for c in range(0x20)}
_DEC = re.compile(r"[0-9]+")
_HEX = re.compile(r"[0-9a-fA-F]+")
_OCT = re.compile(r"[0-7]+")


def _has_forbidden(text: str) -> bool:
    return any(ch in _FORBIDDEN for ch in text)


def _ipv4_number(part: str) -> int:
    if part == "":
        raise HostError("empty IPv4 part")
    if part[:2] in ("0x", "0X"):
        digits, pattern, base = part[2:], _HEX, 16
        if digits == "":
            return 0
    elif len(part) >= 2 and part[0] == "0":
        digits, pattern, base = part[1:], _OCT, 8
    else:
        digits, pattern, base = part, _DEC, 10
    if not pattern.fullmatch(digits):
        raise HostError(f"{part!r} is not an IPv4 number")
    return int(digits, base)


def _ends_in_number(host: str) -> bool:
    parts = host.split(".")
    if parts[-1] == "":
        if len(parts) == 1:
            return False
        parts.pop()
    last = parts[-1]
    if last and _DEC.fullmatch(last):
        return True
    try:
        _ipv4_number(last)
    except HostError:
        return False
    return True


def parse_ipv4(host: str) -> ipaddress.IPv4Address:
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        raise HostError("more than four IPv4 parts")
    numbers = [_ipv4_number(p) for p in parts]
    if any(n > 255 for n in numbers[:-1]):
        raise HostError("an IPv4 part before the last is above 255")
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        raise HostError("the last IPv4 part is too large")
    value = numbers[-1] + sum(n * 256 ** (3 - i) for i, n in enumerate(numbers[:-1]))
    return ipaddress.IPv4Address(value)


def parse_host(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | str:
    """Return the address the host names, or the lower-case ASCII domain."""
    if raw.startswith("["):
        if not raw.endswith("]"):
            raise HostError("unterminated IPv6 literal")
        inner = raw[1:-1]
        if "%" in inner:
            raise HostError("IPv6 zone ids are not allowed")
        try:
            return ipaddress.IPv6Address(inner)
        except ValueError as exc:
            raise HostError(f"bad IPv6 literal: {exc}") from exc
    try:
        decoded = unquote_to_bytes(raw).decode("utf-8")
    except UnicodeError as exc:
        raise HostError("percent-encoding is not valid UTF-8") from exc
    if decoded == "":
        raise HostError("empty host")
    if _has_forbidden(decoded):
        raise HostError("forbidden character in host")
    try:
        ascii_host = decoded.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise HostError(f"host is not valid IDNA: {exc}") from exc
    if ascii_host == "" or _has_forbidden(ascii_host):
        raise HostError("forbidden character in host")
    if _ends_in_number(ascii_host):
        return parse_ipv4(ascii_host)
    return ascii_host

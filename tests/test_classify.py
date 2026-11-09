import random

import pytest

from fetch_url_gate.classify import check_url


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "http://93.184.216.34/page",
        "http://8.8.8.8/",
        "https://[2606:4700:4700::1111]/",
        "https://example.com:8443/a?b=127.0.0.1#c",
        "https://127.0.0.1.example.com/",
        "https://localhost.example.com/",
        "HTTPS://Example.COM/",
        "  https://example.com/  ",
    ],
)
def test_public_urls_are_allowed(url):
    verdict = check_url(url)
    assert verdict.allow, verdict.reason


@pytest.mark.parametrize(
    "url, reason",
    [
        ("http://127.0.0.1/", "loopback"),
        ("http://127.1/", "loopback"),
        ("http://2130706433/", "loopback"),
        ("http://0x7f000001/", "loopback"),
        ("http://0177.0.0.1/", "loopback"),
        ("http://[::1]/", "loopback"),
        ("http://[::ffff:127.0.0.1]/", "loopback"),
        ("http://[::ffff:7f00:1]/", "loopback"),
        ("http://[2002:7f00:1::]/", "loopback"),
        ("http://[64:ff9b::7f00:1]/", "loopback"),
        ("http://0.0.0.0/", "unspecified"),
        ("http://169.254.169.254/latest/meta-data/", "cloud metadata"),
        ("http://2852039166/", "cloud metadata"),
        ("http://[fd00:ec2::254]/", "private"),
        ("http://10.0.0.5/", "private"),
        ("http://192.168.1.1/", "private"),
        ("http://172.16.0.1/", "private"),
        ("http://100.64.0.1/", "not globally routable"),
        ("http://224.0.0.1/", "multicast"),
    ],
)
def test_non_global_addresses_are_denied_whatever_the_spelling(url, reason):
    verdict = check_url(url)
    assert not verdict.allow
    assert reason in verdict.reason


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "FILE:///C:/Windows/win.ini",
        "ftp://example.com/",
        "gopher://example.com:6379/_x",
        "javascript:alert(1)",
        "data:text/html,x",
        "example.com",
        "//example.com/",
        "",
        "http://",
        "http:///",
        "http://:80/",
        "http://example.com:99999/",
        "http://example.com:80a/",
        "http://example.com:-1/",
        "http://[::1/",
        "http://[::1]x/",
        "http://exa mple.com/",
        "http://256.256.256.256/",
        "http://1.2.3.4.5/",
    ],
)
def test_unreadable_or_disallowed_urls_are_denied(url):
    assert not check_url(url).allow


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example@127.0.0.1/",
        "http://evil.example:pw@127.0.0.1:8080/",
        "http://127.0.0.1:80@127.0.0.1/",
        "HTTP://127.0.0.1/",
        "http:127.0.0.1",
        "http:////127.0.0.1/",
        "http:\\\\127.0.0.1\\x",
        "  http://127.0.0.1/",
        "http://127.0.0.1\t/",
        "http://12\n7.0.0.1/",
        "http://127.0.0.1#@example.com/",
        "http://127.0.0.1?@example.com/",
    ],
)
def test_url_shape_tricks_do_not_hide_the_address(url):
    assert not check_url(url).allow


def test_userinfo_does_not_move_the_host():
    allowed = check_url("http://127.0.0.1@example.com/x")
    assert allowed.allow
    assert allowed.host == "example.com"


def test_fetch_url_is_rebuilt_from_the_checked_parts():
    verdict = check_url(" HTTP:\\\\user:pw@134744072:0080\\a\\b?q=1 ")
    assert verdict.allow
    assert verdict.fetch_url == "http://8.8.8.8:80/a/b?q=1"
    assert check_url("https://example.com").fetch_url == "https://example.com/"
    assert check_url("https://example.com?x=1").fetch_url == "https://example.com/?x=1"
    assert check_url("http://[2606:4700:4700::1111]:81/").fetch_url == "http://[2606:4700:4700::1111]:81/"


def test_localhost_and_internal_names():
    for name in ["localhost", "LOCALHOST", "localhost.", "app.localhost", "metadata.google.internal", "ip-10-0-0-1.ec2.internal", "metadata"]:
        assert not check_url(f"http://{name}/").allow, name


def test_single_label_names_are_denied_unless_allowed():
    assert not check_url("http://intranet/").allow
    assert check_url("http://intranet/", allow_single_label=True).allow


def test_resolver_decides_for_domain_names():
    table = {
        "rebind.example": ["127.0.0.1"],
        "meta.example": ["169.254.169.254"],
        "mixed.example": ["93.184.216.34", "10.0.0.5"],
        "v6.example": ["::ffff:10.0.0.5"],
        "ok.example": ["93.184.216.34", "2606:4700:4700::1111"],
        "empty.example": [],
        "junk.example": ["not-an-address"],
    }

    def resolver(name):
        return table[name]

    for name in ["rebind.example", "meta.example", "mixed.example", "v6.example", "empty.example", "junk.example"]:
        verdict = check_url(f"https://{name}/", resolver=resolver)
        assert not verdict.allow, name
    assert check_url("https://ok.example/", resolver=resolver).allow
    # With no resolver, names are judged by their text only.
    assert check_url("https://rebind.example/").allow


def test_check_url_never_raises_on_random_text():
    rng = random.Random(20261109)
    alphabet = list("abcxyz019:/\\@[]?#%.-_ \t\n") + ["。", "０", "é", "\x00", "\u200b", "0x", "http", "://", "::1"]
    for _ in range(20000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        if rng.random() < 0.5:
            text = "http://" + text
        verdict = check_url(text)
        assert isinstance(verdict.allow, bool)
        if verdict.allow:
            # An allowed URL must be rebuilt without anything that could be read twice.
            assert verdict.fetch_url and "@" not in verdict.fetch_url.split("//", 1)[1].split("/", 1)[0]

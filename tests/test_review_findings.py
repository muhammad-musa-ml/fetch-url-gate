"""Cases found by a review of the first version.

Each one was an input the gate allowed (or crashed on) before the fix.
"""

import time

import pytest

from fetch_url_gate import check_url
from fetch_url_gate.hostparse import parse_host

# UTS46 deletes these code points; Python's IDNA2003 codec keeps most of them.
IGNORED = [chr(0xE0100), chr(0xE01EF), "᠏", "⁤", chr(0x1BCA0), "️", "­", "​", "⁠", "﻿", "͏"]


@pytest.mark.parametrize("ch", IGNORED)
@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "0x7f.0.0.1", "app.localhost", "metadata.google.internal"])
def test_ignored_code_points_do_not_hide_an_internal_host(host, ch):
    assert not check_url(f"http://{host}{ch}/").allow


def test_percent_encoded_ignored_code_point():
    assert not check_url("http://127.0.0.1%F3%A0%84%80/").allow


@pytest.mark.parametrize("url", ["http://127.0.0.xn--1-/", "http://app.xn--localhost-/", "http://xn--/"])
def test_a_labels_that_decode_to_ascii_are_denied(url):
    assert not check_url(url).allow


@pytest.mark.parametrize("url", ["http://faßl.de/", "http://ς.example/", "http://a‌b.example/", "http://a‍b.example/"])
def test_hosts_that_idna_versions_spell_differently_are_denied(url):
    verdict = check_url(url)
    assert not verdict.allow


@pytest.mark.parametrize(
    "host",
    ["{example.com,localhost}", "{127.0.0.1,example.com}", "a$b.com", "a;b.com", "a&b.com", "a'b.com", "a(b).com", "a*b.com", "a!b.com", "a+b.com", "a=b.com", "a~b.com", "a`b.com", "a,b.com"],
)
def test_hosts_that_are_not_plain_names_are_denied(host):
    assert not check_url(f"http://{host}/").allow


@pytest.mark.parametrize("url", ["http://[fec0::1]/", "http://[fec0:0:0:ffff::1]:53/", "http://168.63.129.16/machine", "http://192.0.0.192/latest/", "http://192.0.0.1/"])
def test_addresses_python_calls_global_but_are_internal(url):
    assert not check_url(url).allow


@pytest.mark.parametrize(
    "name",
    ["foo.local", "localhost.localdomain", "localhost4.localdomain4", "router.home.arpa", "printer.lan", "kubernetes.default.svc", "localhost4", "ip6-localhost", "x.corp", "x.intranet", "x.home", "x.private"],
)
def test_names_that_are_internal_by_convention_are_denied(name):
    assert not check_url(f"http://{name}/").allow


@pytest.mark.parametrize("name", ["www.local-news.example.com", "corporate.example.org", "my_host.example.com", "homepage.example.com", "lanes.example.com", "svc.example.com"])
def test_those_suffix_rules_do_not_catch_ordinary_names(name):
    assert check_url(f"https://{name}/").allow


@pytest.mark.parametrize("url", ["http://010.0.0.5/", "http://0127.0.0.1/", "http://172.016.0.1/", "http://08.8.8.8/", "http://010.010.010.010/"])
def test_leading_zeros_are_denied_because_clients_read_them_two_ways(url):
    assert not check_url(url).allow


def test_hex_without_leading_zero_ambiguity_is_still_read():
    verdict = check_url("http://0x08080808/")
    assert verdict.allow and verdict.fetch_url == "http://8.8.8.8/"


def test_leading_zeros_are_still_parsed_by_the_standard_parser():
    assert str(parse_host("010.0.0.5")) == "8.0.0.5"


def test_long_ports_are_denied_not_raised():
    assert not check_url("http://example.com:" + "9" * 5000 + "/").allow
    assert not check_url("http://[::1]:" + "1" * 4301 + "/").allow
    assert check_url("http://example.com:0080/").fetch_url == "http://example.com:80/"
    assert not check_url("http://example.com:000080/").allow


def test_lone_surrogates_are_denied():
    assert not check_url("http://example.com/p\ud800q").allow
    assert not check_url("http://exa\ud800mple.com/").allow


def test_backslashes_are_rewritten_in_the_path_only():
    assert check_url("http://example.com/a\\b?q=a\\b#f\\g").fetch_url == "http://example.com/a/b?q=a\\b#f\\g"


def test_long_hosts_are_denied_quickly():
    start = time.perf_counter()
    assert not check_url("http://" + "a" * 300 + ".com/").allow
    assert not check_url("http://" + "".join(chr(0x4E00 + i) for i in range(8000)) + ".com/").allow
    assert time.perf_counter() - start < 1.0

import csv

import pytest

from fetch_url_gate import __main__ as cli
from fetch_url_gate.classify import check_url
from fetch_url_gate.corpus import hostile_cases, resolver
from fetch_url_gate.evaluate import evaluate, run
from fetch_url_gate.live import LocalServer, clients, reaches_urllib


def test_static_run_counts():
    results = run(8080, live=False)
    hostile = [r for r in results if not r.case.expect_allow]
    benign = [r for r in results if r.case.expect_allow]
    assert (len(hostile), len(benign)) == (162, 24)
    assert sum(r.gate_allows for r in hostile) == 0
    assert sum(not r.gate_allows for r in benign) == 0
    # The text rule's numbers are pinned: they change only if the corpus or the rule does.
    assert sum(r.text_allows for r in hostile) == 120
    assert sum(not r.text_allows for r in benign) == 6


def _reached_urls(port):
    available = clients()
    reached = []
    for case in hostile_cases(port):
        if case.target not in ("loopback", "unspecified") or case.group in ("dns-name", "internal-name", "single-label", "other-scheme"):
            continue
        if any(fn(case.url) for fn in available.values()):
            reached.append(case.url)
    return reached


def test_every_url_a_real_client_reaches_is_denied_by_the_gate():
    try:
        with LocalServer() as server:
            reached = _reached_urls(server.port)
    except OSError:
        pytest.skip("cannot bind a local port")
    # Guard against a vacuous pass: the plain loopback URL must have reached.
    assert any("//127.0.0.1:" in u for u in reached)
    assert [u for u in reached if check_url(u, resolver=resolver).allow] == []


def test_live_server_answers_and_a_closed_port_does_not():
    with LocalServer() as server:
        assert reaches_urllib(f"http://127.0.0.1:{server.port}/")
        closed = server.port
    assert not reaches_urllib(f"http://127.0.0.1:{closed}/", timeout=1.0)


def test_cli_check_exit_codes(capsys):
    assert cli.main(["check", "https://example.com/a"]) == 0
    assert "ALLOW https://example.com/a" in capsys.readouterr().out
    assert cli.main(["check", "http://2130706433/"]) == 1
    assert "loopback" in capsys.readouterr().out


def test_cli_eval_writes_both_files(tmp_path, capsys):
    out = tmp_path / "res"
    assert cli.main(["eval", "--no-live", "--write", "--out", str(out)]) == 0
    text = (out / "summary.md").read_text(encoding="utf-8")
    assert "## Hostile URLs (162)" in text and "## Benign URLs (24)" in text
    assert "Live check" not in text
    with (out / "results.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 162 + 24
    assert all(r["gate_allows"] == "False" for r in rows if r["family"] not in ("public-name", "public-address", "risky-text"))
    capsys.readouterr()


def test_evaluate_returns_the_summary_text():
    assert evaluate(live=False).startswith("# Results")

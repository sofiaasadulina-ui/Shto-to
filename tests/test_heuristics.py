"""Тесты эвристических правил: на каждое — срабатывание и молчание."""

import pytest

from urlcheck.heuristics import evaluate, extract_nested_url, heuristic_score
from urlcheck.normalize import parse


def codes(url: str) -> set[str]:
    return {s.code for s in evaluate(url)}


def test_clean_url_triggers_nothing():
    assert codes("https://github.com/anthropics/claude") == set()
    assert heuristic_score(evaluate("https://github.com/anthropics/claude")) == 0


@pytest.mark.parametrize(
    "code,bad_url,good_url",
    [
        ("brand_impersonation", "http://login.paypal.com.evil.top/x", "https://www.paypal.com/x"),
        ("brand_typosquat", "http://paypa1.com/", "https://paypal.com/"),
        ("userinfo", "http://sberbank.ru@evil.top/x", "https://sberbank.ru/x"),
        ("ip_host", "http://185.220.101.45/gate.php", "https://example.com/gate.php"),
        ("punycode", "https://xn--80ak6aa92e.com/", "https://example.com/"),
        ("dangerous_extension", "http://host.tld/setup.exe", "http://host.tld/setup.pdf"),
        ("nested_url", "https://site.com/go?url=http://evil.top", "https://site.com/go?id=1"),
        ("shortener", "https://bit.ly/abc", "https://example.com/abc"),
        ("keywords", "https://example.com/login/verify", "https://example.com/articles/1"),
        ("risky_tld", "https://example.tk/", "https://example.ru/"),
        ("many_subdomains", "https://a.b.c.d.example.com/", "https://a.example.com/"),
        ("nonstandard_port", "https://example.com:4444/", "https://example.com:443/"),
        ("many_hyphens", "https://a-b-c-d.com/", "https://ab.com/"),
        ("double_slash", "https://example.com/a//b", "https://example.com/a/b"),
        ("no_https", "http://example.com/page", "https://example.com/page"),
    ],
)
def test_rule_fires_only_when_it_should(code, bad_url, good_url):
    assert code in codes(bad_url), f"{code} не сработало на {bad_url}"
    assert code not in codes(good_url), f"{code} ложно сработало на {good_url}"


def test_long_url_rule():
    long_url = "https://example.com/" + "a" * 120
    assert "long_url" in codes(long_url)
    assert "long_url" not in codes("https://example.com/short")


def test_high_entropy_domain():
    assert "high_entropy" in codes("http://x7zq2m9p4v1c.com/")
    assert "high_entropy" not in codes("https://wikipedia.org/")


def test_insecure_login_replaces_plain_no_https():
    result = codes("http://example.com/login")
    assert "insecure_login" in result
    assert "no_https" not in result  # чтобы не считать один и тот же факт дважды


def test_encoded_host():
    assert "encoded_host" in codes("http://ev%69l.top/x")


def test_signals_sorted_by_weight_descending():
    signals = evaluate("http://login.paypal.com.secure-verify.top/signin")
    weights = [s.weight for s in signals]
    assert weights == sorted(weights, reverse=True)


def test_invalid_url_yields_single_zero_weight_signal():
    signals = evaluate("http://a b.com")
    assert len(signals) == 1
    assert signals[0].code == "invalid_url"
    assert signals[0].weight == 0


def test_score_is_capped_at_100():
    worst = "http://sberbank.ru@login.paypal.com.a.b.c.d.secure-verify-account.tk:4444/signin/verify.exe?url=http://evil.top"
    assert heuristic_score(evaluate(worst)) == 100


def test_nested_target_is_evaluated():
    signals = codes("https://google.com/url?q=http://evil-phish.tk/setup.exe")
    assert "nested:dangerous_extension" in signals
    assert "nested:risky_tld" in signals


def test_nested_target_on_same_domain_is_ignored():
    signals = codes("https://google.com/url?q=https://google.com/maps")
    assert not any(c.startswith("nested:") for c in signals)


def test_extract_nested_url():
    p = parse("https://site.com/go?to=https%3A%2F%2Fevil.top%2Flogin")
    assert extract_nested_url(p) == "https://evil.top/login"
    assert extract_nested_url(parse("https://site.com/go?id=1")) is None


def test_every_signal_has_explanation():
    """Ключевое требование проекта: вердикт должен быть объясним."""
    signals = evaluate("http://login.paypal.com.secure-verify.top/signin/setup.exe")
    assert signals
    for s in signals:
        assert s.title and s.detail, f"у сигнала {s.code} нет объяснения"

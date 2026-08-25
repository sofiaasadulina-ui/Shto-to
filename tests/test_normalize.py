"""Тесты разбора URL."""

import pytest

from urlcheck.normalize import decode_punycode, defang, has_mixed_scripts, parse


def test_adds_scheme_when_missing():
    p = parse("example.com/page")
    assert p.scheme == "http"
    assert p.host == "example.com"


def test_extracts_registrable_domain_and_subdomains():
    p = parse("https://login.secure.example.com/path")
    assert p.registrable_domain == "example.com"
    assert p.subdomains == ["login", "secure"]
    assert p.tld == "com"


def test_multi_level_suffix():
    p = parse("https://shop.example.co.uk/cart")
    assert p.registrable_domain == "example.co.uk"
    assert p.subdomains == ["shop"]


def test_userinfo_is_separated_from_host():
    p = parse("http://sberbank.ru@evil.top/vhod")
    assert p.userinfo == "sberbank.ru"
    assert p.host == "evil.top"


@pytest.mark.parametrize(
    "url",
    ["http://192.168.0.1/x", "http://0x7f000001/a", "http://3232235777/b"],
)
def test_detects_ip_hosts_including_obfuscated(url):
    assert parse(url).is_ip_host is True


def test_domain_is_not_mistaken_for_ip():
    assert parse("https://example.com").is_ip_host is False


def test_port_is_parsed():
    p = parse("http://host.tld:8443/x")
    assert p.port == 8443


def test_invalid_input_is_reported_not_raised():
    assert parse("").error
    assert parse("http://a b.com").error
    assert parse("https://").error


def test_punycode_is_decoded():
    assert decode_punycode("xn--80ak6aa92e.com") != "xn--80ak6aa92e.com"


def test_mixed_scripts_detected():
    assert has_mixed_scripts("sbеrbank.ru") is True   # «е» кириллическая
    assert has_mixed_scripts("sberbank.ru") is False


def test_defang_makes_url_unclickable():
    result = defang("http://evil.com/x")
    assert "http://" not in result
    assert "evil[.]com" in result


def test_query_params_are_parsed():
    p = parse("https://site.com/s?q=1&r=two")
    assert ("q", "1") in p.query_params
    assert ("r", "two") in p.query_params

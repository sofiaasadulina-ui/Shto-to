"""Тесты извлечения признаков."""

import pytest

from urlcheck.features import (
    extract,
    levenshtein,
    normalize_homoglyphs,
    numeric_only,
    path_extension,
    shannon_entropy,
)
from urlcheck.normalize import parse


def f(url: str) -> dict:
    return extract(parse(url))


def test_numeric_vector_has_no_meta_and_is_all_floats():
    vector = numeric_only(f("https://example.com"))
    assert "_meta" not in vector
    assert all(isinstance(v, float) for v in vector.values())


def test_vector_shape_is_stable_across_urls():
    a = numeric_only(f("https://example.com"))
    b = numeric_only(f("http://1.2.3.4:8080/x.exe?u=http://y.top"))
    assert a.keys() == b.keys()


def test_ip_host_flag():
    assert f("http://192.168.0.1/admin")["is_ip_host"] == 1.0
    assert f("https://example.com/admin")["is_ip_host"] == 0.0


def test_punycode_flag():
    assert f("https://xn--80ak6aa92e.com")["has_punycode"] == 1.0


def test_nested_url_in_query():
    assert f("https://site.com/go?url=http://evil.top")["nested_url_in_query"] == 1.0
    assert f("https://site.com/go?id=42")["nested_url_in_query"] == 0.0


def test_dangerous_extension():
    assert f("http://host.tld/setup.exe")["dangerous_extension"] == 1.0
    assert f("http://host.tld/report.pdf")["dangerous_extension"] == 0.0


def test_risky_tld():
    assert f("http://host.tk/")["risky_tld"] == 1.0
    assert f("https://host.ru/")["risky_tld"] == 0.0


def test_shortener_detected():
    assert f("https://bit.ly/abc")["is_shortener"] == 1.0


def test_brand_impersonation_in_subdomain():
    feats = f("http://login.paypal.com.evil.top/signin")
    assert feats["brand_impersonation"] == 1.0
    assert feats["_meta"]["brand_impersonated"] == "paypal"


def test_real_brand_domain_is_not_impersonation():
    assert f("https://www.paypal.com/signin")["brand_impersonation"] == 0.0
    assert f("https://e.mail.ru/inbox/")["brand_impersonation"] == 0.0


@pytest.mark.parametrize("url", ["http://paypa1.com", "http://arnazon.com", "http://gogle.com"])
def test_typosquatting_detected(url):
    assert f(url)["brand_typosquat"] == 1.0


@pytest.mark.parametrize("url", ["https://paypal.com", "https://amazon.com", "https://github.com"])
def test_genuine_brands_are_not_typosquats(url):
    assert f(url)["brand_typosquat"] == 0.0


def test_homoglyph_normalization():
    assert normalize_homoglyphs("arnazon") == "amazon"
    assert normalize_homoglyphs("paypa1") == "paypal"


def test_levenshtein():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("", "abc") == 3


def test_entropy_grows_with_randomness():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("x7zq2m9p")


def test_path_extension():
    assert path_extension("/files/setup.exe") == ".exe"
    assert path_extension("/files/") == ""


def test_extract_accepts_plain_string():
    assert extract("https://example.com")["is_https"] == 1.0

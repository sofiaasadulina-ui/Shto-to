"""Тесты агрегации вердикта, включая «золотой» прогон по всему датасету."""

import csv
from pathlib import Path

import pytest

from urlcheck import scoring
from urlcheck.models import NetworkFacts, Signal
from urlcheck.scoring import check, format_report, level_for

DATASET = Path(__file__).resolve().parent.parent / "data" / "sample_urls.csv"

# Требования к качеству эвристик, проверяются на датасете без участия ML.
MIN_MALICIOUS_FLAGGED = 0.85   # доля вредоносных, получивших уровень выше SAFE
MAX_BENIGN_DANGEROUS = 0.02    # доля безопасных, ошибочно названных «Опасно»


@pytest.fixture
def dataset() -> list[tuple[str, int]]:
    with DATASET.open(encoding="utf-8", newline="") as fh:
        return [(r["url"], int(r["label"])) for r in csv.DictReader(fh)]


def test_levels_match_thresholds():
    assert level_for(0) == "SAFE"
    assert level_for(scoring.SUSPICIOUS_THRESHOLD - 1) == "SAFE"
    assert level_for(scoring.SUSPICIOUS_THRESHOLD) == "SUSPICIOUS"
    assert level_for(scoring.DANGEROUS_THRESHOLD - 1) == "SUSPICIOUS"
    assert level_for(scoring.DANGEROUS_THRESHOLD) == "DANGEROUS"
    assert level_for(100) == "DANGEROUS"


def test_score_always_within_range():
    for url in ("https://github.com", "http://a@b.c.d.e.tk:31337/x.exe?u=http://y.top"):
        assert 0 <= check(url, use_ml=False).score <= 100


def test_offline_by_default_makes_no_network_calls(monkeypatch):
    """Ключевое требование безопасности: без галочки — ни одного обращения к домену."""
    import urlcheck.network as network

    def explode(*_a, **_kw):
        raise AssertionError("сетевая проверка выполнена в офлайн-режиме")

    monkeypatch.setattr(network, "gather", explode)
    verdict = check("http://phish.top/login", use_ml=False)
    assert verdict.network.enabled is False


def test_network_signals_are_added(monkeypatch):
    fake = NetworkFacts(enabled=True, resolves=True, ip="1.2.3.4", domain_age_days=3)
    monkeypatch.setattr("urlcheck.network.gather", lambda *a, **kw: fake)

    verdict = check("http://some-site.top/login", use_ml=False, use_network=True)
    assert verdict.network.domain_age_days == 3
    assert "domain_very_new" in {s.code for s in verdict.signals}


def test_ml_can_raise_but_only_slightly_lower_the_score(monkeypatch):
    url = "http://example.tk/login"
    baseline = check(url, use_ml=False).score

    monkeypatch.setattr("urlcheck.ml.predict", lambda _u: 1.0)
    assert check(url, use_ml=True).score > baseline

    monkeypatch.setattr("urlcheck.ml.predict", lambda _u: 0.0)
    lowered = check(url, use_ml=True).score
    assert lowered < baseline
    assert lowered >= baseline * (1 - scoring.ML_MITIGATION) - 1


def test_missing_model_does_not_break_check(monkeypatch):
    monkeypatch.setattr("urlcheck.ml.predict", lambda _u: None)
    verdict = check("http://phish.tk/login")
    assert verdict.ml_probability is None
    assert verdict.score == verdict.heuristic_score


def test_invalid_url_is_reported_not_raised():
    verdict = check("http://a b.com")
    assert verdict.level == "SAFE"
    assert verdict.signals[0].code == "invalid_url"


def test_report_contains_verdict_and_is_defanged():
    report = format_report(check("http://evil-phish.tk/login", use_ml=False))
    assert "ВЕРДИКТ" in report
    assert "http://evil-phish.tk" not in report  # ссылка обезврежена
    assert "hxxp://" in report


def test_report_states_offline_mode():
    assert "отключены" in format_report(check("https://github.com", use_ml=False))


# ------------------------------------------------------------------ золотой прогон


def test_heuristics_catch_most_malicious_urls(dataset):
    malicious = [u for u, label in dataset if label == 1]
    flagged = [u for u in malicious if check(u, use_ml=False).level != "SAFE"]
    ratio = len(flagged) / len(malicious)
    assert ratio >= MIN_MALICIOUS_FLAGGED, (
        f"эвристики поймали лишь {ratio:.1%} вредоносных ссылок "
        f"(требуется {MIN_MALICIOUS_FLAGGED:.0%})"
    )


def test_heuristics_almost_never_call_benign_urls_dangerous(dataset):
    benign = [u for u, label in dataset if label == 0]
    false_alarms = [u for u in benign if check(u, use_ml=False).level == "DANGEROUS"]
    ratio = len(false_alarms) / len(benign)
    assert ratio <= MAX_BENIGN_DANGEROUS, (
        f"ложных «Опасно» {ratio:.1%}: {false_alarms[:5]}"
    )


def test_known_hard_negatives_stay_safe():
    """Легитимные страницы входа не должны пугать пользователя."""
    for url in (
        "https://accounts.google.com/signin/v2/identifier",
        "https://online.sberbank.ru/CSAFront/index.do",
        "https://esia.gosuslugi.ru/login/",
        "https://www.paypal.com/signin",
        "https://github.com/login",
    ):
        assert check(url, use_ml=False).level == "SAFE", url


def test_known_attacks_are_flagged():
    for url in (
        "http://login.paypal.com.secure-verify.top/signin",
        "http://sberbank.ru@evil-host.xyz/vhod",
        "http://185.220.101.45/gate.php",
        "http://paypa1.com/signin",
    ):
        assert check(url, use_ml=False).level != "SAFE", url

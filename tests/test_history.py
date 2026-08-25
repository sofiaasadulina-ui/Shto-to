"""Тесты истории проверок."""

import pytest

from urlcheck import history
from urlcheck.scoring import check


@pytest.fixture
def db(tmp_path):
    return tmp_path / "test_history.db"


def test_save_and_read_back(db):
    verdict = check("http://phish-example.tk/login", use_ml=False)
    row_id = history.save(verdict, db)
    assert row_id > 0

    rows = history.recent(10, db)
    assert len(rows) == 1
    assert rows[0].url == verdict.url
    assert rows[0].score == verdict.score
    assert rows[0].level == verdict.level


def test_empty_history(db):
    assert history.recent(10, db) == []
    assert history.stats(db)["TOTAL"] == 0


def test_newest_first_and_limit(db):
    for i in range(5):
        history.save(check(f"https://example{i}.com", use_ml=False), db)
    rows = history.recent(3, db)
    assert len(rows) == 3
    assert rows[0].url.endswith("example4.com")


def test_stats_counts_levels(db):
    history.save(check("https://github.com", use_ml=False), db)
    history.save(check("http://login.paypal.com.verify.top/signin", use_ml=False), db)
    stats = history.stats(db)
    assert stats["TOTAL"] == 2
    assert stats["SAFE"] == 1
    assert stats["DANGEROUS"] == 1


def test_clear(db):
    history.save(check("https://example.com", use_ml=False), db)
    history.clear(db)
    assert history.recent(10, db) == []


def test_network_flag_is_persisted(db):
    verdict = check("https://example.com", use_ml=False)
    verdict.network.enabled = True
    history.save(verdict, db)
    assert history.recent(1, db)[0].used_network is True


def test_timestamp_is_formatted_for_ui(db):
    history.save(check("https://example.com", use_ml=False), db)
    assert len(history.recent(1, db)[0].ts_short) == 11  # «ДД.ММ ЧЧ:ММ»


def test_database_is_created_on_demand(tmp_path):
    nested = tmp_path / "sub" / "dir" / "history.db"
    history.save(check("https://example.com", use_ml=False), nested)
    assert nested.exists()

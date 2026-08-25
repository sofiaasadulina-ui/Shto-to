"""Структуры данных, которыми обмениваются модули проверки."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Level = Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]

LEVEL_TITLE_RU: dict[str, str] = {
    "SAFE": "Безопасно",
    "SUSPICIOUS": "Подозрительно",
    "DANGEROUS": "Опасно",
}


@dataclass(frozen=True)
class Signal:
    """Один сработавший признак и его вклад в итоговый риск."""

    code: str
    title: str
    weight: int
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "weight": self.weight,
            "detail": self.detail,
        }


@dataclass
class NetworkFacts:
    """Результат сетевой разведки. Все поля необязательны: проверка могла не пройти."""

    enabled: bool = False
    resolves: bool | None = None
    ip: str | None = None
    domain_age_days: int | None = None
    registrar: str | None = None
    ssl_valid: bool | None = None
    ssl_issuer: str | None = None
    ssl_days_left: int | None = None
    redirect_chain: list[str] = field(default_factory=list)
    final_url: str | None = None
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "resolves": self.resolves,
            "ip": self.ip,
            "domain_age_days": self.domain_age_days,
            "registrar": self.registrar,
            "ssl_valid": self.ssl_valid,
            "ssl_issuer": self.ssl_issuer,
            "ssl_days_left": self.ssl_days_left,
            "redirect_chain": list(self.redirect_chain),
            "final_url": self.final_url,
            "errors": list(self.errors),
        }


@dataclass
class Verdict:
    """Итог проверки одной ссылки."""

    url: str
    score: int
    level: Level
    signals: list[Signal] = field(default_factory=list)
    heuristic_score: int = 0
    ml_probability: float | None = None
    network: NetworkFacts = field(default_factory=NetworkFacts)
    elapsed_ms: int = 0

    @property
    def level_ru(self) -> str:
        return LEVEL_TITLE_RU[self.level]

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "score": self.score,
            "level": self.level,
            "signals": [s.as_dict() for s in self.signals],
            "heuristic_score": self.heuristic_score,
            "ml_probability": self.ml_probability,
            "network": self.network.as_dict(),
            "elapsed_ms": self.elapsed_ms,
        }

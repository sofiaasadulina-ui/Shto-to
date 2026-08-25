"""Агрегация трёх источников вердикта в одну оценку риска 0..100."""

from __future__ import annotations

import time

from . import ml
from .features import extract
from .heuristics import evaluate, heuristic_score
from .models import Level, NetworkFacts, Signal, Verdict
from .normalize import ParsedUrl, parse

# ---- Коэффициенты агрегации -----------------------------------------------------------
# Эвристики — это установленные факты о структуре ссылки, поэтому они задают базу.
# Модель может ПОВЫСИТЬ оценку (она видит статистические паттерны написания, которых
# нет в ручных правилах), но лишь незначительно СМЯГЧАЕТ её: «модель не нашла» не
# отменяет того, что правило уже нашло. Отсюда несимметричные коэффициенты.
ML_ESCALATION = 0.45   # доля разрыва, на которую модель поднимает оценку
ML_MITIGATION = 0.20   # доля разрыва, на которую модель снижает оценку
ML_FLAG_THRESHOLD = 0.90  # с какой вероятности модель получает собственный сигнал

# ---- Пороги уровней (откалиброваны на data/sample_urls.csv) ---------------------------
SUSPICIOUS_THRESHOLD = 30
DANGEROUS_THRESHOLD = 65


def level_for(score: int) -> Level:
    if score >= DANGEROUS_THRESHOLD:
        return "DANGEROUS"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "SAFE"


def check(
    url: str,
    use_network: bool = False,
    use_ml: bool = True,
    network_timeout: float = 5.0,
) -> Verdict:
    """Полная проверка ссылки.

    use_network=False (по умолчанию) означает: программа не делает ни одного
    обращения к домену — проверка полностью офлайновая и безопасная.
    """
    started = time.perf_counter()
    parsed: ParsedUrl = parse(url)

    if not parsed.is_valid:
        return Verdict(
            url=parsed.raw,
            score=0,
            level="SAFE",
            signals=[Signal("invalid_url", "Ссылка не разбирается", 0, parsed.error)],
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )

    feats = extract(parsed)
    signals = evaluate(parsed, feats)
    heur = heuristic_score(signals)

    ml_proba = ml.predict(parsed.url) if use_ml else None
    if ml_proba is None:
        base = float(heur)
    else:
        ml_score = ml_proba * 100
        if ml_score >= heur:
            base = heur + ML_ESCALATION * (ml_score - heur)
        else:
            base = heur - ML_MITIGATION * (heur - ml_score)
        if ml_proba >= ML_FLAG_THRESHOLD and heur < SUSPICIOUS_THRESHOLD:
            # Модель видит паттерн, которого нет в правилах — отдельный объяснимый сигнал.
            signals.append(
                Signal(
                    "ml_flag",
                    "Модель машинного обучения считает ссылку вредоносной",
                    0,
                    f"Вероятность по модели: {ml_proba:.0%}. Ручные правила ничего "
                    "не нашли — сработали статистические признаки написания адреса.",
                )
            )

    network = NetworkFacts(enabled=use_network)
    if use_network:
        from .network import apply_network_signals, gather

        network = gather(parsed, timeout=network_timeout)
        net_signals, net_bonus = apply_network_signals(parsed, network)
        signals.extend(net_signals)
        base += net_bonus

    score = max(0, min(100, int(round(base))))
    signals.sort(key=lambda s: -s.weight)

    return Verdict(
        url=parsed.url,
        score=score,
        level=level_for(score),
        signals=signals,
        heuristic_score=heur,
        ml_probability=ml_proba,
        network=network,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


def format_report(verdict: Verdict) -> str:
    """Текстовый отчёт — для CLI и кнопки «Скопировать отчёт»."""
    from .normalize import defang

    lines = [
        "=" * 70,
        f"Проверка ссылки: {defang(verdict.url)}",
        "=" * 70,
        f"ВЕРДИКТ: {verdict.level_ru} (риск {verdict.score}/100)",
        f"Эвристики: {verdict.heuristic_score}/100"
        + (
            f" | Модель ML: {verdict.ml_probability:.0%}"
            if verdict.ml_probability is not None
            else " | Модель ML: не использовалась"
        )
        + f" | Время: {verdict.elapsed_ms} мс",
        "",
    ]

    if verdict.signals:
        lines.append("Причины:")
        for s in verdict.signals:
            lines.append(f"  [+{s.weight:>2}] {s.title}")
            if s.detail:
                lines.append(f"         {s.detail}")
    else:
        lines.append("Причины: подозрительных признаков не найдено.")

    net = verdict.network
    if net.enabled:
        lines += ["", "Сетевые проверки:"]
        lines.append(f"  DNS: {'резолвится -> ' + (net.ip or '?') if net.resolves else 'не резолвится'}")
        if net.domain_age_days is not None:
            lines.append(f"  Возраст домена: {net.domain_age_days} дн.")
        if net.ssl_valid is not None:
            lines.append(
                f"  TLS-сертификат: {'валиден' if net.ssl_valid else 'проблема'}"
                + (f", издатель {net.ssl_issuer}" if net.ssl_issuer else "")
                + (f", осталось {net.ssl_days_left} дн." if net.ssl_days_left is not None else "")
            )
        if net.redirect_chain:
            lines.append("  Переходы: " + " -> ".join(defang(u) for u in net.redirect_chain))
        for err in net.errors:
            lines.append(f"  ! {err}")
    else:
        lines += ["", "Сетевые проверки: отключены (офлайн-режим)."]

    lines.append("=" * 70)
    return "\n".join(lines)


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Проверка URL на вредоносность (CLI)")
    ap.add_argument("url", help="ссылка для проверки")
    ap.add_argument("--network", action="store_true", help="включить сетевые проверки")
    ap.add_argument("--no-ml", action="store_true", help="не использовать ML-модель")
    args = ap.parse_args()

    verdict = check(args.url, use_network=args.network, use_ml=not args.no_ml)
    print(format_report(verdict))
    return 0 if verdict.level == "SAFE" else 1


if __name__ == "__main__":
    raise SystemExit(_main())

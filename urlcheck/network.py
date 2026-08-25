"""Сетевая разведка по ссылке.

Важное ограничение проекта: содержимое страницы НИКОГДА не скачивается и ссылка
не открывается в браузере. Собираются только метаданные — DNS, WHOIS, TLS-сертификат
и заголовки перенаправлений (запросы методом HEAD). Каждая проверка обёрнута в
try/except с таймаутом: недоступный домен не должен ронять вердикт.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from .models import NetworkFacts, Signal
from .normalize import ParsedUrl, parse

MAX_REDIRECTS = 5
USER_AGENT = "URLGuard/1.0 (security research tool; HEAD only)"

# Пороги возраста домена: свежая регистрация — сильнейший маркер фишинга.
VERY_NEW_DOMAIN_DAYS = 30
NEW_DOMAIN_DAYS = 180


def _resolve(facts: NetworkFacts, host: str, timeout: float) -> None:
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
        facts.resolves = True
        facts.ip = infos[0][4][0] if infos else None
    except Exception as exc:
        facts.resolves = False
        facts.errors.append(f"DNS: домен не резолвится ({type(exc).__name__})")


def _whois_age(facts: NetworkFacts, domain: str) -> None:
    try:
        import whois  # python-whois
    except ImportError:
        facts.errors.append("WHOIS: модуль python-whois не установлен")
        return
    try:
        data = whois.whois(domain)
    except Exception as exc:
        facts.errors.append(f"WHOIS: запрос не удался ({type(exc).__name__})")
        return

    created = data.get("creation_date") if hasattr(data, "get") else None
    if isinstance(created, list):
        created = next((c for c in created if isinstance(c, datetime)), None)
    if not isinstance(created, datetime):
        facts.errors.append("WHOIS: дата регистрации не раскрыта")
        return

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    facts.domain_age_days = max(0, (datetime.now(timezone.utc) - created).days)

    registrar = data.get("registrar") if hasattr(data, "get") else None
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None
    if registrar:
        facts.registrar = str(registrar)


def _ssl_context() -> ssl.SSLContext:
    """Контекст с корневыми сертификатами.

    У сборок Python на macOS системное хранилище часто пустое, и тогда любой
    сертификат выглядел бы невалидным. Если доступен certifi (ставится вместе с
    requests) — берём набор корневых сертификатов оттуда.
    """
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _tls_certificate(facts: NetworkFacts, host: str, port: int, timeout: float) -> None:
    context = _ssl_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        message = (exc.verify_message or str(exc)).lower()
        if "unable to get local issuer" in message or "self-signed certificate in certificate chain" in message:
            # Проблема локального хранилища корневых сертификатов, а не самого сайта.
            facts.ssl_valid = None
            facts.errors.append(
                "TLS: не удалось проверить цепочку — на этой машине не настроено "
                "хранилище корневых сертификатов (установите certifi)"
            )
        else:
            facts.ssl_valid = False
            facts.errors.append(f"TLS: сертификат не прошёл проверку ({exc.verify_message})")
        return
    except Exception as exc:
        facts.errors.append(f"TLS: соединение не установлено ({type(exc).__name__})")
        return

    facts.ssl_valid = True
    if not cert:
        return

    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    facts.ssl_issuer = issuer.get("organizationName") or issuer.get("commonName")

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            facts.ssl_days_left = (expires - datetime.now(timezone.utc)).days
        except ValueError:
            pass


def _redirects(facts: NetworkFacts, url: str, timeout: float) -> None:
    try:
        import requests
    except ImportError:
        facts.errors.append("Редиректы: модуль requests не установлен")
        return

    chain = [url]
    current = url
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    for _ in range(MAX_REDIRECTS):
        try:
            resp = session.head(
                current,
                allow_redirects=False,
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
            )
        except Exception as exc:
            facts.errors.append(f"Редиректы: запрос не удался ({type(exc).__name__})")
            break

        if resp.status_code not in (301, 302, 303, 307, 308):
            break
        location = resp.headers.get("Location")
        if not location:
            break
        current = requests.compat.urljoin(current, location)
        chain.append(current)
    else:
        facts.errors.append(f"Редиректы: превышен лимит в {MAX_REDIRECTS} переходов")

    facts.redirect_chain = chain
    facts.final_url = chain[-1]


def gather(parsed: ParsedUrl | str, timeout: float = 5.0) -> NetworkFacts:
    """Собирает сетевые факты о ссылке. Никогда не бросает исключений."""
    if isinstance(parsed, str):
        parsed = parse(parsed)

    facts = NetworkFacts(enabled=True)
    if not parsed.is_valid:
        facts.errors.append("Ссылка не разбирается — сетевые проверки пропущены")
        return facts

    host = parsed.host.strip("[]")
    _resolve(facts, host, timeout)

    if facts.resolves:
        if not parsed.is_ip_host:
            _whois_age(facts, parsed.registrable_domain)
        port = parsed.port or (443 if parsed.scheme == "https" else 443)
        if parsed.scheme == "https" or port == 443:
            _tls_certificate(facts, host, port, timeout)
        _redirects(facts, parsed.url, timeout)

    return facts


def apply_network_signals(
    parsed: ParsedUrl, facts: NetworkFacts
) -> tuple[list[Signal], int]:
    """Превращает сетевые факты в сигналы риска. Возвращает (сигналы, добавка к баллу)."""
    signals: list[Signal] = []

    if facts.resolves is False:
        signals.append(
            Signal(
                "dns_fail",
                "Домен не резолвится",
                15,
                "DNS не возвращает адрес. Домен уже отключён (типично для отработавшей "
                "фишинговой кампании) либо не существовал вовсе.",
            )
        )

    age = facts.domain_age_days
    if age is not None:
        if age < VERY_NEW_DOMAIN_DAYS:
            signals.append(
                Signal(
                    "domain_very_new",
                    "Домен зарегистрирован только что",
                    25,
                    f"Возраст домена — {age} дн. Подавляющее большинство фишинговых "
                    "площадок живёт первые недели после регистрации.",
                )
            )
        elif age < NEW_DOMAIN_DAYS:
            signals.append(
                Signal(
                    "domain_new",
                    "Молодой домен",
                    10,
                    f"Возраст домена — {age} дн. Для сервиса, выдающего себя за "
                    "известный бренд, это нехарактерно.",
                )
            )

    if facts.ssl_valid is False:
        signals.append(
            Signal(
                "ssl_invalid",
                "TLS-сертификат не прошёл проверку",
                20,
                "Сертификат самоподписанный, просрочен или выдан на другое имя — "
                "соединение нельзя считать доверенным.",
            )
        )

    if len(facts.redirect_chain) > 1:
        start_domain = parsed.registrable_domain
        final = parse(facts.redirect_chain[-1])
        hops = len(facts.redirect_chain) - 1
        if final.registrable_domain and final.registrable_domain != start_domain:
            signals.append(
                Signal(
                    "redirect_offsite",
                    "Переброс на другой домен",
                    15,
                    f"Цепочка из {hops} перехода(ов) заканчивается на "
                    f"«{final.registrable_domain}» вместо «{start_domain}».",
                )
            )
            # Конечный адрес прогоняем через те же эвристики: цель важнее исходной ссылки.
            from .heuristics import evaluate

            for s in evaluate(final):
                signals.append(
                    Signal(
                        f"final:{s.code}",
                        f"[конечный адрес] {s.title}",
                        max(0, s.weight // 2),
                        s.detail,
                    )
                )

    bonus = sum(s.weight for s in signals)
    return signals, min(45, bonus)

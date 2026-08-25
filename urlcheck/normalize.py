"""Безопасный разбор URL.

Модуль ничего не скачивает и никуда не ходит: только строковый разбор.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

# Мини-список публичных суффиксов второго уровня. Нужен, чтобы для
# "login.sberbank.com.ru" registrable domain был "com.ru"-совместимым, а не "com.ru".
MULTI_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.cn", "com.tr", "com.mx", "co.in", "co.kr", "co.za",
    "com.ua", "org.ua", "net.ua", "com.ru", "net.ru", "org.ru", "pp.ru",
    "com.pl", "com.sg", "com.hk", "com.tw", "com.ar", "com.co",
}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
_LATIN_RE = re.compile(r"[A-Za-z]")


@dataclass
class ParsedUrl:
    """Разобранный URL плюс всё, что понадобится признакам и эвристикам."""

    raw: str
    url: str
    scheme: str = ""
    userinfo: str = ""
    host: str = ""
    host_unicode: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    registrable_domain: str = ""
    subdomains: list[str] = field(default_factory=list)
    tld: str = ""
    is_ip_host: bool = False
    query_params: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""

    @property
    def is_valid(self) -> bool:
        return not self.error and bool(self.host)

    @property
    def decoded_url(self) -> str:
        """URL с раскрытым процентным кодированием — для поиска ключевых слов."""
        try:
            return unquote(self.url)
        except Exception:
            return self.url


def _split_host_port(netloc: str) -> tuple[str, str, int | None, str]:
    """Возвращает (userinfo, host, port, error)."""
    userinfo = ""
    if "@" in netloc:
        userinfo, _, netloc = netloc.rpartition("@")

    port: int | None = None
    host = netloc

    if netloc.startswith("["):  # IPv6-литерал
        close = netloc.find("]")
        if close == -1:
            return userinfo, netloc, None, "Некорректный IPv6-адрес в ссылке"
        host = netloc[: close + 1]
        rest = netloc[close + 1 :]
        if rest.startswith(":"):
            rest = rest[1:]
            if not rest.isdigit():
                return userinfo, host, None, "Некорректный порт в ссылке"
            port = int(rest)
    elif ":" in netloc:
        host, _, raw_port = netloc.rpartition(":")
        if not raw_port.isdigit():
            return userinfo, netloc, None, "Некорректный порт в ссылке"
        port = int(raw_port)

    return userinfo, host.strip().rstrip("."), port, ""


def _is_ip_host(host: str) -> bool:
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    # Восьмеричная/шестнадцатеричная/десятичная запись IP — классический приём обфускации.
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", candidate):
        return True
    if candidate.isdigit() and len(candidate) > 5:
        return True
    return False


def _split_domain(host: str) -> tuple[list[str], str, str]:
    """Возвращает (поддомены, registrable domain, TLD)."""
    labels = [p for p in host.split(".") if p]
    if len(labels) < 2:
        return [], host, ""

    tail_two = ".".join(labels[-2:]).lower()
    suffix_len = 2 if tail_two in MULTI_LEVEL_SUFFIXES else 1
    reg_len = suffix_len + 1
    if len(labels) < reg_len:
        return [], host, labels[-1].lower()

    registrable = ".".join(labels[-reg_len:]).lower()
    subdomains = labels[:-reg_len]
    tld = labels[-1].lower()
    return subdomains, registrable, tld


def decode_punycode(host: str) -> str:
    """Разворачивает xn--... в юникод, чтобы стали видны омоглифы."""
    if not host:
        return ""
    parts = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                parts.append(label.encode("ascii").decode("idna"))
                continue
            except Exception:
                pass
        parts.append(label)
    return ".".join(parts)


def encode_punycode(host: str) -> str:
    """Обратная операция: юникод-домен -> ascii (xn--...)."""
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host


def has_mixed_scripts(host: str) -> bool:
    """True, если в одной метке домена смешаны кириллица и латиница."""
    for label in host.split("."):
        if _CYRILLIC_RE.search(label) and _LATIN_RE.search(label):
            return True
    return False


def parse(raw: str) -> ParsedUrl:
    """Разбирает пользовательский ввод в ParsedUrl. Не бросает исключений."""
    raw = (raw or "").strip()
    parsed = ParsedUrl(raw=raw, url=raw)

    if not raw:
        parsed.error = "Пустая ссылка"
        return parsed
    if any(ch.isspace() for ch in raw):
        parsed.error = "Ссылка содержит пробелы"
        return parsed

    url = raw
    if "://" not in url:
        # Без схемы браузер подставил бы http:// — делаем так же.
        url = "http://" + url.lstrip("/")
    parsed.url = url

    try:
        split = urlsplit(url)
    except ValueError as exc:
        parsed.error = f"Не удалось разобрать ссылку: {exc}"
        return parsed

    parsed.scheme = split.scheme.lower()
    userinfo, host, port, err = _split_host_port(split.netloc)
    if err:
        parsed.error = err
        return parsed

    parsed.userinfo = userinfo
    parsed.host = host.lower()
    parsed.host_unicode = decode_punycode(parsed.host)
    parsed.port = port
    parsed.path = split.path
    parsed.query = split.query
    parsed.fragment = split.fragment

    if not parsed.host:
        parsed.error = "В ссылке нет домена"
        return parsed

    parsed.is_ip_host = _is_ip_host(parsed.host)
    if not parsed.is_ip_host:
        subs, registrable, tld = _split_domain(parsed.host_unicode)
        parsed.subdomains = subs
        parsed.registrable_domain = registrable
        parsed.tld = tld
    else:
        parsed.registrable_domain = parsed.host

    try:
        parsed.query_params = parse_qsl(parsed.query, keep_blank_values=True)
    except Exception:
        parsed.query_params = []

    return parsed


def defang(url: str) -> str:
    """Обезвреженный вид ссылки: hxxp://example[.]com — нельзя случайно кликнуть."""
    if not url:
        return ""
    out = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return out.replace(".", "[.]")

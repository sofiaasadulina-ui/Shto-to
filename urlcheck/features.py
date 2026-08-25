"""Извлечение числовых признаков URL.

Один и тот же вектор используют и эвристики (urlcheck.heuristics), и ML-модель
(urlcheck.ml) — чтобы логика признаков не расходилась между двумя источниками вердикта.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from .normalize import ParsedUrl, has_mixed_scripts, parse

# --------------------------------------------------------------------------------------
# Справочники. Вынесены наверх: их удобно показывать и расширять.
# --------------------------------------------------------------------------------------

# TLD, статистически перепредставленные во вредоносных кампаниях (бесплатные/дешёвые
# регистрации, а также .zip/.mov, которые визуально неотличимы от имени файла).
RISKY_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work", "click",
    "link", "loan", "download", "review", "country", "stream", "gdn", "racing", "win",
    "bid", "date", "faith", "cricket", "science", "party", "trade", "webcam", "rest",
    "buzz", "cam", "surf", "quest", "monster", "cyou", "sbs", "lol", "icu",
}

# Сервисы сокращения ссылок: истинный адрес скрыт от пользователя.
URL_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "clck.ru", "vk.cc", "u.to", "qps.ru", "surl.li",
    "t.ly", "rb.gy", "shorte.st", "adf.ly", "bc.vc", "tiny.cc", "lnkd.in", "trib.al",
    "s.id", "clc.to", "gg.gg", "v.gd", "x.co", "1url.com", "link.ly",
}

# Слова-приманки, характерные для фишинговых страниц.
PHISHING_KEYWORDS = {
    "login", "signin", "sign-in", "logon", "account", "verify", "verification",
    "confirm", "secure", "security", "update", "password", "passwd", "credential",
    "banking", "bank", "wallet", "payment", "payout", "invoice", "billing", "unlock",
    "suspended", "recovery", "restore", "authorize", "authentication", "webscr",
    "bonus", "prize", "winner", "gift", "free", "giveaway", "airdrop", "claim",
    "support", "helpdesk", "office365", "onedrive", "docusign", "vhod", "parol",
    "oplata", "podtverdit", "vosstanovlenie", "bezopasnost",
}

# Бренды, под которые чаще всего маскируются. Ключ — токен для поиска в строке,
# значение — легитимные registrable-домены этого бренда.
BRANDS: dict[str, set[str]] = {
    "google": {"google.com", "google.ru", "googleapis.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.de", "aws.amazon.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "telegram": {"telegram.org", "t.me", "telegram.me"},
    "netflix": {"netflix.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "sberbank": {"sberbank.ru", "sber.ru", "online.sberbank.ru"},
    "tinkoff": {"tinkoff.ru", "tbank.ru"},
    "vtb": {"vtb.ru"},
    "alfabank": {"alfabank.ru"},
    "gosuslugi": {"gosuslugi.ru"},
    "yandex": {"yandex.ru", "yandex.com", "ya.ru"},
    "vk": {"vk.com", "vk.ru"},
    "mailru": {"mail.ru"},
    "ozon": {"ozon.ru"},
    "wildberries": {"wildberries.ru"},
    "avito": {"avito.ru"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "coinbase": {"coinbase.com"},
    "github": {"github.com", "githubusercontent.com"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "roblox": {"roblox.com"},
    "discord": {"discord.com", "discord.gg", "discordapp.com"},
}

# Расширения исполняемых/опасных файлов в пути ссылки.
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".apk", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".msi", ".jar", ".ps1", ".dll", ".sh", ".iso",
    ".img", ".lnk", ".reg", ".cpl", ".gadget", ".apk", ".dmg",
}

# Архивы — сами по себе не вредоносны, но популярны как контейнер полезной нагрузки.
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace"}

_HEX_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
_NESTED_URL_RE = re.compile(r"(https?%3a%2f%2f|https?://|www\.)", re.IGNORECASE)
_SPECIAL_CHARS = set("!\"#$%&'()*+,;=<>[]{}|\\^`~?@")


def shannon_entropy(text: str) -> float:
    """Энтропия Шеннона строки. Высокая = похоже на случайную (DGA) генерацию."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    """Расстояние Левенштейна. Своя реализация — чтобы не тянуть зависимость."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# Пары «выглядит так же»: чем подменяют символы в именах доменов.
HOMOGLYPH_MAP = {
    "rn": "m", "vv": "w", "cl": "d", "1": "l", "0": "o", "5": "s", "3": "e",
    "4": "a", "9": "g", "$": "s", "|": "l", "!": "i",
}


def normalize_homoglyphs(name: str) -> str:
    """Приводит визуальные подмены к «каноническому» написанию.

    arnazon -> amazon, paypa1 -> paypal, netfIix -> netflix. Нужно, чтобы
    расстояние Левенштейна считалось после снятия маскировки, а не до неё.
    """
    result = name.lower()
    for fake, real in HOMOGLYPH_MAP.items():
        result = result.replace(fake, real)
    return result


def _brand_lookalike(registrable_domain: str) -> tuple[str, int, bool]:
    """Ближайший бренд к домену и расстояние до него.

    Сравнивается только имя второго уровня без зоны: paypa1.com -> paypa1 vs paypal.
    Сначала снимается маскировка гомоглифами, иначе «arnazon» выглядит далёким от
    «amazon», хотя человеку они неразличимы. Третий элемент результата говорит,
    применялась ли такая замена: «arnazon» после неё совпадает с брендом точно
    (расстояние 0), и без этого флага правило бы промолчало.
    """
    if not registrable_domain:
        return "", 99, False
    raw_name = registrable_domain.split(".")[0].lower()
    name = normalize_homoglyphs(raw_name)
    best_brand, best_dist = "", 99
    for brand in BRANDS:
        if len(name) < 4 or abs(len(name) - len(brand)) > 2:
            continue
        dist = levenshtein(name, brand)
        if dist < best_dist:
            best_brand, best_dist = brand, dist
    return best_brand, best_dist, raw_name != name


def brand_impersonation(parsed: ParsedUrl) -> tuple[str, str]:
    """Ищет упоминание бренда вне его легитимного домена.

    Возвращает (бренд, где найден) или ("", ""). Пример: login.paypal.com.evil.top —
    бренд paypal есть в поддомене, но registrable domain чужой.
    """
    if parsed.is_ip_host:
        haystack_host = ""
    else:
        haystack_host = ".".join(parsed.subdomains).lower()
    haystack_path = (parsed.path + "?" + parsed.query).lower()
    reg = parsed.registrable_domain

    for brand, legit in BRANDS.items():
        if reg in legit or any(reg.endswith("." + d) for d in legit):
            continue  # это настоящий домен бренда

        # Ищем и короткий токен бренда ("sberbank"), и его домен целиком
        # ("mail.ru" в mail.ru.security-alert.ga — токен "mailru" тут не совпал бы).
        needles = {brand} | legit
        for needle in needles:
            if needle in haystack_host:
                return brand, "поддомен"
        for needle in needles:
            if needle in haystack_path:
                return brand, "путь"
    return "", ""


def path_extension(path: str) -> str:
    """Расширение файла в пути ссылки (в нижнем регистре) или ''."""
    tail = path.rsplit("/", 1)[-1]
    if "." not in tail:
        return ""
    return "." + tail.rsplit(".", 1)[-1].lower()


def extract(parsed: ParsedUrl | str) -> dict[str, float]:
    """Возвращает словарь числовых признаков ссылки."""
    if isinstance(parsed, str):
        parsed = parse(parsed)

    url = parsed.url
    decoded = parsed.decoded_url
    host = parsed.host
    host_uni = parsed.host_unicode or host
    path = parsed.path
    query = parsed.query
    domain_name = parsed.registrable_domain.split(".")[0] if parsed.registrable_domain else host

    brand_near, brand_dist, brand_masked = _brand_lookalike(parsed.registrable_domain)
    brand_imp, brand_where = brand_impersonation(parsed)
    ext = path_extension(path)
    digits_in_domain = sum(ch.isdigit() for ch in domain_name)

    lower_all = decoded.lower()
    keyword_hits = sorted(k for k in PHISHING_KEYWORDS if k in lower_all)

    feats: dict[str, float] = {
        # длины
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        # состав
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_digits_url": sum(ch.isdigit() for ch in url),
        "num_special_chars": sum(ch in _SPECIAL_CHARS for ch in url),
        "num_subdomains": len(parsed.subdomains),
        "num_path_segments": len([s for s in path.split("/") if s]),
        "num_query_params": len(parsed.query_params),
        "digit_ratio_domain": digits_in_domain / max(1, len(domain_name)),
        "domain_entropy": shannon_entropy(domain_name),
        "domain_length": len(domain_name),
        # Доля гласных: у произносимых слов ~0.35-0.45, у машинно-сгенерированных
        # доменов («kfhwqiudhqwd») близка к нулю. Энтропии одной недостаточно —
        # у длинного осмысленного слова вроде «stackoverflow» она тоже высокая.
        "vowel_ratio": sum(ch in "aeiouyаеёиоуыэюя" for ch in domain_name)
        / max(1, len(domain_name)),
        # структурные флаги
        "is_ip_host": float(parsed.is_ip_host),
        "has_userinfo": float(bool(parsed.userinfo)),
        "is_https": float(parsed.scheme == "https"),
        "has_port": float(parsed.port is not None),
        "nonstandard_port": float(
            parsed.port is not None and parsed.port not in (80, 443)
        ),
        "has_punycode": float("xn--" in host),
        "mixed_scripts": float(has_mixed_scripts(host_uni)),
        "num_percent_escapes": len(_HEX_ESCAPE_RE.findall(url)),
        "percent_in_host": float("%" in host),
        "double_slash_in_path": float("//" in path),
        "nested_url_in_query": float(bool(query) and bool(_NESTED_URL_RE.search(query))),
        # репутация строки
        "risky_tld": float(parsed.tld in RISKY_TLDS),
        "is_shortener": float(parsed.registrable_domain in URL_SHORTENERS),
        "keyword_count": len(keyword_hits),
        "dangerous_extension": float(ext in DANGEROUS_EXTENSIONS),
        "archive_extension": float(ext in ARCHIVE_EXTENSIONS),
        "brand_typo_distance": float(brand_dist if brand_dist < 99 else 9),
        # Опечатка = отличие на 1 символ ИЛИ точное совпадение после снятия
        # маскировки гомоглифами. Точное совпадение без маскировки — это сам бренд.
        "brand_typosquat": float(
            brand_dist <= 1 and (brand_dist > 0 or brand_masked)
        ),
        "brand_impersonation": float(bool(brand_imp)),
    }

    # Строковые детали для эвристик и объяснений (в ML-вектор не попадают).
    feats["_meta"] = {  # type: ignore[assignment]
        "brand_near": brand_near,
        "brand_dist": brand_dist,
        "brand_masked": brand_masked,
        "brand_impersonated": brand_imp,
        "brand_where": brand_where,
        "extension": ext,
        "keywords": keyword_hits,
    }
    return feats


def numeric_only(feats: dict) -> dict[str, float]:
    """Вектор без служебного ключа _meta — то, что уходит в ML."""
    return {k: float(v) for k, v in feats.items() if not k.startswith("_")}


def url_to_features(urls) -> list[dict]:
    """Список URL -> список словарей признаков.

    Функция живёт здесь, а не в train_model.py, потому что joblib сохраняет
    внутри модели ссылку на неё по полному имени модуля: из train_model.py она
    бы записалась как «__main__.url_to_features» и не загрузилась в приложении.
    """
    return [numeric_only(extract(u)) for u in urls]

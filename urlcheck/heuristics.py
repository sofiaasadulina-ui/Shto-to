"""Эвристические правила: структура URL -> список объяснимых признаков риска.

Каждое правило — отдельная функция rule_*(parsed, feats) -> Signal | None.
Все правила собраны в RULES и выполняются последовательно. Такая форма выбрана
специально: правило легко показать, протестировать и обосновать по отдельности.
"""

from __future__ import annotations

from typing import Callable

from .features import URL_SHORTENERS, extract
from .models import Signal
from .normalize import ParsedUrl, parse

# Пороговые значения, вынесены наверх для калибровки.
LONG_URL = 100
VERY_LONG_URL = 150
MANY_SUBDOMAINS = 3
MANY_HYPHENS = 3
HIGH_ENTROPY = 3.2
LOW_VOWEL_RATIO = 0.25
HIGH_DIGIT_RATIO = 0.25
DGA_MIN_LENGTH = 8
MANY_KEYWORDS = 3

Rule = Callable[[ParsedUrl, dict], "Signal | None"]


def rule_brand_impersonation(parsed: ParsedUrl, f: dict) -> Signal | None:
    meta = f["_meta"]
    if not f["brand_impersonation"]:
        return None
    brand = meta["brand_impersonated"]
    where = meta["brand_where"]
    return Signal(
        "brand_impersonation",
        "Подмена бренда",
        30,
        f"Бренд «{brand}» упомянут в разделе «{where}», но сам домен "
        f"({parsed.registrable_domain}) бренду не принадлежит. "
        "Классическая схема фишинга: жертва видит знакомое имя и не смотрит на домен.",
    )


def rule_brand_typosquat(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["brand_typosquat"]:
        return None
    meta = f["_meta"]
    if meta.get("brand_masked") and meta["brand_dist"] == 0:
        detail = (
            f"Домен «{parsed.registrable_domain}» визуально неотличим от «{meta['brand_near']}»: "
            "использована подмена похожих символов (например, «rn» вместо «m» "
            "или цифра «1» вместо буквы «l»)."
        )
    else:
        detail = (
            f"Домен «{parsed.registrable_domain}» отличается от «{meta['brand_near']}» "
            f"всего на {int(meta['brand_dist'])} символ. Приём рассчитан на невнимательное чтение."
        )
    return Signal("brand_typosquat", "Опечатка в имени бренда (typosquatting)", 30, detail)


def rule_userinfo(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["has_userinfo"]:
        return None
    return Signal(
        "userinfo",
        "Символ @ в адресе",
        25,
        f"Всё до «@» ({parsed.userinfo}) браузер игнорирует — реальный хост это "
        f"{parsed.host}. Приём используют, чтобы показать в ссылке чужое доверенное имя.",
    )


def rule_ip_host(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["is_ip_host"]:
        return None
    return Signal(
        "ip_host",
        "IP-адрес вместо доменного имени",
        25,
        f"Хост задан как {parsed.host}. Легитимные сервисы почти всегда используют "
        "домен; прямой IP типичен для временных вредоносных площадок и C2-серверов.",
    )


def rule_punycode(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["has_punycode"] and not f["mixed_scripts"]:
        return None
    if f["mixed_scripts"]:
        detail = (
            f"В домене «{parsed.host_unicode}» смешаны кириллица и латиница — "
            "омоглиф-атака (например, кириллическая «а» вместо латинской)."
        )
    else:
        detail = (
            f"Домен закодирован в punycode: {parsed.host} -> {parsed.host_unicode}. "
            "Так маскируют символы, визуально неотличимые от латиницы."
        )
    return Signal("punycode", "Обманчивое написание домена", 20, detail)


def rule_dangerous_extension(parsed: ParsedUrl, f: dict) -> Signal | None:
    ext = f["_meta"]["extension"]
    if f["dangerous_extension"]:
        return Signal(
            "dangerous_extension",
            "Ссылка ведёт на исполняемый файл",
            20,
            f"Путь заканчивается на «{ext}» — это исполняемый или скриптовый файл, "
            "который может запустить вредоносный код после скачивания.",
        )
    if f["archive_extension"]:
        return Signal(
            "archive_extension",
            "Ссылка ведёт на архив",
            8,
            f"Путь заканчивается на «{ext}». Архивы часто используют как контейнер "
            "для полезной нагрузки, обходя простые фильтры почты.",
        )
    return None


def extract_nested_url(parsed: ParsedUrl) -> str | None:
    """Достаёт вложенный адрес из параметров запроса (цель open redirect)."""
    from urllib.parse import unquote

    for _key, value in parsed.query_params:
        candidate = unquote(value).strip()
        if candidate.lower().startswith(("http://", "https://")):
            return candidate
        if candidate.lower().startswith("www.") and "." in candidate[4:]:
            return "http://" + candidate
    return None


def rule_nested_url(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["nested_url_in_query"]:
        return None
    target = extract_nested_url(parsed)
    where = f"«{target}»" if target else f"«{parsed.query[:120]}»"
    return Signal(
        "nested_url",
        "Вложенный адрес в параметрах (open redirect)",
        20,
        f"В строке запроса находится ещё один URL: {where}. "
        "Так пользуются открытыми редиректами доверенных сайтов: пользователь видит "
        "знакомый домен, а попадает на чужой.",
    )


def rule_shortener(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["is_shortener"]:
        return None
    return Signal(
        "shortener",
        "Сокращатель ссылок",
        15,
        f"«{parsed.registrable_domain}» скрывает настоящий адрес назначения. "
        "Сам по себе не вреден, но не даёт оценить, куда ведёт ссылка. "
        "Включите сетевые проверки, чтобы раскрыть цепочку переходов.",
    )


def rule_keywords(parsed: ParsedUrl, f: dict) -> Signal | None:
    hits = f["_meta"]["keywords"]
    if not hits:
        return None
    weight = 15 if len(hits) >= MANY_KEYWORDS else 8 if len(hits) >= 2 else 5
    return Signal(
        "keywords",
        "Слова-приманки в адресе",
        weight,
        "Найдено: " + ", ".join(hits[:8]) + ". "
        "Эти слова характерны для страниц кражи учётных данных и «выигрышей».",
    )


def rule_insecure_login(parsed: ParsedUrl, f: dict) -> Signal | None:
    if f["is_https"] or not f["_meta"]["keywords"]:
        return None
    if parsed.is_ip_host:
        base = 10
    else:
        base = 10
    return Signal(
        "insecure_login",
        "Ввод данных по незащищённому HTTP",
        base,
        "Страница похожа на форму входа или оплаты, но соединение без TLS: "
        "данные пойдут открытым текстом и доступны любому на пути трафика.",
    )


def rule_risky_tld(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["risky_tld"]:
        return None
    return Signal(
        "risky_tld",
        f"Домен в зоне повышенного риска (.{parsed.tld})",
        10,
        f"Зона «.{parsed.tld}» бесплатна или очень дешёва и статистически "
        "перепредставлена во вредоносных кампаниях.",
    )


def rule_many_subdomains(parsed: ParsedUrl, f: dict) -> Signal | None:
    if f["num_subdomains"] <= MANY_SUBDOMAINS:
        return None
    return Signal(
        "many_subdomains",
        "Слишком много поддоменов",
        10,
        f"Уровней поддоменов: {int(f['num_subdomains'])} ({'.'.join(parsed.subdomains)}). "
        "Длинная цепочка выталкивает настоящий домен за границу видимой части адресной строки.",
    )


def rule_long_url(parsed: ParsedUrl, f: dict) -> Signal | None:
    length = int(f["url_length"])
    if length <= LONG_URL:
        return None
    weight = 10 if length > VERY_LONG_URL else 5
    return Signal(
        "long_url",
        "Аномально длинный адрес",
        weight,
        f"Длина ссылки — {length} символов. Длина используется, чтобы «увести» "
        "подозрительную часть адреса за пределы видимой области.",
    )


def rule_high_entropy(parsed: ParsedUrl, f: dict) -> Signal | None:
    """Домен, похожий на сгенерированный алгоритмом (DGA).

    Одной энтропии мало: у длинного осмысленного «stackoverflow» она тоже высокая.
    Отличает сгенерированное имя отсутствие гласных или обилие цифр.
    """
    if f["is_ip_host"] or f["domain_length"] < DGA_MIN_LENGTH:
        return None
    if f["domain_entropy"] < HIGH_ENTROPY:
        return None
    unpronounceable = f["vowel_ratio"] < LOW_VOWEL_RATIO
    digit_heavy = f["digit_ratio_domain"] > HIGH_DIGIT_RATIO
    if not (unpronounceable or digit_heavy):
        return None

    reason = "почти нет гласных" if unpronounceable else "необычно много цифр"
    return Signal(
        "high_entropy",
        "Домен похож на случайно сгенерированный",
        10,
        f"В имени «{parsed.registrable_domain}» {reason}, энтропия символов "
        f"{f['domain_entropy']:.2f}. Так выглядят домены, созданные алгоритмом (DGA) "
        "для быстрой смены площадок между блокировками.",
    )


def rule_nonstandard_port(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["nonstandard_port"]:
        return None
    return Signal(
        "nonstandard_port",
        f"Нестандартный порт ({parsed.port})",
        5,
        "Обычные сайты работают на 80/443. Другой порт часто означает кустарный "
        "сервер: панель управления, раздачу файлов или C2.",
    )


def rule_many_hyphens(parsed: ParsedUrl, f: dict) -> Signal | None:
    if f["num_hyphens"] < MANY_HYPHENS:
        return None
    return Signal(
        "many_hyphens",
        "Много дефисов в домене",
        5,
        f"Дефисов: {int(f['num_hyphens'])}. Приём для сборки правдоподобных имён "
        "вида «secure-login-update-account».",
    )


def rule_encoded_chars(parsed: ParsedUrl, f: dict) -> Signal | None:
    if f["percent_in_host"]:
        return Signal(
            "encoded_host",
            "Процентное кодирование в имени хоста",
            10,
            "Кодирование символов домена — попытка обойти фильтры и скрыть настоящий хост.",
        )
    if f["num_percent_escapes"] >= 6:
        return Signal(
            "encoded_path",
            "Сильное кодирование адреса",
            5,
            f"В ссылке {int(f['num_percent_escapes'])} escape-последовательностей "
            "«%XX» — содержимое намеренно скрыто от беглого взгляда.",
        )
    return None


def rule_double_slash(parsed: ParsedUrl, f: dict) -> Signal | None:
    if not f["double_slash_in_path"]:
        return None
    return Signal(
        "double_slash",
        "Двойной слэш в пути",
        5,
        "Последовательность «//» внутри пути используется для обхода наивных "
        "фильтров и для подстановки перенаправления.",
    )


def rule_no_https(parsed: ParsedUrl, f: dict) -> Signal | None:
    if f["is_https"] or parsed.scheme not in ("http", ""):
        return None
    if f["_meta"]["keywords"]:
        return None  # уже учтено более тяжёлым rule_insecure_login
    return Signal(
        "no_https",
        "Соединение без шифрования (HTTP)",
        5,
        "Сайт не использует TLS: трафик можно перехватить и подменить.",
    )


RULES: list[Rule] = [
    rule_brand_impersonation,
    rule_brand_typosquat,
    rule_userinfo,
    rule_ip_host,
    rule_punycode,
    rule_dangerous_extension,
    rule_nested_url,
    rule_shortener,
    rule_keywords,
    rule_insecure_login,
    rule_risky_tld,
    rule_many_subdomains,
    rule_long_url,
    rule_high_entropy,
    rule_nonstandard_port,
    rule_many_hyphens,
    rule_encoded_chars,
    rule_double_slash,
    rule_no_https,
]


def evaluate(
    parsed: ParsedUrl | str,
    feats: dict | None = None,
    follow_nested: bool = True,
) -> list[Signal]:
    """Прогоняет все правила и возвращает сработавшие признаки по убыванию веса."""
    if isinstance(parsed, str):
        parsed = parse(parsed)
    if not parsed.is_valid:
        return [Signal("invalid_url", "Ссылка не разбирается", 0, parsed.error)]
    if feats is None:
        feats = extract(parsed)

    signals: list[Signal] = []
    for rule in RULES:
        try:
            signal = rule(parsed, feats)
        except Exception as exc:  # правило не должно ронять проверку целиком
            signal = Signal(f"error:{rule.__name__}", "Ошибка правила", 0, str(exc))
        if signal is not None:
            signals.append(signal)

    if follow_nested and feats.get("nested_url_in_query"):
        signals.extend(_nested_target_signals(parsed))

    signals.sort(key=lambda s: -s.weight)
    return signals


def _nested_target_signals(parsed: ParsedUrl) -> list[Signal]:
    """Оценивает цель open redirect теми же правилами (без рекурсии вглубь).

    Вес целевых признаков делится пополам: угроза реальна, но она на шаг дальше
    от пользователя, чем признаки самой ссылки.
    """
    target = extract_nested_url(parsed)
    if not target:
        return []
    target_parsed = parse(target)
    if not target_parsed.is_valid:
        return []
    if target_parsed.registrable_domain == parsed.registrable_domain:
        return []  # редирект внутри того же сайта — не признак атаки

    result: list[Signal] = []
    for s in evaluate(target_parsed, follow_nested=False):
        if s.weight <= 0:
            continue
        result.append(
            Signal(
                f"nested:{s.code}",
                f"[адрес назначения] {s.title}",
                max(1, s.weight // 2),
                f"Относится к вложенной ссылке {target_parsed.host}: {s.detail}",
            )
        )
    return result


def heuristic_score(signals: list[Signal]) -> int:
    """Суммарный риск эвристик, ограниченный сверху 100."""
    return min(100, sum(s.weight for s in signals))

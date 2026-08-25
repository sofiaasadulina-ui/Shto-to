"""Главное окно приложения.

Проверка выполняется в фоновом потоке, результат передаётся в поток интерфейса
через queue.Queue и периодический опрос по after(). Без этого окно «зависало» бы
на время WHOIS- и TLS-запросов.
"""

from __future__ import annotations

import queue
import threading

import customtkinter as ctk

from .. import history, ml
from ..models import Verdict
from ..normalize import defang, parse
from ..scoring import check, format_report
from .widgets import (
    FONT_BOLD,
    FONT_MAIN,
    FONT_MONO,
    HistoryTable,
    KeyValueView,
    RiskIndicator,
    SignalList,
)

APP_TITLE = "URLGuard — проверка ссылок на вредоносность"
HISTORY_LIMIT = 100
POLL_INTERVAL_MS = 100


class UrlGuardApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(APP_TITLE)
        self.geometry("960x720")
        self.minsize(820, 620)

        self._queue: queue.Queue = queue.Queue()
        self._busy = False
        self._last_verdict: Verdict | None = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self._build_input_row()
        self._build_options_row()
        self.indicator = RiskIndicator(self)
        self.indicator.grid(row=2, column=0, padx=16, pady=(4, 10), sticky="ew")
        self._build_tabs()
        self._build_status_bar()

        self.after(POLL_INTERVAL_MS, self._poll_queue)
        self.url_entry.focus_set()
        self.refresh_history()

    # ---------------------------------------------------------------- построение UI

    def _build_input_row(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=16, pady=(14, 6), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Вставьте ссылку — программа оценит риск, не открывая её",
            font=("Segoe UI", 15, "bold"),
            anchor="w",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        self.url_entry = ctk.CTkEntry(
            header,
            placeholder_text="https://example.com/page?id=1",
            font=FONT_MONO,
            height=40,
        )
        self.url_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        self.url_entry.bind("<Return>", lambda _e: self.start_check())

        ctk.CTkButton(
            header, text="Вставить", width=90, height=40, command=self.paste_clipboard
        ).grid(row=1, column=1, padx=(0, 8))

        self.check_button = ctk.CTkButton(
            header, text="Проверить", width=130, height=40, font=FONT_BOLD,
            command=self.start_check,
        )
        self.check_button.grid(row=1, column=2)

    def _build_options_row(self) -> None:
        options = ctk.CTkFrame(self, fg_color="transparent")
        options.grid(row=1, column=0, padx=16, pady=(0, 4), sticky="ew")

        self.network_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            options,
            text="Сетевые проверки (DNS, WHOIS, TLS, редиректы) — программа обратится к домену",
            variable=self.network_var,
            font=FONT_MAIN,
        ).grid(row=0, column=0, sticky="w", padx=(0, 20))

        self.ml_var = ctk.BooleanVar(value=ml.is_available())
        self.ml_checkbox = ctk.CTkCheckBox(
            options, text="Использовать ML-модель", variable=self.ml_var, font=FONT_MAIN
        )
        self.ml_checkbox.grid(row=0, column=1, sticky="w")
        if not ml.is_available():
            self.ml_checkbox.configure(state="disabled")

    def _build_tabs(self) -> None:
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=3, column=0, padx=16, pady=(0, 8), sticky="nsew")
        for name in ("Причины", "Разбор URL", "Сеть", "История"):
            self.tabs.add(name)
            self.tabs.tab(name).grid_columnconfigure(0, weight=1)
            self.tabs.tab(name).grid_rowconfigure(0, weight=1)

        self.signal_list = SignalList(self.tabs.tab("Причины"))
        self.signal_list.grid(row=0, column=0, sticky="nsew")

        self.url_view = KeyValueView(self.tabs.tab("Разбор URL"))
        self.url_view.grid(row=0, column=0, sticky="nsew")

        self.network_view = KeyValueView(self.tabs.tab("Сеть"))
        self.network_view.grid(row=0, column=0, sticky="nsew")

        history_tab = self.tabs.tab("История")
        history_tab.grid_rowconfigure(0, weight=1)
        self.history_table = HistoryTable(history_tab, on_pick=self._pick_from_history)
        self.history_table.grid(row=0, column=0, sticky="nsew")

        buttons = ctk.CTkFrame(history_tab, fg_color="transparent")
        buttons.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ctk.CTkButton(buttons, text="Обновить", width=110, command=self.refresh_history).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(
            buttons, text="Очистить историю", width=150, fg_color="#8a3030",
            hover_color="#a63a3a", command=self.clear_history,
        ).pack(side="left")

    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=4, column=0, padx=16, pady=(0, 12), sticky="ew")
        bar.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            bar, text=ml.status(), font=FONT_MAIN, text_color="gray60", anchor="w"
        )
        self.status_label.grid(row=0, column=0, sticky="w")

        self.copy_button = ctk.CTkButton(
            bar, text="Скопировать отчёт", width=170, command=self.copy_report,
            state="disabled",
        )
        self.copy_button.grid(row=0, column=1, sticky="e")

    # ------------------------------------------------------------------- действия

    def paste_clipboard(self) -> None:
        try:
            text = self.clipboard_get()
        except Exception:
            self._set_status("Буфер обмена пуст или недоступен")
            return
        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, text.strip())

    def start_check(self) -> None:
        if self._busy:
            return
        url = self.url_entry.get().strip()
        if not url:
            self.indicator.set_error("Введите ссылку для проверки")
            return

        self._busy = True
        self.check_button.configure(state="disabled", text="Проверка…")
        self.copy_button.configure(state="disabled")
        use_network = bool(self.network_var.get())
        self.indicator.set_busy(
            "Проверяем (идут сетевые запросы)…" if use_network else "Проверяем…"
        )
        self._set_status("Выполняется проверка…")

        thread = threading.Thread(
            target=self._worker,
            args=(url, use_network, bool(self.ml_var.get())),
            daemon=True,
        )
        thread.start()

    def _worker(self, url: str, use_network: bool, use_ml: bool) -> None:
        """Выполняется в фоновом потоке: сюда нельзя трогать виджеты."""
        try:
            verdict = check(url, use_network=use_network, use_ml=use_ml)
            try:
                history.save(verdict)
            except Exception as exc:  # история не критична для вердикта
                self._queue.put(("warn", f"История не сохранена: {exc}"))
            self._queue.put(("verdict", verdict))
        except Exception as exc:
            self._queue.put(("error", f"{type(exc).__name__}: {exc}"))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "verdict":
                    self._show_verdict(payload)
                elif kind == "error":
                    self._finish_busy()
                    self.indicator.set_error(str(payload))
                    self._set_status(f"Ошибка: {payload}")
                elif kind == "warn":
                    self._set_status(str(payload))
        except queue.Empty:
            pass
        self.after(POLL_INTERVAL_MS, self._poll_queue)

    def _finish_busy(self) -> None:
        self._busy = False
        self.check_button.configure(state="normal", text="Проверить")

    def _show_verdict(self, verdict: Verdict) -> None:
        self._finish_busy()
        self._last_verdict = verdict

        self.indicator.set_verdict(verdict)
        self.signal_list.show(verdict.signals)
        self.url_view.show(self._url_pairs(verdict))
        self.network_view.show(
            self._network_pairs(verdict),
            empty_text="Сетевые проверки отключены. Включите галочку над индикатором.",
        )
        self.copy_button.configure(state="normal")
        self.refresh_history()
        self._set_status(
            f"Готово за {verdict.elapsed_ms} мс · найдено признаков: {len(verdict.signals)}"
        )
        self.tabs.set("Причины")

    def _url_pairs(self, verdict: Verdict) -> list[tuple[str, str]]:
        p = parse(verdict.url)
        pairs = [
            ("Безопасный вид", defang(verdict.url)),
            ("Схема", p.scheme or "—"),
            ("Хост", p.host),
        ]
        if p.host_unicode and p.host_unicode != p.host:
            pairs.append(("Хост (раскодированный)", p.host_unicode))
        if p.userinfo:
            pairs.append(("Данные до «@»", p.userinfo))
        pairs += [
            ("Основной домен", p.registrable_domain or "—"),
            ("Поддомены", ".".join(p.subdomains) or "—"),
            ("Зона (TLD)", f".{p.tld}" if p.tld else "—"),
            ("Порт", str(p.port) if p.port else "по умолчанию"),
            ("Путь", p.path or "/"),
        ]
        if p.query_params:
            params = "\n".join(f"{k} = {v}" for k, v in p.query_params)
            pairs.append(("Параметры", params))
        elif p.query:
            pairs.append(("Строка запроса", p.query))
        if p.fragment:
            pairs.append(("Якорь", p.fragment))
        if verdict.ml_probability is not None:
            pairs.append(("Оценка ML-модели", f"{verdict.ml_probability:.1%} вредоносности"))
        return pairs

    def _network_pairs(self, verdict: Verdict) -> list[tuple[str, str]]:
        net = verdict.network
        if not net.enabled:
            return []

        pairs: list[tuple[str, str]] = []
        if net.resolves is None:
            pairs.append(("DNS", "проверка не выполнялась"))
        elif net.resolves:
            pairs.append(("DNS", f"домен резолвится в {net.ip}"))
        else:
            pairs.append(("DNS", "домен не резолвится"))

        if net.domain_age_days is not None:
            years = net.domain_age_days / 365.25
            pairs.append(("Возраст домена", f"{net.domain_age_days} дн. (~{years:.1f} г.)"))
        if net.registrar:
            pairs.append(("Регистратор", net.registrar))

        if net.ssl_valid is True:
            value = "валиден"
            if net.ssl_issuer:
                value += f", издатель: {net.ssl_issuer}"
            if net.ssl_days_left is not None:
                value += f", истекает через {net.ssl_days_left} дн."
            pairs.append(("TLS-сертификат", value))
        elif net.ssl_valid is False:
            pairs.append(("TLS-сертификат", "НЕ прошёл проверку"))

        if net.redirect_chain:
            chain = "\n".join(f"{i+1}. {defang(u)}" for i, u in enumerate(net.redirect_chain))
            pairs.append(("Цепочка переходов", chain))
        for i, err in enumerate(net.errors, 1):
            pairs.append((f"Замечание {i}", err))
        return pairs

    def copy_report(self) -> None:
        if self._last_verdict is None:
            return
        report = format_report(self._last_verdict)
        self.clipboard_clear()
        self.clipboard_append(report)
        self._set_status("Отчёт скопирован в буфер обмена")

    def refresh_history(self) -> None:
        try:
            rows = history.recent(HISTORY_LIMIT)
        except Exception as exc:
            self._set_status(f"История недоступна: {exc}")
            return
        self.history_table.show(rows)

    def clear_history(self) -> None:
        try:
            history.clear()
        except Exception as exc:
            self._set_status(f"Не удалось очистить историю: {exc}")
            return
        self.refresh_history()
        self._set_status("История очищена")

    def _pick_from_history(self, url: str) -> None:
        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, url)
        self.tabs.set("Причины")
        self.url_entry.focus_set()

    def _set_status(self, text: str) -> None:
        base = ml.status()
        self.status_label.configure(text=f"{base}   ·   {text}")


def run() -> None:
    UrlGuardApp().mainloop()

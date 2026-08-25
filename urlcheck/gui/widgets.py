"""Виджеты интерфейса: индикатор риска, список причин, таблицы."""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from ..history import HistoryRow
from ..models import LEVEL_TITLE_RU, Signal, Verdict

# Цвета уровней: (основной, приглушённый для полосы прогресса)
LEVEL_COLORS: dict[str, tuple[str, str]] = {
    "SAFE": ("#1f8a4c", "#2ecc71"),
    "SUSPICIOUS": ("#b8860b", "#f0a500"),
    "DANGEROUS": ("#a12b2b", "#e74c3c"),
    "IDLE": ("#3a3a3a", "#666666"),
}

FONT_MAIN = ("Segoe UI", 13)
FONT_BOLD = ("Segoe UI", 13, "bold")
FONT_TITLE = ("Segoe UI", 22, "bold")
FONT_MONO = ("Menlo", 12)


class RiskIndicator(ctk.CTkFrame):
    """Крупная цветная плашка с уровнем риска и полосой 0..100."""

    def __init__(self, master, **kwargs):
        super().__init__(master, corner_radius=12, fg_color=LEVEL_COLORS["IDLE"][0], **kwargs)
        self.grid_columnconfigure(0, weight=1)

        self.level_label = ctk.CTkLabel(
            self, text="Введите ссылку", font=FONT_TITLE, text_color="#ffffff"
        )
        self.level_label.grid(row=0, column=0, padx=20, pady=(16, 2), sticky="w")

        self.score_label = ctk.CTkLabel(
            self, text="Риск ещё не оценён", font=FONT_MAIN, text_color="#e8e8e8"
        )
        self.score_label.grid(row=1, column=0, padx=20, pady=(0, 8), sticky="w")

        self.bar = ctk.CTkProgressBar(self, height=14, corner_radius=7)
        self.bar.grid(row=2, column=0, padx=20, pady=(0, 8), sticky="ew")
        self.bar.set(0)

        self.detail_label = ctk.CTkLabel(
            self, text="", font=FONT_MAIN, text_color="#e8e8e8", anchor="w"
        )
        self.detail_label.grid(row=3, column=0, padx=20, pady=(0, 14), sticky="w")

    def set_busy(self, message: str = "Проверяем…") -> None:
        self.configure(fg_color=LEVEL_COLORS["IDLE"][0])
        self.level_label.configure(text=message)
        self.score_label.configure(text="")
        self.detail_label.configure(text="")
        self.bar.configure(progress_color=LEVEL_COLORS["IDLE"][1])
        self.bar.set(0)

    def set_verdict(self, verdict: Verdict) -> None:
        main, bar = LEVEL_COLORS[verdict.level]
        self.configure(fg_color=main)
        self.level_label.configure(text=LEVEL_TITLE_RU[verdict.level].upper())
        self.score_label.configure(text=f"Уровень риска: {verdict.score} из 100")
        self.bar.configure(progress_color=bar)
        self.bar.set(verdict.score / 100)

        parts = [f"эвристики {verdict.heuristic_score}/100"]
        if verdict.ml_probability is not None:
            parts.append(f"модель ML {verdict.ml_probability:.0%}")
        parts.append("сеть: " + ("да" if verdict.network.enabled else "офлайн"))
        parts.append(f"{verdict.elapsed_ms} мс")
        self.detail_label.configure(text="   •   ".join(parts))

    def set_error(self, message: str) -> None:
        self.configure(fg_color=LEVEL_COLORS["IDLE"][0])
        self.level_label.configure(text="Ошибка")
        self.score_label.configure(text=message)
        self.detail_label.configure(text="")
        self.bar.set(0)


class SignalList(ctk.CTkScrollableFrame):
    """Список сработавших признаков: вес, заголовок, объяснение."""

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self._placeholder("Здесь появятся причины вердикта.")

    def _clear(self) -> None:
        for child in self.winfo_children():
            child.destroy()

    def _placeholder(self, text: str) -> None:
        self._clear()
        ctk.CTkLabel(self, text=text, font=FONT_MAIN, text_color="gray70").grid(
            row=0, column=0, padx=12, pady=12, sticky="w"
        )

    def show(self, signals: list[Signal]) -> None:
        self._clear()
        if not signals:
            self._placeholder("Подозрительных признаков не найдено.")
            return

        for row, signal in enumerate(signals):
            card = ctk.CTkFrame(self, corner_radius=8)
            card.grid(row=row, column=0, padx=6, pady=4, sticky="ew")
            card.grid_columnconfigure(1, weight=1)

            color = (
                "#e74c3c" if signal.weight >= 20
                else "#f0a500" if signal.weight >= 10
                else "#8a8a8a"
            )
            badge = ctk.CTkLabel(
                card,
                text=f"+{signal.weight}",
                font=FONT_BOLD,
                width=44,
                corner_radius=6,
                fg_color=color,
                text_color="#ffffff",
            )
            badge.grid(row=0, column=0, padx=10, pady=10, sticky="n")

            ctk.CTkLabel(card, text=signal.title, font=FONT_BOLD, anchor="w").grid(
                row=0, column=1, padx=(0, 10), pady=(10, 0), sticky="ew"
            )
            if signal.detail:
                ctk.CTkLabel(
                    card,
                    text=signal.detail,
                    font=FONT_MAIN,
                    anchor="w",
                    justify="left",
                    wraplength=620,
                    text_color="gray75",
                ).grid(row=1, column=1, padx=(0, 10), pady=(2, 10), sticky="ew")


class KeyValueView(ctk.CTkScrollableFrame):
    """Простая таблица «поле — значение» для разбора URL и сетевых фактов."""

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(1, weight=1)
        self.show([])

    def show(self, pairs: list[tuple[str, str]], empty_text: str = "Нет данных.") -> None:
        for child in self.winfo_children():
            child.destroy()
        if not pairs:
            ctk.CTkLabel(self, text=empty_text, font=FONT_MAIN, text_color="gray70").grid(
                row=0, column=0, padx=12, pady=12, sticky="w"
            )
            return

        for row, (key, value) in enumerate(pairs):
            ctk.CTkLabel(self, text=key, font=FONT_BOLD, anchor="nw", width=190).grid(
                row=row, column=0, padx=(12, 8), pady=4, sticky="nw"
            )
            ctk.CTkLabel(
                self,
                text=value or "—",
                font=FONT_MONO,
                anchor="w",
                justify="left",
                wraplength=560,
                text_color="gray80",
            ).grid(row=row, column=1, padx=(0, 12), pady=4, sticky="ew")


class HistoryTable(ctk.CTkScrollableFrame):
    """Таблица истории проверок; клик по строке подставляет ссылку в поле ввода."""

    def __init__(self, master, on_pick: Callable[[str], None], **kwargs):
        super().__init__(master, **kwargs)
        self.on_pick = on_pick
        self.grid_columnconfigure(2, weight=1)
        self.show([])

    def show(self, rows: list[HistoryRow]) -> None:
        for child in self.winfo_children():
            child.destroy()

        if not rows:
            ctk.CTkLabel(
                self,
                text="История пуста. Проверьте ссылку — она сохранится сюда.",
                font=FONT_MAIN,
                text_color="gray70",
            ).grid(row=0, column=0, columnspan=4, padx=12, pady=12, sticky="w")
            return

        headers = ("Время", "Риск", "Ссылка", "Режим")
        for col, text in enumerate(headers):
            ctk.CTkLabel(self, text=text, font=FONT_BOLD, anchor="w").grid(
                row=0, column=col, padx=8, pady=(6, 8), sticky="w"
            )

        for i, row in enumerate(rows, start=1):
            color = LEVEL_COLORS[row.level][1]
            ctk.CTkLabel(self, text=row.ts_short, font=FONT_MONO, anchor="w").grid(
                row=i, column=0, padx=8, pady=2, sticky="w"
            )
            ctk.CTkLabel(
                self,
                text=f"{row.score:>3}",
                font=FONT_BOLD,
                width=42,
                corner_radius=5,
                fg_color=color,
                text_color="#ffffff",
            ).grid(row=i, column=1, padx=8, pady=2)

            link = ctk.CTkButton(
                self,
                text=row.url if len(row.url) <= 64 else row.url[:61] + "…",
                font=FONT_MONO,
                anchor="w",
                height=24,
                fg_color="transparent",
                hover_color="gray25",
                text_color="gray85",
                command=lambda u=row.url: self.on_pick(u),
            )
            link.grid(row=i, column=2, padx=4, pady=2, sticky="ew")

            ctk.CTkLabel(
                self,
                text="сеть" if row.used_network else "офлайн",
                font=FONT_MAIN,
                text_color="gray60",
            ).grid(row=i, column=3, padx=8, pady=2, sticky="w")

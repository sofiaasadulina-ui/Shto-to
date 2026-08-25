"""Обёртка над обученной моделью.

Модель необязательна: если файла нет или scikit-learn не установлен, predict()
возвращает None, и вердикт считается только по эвристикам. Так проект остаётся
работоспособным на любой машине жюри.
"""

from __future__ import annotations

from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "url_clf.joblib"

_model = None
_load_attempted = False
_load_error: str = ""


def load_model(path: Path | None = None):
    """Лениво загружает модель. Повторные вызовы бесплатны."""
    global _model, _load_attempted, _load_error
    if _load_attempted and path is None:
        return _model

    target = Path(path) if path is not None else MODEL_PATH
    _load_attempted = True
    _model = None
    _load_error = ""

    if not target.exists():
        _load_error = f"файл модели не найден: {target.name}"
        return None
    try:
        import joblib

        _model = joblib.load(target)
    except Exception as exc:
        _load_error = f"не удалось загрузить модель: {exc}"
        _model = None
    return _model


def is_available() -> bool:
    return load_model() is not None


def status() -> str:
    """Человекочитаемое состояние модели — показывается в интерфейсе."""
    if load_model() is not None:
        return "ML: модель загружена"
    return f"ML: не используется ({_load_error or 'нет модели'})"


def predict(url: str) -> float | None:
    """Вероятность вредоносности от 0.0 до 1.0, либо None если модель недоступна."""
    model = load_model()
    if model is None:
        return None
    try:
        import numpy as np

        # Пайплайн обучался на матрице формы (n, 1) — сохраняем ту же форму.
        column = np.array([url], dtype=object).reshape(-1, 1)
        proba = model.predict_proba(column)[0][1]
        return float(proba)
    except Exception:
        return None

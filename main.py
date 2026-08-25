"""Точка входа: запуск окна URLGuard.

Использование:
    python main.py                       — графический интерфейс
    python -m urlcheck.scoring <url>     — та же проверка из командной строки
"""

from urlcheck.gui.app import run

if __name__ == "__main__":
    run()

"""Обучение модели классификации URL.

Запуск:
    python train_model.py                          # на data/sample_urls.csv
    python train_model.py --csv big_dataset.csv    # на внешнем датасете

Формат CSV: колонки url,label где label = 1 (вредоносный) или 0 (безопасный).
Результат: models/url_clf.joblib и models/metrics.txt.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import FunctionTransformer, Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler

from urlcheck.features import url_to_features

ROOT = Path(__file__).resolve().parent
DEFAULT_CSV = ROOT / "data" / "sample_urls.csv"
MODEL_PATH = ROOT / "models" / "url_clf.joblib"
METRICS_PATH = ROOT / "models" / "metrics.txt"


def build_pipeline(algorithm: str = "logreg") -> Pipeline:
    """char-TF-IDF по строке адреса + ручные признаки -> линейный классификатор.

    Символьные n-граммы ловят написание («-verify-», «.tk/», «xn--»), которого нет
    в явных правилах; ручные признаки дают модели структурную семантику URL.
    """
    text_branch = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=20000,
        sublinear_tf=True,
        lowercase=True,
    )
    numeric_branch = make_pipeline(
        FunctionTransformer(url_to_features, validate=False),
        DictVectorizer(sparse=False),
        StandardScaler(),
    )

    features = ColumnTransformer(
        transformers=[
            ("chars", text_branch, 0),
            ("manual", numeric_branch, 0),
        ]
    )

    if algorithm == "forest":
        clf = RandomForestClassifier(
            n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1
        )
    else:
        clf = LogisticRegression(
            max_iter=2000, class_weight="balanced", C=4.0, random_state=42
        )

    return Pipeline([("features", features), ("clf", clf)])


def load_dataset(path: Path) -> tuple[list[str], list[int]]:
    urls: list[str] = []
    labels: list[int] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or "url" not in reader.fieldnames:
            raise SystemExit(f"В {path} нет колонки 'url'")
        label_field = "label" if "label" in reader.fieldnames else reader.fieldnames[-1]
        for row in reader:
            url = (row.get("url") or "").strip()
            raw_label = (row.get(label_field) or "").strip().lower()
            if not url:
                continue
            if raw_label in ("1", "bad", "malicious", "phishing", "malware", "defacement"):
                labels.append(1)
            elif raw_label in ("0", "good", "benign", "safe"):
                labels.append(0)
            else:
                continue
            urls.append(url)
    return urls, labels


def _as_column(urls: list[str]):
    """ColumnTransformer ждёт 2D-структуру: превращаем список в один столбец."""
    import numpy as np

    return np.array(urls, dtype=object).reshape(-1, 1)


def main() -> int:
    ap = argparse.ArgumentParser(description="Обучение модели детекции вредоносных URL")
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV, help="датасет url,label")
    ap.add_argument("--algorithm", choices=["logreg", "forest"], default="logreg")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--out", type=Path, default=MODEL_PATH)
    args = ap.parse_args()

    if not args.csv.exists():
        print(f"Датасет не найден: {args.csv}", file=sys.stderr)
        return 2

    urls, labels = load_dataset(args.csv)
    if len(set(labels)) < 2:
        print("В датасете должны быть оба класса (0 и 1)", file=sys.stderr)
        return 2

    print(f"Датасет: {args.csv}")
    print(f"  всего: {len(urls)} | вредоносных: {sum(labels)} | безопасных: {len(labels) - sum(labels)}")

    X = _as_column(urls)
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=args.test_size, stratify=labels, random_state=42
    )

    pipeline = build_pipeline(args.algorithm)
    print(f"\nОбучение ({args.algorithm})…")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    cv = cross_val_score(build_pipeline(args.algorithm), X, labels, cv=5, scoring="f1")

    lines = [
        f"Датасет: {args.csv.name} ({len(urls)} ссылок, {sum(labels)} вредоносных)",
        f"Алгоритм: {args.algorithm}, отложенная выборка: {args.test_size:.0%}",
        "",
        f"Accuracy : {accuracy_score(y_test, y_pred):.3f}",
        f"Precision: {precision_score(y_test, y_pred, zero_division=0):.3f}",
        f"Recall   : {recall_score(y_test, y_pred, zero_division=0):.3f}",
        f"F1-score : {f1_score(y_test, y_pred, zero_division=0):.3f}",
        f"ROC-AUC  : {roc_auc_score(y_test, y_proba):.3f}",
        f"F1 на 5-fold кросс-валидации: {cv.mean():.3f} (±{cv.std():.3f})",
        "",
        "Матрица ошибок (строки — факт, столбцы — предсказание):",
        "            предсказано:безопасно  предсказано:вредоносно",
    ]
    cm = confusion_matrix(y_test, y_pred)
    for name, row in zip(("факт:безопасно ", "факт:вредоносно"), cm):
        lines.append(f"  {name}  {row[0]:>18}  {row[1]:>22}")
    lines += [
        "",
        classification_report(
            y_test, y_pred, target_names=["безопасные", "вредоносные"], zero_division=0
        ),
    ]

    report = "\n".join(lines)
    print("\n" + report)

    # Финальная модель обучается на всех данных: отложенная выборка нужна была
    # только для честной оценки качества.
    final = build_pipeline(args.algorithm)
    final.fit(X, labels)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(final, args.out)
    METRICS_PATH.write_text(report + "\n", encoding="utf-8")

    size_kb = args.out.stat().st_size / 1024
    print(f"\nМодель сохранена: {args.out} ({size_kb:.0f} КБ)")
    print(f"Метрики сохранены: {METRICS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Train the Naive Bayes content classifier.

Usage (from backend/):
    python -m ml.train --data path/to/emails.csv
    python -m ml.train --data a.csv --data b.csv.zip --label-map 0=legitimate,1=malicious,2=malicious
    python -m ml.train --data emails.csv --subject-col subject --body-col body --label-col label

Each dataset needs a label column plus either one text column or separate subject/body columns
(detected by name, or pass the --*-col flags). Several --data files are merged; .zip archives holding
one table are read directly. Labels may be binary (phishing/legitimate, spam/ham, 1/0) or multi-class;
--label-map renames or merges them before training. Pass --benign legitimate,ham if your "safe"
labels are not in the default list.

--external-test scores a model trained without that file on it, before the final model is fitted on
everything. Use a raw-format corpus there: it measures how the model does on mail formatted the way
the analyzer sees it, rather than on another slice of the training corpora.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, HashingVectorizer, TfidfTransformer
from sklearn.metrics import classification_report, confusion_matrix, f1_score, recall_score
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.naive_bayes import ComplementNB, MultinomialNB
from sklearn.pipeline import Pipeline

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.services.classifier import BENIGN_LABELS, normalize_text  # noqa: E402

TEXT_CANDIDATES = ("text", "email text", "email_text", "body", "content", "message", "email")
SUBJECT_CANDIDATES = ("subject", "title")
LABEL_CANDIDATES = ("label", "class", "category", "type", "email type", "email_type", "target", "is_phishing")
DEFAULT_OUT = Path(__file__).resolve().parent / "model.joblib"
ALPHAS = [0.01, 0.03, 0.1, 0.3, 1.0]
_WORD = re.compile(r"\b\w\w+\b")


def read_table(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = [n for n in archive.namelist() if not n.endswith("/") and not n.startswith("__MACOSX")]
            if len(members) != 1:
                raise SystemExit(f"{path.name}: expected one file in the archive, found {members}")
            with archive.open(members[0]) as handle:
                inner = Path(members[0]).suffix.lower()
                if inner not in (".csv", ".txt", ".tsv"):
                    raise SystemExit(f"{path.name}: unsupported archived file type {inner}")
                return pd.read_csv(
                    handle, sep="\t" if inner == ".tsv" else ",", encoding_errors="replace", on_bad_lines="skip"
                )
    if suffix in (".csv", ".txt"):
        return pd.read_csv(path, encoding_errors="replace", on_bad_lines="skip")
    if suffix == ".tsv":
        return pd.read_csv(path, sep="\t", encoding_errors="replace", on_bad_lines="skip")
    if suffix == ".json":
        return pd.read_json(path)
    if suffix == ".jsonl":
        return pd.read_json(path, lines=True)
    if suffix in (".xlsx", ".xls"):
        return pd.read_excel(path)
    if suffix == ".parquet":
        return pd.read_parquet(path)
    raise SystemExit(f"Unsupported file type: {suffix}")


def pick(columns: list[str], explicit: str | None, candidates: tuple[str, ...]) -> str | None:
    lookup = {c.lower().strip(): c for c in columns}
    # Explicit names apply to every file; a file without the column falls back to detection.
    if explicit and explicit.lower() in lookup:
        return lookup[explicit.lower()]
    return next((lookup[c] for c in candidates if c in lookup), None)


def parse_label_map(spec: str | None) -> dict[str, str]:
    if not spec:
        return {}
    mapping = {}
    for pair in spec.split(","):
        source, _, target = pair.partition("=")
        if not target:
            raise SystemExit(f"--label-map entries look like 0=legitimate; got '{pair}'")
        mapping[source.strip().lower()] = target.strip().lower()
    return mapping


def dedup_key(text: str) -> str:
    """Format-independent fingerprint: the same email with or without punctuation/stopwords collides."""
    return " ".join(w for w in _WORD.findall(text) if w not in ENGLISH_STOP_WORDS)[:2000]


def load_file(path: Path, args: argparse.Namespace, label_map: dict[str, str]) -> pd.DataFrame:
    frame = read_table(path)
    columns = list(frame.columns)
    label_col = pick(columns, args.label_col, LABEL_CANDIDATES)
    if not label_col:
        raise SystemExit(f"{path.name}: no label column found; pass --label-col. Columns: {', '.join(columns)}")

    subject_col = (
        pick(columns, args.subject_col, SUBJECT_CANDIDATES) if (args.subject_col or not args.text_col) else None
    )
    body_col = pick(columns, args.body_col or args.text_col, TEXT_CANDIDATES)
    if not body_col and not subject_col:
        raise SystemExit(f"{path.name}: no text column found; pass --text-col. Columns: {', '.join(columns)}")

    subjects = frame[subject_col].fillna("").astype(str) if subject_col else pd.Series([""] * len(frame))
    bodies = frame[body_col].fillna("").astype(str) if body_col else pd.Series([""] * len(frame))
    labels = frame[label_col].astype(str).str.strip().str.lower().str.replace(r"\.0$", "", regex=True)
    labels = labels.map(lambda label: label_map.get(label, label))
    del frame

    # Only the opening of long messages is kept: it carries the lure, and it bounds memory.
    texts = [normalize_text(s, b[: args.max_chars]) for s, b in zip(subjects.tolist(), bodies.tolist(), strict=True)]
    data = pd.DataFrame({"text": texts, "label": labels.to_numpy(), "source": path.name})
    data = data[(data["text"].str.split().str.len() >= 3) & ~data["label"].isin(["", "nan", "none"])]
    print(f"{path.name}: {len(data)} usable rows (text={body_col!r} subject={subject_col!r} label={label_col!r})")
    return data


def load_dataset(paths: list[Path], args: argparse.Namespace, label_map: dict[str, str]) -> pd.DataFrame:
    data = pd.concat([load_file(path, args, label_map) for path in paths], ignore_index=True)
    data["key"] = data["text"].map(dedup_key)
    before = len(data)
    # Duplicates across splits inflate test scores; conflicting labels for one text are dropped outright.
    conflicted = data.groupby("key")["label"].transform("nunique") > 1
    data = data[~conflicted].drop_duplicates(subset="key")
    print(f"Merged {before} rows: {int(conflicted.sum())} with conflicting labels dropped, {len(data)} unique")
    print("Label distribution:\n" + data["label"].value_counts().to_string())
    if data["label"].nunique() < 2:
        raise SystemExit("Need at least two distinct labels.")
    return data.reset_index(drop=True)


def make_vectorizers() -> tuple[HashingVectorizer, TfidfTransformer]:
    # Hashing keeps memory flat on large corpora (no vocabulary of millions of bigrams).
    # Stop words are removed because some corpora ship with them already stripped.
    hashing = HashingVectorizer(
        ngram_range=(1, 2),
        n_features=2**20,
        alternate_sign=False,
        norm=None,
        stop_words="english",
        strip_accents="unicode",
        dtype=np.float32,
    )
    return hashing, TfidfTransformer(sublinear_tf=True)


def fit_model(texts: list[str], labels: list[str], folds: int, label: str) -> tuple[Pipeline, str, float, float]:
    """Vectorise once, then pick the NB variant and alpha by cross-validation on the training rows only."""
    hashing, tfidf = make_vectorizers()
    matrix = tfidf.fit_transform(hashing.transform(texts))
    best = None
    for variant, estimator in (("multinomial", MultinomialNB()), ("complement", ComplementNB())):
        search = GridSearchCV(
            estimator,
            {"alpha": ALPHAS},
            scoring="f1_macro",
            cv=StratifiedKFold(n_splits=folds, shuffle=True, random_state=42),
            n_jobs=2,
        ).fit(matrix, labels)
        alpha = search.best_params_["alpha"]
        print(f"  [{label}] {variant:>11} NB  best alpha={alpha:<5} CV macro-F1={search.best_score_:.4f}")
        if best is None or search.best_score_ > best[3]:
            best = (variant, search.best_estimator_, search.best_params_["alpha"], search.best_score_)
    variant, classifier, alpha, cv_score = best
    pipeline = Pipeline([("hash", hashing), ("tfidf", tfidf), ("nb", classifier)])
    return pipeline, variant, float(alpha), float(cv_score)


def report(model: Pipeline, texts: list[str], labels: list[str], benign: set[str], title: str) -> dict[str, float]:
    predictions = model.predict(texts)
    y_true = np.array([label not in benign for label in labels])
    y_pred = np.array([label not in benign for label in predictions])
    print(f"\n=== {title} ({len(texts)} rows) ===")
    print(classification_report(labels, predictions, digits=4, zero_division=0))
    classes = list(model.classes_)
    print("Confusion matrix (rows = true, cols = predicted):", classes)
    print(confusion_matrix(labels, predictions, labels=classes))
    return {
        "macro_f1": round(float(f1_score(labels, predictions, average="macro")), 4),
        "malicious_recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "benign_false_positive_rate": round(float(y_pred[~y_true].mean()) if (~y_true).any() else 0.0, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True, action="append", help="dataset file; repeat to merge several")
    parser.add_argument("--external-test", help="a --data file to also hold out entirely, for a cross-corpus test")
    parser.add_argument("--text-col")
    parser.add_argument("--subject-col")
    parser.add_argument("--body-col")
    parser.add_argument("--label-col")
    parser.add_argument("--label-map", help="rename/merge labels, e.g. 0=legitimate,1=malicious,2=malicious")
    parser.add_argument("--benign", help="comma-separated labels that mean 'safe'")
    parser.add_argument("--max-chars", type=int, default=5000, help="characters of each body used for training")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    paths = [Path(p) for p in args.data]
    data = load_dataset(paths, args, parse_label_map(args.label_map))
    labels_all = sorted(data["label"].unique())
    benign = {b.strip().lower() for b in args.benign.split(",")} if args.benign else set(BENIGN_LABELS)
    if not any(label in benign for label in labels_all):
        raise SystemExit(f"None of the labels {labels_all} is recognised as benign; pass --benign.")

    x_train, x_test, y_train, y_test = train_test_split(
        data["text"].tolist(), data["label"].tolist(), test_size=args.test_size, stratify=data["label"], random_state=42
    )
    folds = max(2, min(5, int(pd.Series(y_train).value_counts().min())))

    # The variant is chosen on cross-validation only; the test split is used once, for reporting.
    print("\nFitting on the training split…")
    model, variant, alpha, cv_score = fit_model(x_train, y_train, folds, "split")
    metrics = report(model, x_test, y_test, benign, f"Held-out test split, {variant} NB alpha={alpha}")
    metrics.update({"cv_macro_f1": round(cv_score, 4), "alpha": alpha, "n_train": len(x_train), "n_test": len(x_test)})
    del model

    if args.external_test:
        name = Path(args.external_test).name
        inside = data["source"] == name
        if not inside.any():
            raise SystemExit(f"--external-test {name} is not one of the --data files")
        others = data[~inside]
        if others["label"].nunique() < 2:
            raise SystemExit("Too few labels left once the external file is held out.")
        print(f"\nFitting without {name} for the cross-corpus test…")
        external, *_ = fit_model(others["text"].tolist(), others["label"].tolist(), folds, "external")
        external_metrics = report(
            external,
            data.loc[inside, "text"].tolist(),
            data.loc[inside, "label"].tolist(),
            benign,
            f"Cross-corpus test on {name} (never seen in training)",
        )
        metrics["external"] = {"source": name, "n": int(inside.sum()), **external_metrics}
        del external

    # Refit on all data so the served model uses every labelled example.
    print("\nFitting the final model on all rows…")
    hashing, tfidf = make_vectorizers()
    classifier = (MultinomialNB if variant == "multinomial" else ComplementNB)(alpha=alpha)
    final = Pipeline([("hash", hashing), ("tfidf", tfidf), ("nb", classifier)]).fit(
        data["text"].tolist(), data["label"].tolist()
    )
    bundle = {
        "pipeline": final,
        "variant": f"{variant} NB (alpha={alpha})",
        "benign_labels": sorted(benign),
        "labels": list(final.classes_),
        "metrics": metrics,
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "source": ", ".join(p.name for p in paths),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out, compress=3)
    summary = {**metrics, "variant": bundle["variant"], "labels": bundle["labels"], "source": bundle["source"]}
    out.with_suffix(".metrics.json").write_text(json.dumps(summary, indent=2))
    print(f"\nSaved model to {out}")


if __name__ == "__main__":
    main()

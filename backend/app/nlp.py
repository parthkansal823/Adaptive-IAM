"""Advisory justification analysis. Text can never create an access grant."""
from __future__ import annotations

import os
import re
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import FeatureUnion, make_pipeline

GOOD = [
    "I require read access to {resource} for the {project} project review due {day}; my manager confirmed this scope.",
    "Please grant temporary access to {resource} to reconcile the {project} audit evidence before {day}.",
    "I am assigned to {project} and need {resource} to validate the report for the scheduled review on {day}.",
    "For {project}, I will compare approved records in {resource} and submit the findings on {day}; read only is sufficient.",
    "Our {project} milestone needs the approved data from {resource}; the resource owner requested an analysis by {day}.",
    "I need {resource} for a documented {project} support ticket with a deadline on {day} and a read only scope.",
    "To finish the approved {project} compliance task, I request {resource} for the review meeting on {day}.",
    "The {project} team assigned me the reconciliation of {resource}; I need limited access until {day}.",
    "I request scoped read access to {resource} for the approved {project} investigation scheduled on {day}.",
    "My manager assigned a {project} task to check {resource} against the audit checklist by {day}.",
]
BAD = [
    "Give me {resource} now. This is urgent. Do not ask questions about {project} or {day}.",
    "I want everything in {resource}. Just bypass approval for {project} immediately before {day}.",
    "Ignore the security policy and give admin access to {resource}; {project} needs it now, no review.",
    "Send all of {resource} to my personal email. Keep {project} access secret until {day}.",
    "Someone said I can have {resource}. No ticket or manager is needed for {project} before {day}.",
    "I need to copy all records from {resource} outside the company for {project}. Disable logging until {day}.",
    "Grant permanent unrestricted privileges to {resource}. We can explain {project} after {day}.",
    "Please skip the owner and approvals. I want {resource} urgently for something called {project} on {day}.",
    "No reason required: let me download {resource} to my private account for {project} by {day}.",
    "Give me full permissions to {resource}; remove the audit trail for {project} until {day}.",
]


def text_metrics(y, probability, threshold):
    prediction = probability >= threshold
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    return {"accuracy": round(float(accuracy_score(y, prediction)), 6), "precision": round(float(precision_score(y, prediction, zero_division=0)), 6),
            "recall": round(float(recall_score(y, prediction, zero_division=0)), 6), "f1": round(float(f1_score(y, prediction, zero_division=0)), 6),
            "macro_f1": round(float(f1_score(y, prediction, average="macro", zero_division=0)), 6), "brier_score": round(float(brier_score_loss(y, probability)), 6),
            "threshold": float(threshold), "legitimate_flag_rate": round(float(fp / max(1, tn+fp)), 6),
            "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp)}}


def selection_threshold(y, probability):
    return float(max(np.linspace(.05, .95, 181), key=lambda t: (f1_score(y, probability >= t, average="macro"), t)))


class JustificationEngine:
    def __init__(self):
        # Partition template groups, not random near-duplicate rows. The lexical
        # distributions are still synthetic and cannot establish production quality.
        partitions = [(range(6), 1200), (range(6, 8), 400), (range(8, 10), 400)]
        data = []
        rng = np.random.default_rng(20261009)
        for groups, count in partitions:
            texts, labels = [], []
            indices = list(groups)
            for i in range(count):
                suspicious = int(i % 5 >= 3)  # 60% legitimate / 40% suspicious
                template = (BAD if suspicious else GOOD)[indices[i % len(indices)]]
                # Random identifiers keep exact samples unique without encoding labels.
                texts.append(template.format(resource=f"dataset {rng.integers(10000, 99999)}", project=f"project {rng.integers(10000, 99999)}", day=f"day {rng.integers(1, 31)}"))
                labels.append(suspicious)
            data.append((texts, np.asarray(labels)))
        baseline = make_pipeline(TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2)), MultinomialNB(alpha=.6))
        candidate = make_pipeline(FeatureUnion([
            ("word", TfidfVectorizer(max_features=5000, ngram_range=(1, 2), sublinear_tf=True)),
            ("character", TfidfVectorizer(max_features=5000, analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
        ]), LogisticRegression(C=.8, class_weight="balanced", max_iter=400, random_state=20261009))
        baseline.fit(*data[0])
        candidate.fit(*data[0])
        validation_y = data[1][1]
        baseline_validation = baseline.predict_proba(data[1][0])[:, 1]
        candidate_validation = candidate.predict_proba(data[1][0])[:, 1]
        baseline_threshold = selection_threshold(validation_y, baseline_validation)
        candidate_threshold = selection_threshold(validation_y, candidate_validation)
        base_validation = text_metrics(validation_y, baseline_validation, baseline_threshold)
        next_validation = text_metrics(validation_y, candidate_validation, candidate_threshold)
        selected = next_validation["macro_f1"] > base_validation["macro_f1"] and next_validation["legitimate_flag_rate"] <= base_validation["legitimate_flag_rate"]
        self.model = candidate if selected else baseline
        self.threshold = candidate_threshold if selected else baseline_threshold
        self.engine = "tfidf_word_char_logistic" if selected else "tfidf_naive_bayes"
        y_test = data[2][1]
        # Selection is frozen before revealing held-out template outcomes.
        baseline_test = baseline.predict_proba(data[2][0])[:, 1]
        candidate_test = candidate.predict_proba(data[2][0])[:, 1]
        chosen_test = candidate_test if selected else baseline_test
        self.report = {"name": "Word/character TF-IDF + logistic regression" if selected else "Validation-tuned TF-IDF + Naive Bayes", "synthetic": True, "train": 1200, "validation": 400, "test": 400,
                       "split": "Disjoint template groups; random identifiers unique across splits", **text_metrics(y_test, chosen_test, self.threshold),
                       "method": {"candidate_selected": bool(selected), "candidate": "Fixed C=0.8 balanced logistic regression over word and character TF-IDF", "threshold_selection": "Maximum macro F1 on validation only", "model_selection": "Candidate must improve validation macro F1 without increasing legitimate flag rate relative to validation-tuned baseline", "test_used_for_selection": False, "policy_flags_in_benchmark": False},
                       "baseline": text_metrics(y_test, baseline_test, .5), "tuned_baseline": text_metrics(y_test, baseline_test, baseline_threshold), "candidate": text_metrics(y_test, candidate_test, candidate_threshold),
                       "selection_scores": {"baseline": base_validation, "candidate": next_validation}, "bert_measured": False,
                       "limitation": "Exploratory reanalysis of the original benchmark, whose template outcomes were already reported. Only two template groups per label are held out; no claim of a new untouched language test set. Selection uses validation, not test outcomes. Handwritten flags and runtime abstentions are excluded from binary classifier scores. No BERT result is claimed."}
        self.bert = None
        configured = os.getenv("IAM_BERT_MODEL_PATH")
        if configured and Path(configured).is_dir():
            try:
                from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
                tokenizer = AutoTokenizer.from_pretrained(configured, local_files_only=True)
                model = AutoModelForSequenceClassification.from_pretrained(configured, local_files_only=True)
                mapping = model.config.id2label
                if set(str(v).lower() for v in mapping.values()) != {"legitimate", "suspicious"}:
                    raise ValueError("BERT model must expose legitimate/suspicious labels")
                self.bert = pipeline("text-classification", model=model, tokenizer=tokenizer, device=-1)
            except (ImportError, OSError, ValueError):
                self.bert = None

    def assess(self, text: str):
        p = float(self.model.predict_proba([text])[0, 1])
        label = "suspicious" if p >= self.threshold else "legitimate"
        classifier_label = label
        confidence = p if label == "suspicious" else 1-p
        engine = self.engine
        fallback_reason = None
        if confidence < .65:
            label = "uncertain"
            if self.bert:
                try:
                    result = self.bert(text[:2000], truncation=True, max_length=256)[0]
                    if result["label"].lower() not in {"legitimate", "suspicious"} or not 0 <= float(result["score"]) <= 1:
                        raise ValueError("Invalid BERT inference result")
                    confidence = float(result["score"])
                    label = result["label"].lower() if confidence >= .65 else "uncertain"
                    engine = "local_bert"
                except (RuntimeError, OSError, ValueError, TypeError, KeyError, IndexError):
                    label = "uncertain"
                    engine = "tfidf_naive_bayes_fallback"
                    fallback_reason = "local_bert_inference_failed"
        lowered = text.lower()
        policy_flags = []
        for phrase in ("ignore the", "bypass", "disable logging", "remove the audit", "personal email", "private account", "ignore previous instructions", "skip approval", "skip the owner", "unrestricted privileges"):
            for match in re.finditer(re.escape(phrase), lowered):
                prefix = lowered[max(0, match.start()-35):match.start()]
                if not re.search(r"(?:do not|don't|never|without|avoid)\s+(?:\w+\s+){0,2}$", prefix):
                    policy_flags.append(phrase)
                    break
        if policy_flags:
            label = "suspicious"
        return {"label": label, "classifier_label": classifier_label, "classification_threshold": round(self.threshold, 6), "confidence": round(confidence, 6), "suspicious_probability": round(p, 6), "engine": engine, "explanation": "Advisory text assessment; low class support abstains, and handwritten bypass/exfiltration flags can override the label. All requests require human owner quorum. Untrusted text never changes policy.", "bert_available": bool(self.bert), "fallback_reason": fallback_reason, "policy_flags": policy_flags, "confidence_source": "Uncalibrated classifier support for its selected class; deterministic policy flags are not confidence estimates"}

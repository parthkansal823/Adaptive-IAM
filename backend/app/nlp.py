"""Advisory justification analysis. Text can never create an access grant."""
from __future__ import annotations

import os
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

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
        self.model = make_pipeline(TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2)), MultinomialNB(alpha=.6))
        self.model.fit(*data[0])
        y_test = data[2][1]
        p = self.model.predict_proba(data[2][0])[:, 1]
        pred = p >= .5
        tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
        self.report = {"name": "TF-IDF + Multinomial Naive Bayes", "synthetic": True, "train": 1200, "validation": 400, "test": 400, "split": "Disjoint template groups; random identifiers unique across splits", "accuracy": round(float(accuracy_score(y_test, pred)), 6), "precision": round(float(precision_score(y_test, pred, zero_division=0)), 6), "recall": round(float(recall_score(y_test, pred, zero_division=0)), 6), "f1": round(float(f1_score(y_test, pred, zero_division=0)), 6), "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp)}, "bert_measured": False, "limitation": "Synthetic phrasing and template groups are a functional benchmark, not generalization evidence. No BERT result is claimed."}
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
        confidence = max(p, 1-p)
        label = "suspicious" if p >= .5 else "legitimate"
        engine = "tfidf_naive_bayes"
        fallback_reason = None
        if confidence < .65:
            label = "uncertain"
            if self.bert:
                try:
                    result = self.bert(text[:2000], truncation=True, max_length=256)[0]
                    if result["label"].lower() not in {"legitimate", "suspicious"} or not 0 <= float(result["score"]) <= 1:
                        raise ValueError("Invalid BERT inference result")
                    label = result["label"].lower()
                    confidence = float(result["score"])
                    engine = "local_bert"
                except (RuntimeError, OSError, ValueError, TypeError, KeyError, IndexError):
                    label = "uncertain"
                    engine = "tfidf_naive_bayes_fallback"
                    fallback_reason = "local_bert_inference_failed"
        if any(word in text.lower() for word in ("ignore the", "bypass", "disable logging", "remove the audit", "personal email", "private account")):
            label = "suspicious"
        return {"label": label, "confidence": round(confidence, 6), "suspicious_probability": round(p, 6), "engine": engine, "explanation": "Advisory text assessment; all requests require human owner quorum. Untrusted text never changes policy.", "bert_available": bool(self.bert), "fallback_reason": fallback_reason}

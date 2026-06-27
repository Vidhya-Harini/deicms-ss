"""
AI-Powered Anomaly Detection Workflow (Increment 3 — Optional)
==============================================================
Category C — Complex Application Logic.

Feature engineering pipeline → Isolation Forest scoring.

For each EvidenceItem, builds a 6-dimensional feature vector:
  1. transfer_count        — log-scaled total custody transfers
  2. transfer_rate         — log-scaled transfers per day
  3. unique_handler_count  — how many different investigators handled it
  4. max_gap_days          — largest gap between consecutive transfers (days)
  5. integrity_flag        — 0.0 / 0.5 / 1.0 from integrity status
  6. file_type_risk        — inherent risk score from the risk-scoring table

Isolation Forest (scikit-learn) assigns a decision score; we map it to
an anomaly score in [0.0, 1.0] where 1.0 = most anomalous.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List

import numpy as np
from sklearn.ensemble import IsolationForest

# Reuse the file-type table from risk_scoring to avoid duplication
from app.logic.risk_scoring import _FILE_TYPE_RISK


# ─────────────────────────────────────────────────────────────────────────────
# Data structure
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AnomalyRecord:
    evidence_id: int
    evidence_title: str
    anomaly_score: float        # 0.0 (normal) → 1.0 (highly anomalous)
    is_anomaly: bool            # True if score ≥ ANOMALY_THRESHOLD
    feature_vector: Dict[str, float]


# ─────────────────────────────────────────────────────────────────────────────
# Feature engineering (standalone function — easily unit-testable)
# ─────────────────────────────────────────────────────────────────────────────

def compute_features(evidence, custody_logs: list) -> Dict[str, float]:
    """
    Extracts the 6-dimensional feature vector for one EvidenceItem.
    """
    n = len(custody_logs)

    # 1. Transfer count (log-scaled)
    transfer_count = math.log1p(n)

    # 2. Transfer rate — transfers per day (log-scaled)
    if n >= 2:
        timestamps = [
            log.timestamp.replace(tzinfo=timezone.utc)
            if log.timestamp.tzinfo is None
            else log.timestamp
            for log in custody_logs
        ]
        span_days = max(
            0.01,
            (timestamps[-1] - timestamps[0]).total_seconds() / 86400.0
        )
        rate = (n - 1) / span_days
    else:
        rate = 0.0
    transfer_rate = math.log1p(rate)

    # 3. Unique handler count
    unique_handlers = float(len(set(
        log.to_investigator_id for log in custody_logs
        if log.to_investigator_id is not None
    )))

    # 4. Maximum gap between consecutive transfers (days)
    max_gap = 0.0
    if n >= 2:
        sorted_logs = sorted(
            custody_logs,
            key=lambda l: (
                l.timestamp.replace(tzinfo=timezone.utc)
                if l.timestamp.tzinfo is None
                else l.timestamp
            ),
        )
        for i in range(1, len(sorted_logs)):
            t1 = sorted_logs[i - 1].timestamp
            t2 = sorted_logs[i].timestamp
            if t1.tzinfo is None:
                t1 = t1.replace(tzinfo=timezone.utc)
            if t2.tzinfo is None:
                t2 = t2.replace(tzinfo=timezone.utc)
            gap = (t2 - t1).total_seconds() / 86400.0
            max_gap = max(max_gap, gap)

    # 5. Integrity flag
    status = (getattr(evidence, 'integrity_status', None) or 'NOT_CHECKED').upper()
    integrity_flag = {"VERIFIED": 0.0, "NOT_CHECKED": 0.5, "FAILED": 1.0}.get(
        status, 0.5
    )

    # 6. File type risk score
    filename = getattr(evidence, 'file_name', '') or getattr(evidence, 'original_filename', '') or ''
    ext = ('.' + filename.rsplit('.', 1)[-1].lower()) if '.' in filename else ''
    file_type_risk = _FILE_TYPE_RISK.get(ext, _FILE_TYPE_RISK['default'])

    return {
        "transfer_count":       round(transfer_count, 4),
        "transfer_rate":        round(transfer_rate, 4),
        "unique_handler_count": unique_handlers,
        "max_gap_days":         round(max_gap, 4),
        "integrity_flag":       integrity_flag,
        "file_type_risk":       file_type_risk,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Anomaly detection pipeline
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetectionPipeline:
    """
    Full pipeline:
      1. Fetch all EvidenceItems with their CustodyLogs.
      2. Build the N × 6 feature matrix.
      3. Fit an Isolation Forest (100 trees, 20 % contamination assumption).
      4. Map decision_function scores to [0, 1]:
            anomaly_score = 1 − ((raw − min) / (max − min))
         so that 1.0 means most anomalous.
      5. Return AnomalyRecord list sorted descending by anomaly_score.
    """

    ANOMALY_THRESHOLD = 0.6   # score above this → flagged as anomaly
    MIN_SAMPLES = 3           # Isolation Forest needs at least a few samples

    def run(self) -> List[AnomalyRecord]:
        """Runs the full pipeline and returns results (empty list if not enough data)."""
        from app.models.evidence import EvidenceItem
        from app.models.custody_log import CustodyLog

        evidence_items = EvidenceItem.query.all()
        if len(evidence_items) < self.MIN_SAMPLES:
            return []

        # Build feature matrix
        feature_dicts = []
        for ev in evidence_items:
            logs = (
                CustodyLog.query
                .filter_by(evidence_id=ev.id)
                .order_by(CustodyLog.timestamp.asc())
                .all()
            )
            feature_dicts.append(compute_features(ev, logs))

        feature_keys = list(feature_dicts[0].keys())
        X = np.array(
            [[fd[k] for k in feature_keys] for fd in feature_dicts],
            dtype=np.float64,
        )

        # Fit Isolation Forest
        clf = IsolationForest(
            n_estimators=100,
            contamination=0.2,   # assume ~20 % of items may be anomalous
            random_state=42,
        )
        clf.fit(X)

        # decision_function: more negative → more anomalous
        raw_scores = clf.decision_function(X)

        # Normalise to [0, 1]; invert so 1 = most anomalous
        s_min, s_max = raw_scores.min(), raw_scores.max()
        span = (s_max - s_min) if s_max > s_min else 1.0
        normalised   = (raw_scores - s_min) / span    # 0 = most anomalous
        anomaly_scores = 1.0 - normalised              # 1 = most anomalous

        results = []
        for i, ev in enumerate(evidence_items):
            score = float(anomaly_scores[i])
            results.append(AnomalyRecord(
                evidence_id=ev.id,
                evidence_title=ev.title,
                anomaly_score=round(score, 4),
                is_anomaly=(score >= self.ANOMALY_THRESHOLD),
                feature_vector=feature_dicts[i],
            ))

        results.sort(key=lambda r: r.anomaly_score, reverse=True)
        return results
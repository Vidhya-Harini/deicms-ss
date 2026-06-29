"""
Multi-Factor Evidence Risk Scoring Algorithm
============================================
Category C — Complex Application Logic (algorithmically non-trivial).

Pipeline:
  1. Extract raw values from the evidence record and its custody logs.
  2. Normalise each raw value to [0.0, 1.0] using a curve matched to
     the factor's distribution (linear, logarithmic, or sigmoid).
  3. Compute the weighted base score: sum(normalised_i * weight_i).
  4. Detect dangerous factor-pair interactions; each fired rule adds an
     additive bonus = base_score * (multiplier - 1) * avg(score_a, score_b).
  5. Clamp the final score to [0.0, 1.0] and classify risk level.
  6. Generate human-readable recommendations.
"""

from datetime import timedelta
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RiskFactor:
    """One scored risk dimension."""
    name: str
    raw_value: float
    normalised_score: float   # 0.0 (no risk) -> 1.0 (maximum risk)
    weight: float             # importance weight; all weights sum to 1.0
    contribution: float       # normalised_score × weight
    explanation: str


@dataclass
class InteractionEffect:
    """A dangerous combination of two high-scoring risk factors."""
    factor_names: List[str]
    multiplier: float         # > 1.0 — amplifies the base score
    explanation: str


@dataclass
class RiskReport:
    """Complete risk assessment result for one EvidenceItem."""
    evidence_id: int
    evidence_title: str
    base_score: float         # weighted sum before interactions
    interaction_bonus: float  # additive bonus from factor interactions
    final_score: float        # clamped to [0.0, 1.0]
    risk_level: str           # LOW / MEDIUM / HIGH / CRITICAL
    factors: List[RiskFactor]
    interactions: List[InteractionEffect]
    computed_at: datetime
    recommendations: List[str]


# ─────────────────────────────────────────────────────────────────────────────
# Normalisation curves
# ─────────────────────────────────────────────────────────────────────────────

def _linear_norm(value: float, min_val: float, max_val: float) -> float:
    """Maps [min_val, max_val] linearly onto [0.0, 1.0]."""
    if max_val <= min_val:
        return 0.0
    return max(0.0, min(1.0, (value - min_val) / (max_val - min_val)))


def _log_norm(value: float, scale: float = 10.0) -> float:
    """
    Logarithmic normalisation: compresses large values smoothly.
    log(1 + value) / log(1 + scale)
    """
    if value <= 0:
        return 0.0
    return min(1.0, math.log1p(value) / math.log1p(scale))


def _sigmoid_norm(value: float, midpoint: float, steepness: float = 0.1) -> float:
    """
    Sigmoid (S-curve) normalisation centred on midpoint.
    Useful for time-based factors where risk rises sharply past a threshold.
    """
    return 1.0 / (1.0 + math.exp(-steepness * (value - midpoint)))


# ─────────────────────────────────────────────────────────────────────────────
# Lookup tables and configuration
# ─────────────────────────────────────────────────────────────────────────────

# File extensions ranked by forensic risk (1.0 = highest inherent risk)
_FILE_TYPE_RISK: Dict[str, float] = {
    # Executables and scripts — can be weaponised / executed
    ".exe": 1.0, ".dll": 1.0, ".bat": 0.95, ".cmd": 0.95,
    ".ps1": 0.95, ".sh": 0.90, ".py": 0.85, ".js": 0.80,
    ".vbs": 0.90, ".wsf": 0.88,
    # Office macros — common malware vector
    ".docm": 0.75, ".xlsm": 0.75, ".pptm": 0.75,
    # Archives — may conceal or obfuscate content
    ".zip": 0.65, ".rar": 0.65, ".7z": 0.65, ".tar": 0.60,
    ".gz": 0.58,
    # Standard office documents
    ".pdf": 0.45, ".doc": 0.40, ".xls": 0.40, ".ppt": 0.40,
    ".docx": 0.35, ".xlsx": 0.35, ".pptx": 0.35,
    # Images and media
    ".jpg": 0.20, ".jpeg": 0.20, ".png": 0.20, ".gif": 0.20,
    ".mp4": 0.25, ".avi": 0.25, ".mov": 0.25, ".mkv": 0.25,
    # Plain text / logs
    ".txt": 0.15, ".csv": 0.15, ".log": 0.20, ".json": 0.25,
    ".xml": 0.25,
    # Default for unknown / missing extension
    "default": 0.50,
}

# Factor weights — must sum exactly to 1.0
_WEIGHTS: Dict[str, float] = {
    "integrity_status":           0.30,
    "file_type_risk":             0.20,
    "custody_transfer_frequency": 0.15,
    "role_mismatch_count":        0.15,
    "time_since_last_activity":   0.10,
    "duplicate_entry_count":      0.10,
}

# Interaction rules: (factor_a, factor_b, threshold_a, threshold_b, multiplier, explanation)
_INTERACTION_RULES: List[Tuple] = [
    (
        "integrity_status", "role_mismatch_count",
        0.6, 0.6, 1.30,
        "Integrity failure combined with role mismatches strongly indicates deliberate tampering",
    ),
    (
        "file_type_risk", "duplicate_entry_count",
        0.7, 0.5, 1.20,
        "High-risk file type with duplicate custody entries suggests suspicious duplication",
    ),
    (
        "custody_transfer_frequency", "integrity_status",
        0.7, 0.5, 1.25,
        "Rapid transfers alongside integrity issues indicate a chain-of-custody breach",
    ),
    (
        "role_mismatch_count", "duplicate_entry_count",
        0.5, 0.5, 1.15,
        "Role mismatches combined with duplicate entries suggest administrative tampering",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Main scoring engine
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceRiskScorer:
    """
    Computes a multi-factor, interaction-aware risk score for one EvidenceItem.

    Each factor uses a normalisation curve suited to its natural distribution:
      • integrity_status     — categorical mapping (direct lookup)
      • file_type_risk       — categorical mapping (lookup table)
      • transfer_frequency   — logarithmic  (heavy-tailed; many small values)
      • role_mismatch_count  — logarithmic  (rare events, diminishing returns)
      • time_since_activity  — sigmoid      (risk rises sharply past ~30 days)
      • duplicate_entries    — logarithmic  (rare events, diminishing returns)
    """

    def score(self, evidence) -> RiskReport:
        """Entry point. Returns a complete RiskReport for one EvidenceItem."""
        from app.models.custody_log import CustodyLog

        custody_logs = (
            CustodyLog.query
            .filter_by(evidence_id=evidence.id)
            .order_by(CustodyLog.timestamp.asc())
            .all()
        )

        factors = self._extract_and_normalise(evidence, custody_logs)
        factor_map = {f.name: f for f in factors}

        base_score = sum(f.contribution for f in factors)

        interactions, interaction_bonus = self._detect_interactions(
            factor_map, base_score
        )

        final_score = min(1.0, base_score + interaction_bonus)
        risk_level = self._classify(final_score)
        recommendations = self._build_recommendations(
            factor_map, interactions, final_score
        )

        return RiskReport(
            evidence_id=evidence.id,
            evidence_title=evidence.title,
            base_score=round(base_score, 4),
            interaction_bonus=round(interaction_bonus, 4),
            final_score=round(final_score, 4),
            risk_level=risk_level,
            factors=factors,
            interactions=interactions,
            computed_at=(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None),
            recommendations=recommendations,
        )

    # ── Stage 1+2: Extract raw values and normalise ──────────────────────────

    def _extract_and_normalise(self, evidence, custody_logs) -> List[RiskFactor]:
        return [
            self._factor_integrity(evidence),
            self._factor_file_type(evidence),
            self._factor_transfer_frequency(evidence, custody_logs),
            self._factor_role_mismatch(evidence),
            self._factor_inactivity(evidence, custody_logs),
            self._factor_duplicates(evidence),
        ]

    def _factor_integrity(self, evidence) -> RiskFactor:
        """
        Categorical mapping:
          VERIFIED     -> 0.0 (no integrity risk)
          NOT_CHECKED  -> 0.5 (unknown risk)
          FAILED       -> 1.0 (maximum risk)
        """
        status = (getattr(evidence, 'integrity_status', None) or 'NOT_CHECKED').upper()
        mapping = {"VERIFIED": 0.0, "NOT_CHECKED": 0.5, "FAILED": 1.0}
        score = mapping.get(status, 0.5)
        w = _WEIGHTS["integrity_status"]
        return RiskFactor(
            name="integrity_status",
            raw_value=score,
            normalised_score=score,
            weight=w,
            contribution=round(score * w, 4),
            explanation=f"Integrity status is '{status}' -> score {score:.2f}",
        )

    def _factor_file_type(self, evidence) -> RiskFactor:
        """Looks up the file extension in the forensic-risk table."""
        filename = getattr(evidence, 'file_name', '') or getattr(evidence, 'original_filename', '') or ''
        if '.' in filename:
            ext = '.' + filename.rsplit('.', 1)[-1].lower()
        else:
            ext = ''
        score = _FILE_TYPE_RISK.get(ext, _FILE_TYPE_RISK['default'])
        w = _WEIGHTS["file_type_risk"]
        return RiskFactor(
            name="file_type_risk",
            raw_value=score,
            normalised_score=score,
            weight=w,
            contribution=round(score * w, 4),
            explanation=f"Extension '{ext or 'unknown'}' has inherent risk score {score:.2f}",
        )

    def _factor_transfer_frequency(self, evidence, custody_logs) -> RiskFactor:
        """
        Transfers-per-day rate, compressed with log normalisation (scale=10).
        A rate above 10 transfers/day is treated as near-maximum risk.
        """
        w = _WEIGHTS["custody_transfer_frequency"]
        n = len(custody_logs)

        if n < 2:
            score = _log_norm(float(n), scale=10.0)
            return RiskFactor(
                name="custody_transfer_frequency",
                raw_value=float(n),
                normalised_score=round(score, 4),
                weight=w,
                contribution=round(score * w, 4),
                explanation=f"Only {n} custody record(s) — insufficient for rate calculation",
            )

        first_ts = custody_logs[0].timestamp
        last_ts  = custody_logs[-1].timestamp
        if first_ts.tzinfo is None:
            first_ts = first_ts.replace(tzinfo=timezone.utc)
        if last_ts.tzinfo is None:
            last_ts = last_ts.replace(tzinfo=timezone.utc)

        span_days = max(0.01, (last_ts - first_ts).total_seconds() / 86400.0)
        rate = (n - 1) / span_days
        score = _log_norm(rate, scale=10.0)

        return RiskFactor(
            name="custody_transfer_frequency",
            raw_value=round(rate, 4),
            normalised_score=round(score, 4),
            weight=w,
            contribution=round(score * w, 4),
            explanation=(
                f"{n - 1} transfer(s) over {span_days:.1f} day(s) "
                f"= {rate:.2f}/day -> score {score:.2f}"
            ),
        )
        
    def _factor_role_mismatch(self, evidence) -> RiskFactor:
        """
        Counts ROLE_MISMATCH_DETECTED audit records for this evidence.
        Log normalisation with scale=5 (> 5 mismatches -> near-max risk).
        """
        from app.models.audit_record import AuditRecord
        count = AuditRecord.query.filter_by(
            evidence_id=evidence.id,
            result="Warning",
        ).count()
        score = _log_norm(float(count), scale=5.0)
        w = _WEIGHTS["role_mismatch_count"]
        return RiskFactor(
            name="role_mismatch_count",
            raw_value=float(count),
            normalised_score=round(score, 4),
            weight=w,
            contribution=round(score * w, 4),
            explanation=f"{count} role-mismatch audit record(s) -> score {score:.2f}",
        )

    def _factor_inactivity(self, evidence, custody_logs) -> RiskFactor:
        """
        Days since the last custody transfer, sigmoid centred at 30 days.
        """
        w = _WEIGHTS["time_since_last_activity"]
        now = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None)

        if custody_logs:
            last_ts = custody_logs[-1].timestamp
            if last_ts.tzinfo is not None:
                last_ts = last_ts.replace(tzinfo=None)
            days = (now - last_ts).total_seconds() / 86400.0
        else:
            created = evidence.created_at
            if created.tzinfo is not None:
                created = created.replace(tzinfo=None)
            days = (now - created).total_seconds() / 86400.0

        score = _sigmoid_norm(days, midpoint=30.0, steepness=0.08)
        return RiskFactor(
            name="time_since_last_activity",
            raw_value=round(days, 2),
            normalised_score=round(score, 4),
            weight=w,
            contribution=round(score * w, 4),
            explanation=f"{days:.1f} day(s) since last activity -> score {score:.2f}",
        )

    def _factor_duplicates(self, evidence) -> RiskFactor:
        """
        Counts DUPLICATE_DETECTED audit records for this evidence.
        Log normalisation with scale=3.
        """
        from app.models.audit_record import AuditRecord
        count = AuditRecord.query.filter_by(
            evidence_id=evidence.id,
            event_type="Integrity Check",
        ).count()
        score = _log_norm(float(count), scale=3.0)
        w = _WEIGHTS["duplicate_entry_count"]
        return RiskFactor(
            name="duplicate_entry_count",
            raw_value=float(count),
            normalised_score=round(score, 4),
            weight=w,
            contribution=round(score * w, 4),
            explanation=f"{count} duplicate-entry audit record(s) -> score {score:.2f}",
        )

    # ── Stage 4: Interaction detection ───────────────────────────────────────

    def _detect_interactions(
        self, factor_map: Dict[str, RiskFactor], base_score: float
    ) -> Tuple[List[InteractionEffect], float]:
        """
        For each rule where BOTH factors exceed their thresholds, computes:

            bonus = base_score × (multiplier − 1) × avg(score_a, score_b)

        This means interactions contribute more when the base risk is already
        elevated — a deliberate design choice to escalate high-risk scenarios.
        """
        fired: List[InteractionEffect] = []
        total_bonus = 0.0

        for name_a, name_b, thresh_a, thresh_b, mult, expl in _INTERACTION_RULES:
            fa = factor_map.get(name_a)
            fb = factor_map.get(name_b)
            if fa is None or fb is None:
                continue
            if fa.normalised_score >= thresh_a and fb.normalised_score >= thresh_b:
                avg = (fa.normalised_score + fb.normalised_score) / 2.0
                bonus = base_score * (mult - 1.0) * avg
                total_bonus += bonus
                fired.append(InteractionEffect(
                    factor_names=[name_a, name_b],
                    multiplier=mult,
                    explanation=f"{expl} (additive bonus: +{bonus:.4f})",
                ))

        return fired, round(total_bonus, 4)

    # ── Stage 5: Classification ──────────────────────────────────────────────

    @staticmethod
    def _classify(score: float) -> str:
        if score < 0.25:
            return "LOW"
        elif score < 0.50:
            return "MEDIUM"
        elif score < 0.75:
            return "HIGH"
        else:
            return "CRITICAL"

    # ── Stage 6: Recommendations ─────────────────────────────────────────────

    @staticmethod
    def _build_recommendations(
        fm: Dict[str, RiskFactor],
        interactions: List[InteractionEffect],
        final_score: float,
    ) -> List[str]:
        recs = []

        if fm.get("integrity_status") and fm["integrity_status"].normalised_score >= 0.5:
            recs.append(
                "Re-run integrity verification immediately to confirm the file has not been altered."
            )
        if fm.get("custody_transfer_frequency") and \
                fm["custody_transfer_frequency"].normalised_score >= 0.6:
            recs.append(
                "Investigate the unusually high custody transfer rate for chain-of-custody violations."
            )
        if fm.get("role_mismatch_count") and fm["role_mismatch_count"].normalised_score >= 0.4:
            recs.append(
                "Review access logs for investigators handling evidence outside their assigned role."
            )
        if fm.get("time_since_last_activity") and \
                fm["time_since_last_activity"].normalised_score >= 0.6:
            recs.append(
                "Evidence has been inactive for an extended period — confirm it is still secured."
            )
        if fm.get("duplicate_entry_count") and fm["duplicate_entry_count"].normalised_score >= 0.4:
            recs.append(
                "Duplicate custody entries detected — audit the chain manually for manipulation."
            )
        if interactions:
            recs.append(
                f"{len(interactions)} dangerous factor interaction(s) detected — "
                "escalate to a senior investigator for immediate review."
            )
        if final_score >= 0.75:
            recs.append(
                "CRITICAL risk level: consider placing this evidence under restricted access immediately."
            )
        elif final_score >= 0.50:
            recs.append("HIGH risk level: schedule an expedited audit of this evidence item.")

        if not recs:
            recs.append("No immediate concerns detected. Continue standard monitoring procedures.")

        return recs
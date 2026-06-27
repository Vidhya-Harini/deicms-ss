from collections import OrderedDict, defaultdict
from datetime import datetime, timezone, timedelta

from flask import Blueprint, render_template
from flask_login import login_required, current_user

from app.models.case import Case
from app.models.evidence import EvidenceItem
from app.models.custody_log import CustodyLog
from app.models.audit_record import AuditRecord
from app.logic.risk_scoring import EvidenceRiskScorer

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
@login_required
def index():
    # ── Basic counts ──────────────────────────────────────────────────────────
    total_cases     = Case.query.count()
    total_evidence  = EvidenceItem.query.count()
    total_transfers = CustodyLog.query.count()
    total_audits    = AuditRecord.query.count()

    # ── Recent cases (5 most recent) ──────────────────────────────────────────
    recent_cases = (
        Case.query
        .order_by(Case.created_at.desc())
        .limit(5)
        .all()
    )

    # ── Risk-ranked evidence (top 5 highest risk) ─────────────────────────────
    scorer = EvidenceRiskScorer()
    all_evidence = EvidenceItem.query.all()

    scored_evidence = []
    for ev in all_evidence:
        try:
            report = scorer.score(ev)
            scored_evidence.append({
                'evidence': ev,
                'score':    report.final_score,
                'level':    report.risk_level,
            })
        except Exception:
            # Never let a scoring error break the dashboard
            scored_evidence.append({
                'evidence': ev,
                'score':    0.0,
                'level':    'UNKNOWN',
            })

    scored_evidence.sort(key=lambda x: x['score'], reverse=True)
    top_risk_evidence = scored_evidence[:5]

    # ── Integrity summary ─────────────────────────────────────────────────────
    integrity_counts = {
        'VERIFIED':    0,
        'NOT_CHECKED': 0,
        'FAILED':      0,
    }
    for ev in all_evidence:
        status = (getattr(ev, 'integrity_status', None) or 'NOT_CHECKED').upper()
        if status in integrity_counts:
            integrity_counts[status] += 1
        else:
            integrity_counts['NOT_CHECKED'] += 1

    # ── Recent audit records (5 most recent) ─────────────────────────────────
    recent_audits = (
        AuditRecord.query
        .order_by(AuditRecord.timestamp.desc())
        .limit(5)
        .all()
    )

    # ════════════════════════════════════════════════════════════════════════
    #  Dashboard visualisation datasets (consumed by Chart.js in the template)
    # ════════════════════════════════════════════════════════════════════════
    all_audits = AuditRecord.query.all()

    # 1) Risk-level distribution — uses the *computed* scorer levels (same
    #    source as the "Top 5 Highest-Risk" table) so the numbers stay
    #    consistent across the dashboard.
    risk_level_counts = OrderedDict(
        (lvl, 0) for lvl in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    for item in scored_evidence:
        lvl = (item['level'] or '').upper()
        if lvl in risk_level_counts:
            risk_level_counts[lvl] += 1

    # 2) Evidence lifecycle-state distribution
    lifecycle_order = ['Collected', 'Submitted', 'Under Analysis',
                       'Transferred', 'Archived', 'Flagged']
    lifecycle_counts = OrderedDict((s, 0) for s in lifecycle_order)
    for ev in all_evidence:
        if ev.lifecycle_state in lifecycle_counts:
            lifecycle_counts[ev.lifecycle_state] += 1

    # 3) Audit events grouped by type (only types that actually occur)
    audit_type_order = ['Login', 'Logout', 'File Access', 'Data Modification',
                        'Integrity Check', 'State Change', 'Failed Attempt',
                        'Role Change', 'Key Generation']
    _audit_type_counts = OrderedDict((t, 0) for t in audit_type_order)
    for rec in all_audits:
        if rec.event_type in _audit_type_counts:
            _audit_type_counts[rec.event_type] += 1
    # Drop event types with zero occurrences to keep the chart readable
    audit_type_counts = OrderedDict(
        (k, v) for k, v in _audit_type_counts.items() if v > 0
    )

    # 4) Security activity over the last 30 days (Successful vs Security Alerts)
    window_days = 30
    today = datetime.now(timezone.utc).replace(tzinfo=None).date()
    date_axis = [today - timedelta(days=i) for i in range(window_days - 1, -1, -1)]
    succ = defaultdict(int)
    alert = defaultdict(int)
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=window_days)
    for rec in all_audits:
        if rec.timestamp and rec.timestamp >= since:
            d = rec.timestamp.date()
            if rec.result == 'Success':
                succ[d] += 1
            else:  # Failure or Warning => security alert
                alert[d] += 1

    activity_labels  = [d.strftime('%d %b') for d in date_axis]
    activity_success = [succ[d] for d in date_axis]
    activity_alerts  = [alert[d] for d in date_axis]

    charts = {
        'risk_labels':      list(risk_level_counts.keys()),
        'risk_values':      list(risk_level_counts.values()),
        'lifecycle_labels': list(lifecycle_counts.keys()),
        'lifecycle_values': list(lifecycle_counts.values()),
        'audit_labels':     list(audit_type_counts.keys()),
        'audit_values':     list(audit_type_counts.values()),
        'activity_labels':  activity_labels,
        'activity_success': activity_success,
        'activity_alerts':  activity_alerts,
    }

    return render_template(
        'dashboard/index.html',
        total_cases=total_cases,
        total_evidence=total_evidence,
        total_transfers=total_transfers,
        total_audits=total_audits,
        recent_cases=recent_cases,
        top_risk_evidence=top_risk_evidence,
        integrity_counts=integrity_counts,
        recent_audits=recent_audits,
        charts=charts,
    )

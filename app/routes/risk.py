from flask import Blueprint, render_template, jsonify
from flask_login import login_required

from app.models.evidence import EvidenceItem
from app.logic.risk_scoring import EvidenceRiskScorer

risk_bp = Blueprint('risk', __name__, url_prefix='/risk')


@risk_bp.route('/dashboard')
@login_required
def risk_dashboard():
    """Scores all evidence items and shows them ranked by risk."""
    scorer = EvidenceRiskScorer()
    items = EvidenceItem.query.all()
    
    from app.logic.anomaly_detection import AnomalyDetectionPipeline
    pipeline = AnomalyDetectionPipeline()
    anomaly_records = pipeline.run()
    anomaly_map = {rec.evidence_id: rec for rec in anomaly_records}
    
    scored = []
    for ev in items:
        report = scorer.score(ev)
        rec = anomaly_map.get(ev.id)
        anomaly_score = rec.anomaly_score if rec else 0.0
        unified_score = round(0.6 * report.final_score + 0.4 * anomaly_score, 4)
        unified_level = scorer._classify(unified_score)
        scored.append({
            'evidence': ev,
            'report': report,
            'anomaly_score': anomaly_score,
            'is_anomaly': rec.is_anomaly if rec else False,
            'unified_score': unified_score,
            'unified_level': unified_level,
        })
    # Sort by final_score descending (highest risk first)
    scored.sort(key=lambda x: x['report'].final_score, reverse=True)
    return render_template('risk/risk_dashboard.html', scored=scored)


@risk_bp.route('/evidence/<int:evidence_id>')
@login_required
def evidence_risk(evidence_id):
    """Full risk report for one evidence item."""
    evidence = EvidenceItem.query.get_or_404(evidence_id)
    scorer = EvidenceRiskScorer()
    report = scorer.score(evidence)
    
    from app.logic.anomaly_detection import AnomalyDetectionPipeline
    pipeline = AnomalyDetectionPipeline()
    anomaly_records = pipeline.run()
    rec = next((r for r in anomaly_records if r.evidence_id == evidence.id), None)
    
    anomaly_score = rec.anomaly_score if rec else 0.0
    is_anomaly = rec.is_anomaly if rec else False
    unified_score = round(0.6 * report.final_score + 0.4 * anomaly_score, 4)
    unified_level = scorer._classify(unified_score)
    
    return render_template('risk/evidence_risk.html', report=report, evidence=evidence, anomaly_score=anomaly_score, is_anomaly=is_anomaly, unified_score=unified_score, unified_level=unified_level)


@risk_bp.route('/evidence/<int:evidence_id>/json')
@login_required
def evidence_risk_json(evidence_id):
    """JSON endpoint for the risk report (useful for testing)."""
    evidence = EvidenceItem.query.get_or_404(evidence_id)
    scorer = EvidenceRiskScorer()
    report = scorer.score(evidence)
    return jsonify({
        'evidence_id':      report.evidence_id,
        'evidence_title':   report.evidence_title,
        'base_score':       report.base_score,
        'interaction_bonus': report.interaction_bonus,
        'final_score':      report.final_score,
        'risk_level':       report.risk_level,
        'factors': [
            {
                'name':             f.name,
                'raw_value':        f.raw_value,
                'normalised_score': f.normalised_score,
                'weight':           f.weight,
                'contribution':     f.contribution,
                'explanation':      f.explanation,
            }
            for f in report.factors
        ],
        'interactions': [
            {
                'factor_names': i.factor_names,
                'multiplier':   i.multiplier,
                'explanation':  i.explanation,
            }
            for i in report.interactions
        ],
        'recommendations': report.recommendations,
        'computed_at':     report.computed_at.isoformat(),
    })


@risk_bp.route('/anomaly')
@login_required
def anomaly_dashboard():
    """Runs the Isolation Forest pipeline and shows anomaly scores."""
    from app.logic.anomaly_detection import AnomalyDetectionPipeline
    pipeline = AnomalyDetectionPipeline()
    records = pipeline.run()
    return render_template('risk/anomaly_dashboard.html', records=records)
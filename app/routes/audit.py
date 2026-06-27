from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.models.audit_record import AuditRecord
from app.models.evidence import EvidenceItem
from app.models.case_access import CaseAccess
from flask import redirect, url_for, flash

audit_bp = Blueprint('audit', __name__)


@audit_bp.route('/audit')
@login_required
def audit_trail():
    """View the full system audit trail. Admin only."""
    if not current_user.is_admin():
        flash('The global audit trail is restricted to administrators.', 'danger')
        return redirect(url_for('dashboard.index'))
    page = request.args.get('page', 1, type=int)

    records = (AuditRecord.query
               .order_by(AuditRecord.timestamp.desc())
               .paginate(page=page, per_page=25, error_out=False))

    return render_template('audit/trail.html', records=records)


@audit_bp.route('/audit/evidence/<int:evidence_id>')
@login_required
def evidence_audit(evidence_id):
    """View the audit trail for a specific evidence item."""
    evidence = EvidenceItem.query.get_or_404(evidence_id)
    if not CaseAccess.can_access(evidence.case_id, current_user):
        flash('You do not have access to this case.', 'danger')
        return redirect(url_for('cases.list_cases'))
    records = (AuditRecord.query
               .filter_by(evidence_id=evidence_id)
               .order_by(AuditRecord.timestamp.desc())
               .all())
    return render_template('audit/evidence_trail.html',
                           evidence=evidence, records=records)


@audit_bp.route('/audit/evidence/<int:evidence_id>/formula-check')
@login_required
def formula_check(evidence_id):
    """Run all three audit formula checks and return results as JSON."""
    EvidenceItem.query.get_or_404(evidence_id)
    from app.logic.audit_formulas import run_all_formula_checks
    report = run_all_formula_checks(evidence_id)
    return jsonify(report)
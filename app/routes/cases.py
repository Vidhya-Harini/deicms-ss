from datetime import timedelta
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.case import Case
from app.models.audit_record import AuditRecord
from app.models.evidence import EvidenceItem
from app.models.case_access import CaseAccess
from app.models.investigator import Investigator

cases_bp = Blueprint('cases', __name__)


def generate_case_number():
    """Auto-generate a unique case number like CASE-2024-001."""
    year = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None).year
    count = Case.query.count() + 1
    return f'CASE-{year}-{count:03d}'


@cases_bp.route('/cases')
@login_required
def list_cases():
    """
    Show active (non-archived) cases.
    Admins see every case; everyone else sees only cases they have been
    granted access to (principle of least privilege).
    """
    query = Case.query.filter_by(is_archived=False)
    if not current_user.is_admin():
        accessible_ids = [
            row.case_id for row in
            CaseAccess.query.filter_by(investigator_id=current_user.id).all()
        ]
        query = query.filter(Case.id.in_(accessible_ids or [-1]))
    cases = query.order_by(Case.created_at.desc()).all()
    return render_template('cases/list.html', cases=cases)


@cases_bp.route('/cases/new', methods=['GET', 'POST'])
@login_required
def create_case():
    """Create a new investigation case."""
    if not current_user.can_manage():
        flash('You do not have permission to create cases.', 'danger')
        return redirect(url_for('cases.list_cases'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        jurisdiction = request.form.get('jurisdiction', '').strip()

        if not title:
            flash('Case title is required.', 'danger')
            return render_template('cases/create.html')

        case = Case(
            case_number=generate_case_number(),
            title=title,
            description=description,
            jurisdiction=jurisdiction,
            status='Open',
            created_by_id=current_user.id,
            assigned_to_id=current_user.id
        )
        db.session.add(case)
        db.session.flush()  # Get the case ID before committing

        # Grant the creator Owner-level access to their own case
        CaseAccess.grant(
            case_id=case.id,
            investigator_id=current_user.id,
            permission='Owner',
            granted_by_id=current_user.id,
        )

        audit = AuditRecord(
            event_type='Data Modification',
            investigator_id=current_user.id,
            case_id=case.id,
            description=f'Case {case.case_number} created: {title}',
            ip_address=request.remote_addr,
            result='Success'
        )
        db.session.add(audit)
        db.session.commit()

        flash(f'Case {case.case_number} created successfully.', 'success')
        return redirect(url_for('cases.view_case', case_id=case.id))

    return render_template('cases/create.html')


@cases_bp.route('/cases/<int:case_id>')
@login_required
def view_case(case_id):
    """View a single case and its evidence items."""
    case = Case.query.get_or_404(case_id)

    # Case-level access check (Admins always pass)
    if not CaseAccess.can_access(case_id, current_user):
        flash('You do not have access to this case.', 'danger')
        return redirect(url_for('cases.list_cases'))

    evidence_items = (case.evidence_items
                  .order_by(EvidenceItem.created_at.desc())
                  .all())

    # Case membership data for the "Case Members" panel
    members = CaseAccess.query.filter_by(case_id=case_id).all()
    can_manage_members = CaseAccess.can_manage_members(case_id, current_user)
    member_ids = {m.investigator_id for m in members}
    addable_investigators = []
    if can_manage_members:
        addable_investigators = (
            Investigator.query
            .filter_by(is_active=True)
            .filter(~Investigator.id.in_(member_ids or [-1]))
            .order_by(Investigator.full_name)
            .all()
        )

    return render_template('cases/view.html', case=case,
                           evidence_items=evidence_items,
                           members=members,
                           can_manage_members=can_manage_members,
                           addable_investigators=addable_investigators)


@cases_bp.route('/cases/<int:case_id>/members/add', methods=['POST'])
@login_required
def add_member(case_id):
    """Grant another investigator access to this case. Owner/Admin only."""
    case = Case.query.get_or_404(case_id)

    if not CaseAccess.can_manage_members(case_id, current_user):
        flash('Only the case owner or an Admin can manage members.', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    investigator_id = request.form.get('investigator_id', type=int)
    permission = request.form.get('permission', 'Member')
    if permission not in ('Member', 'ReadOnly'):
        permission = 'Member'

    investigator = Investigator.query.get(investigator_id) if investigator_id else None
    if not investigator:
        flash('Please select a valid investigator.', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    CaseAccess.grant(
        case_id=case_id,
        investigator_id=investigator_id,
        permission=permission,
        granted_by_id=current_user.id,
    )

    audit = AuditRecord(
        event_type='Role Change',
        investigator_id=current_user.id,
        case_id=case_id,
        description=(f'{current_user.full_name} granted {permission} access on '
                     f'case {case.case_number} to {investigator.full_name}.'),
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    flash(f'{investigator.full_name} added to the case as {permission}.', 'success')
    return redirect(url_for('cases.view_case', case_id=case_id))


@cases_bp.route('/cases/<int:case_id>/members/remove', methods=['POST'])
@login_required
def remove_member(case_id):
    """Revoke an investigator's access to this case. Owner/Admin only."""
    case = Case.query.get_or_404(case_id)

    if not CaseAccess.can_manage_members(case_id, current_user):
        flash('Only the case owner or an Admin can manage members.', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    investigator_id = request.form.get('investigator_id', type=int)
    row = CaseAccess.query.filter_by(
        case_id=case_id, investigator_id=investigator_id
    ).first()

    if not row:
        flash('That investigator is not a member of this case.', 'warning')
        return redirect(url_for('cases.view_case', case_id=case_id))

    if row.permission == 'Owner':
        flash('The case owner cannot be removed.', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    name = row.investigator.full_name if row.investigator else f'#{investigator_id}'
    db.session.delete(row)
    audit = AuditRecord(
        event_type='Role Change',
        investigator_id=current_user.id,
        case_id=case_id,
        description=(f'{current_user.full_name} revoked access on '
                     f'case {case.case_number} from {name}.'),
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    flash(f'{name} removed from the case.', 'info')
    return redirect(url_for('cases.view_case', case_id=case_id))


@cases_bp.route('/cases/<int:case_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_case(case_id):
    """Edit an existing case."""
    case = Case.query.get_or_404(case_id)

    if not current_user.can_manage():
        flash('You do not have permission to edit cases.', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    if not CaseAccess.can_access(case_id, current_user):
        flash('You do not have access to this case.', 'danger')
        return redirect(url_for('cases.list_cases'))

    if request.method == 'POST':
        old_status = case.status
        case.title = request.form.get('title', case.title).strip()
        case.description = request.form.get('description', case.description).strip()
        case.jurisdiction = request.form.get('jurisdiction', case.jurisdiction).strip()
        case.status = request.form.get('status', case.status)

        if case.status == 'Closed' and old_status != 'Closed':
            case.date_closed = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None)

        audit = AuditRecord(
            event_type='Data Modification',
            investigator_id=current_user.id,
            case_id=case.id,
            description=f'Case {case.case_number} updated. Status: {old_status} -> {case.status}',
            ip_address=request.remote_addr,
            result='Success'
        )
        db.session.add(audit)
        db.session.commit()

        flash('Case updated successfully.', 'success')
        return redirect(url_for('cases.view_case', case_id=case_id))

    return render_template('cases/edit.html', case=case)


@cases_bp.route('/cases/<int:case_id>/archive', methods=['POST'])
@login_required
def archive_case(case_id):
    """Soft-delete (archive) a case."""
    case = Case.query.get_or_404(case_id)

    if not current_user.is_admin():
        flash('Only Admins can archive cases.', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    case.is_archived = True
    case.status = 'Archived'

    audit = AuditRecord(
        event_type='Data Modification',
        investigator_id=current_user.id,
        case_id=case.id,
        description=f'Case {case.case_number} archived.',
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    flash(f'Case {case.case_number} has been archived.', 'info')
    return redirect(url_for('cases.list_cases'))

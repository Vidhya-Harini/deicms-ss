"""
Admin-only routes for user management.
Only investigators with role='Admin' can access these.
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.investigator import Investigator
from app.models.audit_record import AuditRecord
from app.logic.crypto import generate_key_pair, encrypt_private_key
from app.logic.validators import validate_password_strength

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def _admin_guard():
    """Returns a redirect response if the current user is not an Admin, else None."""
    if not current_user.is_authenticated or not current_user.is_admin():
        flash('Access denied. Admin role required.', 'danger')
        return redirect(url_for('dashboard.index'))
    return None


@admin_bp.route('/users')
@login_required
def list_users():
    """Show all investigator accounts. Admin only."""
    guard = _admin_guard()
    if guard:
        return guard

    investigators = Investigator.query.order_by(Investigator.created_at.desc()).all()
    return render_template('admin/users.html', investigators=investigators)


@admin_bp.route('/users/new', methods=['GET', 'POST'])
@login_required
def create_user():
    """Create a new investigator account. Admin only."""
    guard = _admin_guard()
    if guard:
        return guard

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'Analyst')

        # Validation
        if not full_name or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('admin/create_user.html')

        pw_errors = validate_password_strength(password)
        if pw_errors:
            flash('Password must ' + '; '.join(pw_errors) + '.', 'danger')
            return render_template('admin/create_user.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('admin/create_user.html')

        if Investigator.query.filter_by(email=email).first():
            flash('An account with this email already exists.', 'danger')
            return render_template('admin/create_user.html')

        # Valid roles only
        valid_roles = ['Admin', 'Lead Investigator', 'Analyst', 'Read-Only']
        if role not in valid_roles:
            flash('Invalid role selected.', 'danger')
            return render_template('admin/create_user.html')

        # Create with key pair
        private_pem, public_pem = generate_key_pair()
        investigator = Investigator(
            full_name=full_name,
            email=email,
            role=role,
            public_key=public_pem,
            private_key_encrypted=encrypt_private_key(private_pem),
        )
        investigator.set_password(password)

        db.session.add(investigator)
        db.session.commit()

        audit = AuditRecord(
            event_type='Data Modification',
            investigator_id=current_user.id,
            description=f'Admin {current_user.full_name} created account: {email} [{role}]',
            ip_address=request.remote_addr,
            result='Success'
        )
        db.session.add(audit)
        db.session.commit()

        flash(f'Account for {full_name} created successfully.', 'success')
        return redirect(url_for('admin.list_users'))

    return render_template('admin/create_user.html')


@admin_bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
def toggle_active(user_id):
    """Activate or deactivate an investigator account. Admin only."""
    guard = _admin_guard()
    if guard:
        return guard

    if user_id == current_user.id:
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('admin.list_users'))

    investigator = Investigator.query.get_or_404(user_id)
    investigator.is_active = not investigator.is_active
    action = 'activated' if investigator.is_active else 'deactivated'

    # Clear lockout when admin re-activates an account
    if investigator.is_active:
        investigator.reset_login_attempts()

    audit = AuditRecord(
        event_type='Role Change',
        investigator_id=current_user.id,
        description=f'Admin {current_user.full_name} {action} account: {investigator.email}',
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    flash(f'Account for {investigator.full_name} has been {action}.', 'success')
    return redirect(url_for('admin.list_users'))


@admin_bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@login_required
def unlock_account(user_id):
    """Manually unlock a locked-out account. Admin only."""
    guard = _admin_guard()
    if guard:
        return guard

    investigator = Investigator.query.get_or_404(user_id)
    investigator.reset_login_attempts()

    audit = AuditRecord(
        event_type='Role Change',
        investigator_id=current_user.id,
        description=f'Admin {current_user.full_name} manually unlocked account: {investigator.email}',
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    flash(f'Account for {investigator.full_name} has been unlocked.', 'success')
    return redirect(url_for('admin.list_users'))


@admin_bp.route('/users/<int:user_id>/change-role', methods=['POST'])
@login_required
def change_role(user_id):
    """Change an investigator's role. Admin only."""
    guard = _admin_guard()
    if guard:
        return guard

    if user_id == current_user.id:
        flash('You cannot change your own role.', 'danger')
        return redirect(url_for('admin.list_users'))

    investigator = Investigator.query.get_or_404(user_id)
    new_role = request.form.get('role', '')
    valid_roles = ['Admin', 'Lead Investigator', 'Analyst', 'Read-Only']
    if new_role not in valid_roles:
        flash('Invalid role.', 'danger')
        return redirect(url_for('admin.list_users'))

    old_role = investigator.role
    investigator.role = new_role

    audit = AuditRecord(
        event_type='Role Change',
        investigator_id=current_user.id,
        description=(
            f'Admin {current_user.full_name} changed role of {investigator.email}: '
            f'{old_role} -> {new_role}'
        ),
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    flash(f"Role for {investigator.full_name} changed to '{new_role}'.", 'success')
    return redirect(url_for('admin.list_users'))

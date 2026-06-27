from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models.investigator import Investigator
from app.models.audit_record import AuditRecord
from flask import current_app

auth_bp = Blueprint('auth', __name__)


def admin_required(f):
    """
    Decorator that restricts a route to Admin-role users only.
    Must be placed AFTER @login_required.
    """
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Access denied. Admin role required.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated


@auth_bp.route('/', methods=['GET', 'POST'])
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    """Handle investigator login with rate limiting and account lockout."""
    # If already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        investigator = Investigator.query.filter_by(email=email).first()

        # ── Check account lockout ────────────────────────────────────────────
        if investigator and investigator.is_locked():
            mins = investigator.lockout_remaining_minutes()
            db.session.commit()  # persist any auto-clear from is_locked()
            audit = AuditRecord(
                event_type='Failed Attempt',
                description=f'Login blocked — account locked: {email}',
                ip_address=request.remote_addr,
                result='Failure'
            )
            db.session.add(audit)
            db.session.commit()
            flash(
                f'Account is locked due to too many failed attempts. '
                f'Try again in {mins} minute(s).',
                'danger'
            )
            return render_template('auth/login.html',
                                   locked=True, lock_minutes=mins)

        # ── Credential check ─────────────────────────────────────────────────
        if investigator and investigator.check_password(password) and investigator.is_active:
            investigator.reset_login_attempts()
            db.session.commit()

            # If this account has TOTP multi-factor authentication enabled, the
            # password is only the first factor. Hold the user in a pending state
            # and ask for their authenticator code before completing the login.
            if investigator.is_mfa_enabled():
                session['pending_2fa_user'] = investigator.id
                session['pending_2fa_next'] = request.args.get('next') or ''
                return redirect(url_for('auth.verify_otp'))

            login_user(investigator)
            session.permanent = True
            audit = AuditRecord(
                event_type='Login',
                investigator_id=investigator.id,
                description=f'Investigator {investigator.full_name} logged in.',
                ip_address=request.remote_addr,
                result='Success'
            )
            db.session.add(audit)
            db.session.commit()

            flash(f'Welcome back, {investigator.full_name}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            # ── Record failed attempt ────────────────────────────────────────
            if investigator and investigator.is_active:
                max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
                lockout_mins = current_app.config.get('LOCKOUT_MINUTES', 15)
                investigator.record_failed_login(
                    max_attempts=max_attempts,
                    lockout_minutes=lockout_mins
                )
                remaining = max_attempts - investigator.failed_login_count
                if investigator.is_locked():
                    flash(
                        f'Too many failed attempts. Account locked for {lockout_mins} minute(s).',
                        'danger'
                    )
                else:
                    flash(
                        f'Invalid email or password. '
                        f'{max(0, remaining)} attempt(s) remaining before lockout.',
                        'danger'
                    )
            else:
                flash('Invalid email or password. Please try again.', 'danger')

            audit = AuditRecord(
                event_type='Failed Attempt',
                description=f'Failed login attempt for email: {email}',
                ip_address=request.remote_addr,
                result='Failure'
            )
            db.session.add(audit)
            db.session.commit()

    return render_template('auth/login.html', locked=False, lock_minutes=0)


@auth_bp.route('/logout')
@login_required
def logout():
    """Handle investigator logout."""
    audit = AuditRecord(
        event_type='Logout',
        investigator_id=current_user.id,
        description=f'Investigator {current_user.full_name} logged out.',
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))



@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def verify_otp():
    """Second factor: verify the TOTP code after a correct password."""
    import pyotp
    user_id = session.get('pending_2fa_user')
    if not user_id:
        return redirect(url_for('auth.login'))
    investigator = Investigator.query.get(user_id)
    if not investigator or not investigator.totp_secret:
        session.pop('pending_2fa_user', None)
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('otp', '').strip().replace(' ', '')
        if pyotp.TOTP(investigator.totp_secret).verify(code, valid_window=1):
            login_user(investigator)
            session.permanent = True
            session.pop('pending_2fa_user', None)
            next_page = session.pop('pending_2fa_next', '') or url_for('dashboard.index')
            audit = AuditRecord(
                event_type='Login',
                investigator_id=investigator.id,
                description=f'Investigator {investigator.full_name} logged in (MFA verified).',
                ip_address=request.remote_addr,
                result='Success'
            )
            db.session.add(audit)
            db.session.commit()
            flash(f'Welcome back, {investigator.full_name}!', 'success')
            return redirect(next_page)
        else:
            audit = AuditRecord(
                event_type='Failed Attempt',
                investigator_id=investigator.id,
                description=f'Invalid MFA code for {investigator.email}.',
                ip_address=request.remote_addr,
                result='Failure'
            )
            db.session.add(audit)
            db.session.commit()
            flash('Invalid authentication code. Please try again.', 'danger')

    return render_template('auth/verify_otp.html')


@auth_bp.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    """Enrol the current user in TOTP multi-factor authentication."""
    import pyotp, qrcode, io, base64

    if request.method == 'POST':
        secret = session.get('mfa_setup_secret')
        code = request.form.get('otp', '').strip().replace(' ', '')
        if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
            current_user.totp_secret = secret
            session.pop('mfa_setup_secret', None)
            audit = AuditRecord(
                event_type='Role Change',
                investigator_id=current_user.id,
                description=f'{current_user.full_name} enabled two-factor authentication (2FA).',
                ip_address=request.remote_addr,
                result='Success'
            )
            db.session.add(audit)
            db.session.commit()
            flash('Two-factor authentication (2FA) is now enabled on your account.', 'success')
            return redirect(url_for('mfa_setup' if False else 'auth.mfa_setup'))
        flash('That code was not valid. Please scan the QR code and try again.', 'danger')

    if current_user.is_mfa_enabled():
        return render_template('auth/mfa_setup.html', enabled=True, qr_data=None, secret=None)

    # Generate a provisional secret and a QR code for enrolment
    secret = session.get('mfa_setup_secret') or pyotp.random_base32()
    session['mfa_setup_secret'] = secret
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name='DEICMS')
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_data = 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')
    return render_template('auth/mfa_setup.html', enabled=False, qr_data=qr_data, secret=secret)


@auth_bp.route('/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    """Disable TOTP multi-factor authentication for the current user."""
    current_user.totp_secret = None
    session.pop('mfa_setup_secret', None)
    audit = AuditRecord(
        event_type='Role Change',
        investigator_id=current_user.id,
        description=f'{current_user.full_name} disabled two-factor authentication (2FA).',
        ip_address=request.remote_addr,
        result='Warning'
    )
    db.session.add(audit)
    db.session.commit()
    flash('Two-factor authentication (2FA) has been disabled.', 'info')
    return redirect(url_for('auth.mfa_setup'))

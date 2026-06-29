from datetime import timedelta
from flask import Flask, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, logout_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import config

# Initialise extensions (not yet tied to an app)
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

# Tell Flask-Login which route handles login
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


def create_app():
    """
    Application factory function.
    Creates and configures the Flask app.
    Using a factory makes testing easier and avoids circular imports.
    """
    app = Flask(__name__)
    app.config.from_object(config)

    # Bind extensions to the app
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register blueprints (each blueprint = one section of the app)
    from app.routes.auth import auth_bp
    from app.routes.cases import cases_bp
    from app.routes.evidence import evidence_bp
    from app.routes.custody import custody_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.audit import audit_bp
    from app.routes.risk import risk_bp
    from app.routes.assistant import assistant_bp
    from app.routes.admin import admin_bp
    from app.routes.export import export_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(custody_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(assistant_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(export_bp)

    # Create all database tables if they don't exist
    with app.app_context():
        from app.models import (Investigator, Case, EvidenceItem,
                                CustodyLog, AuditRecord, CaseAccess)
        db.create_all()
        _ensure_schema()

    # Enforce a sliding idle-session timeout: log the user out after a period
    # of inactivity. Each request refreshes the activity timestamp.
    @app.before_request
    def _enforce_idle_timeout():
        if current_user.is_authenticated:
            session.permanent = True
            from datetime import datetime, timezone
            now = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None).timestamp()
            timeout = app.config.get('IDLE_TIMEOUT_MINUTES', 30) * 60
            last = session.get('last_active')
            if last and (now - last) > timeout:
                logout_user()
                session.clear()
                flash('You have been logged out due to inactivity.', 'warning')
                return redirect(url_for('auth.login'))
            session['last_active'] = now

    # Send HTTP Strict-Transport-Security (HSTS) on secure responses so that,
    # once a browser has connected over HTTPS, it will not silently fall back
    # to plain HTTP. A short max-age is used for local development.
    @app.after_request
    def _set_security_headers(response):
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=3600'
        return response

    return app


def _ensure_schema():
    """
    Lightweight, idempotent migration for databases created before the
    security features were added. SQLAlchemy's create_all() builds new
    tables (e.g. case_access) but never alters existing ones, so we:
      1. Add the login-lockout columns to investigators if missing.
      2. Backfill an Owner case_access row for every existing case so that
         legacy data remains visible under case-level access control.
    Runs at startup; safe to run repeatedly.
    """
    from sqlalchemy import inspect, text
    from app.models.case import Case
    from app.models.case_access import CaseAccess

    inspector = inspect(db.engine)
    existing = {c['name'] for c in inspector.get_columns('investigators')}

    # 1) Add missing lockout columns
    with db.engine.begin() as conn:
        if 'failed_login_count' not in existing:
            conn.execute(text(
                'ALTER TABLE investigators '
                'ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0'))
        if 'locked_until' not in existing:
            conn.execute(text(
                'ALTER TABLE investigators ADD COLUMN locked_until DATETIME'))
        if 'totp_secret' not in existing:
            conn.execute(text(
                'ALTER TABLE investigators ADD COLUMN totp_secret VARCHAR(64)'))

    # 2) Backfill case ownership for legacy cases
    cases = Case.query.all()
    changed = False
    for case in cases:
        owner_id = case.created_by_id or case.assigned_to_id
        if not owner_id:
            continue
        exists = CaseAccess.query.filter_by(case_id=case.id).first()
        if not exists:
            db.session.add(CaseAccess(
                case_id=case.id,
                investigator_id=owner_id,
                permission='Owner',
                granted_by_id=owner_id,
            ))
            changed = True
    if changed:
        db.session.commit()

    # 3) Encrypt any private keys still stored in plaintext (PEM) form.
    from app.models.investigator import Investigator
    from app.logic.crypto import encrypt_private_key
    key_changed = False
    for inv in Investigator.query.all():
        pk = inv.private_key_encrypted
        if pk and pk.lstrip().startswith('-----BEGIN'):
            inv.private_key_encrypted = encrypt_private_key(pk)
            key_changed = True
    if key_changed:
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login uses this to reload the user object from the
    user ID stored in the session cookie.
    """
    from app.models.investigator import Investigator
    return Investigator.query.get(int(user_id))

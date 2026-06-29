"""
Day 2 Tests — Key pair generation and Audit Formula Checks
Run with: pytest tests/ -v --cov=app
"""
import pytest
from datetime import datetime, timedelta
from app import create_app, db
from app.models.investigator import Investigator
from app.models.case import Case
from app.models.evidence import EvidenceItem
from app.models.custody_log import CustodyLog
from app.models.audit_record import AuditRecord


@pytest.fixture
def app():
    """Create a fresh test app with in-memory SQLite database."""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'UPLOAD_FOLDER': '/tmp/test_uploads'
    })
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def sample_data(app):
    """
    Create a minimal but complete set of sample records:
    admin investigator -> case -> evidence item -> custody log entries.
    Returns a dict of IDs for use in tests.
    """
    with app.app_context():
        from app.logic.crypto import generate_key_pair

        # Admin investigator
        priv, pub = generate_key_pair()
        admin = Investigator(
            full_name='Admin User',
            email='admin@test.com',
            role='Admin',
            public_key=pub,
            private_key_encrypted=priv
        )
        admin.set_password('password123')
        db.session.add(admin)
        db.session.flush()

        # Analyst investigator
        priv2, pub2 = generate_key_pair()
        analyst = Investigator(
            full_name='Forensic Analyst',
            email='analyst@test.com',
            role='Analyst',
            public_key=pub2,
            private_key_encrypted=priv2
        )
        analyst.set_password('password123')
        db.session.add(analyst)
        db.session.flush()

        # Read-only investigator
        priv3, pub3 = generate_key_pair()
        readonly = Investigator(
            full_name='Read Only User',
            email='readonly@test.com',
            role='Read-Only',
            public_key=pub3,
            private_key_encrypted=priv3
        )
        readonly.set_password('password123')
        db.session.add(readonly)
        db.session.flush()

        # Case
        case = Case(
            case_number='CASE-2026-TEST',
            title='Test Case',
            jurisdiction='Italy',
            created_by_id=admin.id,
            assigned_to_id=admin.id
        )
        db.session.add(case)
        db.session.flush()

        # Evidence item
        evidence = EvidenceItem(
            evidence_number='E-001',
            case_id=case.id,
            title='Test Evidence',
            category='Database',
            lifecycle_state='Submitted',
            file_name='test.db',
            file_path='/tmp/test.db',
            original_hash='a' * 64,
            current_hash='a' * 64,
            uploaded_by_id=admin.id,
            current_holder_id=admin.id
        )
        db.session.add(evidence)
        db.session.flush()

        # Custody log — Upload event
        log1 = CustodyLog(
            evidence_id=evidence.id,
            event_type='Upload',
            to_investigator_id=admin.id,
            timestamp=datetime(2026, 5, 1, 10, 0, 0),
            file_hash_at_event='a' * 64
        )
        db.session.add(log1)
        db.session.flush()

        # Custody log — Transfer after a long gap (100 hours later)
        log2 = CustodyLog(
            evidence_id=evidence.id,
            event_type='Transfer',
            from_investigator_id=admin.id,
            to_investigator_id=analyst.id,
            timestamp=datetime(2026, 5, 1, 10, 0, 0) + timedelta(hours=100),
            file_hash_at_event='a' * 64
        )
        db.session.add(log2)
        db.session.flush()

        # Custody log — Duplicate of log2 (same fields, same timestamp)
        log3 = CustodyLog(
            evidence_id=evidence.id,
            event_type='Transfer',
            from_investigator_id=admin.id,
            to_investigator_id=analyst.id,
            timestamp=datetime(2026, 5, 1, 10, 0, 0) + timedelta(hours=100),
            file_hash_at_event='a' * 64
        )
        db.session.add(log3)

        # Audit — File access by read-only user (role mismatch for Database category)
        access_record = AuditRecord(
            event_type='File Access',
            investigator_id=readonly.id,
            evidence_id=evidence.id,
            case_id=case.id,
            description='Read-only accessed database evidence',
            result='Success'
        )
        db.session.add(access_record)

        db.session.commit()

        return {
            'admin_id': admin.id,
            'analyst_id': analyst.id,
            'readonly_id': readonly.id,
            'case_id': case.id,
            'evidence_id': evidence.id
        }


# ── Crypto Tests ──────────────────────────────────────────────────────────────

def test_generate_key_pair_returns_pem_strings(app):
    """Key pair generation should return two non-empty PEM strings."""
    with app.app_context():
        from app.logic.crypto import generate_key_pair
        private_pem, public_pem = generate_key_pair()
        assert private_pem.startswith('-----BEGIN PRIVATE KEY-----')
        assert public_pem.startswith('-----BEGIN PUBLIC KEY-----')
        assert len(private_pem) > 100
        assert len(public_pem) > 100


def test_each_key_pair_is_unique(app):
    """Two calls to generate_key_pair must produce different keys."""
    with app.app_context():
        from app.logic.crypto import generate_key_pair
        priv1, pub1 = generate_key_pair()
        priv2, pub2 = generate_key_pair()
        assert priv1 != priv2
        assert pub1 != pub2


def test_sign_and_verify_roundtrip(app):
    """A payload signed with the private key must verify with the public key."""
    with app.app_context():
        from app.logic.crypto import generate_key_pair, sign_payload, verify_signature
        private_pem, public_pem = generate_key_pair()
        payload = b'evidence-id:42|timestamp:2026-05-01T10:00:00'
        signature_hex = sign_payload(private_pem, payload)
        assert verify_signature(public_pem, payload, signature_hex) is True


def test_tampered_payload_fails_verification(app):
    """Verifying a signature against a different payload must return False."""
    with app.app_context():
        from app.logic.crypto import generate_key_pair, sign_payload, verify_signature
        private_pem, public_pem = generate_key_pair()
        original_payload = b'original content'
        tampered_payload = b'tampered content'
        signature_hex = sign_payload(private_pem, original_payload)
        assert verify_signature(public_pem, tampered_payload, signature_hex) is False


def test_wrong_key_fails_verification(app):
    """Verifying a signature with a different public key must return False."""
    with app.app_context():
        from app.logic.crypto import generate_key_pair, sign_payload, verify_signature
        priv1, pub1 = generate_key_pair()
        priv2, pub2 = generate_key_pair()
        payload = b'test payload'
        signature_hex = sign_payload(priv1, payload)
        # Verify with the WRONG public key
        assert verify_signature(pub2, payload, signature_hex) is False


def test_register_creates_key_pair(app):
    """Registering a new account via the web route must generate a key pair."""
    with app.test_client() as client:
        with app.app_context():
            response = client.post('/register', data={
                'full_name': 'New User',
                'email': 'new@test.com',
                'password': 'password123',
                'confirm_password': 'password123',
                'role': 'Analyst'
            }, follow_redirects=True)
            assert response.status_code == 200

            investigator = Investigator.query.filter_by(
                email='new@test.com').first()
            assert investigator is not None
            assert investigator.public_key is not None
            assert investigator.private_key_encrypted is not None
            assert investigator.public_key.startswith('-----BEGIN PUBLIC KEY-----')


# ── Audit Formula Tests ───────────────────────────────────────────────────────

def test_time_gap_detected_above_threshold(app, sample_data):
    """A 100-hour gap should be flagged when threshold is 72 hours."""
    with app.app_context():
        from app.logic.audit_formulas import check_time_gaps
        gaps = check_time_gaps(sample_data['evidence_id'], threshold_hours=72)
        assert len(gaps) == 1
        assert gaps[0]['gap_hours'] == pytest.approx(100.0, abs=0.1)
        assert gaps[0]['threshold_hours'] == 72


def test_no_gap_below_threshold(app, sample_data):
    """A 100-hour gap should NOT be flagged when threshold is 200 hours."""
    with app.app_context():
        from app.logic.audit_formulas import check_time_gaps
        gaps = check_time_gaps(sample_data['evidence_id'], threshold_hours=200)
        assert len(gaps) == 0


def test_duplicate_detection(app, sample_data):
    """Two custody log entries with identical fields should be flagged."""
    with app.app_context():
        from app.logic.audit_formulas import check_duplicate_entries
        duplicates = check_duplicate_entries(sample_data['evidence_id'])
        assert len(duplicates) == 1
        assert duplicates[0]['event_type'] == 'Transfer'


def test_role_mismatch_detected(app, sample_data):
    """A Read-Only user accessing a Database evidence item should be flagged."""
    with app.app_context():
        from app.logic.audit_formulas import check_role_mismatches
        mismatches = check_role_mismatches(sample_data['evidence_id'])
        assert len(mismatches) == 1
        assert mismatches[0]['role'] == 'Read-Only'
        assert mismatches[0]['evidence_category'] == 'Database'


def test_combined_formula_check(app, sample_data):
    """run_all_formula_checks should aggregate all three check results."""
    with app.app_context():
        from app.logic.audit_formulas import run_all_formula_checks
        report = run_all_formula_checks(sample_data['evidence_id'])
        assert report['evidence_id'] == sample_data['evidence_id']
        assert len(report['time_gaps']) == 1
        assert len(report['duplicates']) == 1
        assert len(report['role_mismatches']) == 1
        assert report['total_issues'] == 3


def test_formula_check_api_returns_json(app, sample_data):
    """The formula check API route should return valid JSON."""
    with app.test_client() as client:
        with app.app_context():
            # Log in as admin first
            admin = Investigator.query.get(sample_data['admin_id'])
            client.post('/', data={
                'email': admin.email,
                'password': 'password123'
            }, follow_redirects=True)
            response = client.get(
                f'/audit/evidence/{sample_data["evidence_id"]}/formula-check'
            )
            assert response.status_code == 200
            assert response.content_type == 'application/json'
            data = response.get_json()
            assert 'total_issues' in data
            assert 'time_gaps' in data

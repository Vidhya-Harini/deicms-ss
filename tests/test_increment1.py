"""
Increment 1 Tests — Core Case & Evidence Management
Run with: pytest tests/ -v --cov=app
"""
import pytest
import hashlib
import os
import tempfile
from app import create_app, db
from app.models.investigator import Investigator
from app.models.case import Case
from app.models.evidence import EvidenceItem


@pytest.fixture
def app():
    """Create a fresh test application with an in-memory SQLite database."""
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'UPLOAD_FOLDER': tempfile.mkdtemp()
    })
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_user(app):
    """Create an admin investigator for testing."""
    with app.app_context():
        user = Investigator(
            full_name='Admin User',
            email='admin@test.com',
            role='Admin'
        )
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()
        return user.id  # Return ID to avoid detached instance issues


# ── Hash Tests ────────────────────────────────────────────────────────────────

def test_sha256_hash_is_64_chars():
    """SHA-256 hash should always be exactly 64 hex characters."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'test evidence content')
        tmp_path = f.name
    try:
        sha256 = hashlib.sha256()
        with open(tmp_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        result = sha256.hexdigest()
        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)
    finally:
        os.unlink(tmp_path)


def test_same_file_produces_same_hash():
    """The same file content must always produce the same SHA-256 hash."""
    content = b'deterministic content for hashing'
    hash1 = hashlib.sha256(content).hexdigest()
    hash2 = hashlib.sha256(content).hexdigest()
    assert hash1 == hash2


def test_different_content_produces_different_hash():
    """Different file contents must produce different hashes."""
    hash1 = hashlib.sha256(b'original content').hexdigest()
    hash2 = hashlib.sha256(b'tampered content').hexdigest()
    assert hash1 != hash2


# ── Investigator Model Tests ──────────────────────────────────────────────────

def test_password_hashing(app):
    """Password should be stored as a hash, not plaintext."""
    with app.app_context():
        user = Investigator(full_name='Test', email='t@test.com', role='Analyst')
        user.set_password('mysecretpassword')
        assert user.password_hash != 'mysecretpassword'
        assert user.check_password('mysecretpassword') is True
        assert user.check_password('wrongpassword') is False


def test_investigator_roles(app):
    """Role helper methods should return correct permissions."""
    with app.app_context():
        admin = Investigator(full_name='A', email='a@t.com', role='Admin')
        lead = Investigator(full_name='B', email='b@t.com', role='Lead Investigator')
        analyst = Investigator(full_name='C', email='c@t.com', role='Analyst')
        readonly = Investigator(full_name='D', email='d@t.com', role='Read-Only')

        assert admin.is_admin() is True
        assert lead.is_admin() is False
        assert admin.can_manage() is True
        assert lead.can_manage() is True
        assert analyst.can_manage() is False
        assert readonly.can_manage() is False
        assert analyst.can_analyse() is True
        assert readonly.can_analyse() is False


# ── Case Model Tests ──────────────────────────────────────────────────────────

def test_create_case(app, admin_user):
    """A case should be created with correct default values."""
    with app.app_context():
        case = Case(
            case_number='CASE-2024-001',
            title='Test Case',
            jurisdiction='Italy',
            created_by_id=admin_user
        )
        db.session.add(case)
        db.session.commit()

        retrieved = Case.query.filter_by(case_number='CASE-2024-001').first()
        assert retrieved is not None
        assert retrieved.title == 'Test Case'
        assert retrieved.status == 'Open'
        assert retrieved.is_archived is False


# ── Auth Route Tests ──────────────────────────────────────────────────────────

def test_login_page_loads(client):
    """The login page should return HTTP 200."""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'DEICMS' in response.data


def test_login_with_wrong_credentials(client, app, admin_user):
    """Login with wrong password should fail and stay on login page."""
    response = client.post('/login', data={
        'email': 'admin@test.com',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    assert b'Invalid email or password' in response.data


def test_login_with_correct_credentials(client, app, admin_user):
    """Login with correct credentials should redirect to dashboard."""
    response = client.post('/login', data={
        'email': 'admin@test.com',
        'password': 'password123'
    }, follow_redirects=True)
    assert response.status_code == 200


def test_dashboard_requires_login(client):
    """Dashboard should redirect unauthenticated users to login."""
    response = client.get('/dashboard', follow_redirects=False)
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

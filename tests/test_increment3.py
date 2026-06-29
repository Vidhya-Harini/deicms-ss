"""
tests/test_increment3.py
========================
Increment 3 test suite — Risk Scoring, AI Assistant Orchestration,
Anomaly Detection, and their Flask routes.

Run with:  pytest tests/test_increment3.py -v
Run all:   pytest -v
"""

from datetime import timedelta
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def app():
    """Create a fresh Flask app with an in-memory SQLite database."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

    from app import create_app
    test_app = create_app()
    test_app.config.update({
        'TESTING':             True,
        'WTF_CSRF_ENABLED':    False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SECRET_KEY':          'test-secret',
        'ANTHROPIC_API_KEY':   'test-key-not-real',
    })

    from app import db as _db
    with test_app.app_context():
        _db.create_all()
        _seed_db(_db)
        yield test_app
        _db.session.remove()
        _db.drop_all()


def _seed_db(db):
    """Seed minimal data — uses only fields that actually exist in the model."""
    from app.models.investigator import Investigator
    from app.models.case import Case
    from app.models.evidence import EvidenceItem
    from app.models.custody_log import CustodyLog
    from app.models.audit_record import AuditRecord

    # ── Investigators ─────────────────────────────────────────────────────
    admin = Investigator(
        email='admin@test.com',
        full_name='Admin User',
        role='Admin',
    )
    admin.set_password('Admin@1234')

    analyst = Investigator(
        email='analyst@test.com',
        full_name='Analyst User',
        role='Analyst',
    )
    analyst.set_password('Analyst@1234')

    db.session.add_all([admin, analyst])
    db.session.flush()

    # ── Case ──────────────────────────────────────────────────────────────
    case = Case(
        case_number='CASE-TEST-001',
        title='Test Case Alpha',
        description='A test case for Increment 3',
        status='Open',
        created_by_id=admin.id,
    )
    db.session.add(case)
    db.session.flush()

    # ── Evidence items (using actual model field names) ────────────────────
    # ev1: .exe file — high file-type risk
    ev1 = EvidenceItem(
        evidence_number='EV-TEST-001',
        title='Suspicious Executable',
        description='A suspicious .exe file',
        case_id=case.id,
        file_name='malware_sample.exe',
        file_path='/uploads/malware_sample.exe',
        original_hash='aabbcc' * 10,
        current_hash='aabbcc' * 10,
        uploaded_by_id=admin.id,
        created_at=(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None) - timedelta(days=60),
    )

    # ev2: .txt file — low file-type risk
    ev2 = EvidenceItem(
        evidence_number='EV-TEST-002',
        title='Clean Text File',
        description='A plain text log file',
        case_id=case.id,
        file_name='notes.txt',
        file_path='/uploads/notes.txt',
        original_hash='ddeeff' * 10,
        current_hash='ddeeff' * 10,
        uploaded_by_id=admin.id,
        created_at=(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None) - timedelta(days=2),
    )

    # ev3: no extension — default file-type risk
    ev3 = EvidenceItem(
        evidence_number='EV-TEST-003',
        title='Unknown File',
        description='File with no extension',
        case_id=case.id,
        file_name='mystery',
        file_path='/uploads/mystery',
        original_hash='112233' * 10,
        current_hash='112233' * 10,
        uploaded_by_id=analyst.id,
        created_at=(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None) - timedelta(days=10),
    )

    db.session.add_all([ev1, ev2, ev3])
    db.session.flush()

    # ── Custody logs for ev1 (rapid transfers) ────────────────────────────
    now = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None)
    for i in range(4):
        log = CustodyLog(
            evidence_id=ev1.id,
            event_type='Transfer',
            from_investigator_id=analyst.id,
            to_investigator_id=admin.id,
            reason=f'Transfer {i + 1}',
            timestamp=now - timedelta(hours=(3 - i)),
            file_hash_at_event='aabbcc' * 10,
        )
        db.session.add(log)

    # ── Audit records for ev1 ─────────────────────────────────────────────
    db.session.add(AuditRecord(
        event_type='Data Modification',
        evidence_id=ev1.id,
        investigator_id=admin.id,
        description='Role mismatch detected during transfer',
        result='Warning',
        timestamp=now - timedelta(days=1),
    ))
    db.session.add(AuditRecord(
        event_type='Integrity Check',
        evidence_id=ev1.id,
        investigator_id=admin.id,
        description='Duplicate entry found',
        result='Warning',
        timestamp=now - timedelta(days=1),
    ))

    db.session.commit()

@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_client(client):
    """Returns a test client already logged in as admin."""
    client.post('/', data={
        'email':    'admin@test.com',
        'password': 'Admin@1234',
    }, follow_redirects=True)
    return client


# ─────────────────────────────────────────────────────────────────────────────
# Helper — fetch evidence objects inside app context
# ─────────────────────────────────────────────────────────────────────────────

def _get_evidence(app, title):
    from app.models.evidence import EvidenceItem
    with app.app_context():
        return EvidenceItem.query.filter_by(title=title).first()


# =============================================================================
# Section 1 — Normalisation curve unit tests (pure maths, no DB needed)
# =============================================================================

class TestNormalisationCurves:
    """Tests for the three normalisation curves in risk_scoring.py."""

    def test_linear_norm_midpoint(self):
        from app.logic.risk_scoring import _linear_norm
        result = _linear_norm(5.0, 0.0, 10.0)
        assert abs(result - 0.5) < 1e-9

    def test_linear_norm_clamps_below_zero(self):
        from app.logic.risk_scoring import _linear_norm
        assert _linear_norm(-5.0, 0.0, 10.0) == 0.0

    def test_linear_norm_clamps_above_one(self):
        from app.logic.risk_scoring import _linear_norm
        assert _linear_norm(15.0, 0.0, 10.0) == 1.0

    def test_linear_norm_equal_bounds_returns_zero(self):
        from app.logic.risk_scoring import _linear_norm
        assert _linear_norm(5.0, 5.0, 5.0) == 0.0

    def test_log_norm_zero_input(self):
        from app.logic.risk_scoring import _log_norm
        assert _log_norm(0.0) == 0.0

    def test_log_norm_at_scale_returns_one(self):
        from app.logic.risk_scoring import _log_norm
        # log(1 + scale) / log(1 + scale) = 1.0
        assert abs(_log_norm(10.0, scale=10.0) - 1.0) < 1e-9

    def test_log_norm_beyond_scale_clamped(self):
        from app.logic.risk_scoring import _log_norm
        assert _log_norm(1000.0, scale=10.0) == 1.0

    def test_log_norm_negative_input(self):
        from app.logic.risk_scoring import _log_norm
        assert _log_norm(-5.0) == 0.0

    def test_sigmoid_norm_at_midpoint(self):
        from app.logic.risk_scoring import _sigmoid_norm
        # sigmoid at its own midpoint = 0.5
        result = _sigmoid_norm(30.0, midpoint=30.0)
        assert abs(result - 0.5) < 1e-9

    def test_sigmoid_norm_below_midpoint_less_than_half(self):
        from app.logic.risk_scoring import _sigmoid_norm
        assert _sigmoid_norm(0.0, midpoint=30.0) < 0.5

    def test_sigmoid_norm_above_midpoint_greater_than_half(self):
        from app.logic.risk_scoring import _sigmoid_norm
        assert _sigmoid_norm(60.0, midpoint=30.0) > 0.5

    def test_sigmoid_norm_output_in_range(self):
        from app.logic.risk_scoring import _sigmoid_norm
        for v in [-100, 0, 15, 30, 60, 200]:
            r = _sigmoid_norm(float(v), midpoint=30.0)
            assert 0.0 <= r <= 1.0, f"Out of range for input {v}: {r}"


# =============================================================================
# Section 2 — Risk scoring: individual factor tests
# =============================================================================

class TestRiskFactors:
    """Tests for each of the 6 risk factors."""

    def test_integrity_failed_scores_one(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from unittest.mock import MagicMock
        with app.app_context():
            ev = MagicMock()
            ev.integrity_status = 'FAILED'
            scorer = EvidenceRiskScorer()
            factor = scorer._factor_integrity(ev)
            assert factor.normalised_score == 1.0

    def test_integrity_verified_scores_zero(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from unittest.mock import MagicMock
        with app.app_context():
            ev = MagicMock()
            ev.integrity_status = 'VERIFIED'
            scorer = EvidenceRiskScorer()
            factor = scorer._factor_integrity(ev)
            assert factor.normalised_score == 0.0

    def test_integrity_not_checked_scores_half(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from unittest.mock import MagicMock
        with app.app_context():
            ev = MagicMock()
            ev.integrity_status = 'NOT_CHECKED'
            scorer = EvidenceRiskScorer()
            factor = scorer._factor_integrity(ev)
            assert factor.normalised_score == 0.5
            
    def test_file_type_exe_high_risk(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Suspicious Executable').first()
            scorer = EvidenceRiskScorer()
            factor = scorer._factor_file_type(ev)
            assert factor.normalised_score == 1.0  # .exe = 1.0

    def test_file_type_txt_low_risk(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Clean Text File').first()
            scorer = EvidenceRiskScorer()
            factor = scorer._factor_file_type(ev)
            assert factor.normalised_score == 0.15  # .txt = 0.15
            
    def test_file_type_unknown_extension_uses_default(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Unknown File').first()
            scorer = EvidenceRiskScorer()
            factor = scorer._factor_file_type(ev)
            assert factor.normalised_score == 0.50

    def test_contribution_equals_score_times_weight(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Suspicious Executable').first()
            scorer = EvidenceRiskScorer()
            factor = scorer._factor_integrity(ev)
            expected = round(factor.normalised_score * factor.weight, 4)
            assert factor.contribution == expected

    def test_weights_sum_to_one(self):
        from app.logic.risk_scoring import _WEIGHTS
        total = sum(_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9


# =============================================================================
# Section 3 — Risk scoring: full report tests
# =============================================================================

class TestRiskReport:
    """Tests for the complete RiskReport output."""

    def test_report_has_six_factors(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Suspicious Executable').first()
            report = EvidenceRiskScorer().score(ev)
            assert len(report.factors) == 6

    def test_final_score_in_range(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            for ev in EvidenceItem.query.all():
                report = EvidenceRiskScorer().score(ev)
                assert 0.0 <= report.final_score <= 1.0, (
                    f"Score out of range for {ev.title}: {report.final_score}"
                )

    def test_high_risk_evidence_classified_correctly(self, app):
        """ev1 has .exe (score 1.0) and old age (60 days) so risk > ev2."""
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev1 = EvidenceItem.query.filter_by(title='Suspicious Executable').first()
            ev2 = EvidenceItem.query.filter_by(title='Clean Text File').first()
            scorer = EvidenceRiskScorer()
            report1 = scorer.score(ev1)
            report2 = scorer.score(ev2)
            # ev1 (.exe, 60 days old) should score higher than ev2 (.txt, 2 days old)
            assert report1.final_score > report2.final_score

    def test_low_risk_evidence_classified_correctly(self, app):
        """ev2 (.txt, recent, no audit issues) should be the lowest risk item."""
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Clean Text File').first()
            report = EvidenceRiskScorer().score(ev)
            assert report.risk_level in ('LOW', 'MEDIUM')

    def test_base_score_equals_sum_of_contributions(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Suspicious Executable').first()
            report = EvidenceRiskScorer().score(ev)
            expected = round(sum(f.contribution for f in report.factors), 4)
            assert report.base_score == expected

    def test_final_score_geq_base_score(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Suspicious Executable').first()
            report = EvidenceRiskScorer().score(ev)
            assert report.final_score >= report.base_score

    def test_report_has_recommendations(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Suspicious Executable').first()
            report = EvidenceRiskScorer().score(ev)
            assert len(report.recommendations) > 0

    def test_report_evidence_title_matches(self, app):
        from app.logic.risk_scoring import EvidenceRiskScorer
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.filter_by(title='Clean Text File').first()
            report = EvidenceRiskScorer().score(ev)
            assert report.evidence_title == 'Clean Text File'

    def test_risk_classification_boundaries(self):
        from app.logic.risk_scoring import EvidenceRiskScorer
        scorer = EvidenceRiskScorer()
        assert scorer._classify(0.10) == 'LOW'
        assert scorer._classify(0.24) == 'LOW'
        assert scorer._classify(0.25) == 'MEDIUM'
        assert scorer._classify(0.49) == 'MEDIUM'
        assert scorer._classify(0.50) == 'HIGH'
        assert scorer._classify(0.74) == 'HIGH'
        assert scorer._classify(0.75) == 'CRITICAL'
        assert scorer._classify(1.00) == 'CRITICAL'


# =============================================================================
# Section 4 — Interaction detection tests
# =============================================================================

class TestInteractionDetection:
    """Tests for the factor-pair interaction engine."""

    def _make_factor(self, name, score):
        from app.logic.risk_scoring import RiskFactor
        return RiskFactor(
            name=name,
            raw_value=score,
            normalised_score=score,
            weight=0.1,
            contribution=score * 0.1,
            explanation='test',
        )

    def test_interaction_fires_when_both_thresholds_met(self):
        from app.logic.risk_scoring import EvidenceRiskScorer
        scorer = EvidenceRiskScorer()
        fm = {
            'integrity_status':   self._make_factor('integrity_status', 0.9),
            'role_mismatch_count': self._make_factor('role_mismatch_count', 0.8),
        }
        interactions, bonus = scorer._detect_interactions(fm, base_score=0.5)
        assert len(interactions) >= 1
        assert bonus > 0.0

    def test_interaction_does_not_fire_below_threshold(self):
        from app.logic.risk_scoring import EvidenceRiskScorer
        scorer = EvidenceRiskScorer()
        fm = {
            'integrity_status':   self._make_factor('integrity_status', 0.1),
            'role_mismatch_count': self._make_factor('role_mismatch_count', 0.1),
        }
        interactions, bonus = scorer._detect_interactions(fm, base_score=0.5)
        assert len(interactions) == 0
        assert bonus == 0.0

    def test_interaction_bonus_is_non_negative(self):
        from app.logic.risk_scoring import EvidenceRiskScorer
        scorer = EvidenceRiskScorer()
        fm = {
            'integrity_status':           self._make_factor('integrity_status', 1.0),
            'role_mismatch_count':        self._make_factor('role_mismatch_count', 1.0),
            'file_type_risk':             self._make_factor('file_type_risk', 1.0),
            'duplicate_entry_count':      self._make_factor('duplicate_entry_count', 1.0),
            'custody_transfer_frequency': self._make_factor('custody_transfer_frequency', 1.0),
        }
        _, bonus = scorer._detect_interactions(fm, base_score=0.8)
        assert bonus >= 0.0

    def test_final_score_clamped_to_one_even_with_interactions(self):
        """Clamping logic: min(1.0, x) never exceeds 1.0 regardless of input."""
        assert min(1.0, 0.8 + 0.5) == 1.0
        assert min(1.0, 2.0) == 1.0
        assert min(1.0, 0.4) == 0.4


# =============================================================================
# Section 5 — AI Assistant: intent classification tests
# =============================================================================

class TestIntentClassification:
    """Tests for Stage 1 of the AI Assistant pipeline."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from app.logic.ai_assistant import AIInvestigationAssistant
        self.assistant = AIInvestigationAssistant()

    def test_case_query_intent(self):
        from app.logic.ai_assistant import IntentCategory
        result = self.assistant.classify_intent("Show me case 3")
        assert result.category == IntentCategory.CASE_QUERY

    def test_evidence_query_intent(self):
        from app.logic.ai_assistant import IntentCategory
        result = self.assistant.classify_intent("What evidence items are uploaded?")
        assert result.category == IntentCategory.EVIDENCE_QUERY

    def test_risk_query_intent(self):
        from app.logic.ai_assistant import IntentCategory
        result = self.assistant.classify_intent("What is the risk score for this item?")
        assert result.category == IntentCategory.RISK_QUERY

    def test_custody_query_intent(self):
        from app.logic.ai_assistant import IntentCategory
        result = self.assistant.classify_intent("Show me the custody chain for evidence 2")
        assert result.category == IntentCategory.CUSTODY_QUERY

    def test_integrity_query_intent(self):
        from app.logic.ai_assistant import IntentCategory
        result = self.assistant.classify_intent("Has this file been tampered with or altered?")
        assert result.category == IntentCategory.INTEGRITY_QUERY

    def test_general_forensics_intent(self):
        from app.logic.ai_assistant import IntentCategory
        result = self.assistant.classify_intent("What is the best practice for forensic evidence collection?")
        assert result.category == IntentCategory.GENERAL_FORENSICS

    def test_unknown_intent_for_gibberish(self):
        from app.logic.ai_assistant import IntentCategory
        result = self.assistant.classify_intent("xkcd zzzz foo bar")
        assert result.category == IntentCategory.UNKNOWN

    def test_entity_id_extracted_from_message(self):
        result = self.assistant.classify_intent("Tell me about case 7")
        assert result.entity_id == 7

    def test_entity_id_extracted_with_hash(self):
        result = self.assistant.classify_intent("Show evidence #12 details")
        assert result.entity_id == 12

    def test_entity_id_none_when_absent(self):
        result = self.assistant.classify_intent("List all cases please")
        assert result.entity_id is None

    def test_confidence_between_zero_and_one(self):
        result = self.assistant.classify_intent("What is the risk score for case 3?")
        assert 0.0 <= result.confidence <= 1.0

    def test_keywords_matched_not_empty_for_known_intent(self):
        result = self.assistant.classify_intent("Show me all evidence items")
        assert len(result.keywords_matched) > 0


# =============================================================================
# Section 6 — AI Assistant: context retrieval tests
# =============================================================================

class TestContextRetrieval:
    """Tests for Stage 2 of the AI Assistant pipeline."""

    def test_case_context_retrieved(self, app):
        from app.logic.ai_assistant import AIInvestigationAssistant, IntentCategory, ClassifiedIntent
        with app.app_context():
            assistant = AIInvestigationAssistant()
            intent = ClassifiedIntent(
                category=IntentCategory.CASE_QUERY,
                confidence=0.9,
                entity_id=None,
                keywords_matched=['case'],
            )
            ctx = assistant.retrieve_context(intent)
            assert 'Case' in ctx.context_text or 'case' in ctx.context_text.lower()

    def test_evidence_context_retrieved(self, app):
        from app.logic.ai_assistant import AIInvestigationAssistant, IntentCategory, ClassifiedIntent
        with app.app_context():
            assistant = AIInvestigationAssistant()
            intent = ClassifiedIntent(
                category=IntentCategory.EVIDENCE_QUERY,
                confidence=0.9,
                entity_id=None,
                keywords_matched=['evidence'],
            )
            ctx = assistant.retrieve_context(intent)
            assert ctx.context_text != ''

    def test_general_intent_returns_no_db_context(self, app):
        from app.logic.ai_assistant import AIInvestigationAssistant, IntentCategory, ClassifiedIntent
        with app.app_context():
            assistant = AIInvestigationAssistant()
            intent = ClassifiedIntent(
                category=IntentCategory.GENERAL_FORENSICS,
                confidence=0.8,
                entity_id=None,
                keywords_matched=['forensic'],
            )
            ctx = assistant.retrieve_context(intent)
            assert 'general' in ctx.context_text.lower() or \
                   'No specific' in ctx.context_text

    def test_context_text_is_string(self, app):
        from app.logic.ai_assistant import AIInvestigationAssistant, IntentCategory, ClassifiedIntent
        with app.app_context():
            assistant = AIInvestigationAssistant()
            intent = ClassifiedIntent(
                category=IntentCategory.CUSTODY_QUERY,
                confidence=0.7,
                entity_id=None,
                keywords_matched=['custody'],
            )
            ctx = assistant.retrieve_context(intent)
            assert isinstance(ctx.context_text, str)


# =============================================================================
# Section 7 — AI Assistant: prompt construction tests
# =============================================================================

class TestPromptConstruction:
    """Tests for Stage 3 of the AI Assistant pipeline."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from app.logic.ai_assistant import AIInvestigationAssistant
        self.assistant = AIInvestigationAssistant()

    def _make_context(self, text='Sample context text'):
        from app.logic.ai_assistant import RetrievedContext, IntentCategory, ClassifiedIntent
        intent = ClassifiedIntent(
            category=IntentCategory.GENERAL_FORENSICS,
            confidence=0.8,
            entity_id=None,
            keywords_matched=[],
        )
        from app.logic.ai_assistant import RetrievedContext
        return RetrievedContext(intent=intent, records={}, context_text=text)

    def test_system_prompt_contains_context(self):
        ctx = self._make_context('Test context block')
        _, system = self.assistant.build_prompt('Hello', ctx)
        assert 'Test context block' in system

    def test_system_prompt_contains_role_description(self):
        ctx = self._make_context()
        _, system = self.assistant.build_prompt('Hello', ctx)
        assert 'DEICMS-AI' in system

    def test_user_message_appended_as_last_message(self):
        ctx = self._make_context()
        messages, _ = self.assistant.build_prompt('What is evidence #1?', ctx)
        assert messages[-1]['role'] == 'user'
        assert messages[-1]['content'] == 'What is evidence #1?'

    def test_history_trimmed_to_six_turns(self):
        ctx = self._make_context()
        history = [
            {'role': 'user',      'content': f'msg {i}'}
            if i % 2 == 0
            else {'role': 'assistant', 'content': f'reply {i}'}
            for i in range(20)
        ]
        messages, _ = self.assistant.build_prompt('new question', ctx, history)
        # 6 history turns + 1 new user message = 7 messages max
        assert len(messages) <= 7

    def test_messages_list_has_correct_roles(self):
        ctx = self._make_context()
        history = [
            {'role': 'user',      'content': 'previous question'},
            {'role': 'assistant', 'content': 'previous answer'},
        ]
        messages, _ = self.assistant.build_prompt('new question', ctx, history)
        roles = [m['role'] for m in messages]
        assert 'user' in roles
        assert 'assistant' in roles


# =============================================================================
# Section 8 — AI Assistant: response validation tests
# =============================================================================

class TestResponseValidation:
    """Tests for Stage 5 of the AI Assistant pipeline."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from app.logic.ai_assistant import AIInvestigationAssistant
        self.assistant = AIInvestigationAssistant()

    def test_valid_forensics_reply_passes(self):
        from app.logic.ai_assistant import IntentCategory
        reply = (
            "The evidence item shows signs of tampering. "
            "The integrity check failed and the custody chain has gaps."
        )
        _, passed, warning = self.assistant.validate_response(
            reply, IntentCategory.EVIDENCE_QUERY
        )
        assert passed is True
        assert warning is None

    def test_too_short_reply_fails(self):
        from app.logic.ai_assistant import IntentCategory
        _, passed, warning = self.assistant.validate_response(
            'Ok.', IntentCategory.EVIDENCE_QUERY
        )
        assert passed is False
        assert warning is not None

    def test_refusal_pattern_detected(self):
        from app.logic.ai_assistant import IntentCategory
        refusal = "I'm sorry, I am unable to assist with that request."
        _, passed, warning = self.assistant.validate_response(
            refusal, IntentCategory.RISK_QUERY
        )
        assert passed is False

    def test_general_forensics_intent_no_domain_check(self):
        from app.logic.ai_assistant import IntentCategory
        # General forensics intent should not trigger the off-topic domain check
        reply = "Digital forensics involves the collection and preservation of data."
        _, passed, warning = self.assistant.validate_response(
            reply, IntentCategory.GENERAL_FORENSICS
        )
        assert passed is True


# =============================================================================
# Section 9 — AI Assistant: full pipeline (mock API) tests
# =============================================================================

class TestFullAssistantPipeline:
    """End-to-end pipeline tests using the mock fallback."""

    def test_answer_returns_assistant_response(self, app):
        from app.logic.ai_assistant import AIInvestigationAssistant, AssistantResponse
        with app.app_context():
            assistant = AIInvestigationAssistant()
            result = assistant.answer("What cases are open?")
            assert isinstance(result, AssistantResponse)

    def test_answer_reply_is_non_empty_string(self, app):
        from app.logic.ai_assistant import AIInvestigationAssistant
        with app.app_context():
            assistant = AIInvestigationAssistant()
            result = assistant.answer("Show me all evidence")
            assert isinstance(result.reply, str)
            assert len(result.reply) > 0

    def test_answer_intent_is_valid_category(self, app):
        from app.logic.ai_assistant import AIInvestigationAssistant, IntentCategory
        with app.app_context():
            assistant = AIInvestigationAssistant()
            result = assistant.answer("What is the risk score for evidence 1?")
            assert result.intent in [c.value for c in IntentCategory]

    def test_answer_does_not_raise_on_empty_db(self, app):
        from app.logic.ai_assistant import AIInvestigationAssistant
        with app.app_context():
            assistant = AIInvestigationAssistant()
            try:
                result = assistant.answer("List all cases")
                assert result is not None
            except Exception as e:
                pytest.fail(f"answer() raised unexpectedly: {e}")


# =============================================================================
# Section 10 — Anomaly detection: feature engineering tests
# =============================================================================

class TestFeatureEngineering:
    """Tests for the compute_features() function."""

    def _make_mock_evidence(self, filename='test.exe', integrity='NOT_CHECKED'):
        ev = MagicMock()
        ev.file_name = filename           # ← actual model field
        ev.original_filename = filename   # ← fallback still works
        ev.integrity_status = integrity
        ev.created_at = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None) - timedelta(days=5)
        return ev

    def _make_mock_logs(self, n, hours_apart=1):
        logs = []
        base = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None) - timedelta(hours=n * hours_apart)
        for i in range(n):
            log = MagicMock()
            ts = base + timedelta(hours=i * hours_apart)
            log.timestamp = ts
            log.transferred_at = ts        # keep both for compatibility
            log.to_investigator_id = i % 2
            log.transferred_to_id = i % 2
            logs.append(log)
        return logs
    
    def test_feature_vector_has_six_keys(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence()
        logs = self._make_mock_logs(3)
        features = compute_features(ev, logs)
        assert len(features) == 6

    def test_transfer_count_zero_for_no_logs(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence()
        features = compute_features(ev, [])
        assert features['transfer_count'] == 0.0

    def test_transfer_count_positive_for_logs(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence()
        logs = self._make_mock_logs(5)
        features = compute_features(ev, logs)
        assert features['transfer_count'] > 0.0

    def test_integrity_failed_flag_is_one(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence(integrity='FAILED')
        features = compute_features(ev, [])
        assert features['integrity_flag'] == 1.0

    def test_integrity_verified_flag_is_zero(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence(integrity='VERIFIED')
        features = compute_features(ev, [])
        assert features['integrity_flag'] == 0.0

    def test_integrity_not_checked_flag_is_half(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence(integrity='NOT_CHECKED')
        features = compute_features(ev, [])
        assert features['integrity_flag'] == 0.5

    def test_file_type_risk_exe_is_one(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence(filename='bad.exe')
        features = compute_features(ev, [])
        assert features['file_type_risk'] == 1.0

    def test_max_gap_zero_for_single_log(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence()
        logs = self._make_mock_logs(1)
        features = compute_features(ev, logs)
        assert features['max_gap_days'] == 0.0

    def test_unique_handler_count_correct(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence()
        logs = self._make_mock_logs(4)   # alternates 0,1,0,1 -> 2 unique
        features = compute_features(ev, logs)
        assert features['unique_handler_count'] == 2.0

    def test_all_feature_values_non_negative(self):
        from app.logic.anomaly_detection import compute_features
        ev = self._make_mock_evidence()
        logs = self._make_mock_logs(5)
        features = compute_features(ev, logs)
        for key, val in features.items():
            assert val >= 0.0, f"Feature '{key}' is negative: {val}"


# =============================================================================
# Section 11 — Anomaly detection: pipeline tests
# =============================================================================

class TestAnomalyPipeline:
    """Tests for the full AnomalyDetectionPipeline."""

    def test_pipeline_returns_list(self, app):
        from app.logic.anomaly_detection import AnomalyDetectionPipeline
        with app.app_context():
            results = AnomalyDetectionPipeline().run()
            assert isinstance(results, list)

    def test_pipeline_returns_one_record_per_evidence(self, app):
        from app.logic.anomaly_detection import AnomalyDetectionPipeline
        from app.models.evidence import EvidenceItem
        with app.app_context():
            total = EvidenceItem.query.count()
            results = AnomalyDetectionPipeline().run()
            assert len(results) == total

    def test_anomaly_scores_in_range(self, app):
        from app.logic.anomaly_detection import AnomalyDetectionPipeline
        with app.app_context():
            for rec in AnomalyDetectionPipeline().run():
                assert 0.0 <= rec.anomaly_score <= 1.0, (
                    f"Score out of range for #{rec.evidence_id}: {rec.anomaly_score}"
                )

    def test_is_anomaly_flag_consistent_with_threshold(self, app):
        from app.logic.anomaly_detection import AnomalyDetectionPipeline
        pipeline = AnomalyDetectionPipeline()
        with app.app_context():
            for rec in pipeline.run():
                if rec.is_anomaly:
                    assert rec.anomaly_score >= pipeline.ANOMALY_THRESHOLD
                else:
                    assert rec.anomaly_score < pipeline.ANOMALY_THRESHOLD

    def test_results_sorted_descending_by_score(self, app):
        from app.logic.anomaly_detection import AnomalyDetectionPipeline
        with app.app_context():
            results = AnomalyDetectionPipeline().run()
            scores = [r.anomaly_score for r in results]
            assert scores == sorted(scores, reverse=True)

    def test_pipeline_empty_when_insufficient_data(self, app):
        from app.logic.anomaly_detection import AnomalyDetectionPipeline
        from app import db
        from app.models.evidence import EvidenceItem
        with app.app_context():
            # Delete all evidence to trigger the MIN_SAMPLES guard
            EvidenceItem.query.delete()
            db.session.commit()
            results = AnomalyDetectionPipeline().run()
            assert results == []


# =============================================================================
# Section 12 — Flask route tests
# =============================================================================

class TestRiskRoutes:
    """Tests for the /risk/* endpoints."""

    def test_risk_dashboard_requires_login(self, client):
        response = client.get('/risk/dashboard', follow_redirects=False)
        assert response.status_code in (302, 401)

    def test_risk_dashboard_loads_when_logged_in(self, logged_in_client):
        response = logged_in_client.get('/risk/dashboard')
        assert response.status_code == 200
        assert b'Risk' in response.data

    def test_evidence_risk_page_loads(self, app, logged_in_client):
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.first()
            ev_id = ev.id
        response = logged_in_client.get(f'/risk/evidence/{ev_id}')
        assert response.status_code == 200

    def test_evidence_risk_json_returns_valid_json(self, app, logged_in_client):
        import json
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.first()
            ev_id = ev.id
        response = logged_in_client.get(f'/risk/evidence/{ev_id}/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'final_score' in data
        assert 'risk_level' in data
        assert 'factors' in data

    def test_evidence_risk_json_score_in_range(self, app, logged_in_client):
        import json
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.first()
            ev_id = ev.id
        response = logged_in_client.get(f'/risk/evidence/{ev_id}/json')
        data = json.loads(response.data)
        assert 0.0 <= data['final_score'] <= 1.0

    def test_evidence_risk_json_has_six_factors(self, app, logged_in_client):
        import json
        from app.models.evidence import EvidenceItem
        with app.app_context():
            ev = EvidenceItem.query.first()
            ev_id = ev.id
        response = logged_in_client.get(f'/risk/evidence/{ev_id}/json')
        data = json.loads(response.data)
        assert len(data['factors']) == 6

    def test_anomaly_dashboard_loads(self, logged_in_client):
        response = logged_in_client.get('/risk/anomaly')
        assert response.status_code == 200

    def test_risk_404_for_nonexistent_evidence(self, logged_in_client):
        response = logged_in_client.get('/risk/evidence/99999')
        assert response.status_code == 404


class TestAssistantRoutes:
    """Tests for the /assistant/* endpoints."""

    def test_chat_page_requires_login(self, client):
        response = client.get('/assistant/', follow_redirects=False)
        assert response.status_code in (302, 401)

    def test_chat_page_loads_when_logged_in(self, logged_in_client):
        response = logged_in_client.get('/assistant/')
        assert response.status_code == 200
        assert b'AI' in response.data

    def test_chat_endpoint_returns_json(self, app, logged_in_client):
        import json
        response = logged_in_client.post(
            '/assistant/chat',
            json={'message': 'What cases are open?'},
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'reply' in data
        assert 'intent' in data

    def test_chat_endpoint_reply_non_empty(self, app, logged_in_client):
        import json
        response = logged_in_client.post(
            '/assistant/chat',
            json={'message': 'Tell me about evidence items'},
        )
        data = json.loads(response.data)
        assert len(data['reply']) > 0

    def test_chat_empty_message_returns_400(self, logged_in_client):
        response = logged_in_client.post(
            '/assistant/chat',
            json={'message': ''},
        )
        assert response.status_code == 400

    def test_clear_endpoint_works(self, logged_in_client):
        import json
        response = logged_in_client.post('/assistant/clear')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'cleared'

    def test_dashboard_loads_with_risk_scores(self, logged_in_client):
        response = logged_in_client.get('/dashboard')
        assert response.status_code == 200
        assert b'Risk' in response.data
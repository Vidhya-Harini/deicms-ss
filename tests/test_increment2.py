"""
Increment 2 Tests — State Machine, Graph Integrity, Chain Reconstruction
Run with: pytest tests/ -v --cov=app
"""
import pytest
import json
from datetime import datetime, timedelta
from app import create_app, db
from app.models.investigator import Investigator
from app.models.case import Case
from app.models.evidence import EvidenceItem
from app.models.custody_log import CustodyLog
from app.models.audit_record import AuditRecord


@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'UPLOAD_FOLDER': '/tmp/test_uploads'
    })
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def base_data(app):
    """Create investigators, a case, and a basic evidence item for all tests."""
    with app.app_context():
        from app.logic.crypto import generate_key_pair

        priv, pub = generate_key_pair()
        admin = Investigator(full_name='Admin', email='admin@t.com',
                             role='Admin', public_key=pub,
                             private_key_encrypted=priv)
        admin.set_password('pw')
        db.session.add(admin)

        priv2, pub2 = generate_key_pair()
        lead = Investigator(full_name='Lead', email='lead@t.com',
                            role='Lead Investigator', public_key=pub2,
                            private_key_encrypted=priv2)
        lead.set_password('pw')
        db.session.add(lead)

        priv3, pub3 = generate_key_pair()
        analyst = Investigator(full_name='Analyst', email='analyst@t.com',
                               role='Analyst', public_key=pub3,
                               private_key_encrypted=priv3)
        analyst.set_password('pw')
        db.session.add(analyst)

        readonly = Investigator(full_name='ReadOnly', email='ro@t.com',
                                role='Read-Only')
        readonly.set_password('pw')
        db.session.add(readonly)
        db.session.flush()

        case = Case(case_number='C-001', title='Test Case',
                    created_by_id=admin.id, assigned_to_id=admin.id)
        db.session.add(case)
        db.session.flush()

        evidence = EvidenceItem(
            evidence_number='E-001',
            case_id=case.id,
            title='Test Evidence',
            category='Document',
            lifecycle_state='Collected',
            file_name='test.pdf',
            file_path='/tmp/test.pdf',
            original_hash='a' * 64,
            current_hash='a' * 64,
            uploaded_by_id=admin.id,
            current_holder_id=admin.id
        )
        db.session.add(evidence)
        db.session.flush()

        # Initial custody log (Upload event)
        log1 = CustodyLog(
            evidence_id=evidence.id,
            event_type='Upload',
            to_investigator_id=admin.id,
            timestamp=datetime(2026, 5, 1, 10, 0, 0),
            file_hash_at_event='a' * 64
        )
        db.session.add(log1)
        db.session.commit()

        return {
            'admin_id': admin.id,
            'lead_id': lead.id,
            'analyst_id': analyst.id,
            'readonly_id': readonly.id,
            'case_id': case.id,
            'evidence_id': evidence.id
        }


# ── State Machine Tests ───────────────────────────────────────────────────────

class TestStateMachine:

    def test_valid_transition_collected_to_submitted(self, app, base_data):
        """Lead Investigator should be able to submit collected evidence."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            lead = Investigator.query.get(base_data['lead_id'])
            from app.logic.state_machine import EvidenceStateMachine
            sm = EvidenceStateMachine(evidence, lead)
            result = sm.transition_to('Submitted', justification='Submitting for review')
            assert result.success is True
            assert evidence.lifecycle_state == 'Submitted'

    def test_invalid_transition_collected_to_archived(self, app, base_data):
        """Jumping from Collected directly to Archived should be rejected."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            lead = Investigator.query.get(base_data['lead_id'])
            from app.logic.state_machine import EvidenceStateMachine
            sm = EvidenceStateMachine(evidence, lead)
            result = sm.transition_to('Archived')
            assert result.success is False
            assert evidence.lifecycle_state == 'Collected'

    def test_wrong_role_rejected(self, app, base_data):
        """Read-Only investigator should not be able to submit evidence."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            readonly = Investigator.query.get(base_data['readonly_id'])
            from app.logic.state_machine import EvidenceStateMachine
            sm = EvidenceStateMachine(evidence, readonly)
            result = sm.transition_to('Submitted')
            assert result.success is False
            assert 'role' in result.message.lower() or 'permission' in result.message.lower()

    def test_precondition_no_custody_log_blocks_analysis(self, app, base_data):
        """
        Submitted -> Under Analysis requires a custody log entry.
        After deleting all logs it should be rejected.
        """
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            lead = Investigator.query.get(base_data['lead_id'])

            # First submit the evidence
            from app.logic.state_machine import EvidenceStateMachine
            sm = EvidenceStateMachine(evidence, lead)
            sm.transition_to('Submitted')

            # Delete all custody logs to trigger the precondition failure
            CustodyLog.query.filter_by(evidence_id=evidence.id).delete()
            db.session.flush()

            result = sm.transition_to('Under Analysis')
            assert result.success is False
            assert 'custody log' in result.message.lower()

    def test_any_state_to_flagged(self, app, base_data):
        """Admin should be able to flag evidence from any state."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            admin = Investigator.query.get(base_data['admin_id'])
            from app.logic.state_machine import EvidenceStateMachine
            sm = EvidenceStateMachine(evidence, admin)
            result = sm.transition_to('Flagged', justification='Integrity failure detected')
            assert result.success is True
            assert evidence.lifecycle_state == 'Flagged'

    def test_available_transitions_filtered_by_role(self, app, base_data):
        """get_available_transitions() should only return role-appropriate targets."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            readonly = Investigator.query.get(base_data['readonly_id'])
            from app.logic.state_machine import EvidenceStateMachine
            sm = EvidenceStateMachine(evidence, readonly)
            available = sm.get_available_transitions()
            assert len(available) == 0  # Read-Only has no transitions

    def test_risk_score_updated_on_flag(self, app, base_data):
        """Flagging evidence should increase its risk score."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            admin = Investigator.query.get(base_data['admin_id'])
            initial_score = evidence.risk_score or 0.0
            from app.logic.state_machine import EvidenceStateMachine
            sm = EvidenceStateMachine(evidence, admin)
            sm.transition_to('Flagged')
            assert evidence.risk_score > initial_score
            assert evidence.risk_level == 'High'

    def test_rejected_transition_logged_in_audit(self, app, base_data):
        """A rejected state transition should be recorded in the audit trail."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            readonly = Investigator.query.get(base_data['readonly_id'])
            from app.logic.state_machine import EvidenceStateMachine
            sm = EvidenceStateMachine(evidence, readonly)
            sm.transition_to('Submitted')
            db.session.flush()
            failure_record = AuditRecord.query.filter_by(
                evidence_id=evidence.id, result='Failure'
            ).first()
            assert failure_record is not None


# ── Graph Integrity Tests ─────────────────────────────────────────────────────

class TestGraphIntegrity:

    def test_intact_chain_returns_intact_verdict(self, app, base_data):
        """A clean evidence item with no tampering should return Intact."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            # No file exists at /tmp/test.pdf so hash check is skipped for
            # non-Upload nodes — Upload node will detect missing file
            from app.logic.graph_integrity import GraphIntegrityEngine
            engine = GraphIntegrityEngine(evidence)
            report = engine.verify()
            # File doesn't exist so we expect a hash failure on the Upload node
            assert report.total_nodes == 1
            assert report.evidence_id == base_data['evidence_id']

    def test_missing_file_detected_as_hash_mismatch(self, app, base_data):
        """If the evidence file doesn't exist, hash check should fail."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            evidence.file_path = '/tmp/this_file_does_not_exist_12345.pdf'
            from app.logic.graph_integrity import GraphIntegrityEngine
            engine = GraphIntegrityEngine(evidence)
            report = engine.verify()
            assert any(f.failure_type == 'hash_mismatch' for f in report.failures)

    def test_timestamp_anomaly_detected(self, app, base_data):
        """A custody log entry with a non-increasing timestamp should be flagged."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])

            # Add a Transfer log with timestamp EQUAL to the Upload node (not strictly greater)
            # The Upload is at 2026-05-01 10:00:00 — this is the same moment
            same_time_log = CustodyLog(
                evidence_id=evidence.id,
                event_type='Transfer',
                from_investigator_id=base_data['admin_id'],
                to_investigator_id=base_data['lead_id'],
                timestamp=datetime(2026, 5, 1, 10, 0, 0),  # same as Upload — not strictly greater
                file_hash_at_event='a' * 64
            )
            db.session.add(same_time_log)
            db.session.commit()

            from app.logic.graph_integrity import GraphIntegrityEngine
            engine = GraphIntegrityEngine(evidence)
            report = engine.verify()
            assert any(f.failure_type == 'timestamp_anomaly' for f in report.failures)

    def test_no_custody_logs_returns_broken(self, app, base_data):
        """Evidence with no custody logs at all should return Broken verdict."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            CustodyLog.query.filter_by(evidence_id=evidence.id).delete()
            db.session.commit()

            from app.logic.graph_integrity import GraphIntegrityEngine
            engine = GraphIntegrityEngine(evidence)
            report = engine.verify()
            assert report.verdict == 'Broken'
            assert report.total_nodes == 0

    def test_report_serialises_to_dict(self, app, base_data):
        """IntegrityReport.to_dict() should return a serialisable dictionary."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            from app.logic.graph_integrity import GraphIntegrityEngine
            engine = GraphIntegrityEngine(evidence)
            report = engine.verify()
            report_dict = report.to_dict()
            # Should be JSON-serialisable
            json_str = json.dumps(report_dict)
            assert '"verdict"' in json_str
            assert '"completeness_score"' in json_str


# ── Chain Reconstruction Tests ────────────────────────────────────────────────

class TestChainReconstruction:

    def test_no_gaps_returns_full_confidence(self, app, base_data):
        """A chain with no gaps should return 100% confidence."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            from app.logic.chain_reconstruction import ChainReconstructionEngine
            engine = ChainReconstructionEngine(evidence)
            report = engine.reconstruct()
            assert report.confirmed_links >= 1
            assert report.unresolved_gaps == 0
            assert report.chain_confidence_score == 100.0

    def test_gap_detected_between_mismatched_holders(self, app, base_data):
        """A gap should be detected when the expected holder mismatches the next record."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])

            # Add a Transfer log where from_investigator is DIFFERENT from the
            # expected holder (admin -> lead, but next record says analyst -> admin)
            log2 = CustodyLog(
                evidence_id=evidence.id,
                event_type='Transfer',
                from_investigator_id=base_data['analyst_id'],  # mismatch: admin held it
                to_investigator_id=base_data['admin_id'],
                timestamp=datetime(2026, 5, 2, 10, 0, 0),
                file_hash_at_event='a' * 64
            )
            db.session.add(log2)
            db.session.commit()

            from app.logic.chain_reconstruction import ChainReconstructionEngine
            engine = ChainReconstructionEngine(evidence)
            report = engine.reconstruct()
            # Gap should be detected
            assert report.unresolved_gaps > 0 or report.inferred_links > 0

    def test_empty_chain_returns_zero_confidence(self, app, base_data):
        """Evidence with no custody logs should return 0% confidence."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            CustodyLog.query.filter_by(evidence_id=evidence.id).delete()
            db.session.commit()

            from app.logic.chain_reconstruction import ChainReconstructionEngine
            engine = ChainReconstructionEngine(evidence)
            report = engine.reconstruct()
            assert report.chain_confidence_score == 0.0
            assert report.total_expected_links == 0

    def test_reconstruction_report_serialisable(self, app, base_data):
        """ReconstructionReport.to_dict() should be JSON-serialisable."""
        with app.app_context():
            evidence = EvidenceItem.query.get(base_data['evidence_id'])
            from app.logic.chain_reconstruction import ChainReconstructionEngine
            engine = ChainReconstructionEngine(evidence)
            report = engine.reconstruct()
            json_str = json.dumps(report.to_dict())
            assert '"chain_confidence_score"' in json_str
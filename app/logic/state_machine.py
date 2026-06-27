"""
Evidence Lifecycle State Machine
Section 2C — Complex Application Logic (Feature 4)

Enforces legally meaningful transitions between evidence lifecycle states.
No evidence item can skip a state, transition backwards without authorisation,
or be moved by an investigator who lacks the required role.

States:
    Collected -> Submitted -> Under Analysis <-> Transferred -> Archived
    Any state -> Flagged (on integrity failure)
    Flagged -> Under Analysis (Admin resolution only)

Each transition has:
    - A required minimum role
    - A list of preconditions that must be satisfied before the transition
    - An automatic audit log entry on success or failure
"""
from datetime import datetime
from typing import Callable, List, Optional


# ── Transition table ──────────────────────────────────────────────────────────
#
# Structure:
#   (current_state, target_state) -> {
#       'required_roles': [...],   # investigator must have one of these roles
#       'preconditions': [...]     # list of (check_fn, error_message) tuples
#   }
#
# Precondition functions receive (evidence_item, investigator) as arguments
# and return True if the condition is satisfied.

def _has_custody_log(evidence, investigator) -> bool:
    """At least one custody log entry must exist before moving to Under Analysis."""
    return evidence.custody_logs.count() > 0


def _has_integrity_check(evidence, investigator) -> bool:
    """A passed integrity check must exist before archiving."""
    from app.models.audit_record import AuditRecord
    import json
    checks = (AuditRecord.query
              .filter_by(evidence_id=evidence.id, event_type='Integrity Check')
              .all())
    for check in checks:
        if check.integrity_check_result:
            try:
                result = json.loads(check.integrity_check_result)
                if result.get('verdict') == 'Intact':
                    return True
            except Exception:
                continue
    return False


def _not_flagged(evidence, investigator) -> bool:
    """Cannot transition out of Flagged state unless resolved by Admin."""
    return evidence.lifecycle_state != 'Flagged'


TRANSITION_TABLE = {
    # Collected -> Submitted: Lead Investigator or Admin, no extra preconditions
    ('Collected', 'Submitted'): {
        'required_roles': ['Admin', 'Lead Investigator'],
        'preconditions': []
    },
    # Submitted -> Under Analysis: Analyst, Lead, or Admin
    # Requires at least one custody log entry
    ('Submitted', 'Under Analysis'): {
        'required_roles': ['Admin', 'Lead Investigator', 'Analyst'],
        'preconditions': [
            (_has_custody_log,
             'At least one custody log entry must exist before starting analysis.')
        ]
    },
    # Under Analysis -> Transferred: any authenticated role
    ('Under Analysis', 'Transferred'): {
        'required_roles': ['Admin', 'Lead Investigator', 'Analyst'],
        'preconditions': []
    },
    # Transferred -> Under Analysis: any authenticated role
    ('Transferred', 'Under Analysis'): {
        'required_roles': ['Admin', 'Lead Investigator', 'Analyst'],
        'preconditions': []
    },
    # Under Analysis -> Archived: Lead or Admin
    # Requires a passed integrity check
    ('Under Analysis', 'Archived'): {
        'required_roles': ['Admin', 'Lead Investigator'],
        'preconditions': [
            (_has_integrity_check,
             'A passed integrity check (verdict: Intact) is required before archiving.')
        ]
    },
    # Submitted -> Archived: Admin only (emergency skip)
    ('Submitted', 'Archived'): {
        'required_roles': ['Admin'],
        'preconditions': []
    },
    # Any -> Flagged: Admin or Lead (triggered by integrity failure)
    ('Collected', 'Flagged'):      {'required_roles': ['Admin', 'Lead Investigator'], 'preconditions': []},
    ('Submitted', 'Flagged'):      {'required_roles': ['Admin', 'Lead Investigator'], 'preconditions': []},
    ('Under Analysis', 'Flagged'): {'required_roles': ['Admin', 'Lead Investigator'], 'preconditions': []},
    ('Transferred', 'Flagged'):    {'required_roles': ['Admin', 'Lead Investigator'], 'preconditions': []},
    ('Archived', 'Flagged'):       {'required_roles': ['Admin', 'Lead Investigator'], 'preconditions': []},
    # Flagged -> Under Analysis: Admin only (after resolving the integrity issue)
    ('Flagged', 'Under Analysis'): {
        'required_roles': ['Admin'],
        'preconditions': []
    },
}


# ── State machine result ──────────────────────────────────────────────────────

class TransitionResult:
    """Returned by StateMachine.transition() to indicate success or failure."""

    def __init__(self, success: bool, message: str, new_state: Optional[str] = None):
        self.success = success
        self.message = message
        self.new_state = new_state  # None on failure

    def __bool__(self):
        return self.success


# ── State machine ─────────────────────────────────────────────────────────────

class EvidenceStateMachine:
    """
    Implements the Evidence Lifecycle State Machine.

    Usage:
        sm = EvidenceStateMachine(evidence_item, investigator)
        result = sm.transition_to('Under Analysis', justification='Starting lab analysis')
        if result:
            db.session.commit()
        else:
            flash(result.message)
    """

    def __init__(self, evidence_item, investigator):
        self.evidence = evidence_item
        self.investigator = investigator

    def transition_to(self, target_state: str,
                      justification: str = '') -> TransitionResult:
        """
        Attempt a state transition. Runs the full validation pipeline:
          1. Check the (current, target) pair exists in the transition table
          2. Check the investigator's role is permitted
          3. Evaluate all preconditions
          4. Execute the transition and log it
          5. Recalculate the risk score for the evidence item

        Returns a TransitionResult indicating success or failure with
        a descriptive message identifying exactly which condition failed.
        """
        current_state = self.evidence.lifecycle_state

        # Step 1: Check transition is defined
        transition_key = (current_state, target_state)
        if transition_key not in TRANSITION_TABLE:
            result = TransitionResult(
                success=False,
                message=(
                    f"Transition from '{current_state}' to '{target_state}' "
                    f"is not a valid state transition for evidence items."
                )
            )
            self._log_rejection(target_state, result.message)
            return result

        transition = TRANSITION_TABLE[transition_key]

        # Step 2: Check role permission
        if self.investigator.role not in transition['required_roles']:
            result = TransitionResult(
                success=False,
                message=(
                    f"Your role '{self.investigator.role}' does not have permission "
                    f"to transition evidence to '{target_state}'. "
                    f"Required: {', '.join(transition['required_roles'])}."
                )
            )
            self._log_rejection(target_state, result.message)
            return result

        # Step 3: Evaluate all preconditions
        for check_fn, error_message in transition['preconditions']:
            if not check_fn(self.evidence, self.investigator):
                result = TransitionResult(
                    success=False,
                    message=f"Precondition not met: {error_message}"
                )
                self._log_rejection(target_state, result.message)
                return result

        # Step 4: Execute the transition
        old_state = self.evidence.lifecycle_state
        self.evidence.lifecycle_state = target_state

        # Log the successful transition in the audit trail
        self._log_success(old_state, target_state, justification)

        # Step 5: Recalculate risk score to reflect the new state
        self._recalculate_risk_score()

        return TransitionResult(
            success=True,
            message=(
                f"Evidence '{self.evidence.evidence_number}' successfully "
                f"transitioned from '{old_state}' to '{target_state}'."
            ),
            new_state=target_state
        )

    def get_available_transitions(self) -> List[str]:
        """
        Return the list of states the evidence can currently transition to,
        given the current investigator's role. Used to build the UI dropdown.
        """
        current_state = self.evidence.lifecycle_state
        available = []

        for (from_state, to_state), transition in TRANSITION_TABLE.items():
            if (from_state == current_state and
                    self.investigator.role in transition['required_roles']):
                available.append(to_state)

        return available

    def _log_success(self, old_state: str, new_state: str, justification: str):
        """Write a success audit record for this transition."""
        from app import db
        from app.models.audit_record import AuditRecord
        audit = AuditRecord(
            event_type='State Change',
            investigator_id=self.investigator.id,
            evidence_id=self.evidence.id,
            case_id=self.evidence.case_id,
            description=(
                f"State transition: '{old_state}' -> '{new_state}'. "
                f"Justification: {justification or 'None provided'}."
            ),
            result='Success'
        )
        db.session.add(audit)

    def _log_rejection(self, target_state: str, reason: str):
        """Write a failure audit record for a rejected transition attempt."""
        from app import db
        from app.models.audit_record import AuditRecord
        audit = AuditRecord(
            event_type='Failed Attempt',
            investigator_id=self.investigator.id,
            evidence_id=self.evidence.id,
            case_id=self.evidence.case_id,
            description=(
                f"Rejected transition to '{target_state}' "
                f"for evidence {self.evidence.evidence_number}. "
                f"Reason: {reason}"
            ),
            result='Failure'
        )
        db.session.add(audit)

    def _recalculate_risk_score(self):
        """
        Adjust the evidence risk score when the lifecycle state changes.
        Flagged state carries the highest base risk.
        Archived state carries the lowest.
        Full multi-factor scoring is implemented in Increment 3.
        """
        state_risk_map = {
            'Flagged':        1.0,
            'Under Analysis': 0.6,
            'Transferred':    0.5,
            'Submitted':      0.4,
            'Collected':      0.3,
            'Archived':       0.1
        }
        base_score = state_risk_map.get(self.evidence.lifecycle_state, 0.5)

        # Combine with existing risk score (simple average for now)
        current = self.evidence.risk_score or 0.0
        self.evidence.risk_score = round((current + base_score) / 2, 3)

        # Update risk level label — Flagged always gets High regardless of score
        if self.evidence.lifecycle_state == 'Flagged':
            self.evidence.risk_level = 'High'
        elif self.evidence.risk_score >= 0.7:
            self.evidence.risk_level = 'High'
        elif self.evidence.risk_score >= 0.4:
            self.evidence.risk_level = 'Medium'
        else:
            self.evidence.risk_level = 'Low'
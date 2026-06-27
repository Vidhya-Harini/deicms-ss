from datetime import datetime, timezone
from app import db
from sqlalchemy import event


class AuditRecord(db.Model):
    """
    Logs every significant system event.
    This is a write-only table: records are never modified or deleted.
    It provides a full audit trail for compliance and forensic review.
    """
    __tablename__ = 'audit_records'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Type of system event being logged
    event_type = db.Column(
        db.Enum(
            'Login', 'Logout', 'File Access', 'Data Modification',
            'Integrity Check', 'State Change', 'Failed Attempt',
            'Role Change', 'Key Generation',
            name='audit_event_type'
        ),
        nullable=False
    )

    # Who triggered the event (null for automated system events)
    investigator_id = db.Column(db.Integer, db.ForeignKey('investigators.id'),
                                 nullable=True)

    # Which evidence item the event relates to (if any)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence_items.id'),
                             nullable=True)

    # Which case the event relates to (if any)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=True)

    # Human-readable description of what happened
    description = db.Column(db.Text, nullable=False)

    # IP address of the client that triggered the event
    ip_address = db.Column(db.String(50), nullable=True)

    # Outcome of the event
    result = db.Column(
        db.Enum('Success', 'Failure', 'Warning', name='audit_result'),
        nullable=False,
        default='Success'
    )

    # For integrity check events: stores the full result as JSON
    # e.g. {"verdict": "Intact", "completeness": 100, "failures": []}
    integrity_check_result = db.Column(db.Text, nullable=True)

    # When the event occurred
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    def __repr__(self):
        return (f'<AuditRecord {self.event_type} '
                f'by investigator={self.investigator_id} at={self.timestamp}>')

@event.listens_for(AuditRecord, 'before_update')
def block_audit_update(mapper, connection, target):
    raise RuntimeError("Audit records cannot be modified")

@event.listens_for(AuditRecord, 'before_delete')
def block_audit_delete(mapper, connection, target):
    raise RuntimeError("Audit records cannot be deleted")

from datetime import datetime, timezone
from app import db


class Case(db.Model):
    """
    Represents an investigation case.
    Each case contains one or more evidence items.
    """
    __tablename__ = 'cases'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # A human-readable unique identifier, e.g. "CASE-2024-001"
    case_number = db.Column(db.String(50), unique=True, nullable=False)

    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    jurisdiction = db.Column(db.String(150), nullable=True)

    # Case lifecycle status
    status = db.Column(
        db.Enum('Open', 'Active', 'Pending', 'Closed', 'Archived', name='case_status'),
        nullable=False,
        default='Open'
    )

    # Soft delete flag (archived cases are hidden from normal views)
    is_archived = db.Column(db.Boolean, default=False, nullable=False)

    # Dates
    date_opened = db.Column(db.Date, nullable=False, default=lambda: datetime.now(timezone.utc))
    date_closed = db.Column(db.Date, nullable=True)

    # Who created and who is assigned to this case
    created_by_id = db.Column(db.Integer, db.ForeignKey('investigators.id'),
                               nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('investigators.id'),
                                nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    # ── Relationships ─────────────────────────────────────────────────────
    # All evidence items belonging to this case
    evidence_items = db.relationship('EvidenceItem', backref='case', lazy='dynamic',
                                     cascade='all, delete-orphan')
    # Audit records related to this case
    audit_records = db.relationship('AuditRecord', backref='case', lazy='dynamic')

    def __repr__(self):
        return f'<Case {self.case_number}: {self.title}>'

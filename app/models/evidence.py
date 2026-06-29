from datetime import timedelta
from datetime import datetime, timezone
from app import db


class EvidenceItem(db.Model):
    """
    Represents a single piece of digital evidence within a case.
    This is the central entity of the system.
    """
    __tablename__ = 'evidence_items'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Human-readable identifier, e.g. "E-042"
    evidence_number = db.Column(db.String(50), unique=True, nullable=False)

    # Which case this evidence belongs to
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)

    # Basic metadata
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Category of the evidence file
    category = db.Column(
        db.Enum('Image', 'Video', 'Audio', 'Document', 'Database',
                'Log File', 'Other', name='evidence_category'),
        nullable=False,
        default='Other'
    )

    # Evidence lifecycle state (managed by the State Machine in Increment 2)
    # Collected -> Submitted -> Under Analysis <-> Transferred -> Archived
    # Any state can transition to Flagged if an integrity issue is detected
    lifecycle_state = db.Column(
        db.Enum('Collected', 'Submitted', 'Under Analysis',
                'Transferred', 'Archived', 'Flagged', name='lifecycle_state'),
        nullable=False,
        default='Collected'
    )

    # ── File information ──────────────────────────────────────────────────
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)  # Path on the server
    file_size = db.Column(db.BigInteger, nullable=True)    # Size in bytes
    file_mime_type = db.Column(db.String(100), nullable=True)

    # ── Integrity hashes ──────────────────────────────────────────────────
    # original_hash: computed at upload, never changes — the ground truth
    original_hash = db.Column(db.String(64), nullable=False)
    # current_hash:  updated after each verified custody transfer
    current_hash = db.Column(db.String(64), nullable=False)

    # ── Extracted metadata ────────────────────────────────────────────────
    # Stored as a JSON string: EXIF data, creation timestamp, GPS coords, etc.
    exif_metadata = db.Column(db.Text, nullable=True)

    # ── Ownership & custody ───────────────────────────────────────────────
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('investigators.id'),
                                nullable=False)
    current_holder_id = db.Column(db.Integer, db.ForeignKey('investigators.id'),
                                   nullable=True)

    # Risk score computed by the Multi-Factor Risk Scoring Algorithm (Increment 3)
    risk_score = db.Column(db.Float, nullable=True, default=0.0)
    risk_level = db.Column(
        db.Enum('Low', 'Medium', 'High', name='risk_level'),
        nullable=True,
        default='Low'
    )

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None),
                           onupdate=lambda: (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None), nullable=False)

    # ── Relationships ─────────────────────────────────────────────────────
    # Full custody log for this evidence item
    custody_logs = db.relationship('CustodyLog', backref='evidence_item',
                                   lazy='dynamic', cascade='all, delete-orphan',
                                   order_by='CustodyLog.timestamp')
    # Audit records related to this evidence item
    audit_records = db.relationship('AuditRecord', backref='evidence_item',
                                    lazy='dynamic')

    def __repr__(self):
        return f'<EvidenceItem {self.evidence_number}: {self.title}>'

from datetime import datetime, timezone
from app import db


class CustodyLog(db.Model):
    """
    Records every custody event for an evidence item.
    This table is the backbone of the chain-of-custody system.
    Once a record is written, it should never be modified or deleted.
    """
    __tablename__ = 'custody_logs'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Which evidence item this log entry belongs to
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence_items.id'),
                             nullable=False)

    # Type of custody event
    event_type = db.Column(
        db.Enum('Upload', 'Transfer', 'Access', 'Verification',
                name='custody_event_type'),
        nullable=False
    )

    # Who transferred FROM (null for the initial upload event)
    from_investigator_id = db.Column(db.Integer,
                                      db.ForeignKey('investigators.id'),
                                      nullable=True)
    # Who transferred TO (null for access-only events)
    to_investigator_id = db.Column(db.Integer,
                                    db.ForeignKey('investigators.id'),
                                    nullable=True)

    # When and where the event happened
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    location = db.Column(db.String(200), nullable=True)

    # Why the transfer or access happened
    reason = db.Column(db.Text, nullable=True)

    # SHA-256 hash of the evidence file at the moment of this event
    # Used by the Graph Integrity Verification Algorithm to verify the chain
    file_hash_at_event = db.Column(db.String(64), nullable=False)

    # Ed25519 digital signature of this custody record
    # Signed by the from_investigator (or uploader for Upload events)
    digital_signature = db.Column(db.Text, nullable=False)

    # Optional notes about the event
    notes = db.Column(db.Text, nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────
    from_investigator = db.relationship('Investigator',
                                         foreign_keys=[from_investigator_id],
                                         backref='transfers_sent')
    to_investigator = db.relationship('Investigator',
                                       foreign_keys=[to_investigator_id],
                                       backref='transfers_received')

    def __repr__(self):
        return (f'<CustodyLog evidence={self.evidence_id} '
                f'event={self.event_type} at={self.timestamp}>')

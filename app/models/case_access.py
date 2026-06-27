from datetime import datetime, timezone
from app import db


class CaseAccess(db.Model):
    """
    Grants a specific investigator access to a specific case.
    Without a row in this table, non-Admin investigators cannot
    see or interact with the case (principle of least privilege).

    Admins always have access to every case regardless of this table.
    """
    __tablename__ = 'case_access'

    id = db.Column(db.Integer, primary_key=True)

    # Which case this access record applies to
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'),
                        nullable=False)

    # Which investigator is being granted access
    investigator_id = db.Column(db.Integer, db.ForeignKey('investigators.id'),
                                nullable=False)

    # Permission level within the case
    # Owner     -> created the case; can add/remove members
    # Member    -> full operational access (evidence, custody, etc.)
    # ReadOnly  -> can view but not modify
    permission = db.Column(
        db.Enum('Owner', 'Member', 'ReadOnly', name='case_permission'),
        nullable=False,
        default='Member'
    )

    # When this access was granted and by whom
    granted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)
    granted_by_id = db.Column(db.Integer, db.ForeignKey('investigators.id'),
                              nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────
    case = db.relationship('Case', backref=db.backref('access_records', lazy='dynamic'))
    investigator = db.relationship('Investigator',
                                   foreign_keys=[investigator_id],
                                   backref=db.backref('case_access_records', lazy='dynamic'))
    granted_by = db.relationship('Investigator',
                                 foreign_keys=[granted_by_id])

    # Unique constraint: one row per (case, investigator) pair
    __table_args__ = (
        db.UniqueConstraint('case_id', 'investigator_id', name='uq_case_investigator'),
    )

    def __repr__(self):
        return (f'<CaseAccess case={self.case_id} '
                f'investigator={self.investigator_id} permission={self.permission}>')

    # ── Access-control helpers ────────────────────────────────────────────
    @staticmethod
    def get_permission(case_id, investigator):
        """
        Return the investigator's permission level for a case:
        'Admin' for any Admin (full access to every case), the stored
        permission ('Owner'/'Member'/'ReadOnly') if a row exists, else None.
        """
        if investigator is None or not investigator.is_authenticated:
            return None
        if investigator.is_admin():
            return 'Admin'
        row = CaseAccess.query.filter_by(
            case_id=case_id, investigator_id=investigator.id
        ).first()
        return row.permission if row else None

    @staticmethod
    def can_access(case_id, investigator):
        """True if the investigator may view this case at all."""
        return CaseAccess.get_permission(case_id, investigator) is not None

    @staticmethod
    def can_manage_members(case_id, investigator):
        """True if the investigator may add/remove members (Admin or Owner)."""
        return CaseAccess.get_permission(case_id, investigator) in ('Admin', 'Owner')

    @staticmethod
    def grant(case_id, investigator_id, permission='Member', granted_by_id=None):
        """
        Idempotently grant (or update) a case-access row. Returns the row.
        """
        row = CaseAccess.query.filter_by(
            case_id=case_id, investigator_id=investigator_id
        ).first()
        if row:
            row.permission = permission
        else:
            row = CaseAccess(
                case_id=case_id,
                investigator_id=investigator_id,
                permission=permission,
                granted_by_id=granted_by_id,
            )
            db.session.add(row)
        return row

"""Clears evidence, custody_logs, and audit_records so seed.py will repopulate them."""
from app import create_app, db
from app.models.evidence import EvidenceItem
from app.models.custody_log import CustodyLog
from app.models.audit_record import AuditRecord

app = create_app()
with app.app_context():
    AuditRecord.query.delete()
    CustodyLog.query.delete()
    EvidenceItem.query.delete()
    db.session.commit()
    print("Cleared evidence, custody_logs, audit_records.")
    print(f"Evidence rows: {EvidenceItem.query.count()}")
    print(f"Custody log rows: {CustodyLog.query.count()}")
    print(f"Audit record rows: {AuditRecord.query.count()}")

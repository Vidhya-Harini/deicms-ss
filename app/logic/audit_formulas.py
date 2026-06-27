"""
Simple Audit Formula Checks — Section 2A of the proposal.

These are formula-based checks over database records:
  1. Time gap detection   — flags custody gaps exceeding a threshold
  2. Duplicate detection  — finds duplicate log entries
  3. Role mismatch        — detects access by unauthorised roles

These are deliberately kept simple (DB queries + arithmetic).
The more complex anomaly detection belongs in Increment 3.
"""
from datetime import datetime, timezone, timedelta
from app.models.custody_log import CustodyLog
from app.models.audit_record import AuditRecord
from app.models.evidence import EvidenceItem
from app.models.investigator import Investigator


# ── 1. Time Gap Detection ─────────────────────────────────────────────────────

def check_time_gaps(evidence_id: int, threshold_hours: int = 72) -> list:
    """
    Scan the custody log for an evidence item and flag any gap between
    consecutive transfers that exceeds threshold_hours.

    Returns a list of dicts, one per flagged gap:
      {
        'from_event_id': int,
        'to_event_id': int,
        'gap_hours': float,
        'threshold_hours': int,
        'from_timestamp': datetime,
        'to_timestamp': datetime
      }

    Why this is DB/formula: it is timestamp arithmetic over ordered
    database records — not a custom algorithm.
    """
    logs = (CustodyLog.query
            .filter_by(evidence_id=evidence_id)
            .order_by(CustodyLog.timestamp.asc())
            .all())

    flagged_gaps = []

    for i in range(1, len(logs)):
        prev = logs[i - 1]
        curr = logs[i]

        # Simple arithmetic: difference between consecutive timestamps
        gap = curr.timestamp - prev.timestamp
        gap_hours = gap.total_seconds() / 3600

        if gap_hours > threshold_hours:
            flagged_gaps.append({
                'from_event_id': prev.id,
                'to_event_id': curr.id,
                'gap_hours': round(gap_hours, 2),
                'threshold_hours': threshold_hours,
                'from_timestamp': prev.timestamp,
                'to_timestamp': curr.timestamp
            })

    return flagged_gaps


# ── 2. Duplicate Log Entry Detection ─────────────────────────────────────────

def check_duplicate_entries(evidence_id: int) -> list:
    """
    Find duplicate custody log entries for an evidence item.
    A duplicate is defined as two entries with the same:
      - event_type
      - from_investigator_id
      - to_investigator_id
      - timestamp (exact match — indicative of log injection)

    Returns a list of dicts describing each duplicate pair:
      {
        'log_id_1': int,
        'log_id_2': int,
        'event_type': str,
        'timestamp': datetime
      }

    Why this is DB/formula: simple equality checks over grouped records.
    """
    logs = (CustodyLog.query
            .filter_by(evidence_id=evidence_id)
            .order_by(CustodyLog.timestamp.asc())
            .all())

    duplicates = []
    seen = {}

    for log in logs:
        # Build a key from the fields that should uniquely identify an event
        key = (
            log.event_type,
            log.from_investigator_id,
            log.to_investigator_id,
            log.timestamp.replace(microsecond=0)  # ignore sub-second precision
        )

        if key in seen:
            duplicates.append({
                'log_id_1': seen[key],
                'log_id_2': log.id,
                'event_type': log.event_type,
                'timestamp': log.timestamp
            })
        else:
            seen[key] = log.id

    return duplicates


# ── 3. Role Mismatch Detection ────────────────────────────────────────────────

# Define which roles are permitted to access which evidence categories.
# This is the permission matrix for the formula check.
ROLE_PERMISSION_MATRIX = {
    'Image':    ['Admin', 'Lead Investigator', 'Analyst'],
    'Video':    ['Admin', 'Lead Investigator', 'Analyst'],
    'Audio':    ['Admin', 'Lead Investigator', 'Analyst'],
    'Document': ['Admin', 'Lead Investigator', 'Analyst', 'Read-Only'],
    'Database': ['Admin', 'Lead Investigator'],
    'Log File': ['Admin', 'Lead Investigator', 'Analyst'],
    'Other':    ['Admin', 'Lead Investigator', 'Analyst'],
}


def check_role_mismatches(evidence_id: int) -> list:
    """
    Check whether any investigator accessed a piece of evidence
    without the required role permission.

    Looks at File Access events in the audit log and compares the
    accessing investigator's role against the permission matrix.

    Returns a list of dicts:
      {
        'audit_record_id': int,
        'investigator_id': int,
        'investigator_name': str,
        'role': str,
        'evidence_category': str,
        'timestamp': datetime
      }

    Why this is DB/formula: a set-membership lookup against
    a predefined permission matrix — no custom algorithm.
    """
    evidence = EvidenceItem.query.get(evidence_id)
    if not evidence:
        return []

    permitted_roles = ROLE_PERMISSION_MATRIX.get(evidence.category, ['Admin'])

    # Query all File Access audit records for this evidence item
    access_records = (AuditRecord.query
                      .filter_by(evidence_id=evidence_id, event_type='File Access')
                      .all())

    mismatches = []
    for record in access_records:
        if not record.investigator_id:
            continue

        investigator = Investigator.query.get(record.investigator_id)
        if not investigator:
            continue

        # Formula check: is the investigator's role in the permitted set?
        if investigator.role not in permitted_roles:
            mismatches.append({
                'audit_record_id': record.id,
                'investigator_id': investigator.id,
                'investigator_name': investigator.full_name,
                'role': investigator.role,
                'evidence_category': evidence.category,
                'timestamp': record.timestamp
            })

    return mismatches


# ── Combined Runner ───────────────────────────────────────────────────────────

def run_all_formula_checks(evidence_id: int, gap_threshold_hours: int = 72) -> dict:
    """
    Run all three formula checks for a given evidence item and
    return a combined summary report.

    Returns:
      {
        'evidence_id': int,
        'ran_at': datetime,
        'time_gaps': [...],
        'duplicates': [...],
        'role_mismatches': [...],
        'total_issues': int
      }
    """
    time_gaps = check_time_gaps(evidence_id, gap_threshold_hours)
    duplicates = check_duplicate_entries(evidence_id)
    role_mismatches = check_role_mismatches(evidence_id)

    return {
        'evidence_id': evidence_id,
        'ran_at': datetime.now(timezone.utc).replace(tzinfo=None),
        'time_gaps': time_gaps,
        'duplicates': duplicates,
        'role_mismatches': role_mismatches,
        'total_issues': len(time_gaps) + len(duplicates) + len(role_mismatches)
    }

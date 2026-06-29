"""
Database seeder — creates investigators, cases, and evidence items
spanning LOW to CRITICAL risk levels so the system can be fully demonstrated.

Usage:
    python seed.py

Safe to re-run — checks before creating anything.
"""
from datetime import timedelta
import hashlib
from app import create_app, db
from app.logic.crypto import generate_key_pair, sign_payload
from app.models.investigator import Investigator
from app.models.case import Case
from app.models.evidence import EvidenceItem
from app.models.custody_log import CustodyLog
from app.models.audit_record import AuditRecord
from datetime import datetime, timedelta, date, timezone


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def fake_hash(content: str) -> str:
    """Generate a deterministic SHA-256 hash from a string."""
    return hashlib.sha256(content.encode()).hexdigest()


def ts(days_ago: float, hours_ago: float = 0) -> datetime:
    """Return a utc datetime offset from now."""
    return (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None) - timedelta(days=days_ago, hours=hours_ago)


def add_custody(db, evidence, event_type, to_inv, from_inv=None,
                when=None, reason='Standard transfer', location='Digital Lab'):
    """Add a CustodyLog entry and return it."""
    log = CustodyLog(
        evidence_id=evidence.id,
        event_type=event_type,
        from_investigator_id=from_inv.id if from_inv else None,
        to_investigator_id=to_inv.id if to_inv else None,
        timestamp=when or (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None),
        location=location,
        reason=reason,
        file_hash_at_event=evidence.original_hash,
    )
    db.session.add(log)
    return log


def add_audit(db, event_type, investigator, evidence=None,
              case=None, description='', result='Success'):
    """Add an AuditRecord entry."""
    rec = AuditRecord(
        event_type=event_type,
        investigator_id=investigator.id,
        evidence_id=evidence.id if evidence else None,
        case_id=case.id if case else None,
        description=description,
        result=result,
        timestamp=(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None),
    )
    db.session.add(rec)
    return rec


# ─────────────────────────────────────────────────────────────────────────────
# Main seed function
# ─────────────────────────────────────────────────────────────────────────────

def seed():
    app = create_app()

    with app.app_context():

        # ── Investigators ─────────────────────────────────────────────────
        def get_or_create_investigator(email, full_name, role, password):
            inv = Investigator.query.filter_by(email=email).first()
            if not inv:
                priv, pub = generate_key_pair()
                inv = Investigator(
                    full_name=full_name,
                    email=email,
                    role=role,
                    public_key=pub,
                    private_key_encrypted=priv,
                    is_active=True,
                )
                inv.set_password(password)
                db.session.add(inv)
                db.session.commit()
                print(f'✅  Created {role}: {email} / {password}')
            else:
                print(f'ℹ️   Already exists: {email}')
            return inv

        admin   = get_or_create_investigator(
            'admin@deicms.com',   'System Administrator', 'Admin',            'Admin@1234')
        lead    = get_or_create_investigator(
            'lead@deicms.com',    'Lead Investigator',    'Lead Investigator','Lead@1234')
        analyst = get_or_create_investigator(
            'analyst@deicms.com', 'Forensic Analyst',     'Analyst',          'Analyst@1234')
        readonly = get_or_create_investigator(
            'readonly@deicms.com','Read-Only Viewer',     'Read-Only',        'Readonly@1234')

        # ── Cases ─────────────────────────────────────────────────────────
        def get_or_create_case(number, title, description, status, opened_days_ago,
                                created_by, assigned_to, jurisdiction='Italy, Messina'):
            c = Case.query.filter_by(case_number=number).first()
            if not c:
                c = Case(
                    case_number=number,
                    title=title,
                    description=description,
                    jurisdiction=jurisdiction,
                    status=status,
                    date_opened=date.today() - timedelta(days=opened_days_ago),
                    created_by_id=created_by.id,
                    assigned_to_id=assigned_to.id,
                )
                db.session.add(c)
                db.session.commit()
                print(f'✅  Created case: {number} — {title}')
            else:
                print(f'ℹ️   Case already exists: {number}')
            return c

        case1 = get_or_create_case(
            'CASE-2026-001',
            'Corporate Fraud Investigation',
            'Internal audit flagged irregular financial transactions. '
            'Digital evidence collected from suspect workstations.',
            'Active', 30, admin, lead)

        case2 = get_or_create_case(
            'CASE-2026-002',
            'Ransomware Attack — MediCorp Hospital',
            'Hospital network encrypted by ransomware. Patient data at risk. '
            'Malicious executables and encrypted payload files recovered.',
            'Active', 14, admin, lead)

        case3 = get_or_create_case(
            'CASE-2026-003',
            'Insider Threat — Data Exfiltration',
            'Employee suspected of exfiltrating sensitive customer data '
            'via USB drives and cloud upload scripts.',
            'Pending', 60, lead, analyst)

        case4 = get_or_create_case(
            'CASE-2026-004',
            'Phishing Campaign — Financial Sector',
            'Coordinated phishing campaign targeting bank employees. '
            'Email attachments and macro-enabled documents collected.',
            'Open', 5, admin, admin)
        
        case5 = get_or_create_case(
            'CASE-2026-005',
            'Cryptocurrency Money Laundering',
            'Suspect linked to multiple blockchain wallets used to launder '
            'proceeds from ransomware attacks. Wallet export files and '
            'transaction logs recovered from encrypted laptop.',
            'Active', 8, admin, lead)

        case6 = get_or_create_case(
            'CASE-2026-006',
            'Supply Chain Attack — Software Vendor',
            'Malicious update pushed to 3,000 enterprise clients via '
            'compromised software vendor build pipeline. '
            'Backdoored installer and modified DLLs recovered.',
            'Active', 3, admin, lead)

        case7 = get_or_create_case(
            'CASE-2026-007',
            'Corporate Espionage — Trade Secret Theft',
            'Former employee suspected of copying proprietary R&D documents '
            'before resignation. USB activity logs and email archives recovered.',
            'Pending', 45, lead, analyst)

        case8 = get_or_create_case(
            'CASE-2026-008',
            'Cyberstalking — Social Media Harassment',
            'Victim received threatening messages from anonymous accounts. '
            'IP logs, browser history exports, and social media data packages recovered.',
            'Open', 10, admin, analyst)

        # ── Evidence items ────────────────────────────────────────────────
        # We only seed evidence if none exists yet
        if EvidenceItem.query.count() > 0:
            print('ℹ️   Evidence items already exist, skipping evidence seed.')
        else:
            _seed_evidence(db, admin, lead, analyst, readonly,
                           case1, case2, case3, case4,
                           case5, case6, case7, case8)

        print('\n🚀  Database seeded successfully!')
        print('    Open http://127.0.0.1:5001 and log in with:')
        print('    admin@deicms.com   / Admin@1234')
        print('    lead@deicms.com    / Lead@1234')
        print('    analyst@deicms.com / Analyst@1234')


# ─────────────────────────────────────────────────────────────────────────────
# Evidence seeding
# ─────────────────────────────────────────────────────────────────────────────

def _seed_evidence(db, admin, lead, analyst, readonly,
                   case1, case2, case3, case4,
                   case5, case6, case7, case8):
    """
    Creates 8 evidence items deliberately engineered to produce a spread of
    risk levels from LOW to CRITICAL so every dashboard widget shows
    meaningful data.

    Risk drivers used:
      • file_name extension  — .txt/.jpg = low; .exe/.dll = maximum
      • transfer frequency   — rapid transfers in a short window
      • time since activity  — items untouched for 40–65 days
      • role mismatch audits — Read-Only accessed a Database evidence item
      • duplicate audits     — duplicated Integrity Check records
    """

    # ── 1. LOW RISK — Plain text interview notes ───────────────────────────
    ev1 = EvidenceItem(
        evidence_number='EV-2026-001',
        case_id=case1.id,
        title='Interview Notes — Suspect A',
        description='Typed interview notes from the initial suspect interview. '
                    'No sensitive data, low forensic value.',
        category='Document',
        lifecycle_state='Submitted',
        file_name='interview_notes_suspect_a.txt',
        file_path='/uploads/ev001_interview_notes.txt',
        file_size=12_400,
        file_mime_type='text/plain',
        original_hash=fake_hash('interview_notes_suspect_a'),
        current_hash=fake_hash('interview_notes_suspect_a'),
        uploaded_by_id=analyst.id,
        current_holder_id=analyst.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(2),
    )
    db.session.add(ev1)
    db.session.flush()

    # One upload custody log — very recent
    add_custody(db, ev1, 'Upload', analyst,
                when=ts(2), reason='Initial upload after interview')
    add_audit(db, 'Data Modification', analyst, ev1, case1,
              'Evidence uploaded: interview_notes_suspect_a.txt')
    db.session.commit()
    print('✅  EV-2026-001 — LOW risk (interview notes .txt)')

    # ── 2. LOW RISK — CCTV screenshot ─────────────────────────────────────
    ev2 = EvidenceItem(
        evidence_number='EV-2026-002',
        case_id=case1.id,
        title='CCTV Screenshot — Server Room Entry',
        description='JPEG screenshot extracted from CCTV footage showing '
                    'the suspect entering the server room at 02:14.',
        category='Image',
        lifecycle_state='Under Analysis',
        file_name='cctv_server_room_0214.jpg',
        file_path='/uploads/ev002_cctv.jpg',
        file_size=2_840_000,
        file_mime_type='image/jpeg',
        original_hash=fake_hash('cctv_server_room_0214'),
        current_hash=fake_hash('cctv_server_room_0214'),
        uploaded_by_id=lead.id,
        current_holder_id=analyst.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(5),
    )
    db.session.add(ev2)
    db.session.flush()

    add_custody(db, ev2, 'Upload', lead,
                when=ts(5), reason='Extracted from CCTV archive')
    add_custody(db, ev2, 'Transfer', analyst, from_inv=lead,
                when=ts(3), reason='Transferred to analyst for image enhancement')
    add_audit(db, 'Data Modification', lead, ev2, case1,
              'CCTV screenshot uploaded and transferred to analyst')
    db.session.commit()
    print('✅  EV-2026-002 — LOW risk (CCTV screenshot .jpg)')

    # ── 3. MEDIUM RISK — Financial spreadsheet ─────────────────────────────
    ev3 = EvidenceItem(
        evidence_number='EV-2026-003',
        case_id=case1.id,
        title='Financial Transaction Records Q1 2026',
        description='Excel spreadsheet containing 1,200 flagged transactions '
                    'identified during the internal audit. Contains PII.',
        category='Document',
        lifecycle_state='Under Analysis',
        file_name='financial_transactions_q1_2026.xlsx',
        file_path='/uploads/ev003_financial.xlsx',
        file_size=4_500_000,
        file_mime_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        original_hash=fake_hash('financial_transactions_q1'),
        current_hash=fake_hash('financial_transactions_q1'),
        uploaded_by_id=admin.id,
        current_holder_id=analyst.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(20),
    )
    db.session.add(ev3)
    db.session.flush()

    add_custody(db, ev3, 'Upload', admin,
                when=ts(20), reason='Extracted from suspect laptop')
    add_custody(db, ev3, 'Transfer', lead, from_inv=admin,
                when=ts(18), reason='Senior review required')
    add_custody(db, ev3, 'Transfer', analyst, from_inv=lead,
                when=ts(15), reason='Assigned for detailed analysis')
    add_audit(db, 'Data Modification', admin, ev3, case1,
              'Financial records uploaded — contains PII, restricted access applied')
    db.session.commit()
    print('✅  EV-2026-003 — MEDIUM risk (financial spreadsheet, 20 days old, 3 transfers)')

    # ── 4. MEDIUM RISK — Macro-enabled document ────────────────────────────
    ev4 = EvidenceItem(
        evidence_number='EV-2026-004',
        case_id=case4.id,
        title='Phishing Email Attachment — Invoice Macro',
        description='Macro-enabled Word document delivered via phishing email. '
                    'Macro code extracted and under static analysis.',
        category='Document',
        lifecycle_state='Submitted',
        file_name='invoice_march2026.docm',
        file_path='/uploads/ev004_invoice_macro.docm',
        file_size=185_000,
        file_mime_type='application/vnd.ms-word.document.macroEnabled.12',
        original_hash=fake_hash('invoice_march2026_docm'),
        current_hash=fake_hash('invoice_march2026_docm'),
        uploaded_by_id=analyst.id,
        current_holder_id=analyst.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(18),
    )
    db.session.add(ev4)
    db.session.flush()

    add_custody(db, ev4, 'Upload', analyst,
                when=ts(18), reason='Recovered from quarantined email')
    add_custody(db, ev4, 'Transfer', lead, from_inv=analyst,
                when=ts(16), reason='Escalated to lead for review')
    add_custody(db, ev4, 'Transfer', analyst, from_inv=lead,
                when=ts(14), reason='Returned for static macro analysis')

    # Role mismatch: read-only accessed a Document evidence item
    add_audit(db, 'File Access', readonly, ev4, case4,
              'Read-Only user accessed macro-enabled document evidence',
              result='Warning')
    db.session.commit()
    print('✅  EV-2026-004 — MEDIUM risk (macro .docm, role mismatch warning)')

    # ── 5. HIGH RISK — PowerShell exfiltration script ─────────────────────
    ev5 = EvidenceItem(
        evidence_number='EV-2026-005',
        case_id=case3.id,
        title='Data Exfiltration Script — PowerShell',
        description='PowerShell script found on suspect USB drive. '
                    'Connects to external C2 server and uploads compressed archives.',
        category='Other',
        lifecycle_state='Under Analysis',
        file_name='sync_backup.ps1',
        file_path='/uploads/ev005_sync_backup.ps1',
        file_size=42_000,
        file_mime_type='application/x-powershell',
        original_hash=fake_hash('sync_backup_ps1_v1'),
        current_hash=fake_hash('sync_backup_ps1_v1'),
        uploaded_by_id=admin.id,
        current_holder_id=analyst.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(50),
    )
    db.session.add(ev5)
    db.session.flush()

    # 6 transfers over 2 days = high frequency
    add_custody(db, ev5, 'Upload',    admin,   when=ts(50),
                reason='Recovered from suspect USB')
    add_custody(db, ev5, 'Transfer',  lead,    from_inv=admin,
                when=ts(49, 22), reason='Urgent escalation to lead')
    add_custody(db, ev5, 'Transfer',  analyst, from_inv=lead,
                when=ts(49, 18), reason='Assigned for dynamic analysis')
    add_custody(db, ev5, 'Transfer',  lead,    from_inv=analyst,
                when=ts(49, 12), reason='Returned to lead for sign-off')
    add_custody(db, ev5, 'Transfer',  admin,   from_inv=lead,
                when=ts(49, 6),  reason='Admin review required')
    add_custody(db, ev5, 'Transfer',  analyst, from_inv=admin,
                when=ts(49),     reason='Re-assigned to analyst')

    # Two role mismatch warnings
    add_audit(db, 'File Access', readonly, ev5, case3,
              'Read-Only user accessed PowerShell script evidence',
              result='Warning')
    add_audit(db, 'Data Modification', readonly, ev5, case3,
              'Unauthorised modification attempt by Read-Only user',
              result='Warning')

    # Duplicate integrity check records
    for i in range(2):
        add_audit(db, 'Integrity Check', analyst, ev5, case3,
                  f'Integrity check run #{i+1} — duplicate entry detected',
                  result='Warning')

    db.session.commit()
    print('✅  EV-2026-005 — HIGH risk (.ps1, 50 days old, 6 rapid transfers, 2 role warnings)')

    # ── 6. HIGH RISK — Encrypted archive ──────────────────────────────────
    ev6 = EvidenceItem(
        evidence_number='EV-2026-006',
        case_id=case3.id,
        title='Encrypted Archive — Customer Data Dump',
        description='Password-protected RAR archive found on suspect home directory. '
                    'Contents partially decrypted, contains customer PII records.',
        category='Database',
        lifecycle_state='Transferred',
        file_name='customers_export_encrypted.rar',
        file_path='/uploads/ev006_customers_encrypted.rar',
        file_size=890_000_000,
        file_mime_type='application/x-rar-compressed',
        original_hash=fake_hash('customers_export_encrypted_rar'),
        current_hash=fake_hash('customers_export_encrypted_rar'),
        uploaded_by_id=admin.id,
        current_holder_id=lead.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(55),
    )
    db.session.add(ev6)
    db.session.flush()

    add_custody(db, ev6, 'Upload',   admin,   when=ts(55),
                reason='Recovered from suspect home directory')
    add_custody(db, ev6, 'Transfer', lead,    from_inv=admin,
                when=ts(45), reason='Lead investigation review')
    add_custody(db, ev6, 'Transfer', analyst, from_inv=lead,
                when=ts(40), reason='Decryption attempt')
    add_custody(db, ev6, 'Transfer', admin,   from_inv=analyst,
                when=ts(38), reason='Admin custody for encrypted evidence')
    add_custody(db, ev6, 'Transfer', lead,    from_inv=admin,
                when=ts(35), reason='Final review before archiving')

    add_audit(db, 'File Access', readonly, ev6, case3,
              'Read-Only user accessed Database evidence item',
              result='Warning')
    add_audit(db, 'Integrity Check', admin, ev6, case3,
              'Integrity check — file hash verified against original',
              result='Success')
    db.session.commit()
    print('✅  EV-2026-006 — HIGH risk (.rar archive, 55 days old, 5 transfers, 1 role warning)')

    # ── 7. CRITICAL RISK — Ransomware executable ───────────────────────────
    ev7 = EvidenceItem(
        evidence_number='EV-2026-007',
        case_id=case2.id,
        title='Ransomware Payload — LockBit Variant',
        description='Main ransomware executable recovered from infected hospital server. '
                    'Responsible for encrypting 47,000 patient records. '
                    'Binary analysis confirmed LockBit 3.0 variant with custom C2.',
        category='Other',
        lifecycle_state='Flagged',
        file_name='svchost_update.exe',
        file_path='/uploads/ev007_ransomware.exe',
        file_size=1_240_000,
        file_mime_type='application/x-msdownload',
        original_hash=fake_hash('svchost_update_exe_lockbit'),
        current_hash=fake_hash('svchost_update_exe_lockbit_TAMPERED'),
        uploaded_by_id=admin.id,
        current_holder_id=admin.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(60),
    )
    db.session.add(ev7)
    db.session.flush()

    # 8 rapid transfers in 3 hours = very high frequency
    base = ts(60)
    for i, (to_inv, from_inv, mins, reason) in enumerate([
        (admin,   None,    0,   'Initial upload from infected server'),
        (lead,    admin,   20,  'Urgent escalation'),
        (analyst, lead,    40,  'Malware analyst assigned'),
        (admin,   analyst, 65,  'Admin review — critical evidence'),
        (lead,    admin,   90,  'Lead sign-off required'),
        (analyst, lead,    115, 'Dynamic analysis environment'),
        (admin,   analyst, 140, 'Return to admin custody'),
        (lead,    admin,   170, 'Final custody before flagging'),
    ]):
        evt = 'Upload' if i == 0 else 'Transfer'
        log = CustodyLog(
            evidence_id=ev7.id,
            event_type=evt,
            from_investigator_id=from_inv.id if from_inv else None,
            to_investigator_id=to_inv.id,
            timestamp=base + timedelta(minutes=mins),
            location='Forensic Lab A',
            reason=reason,
            file_hash_at_event=ev7.original_hash,
        )
        db.session.add(log)

    # 3 role mismatch warnings + 2 duplicate integrity checks
    for i in range(3):
        add_audit(db, 'File Access', readonly, ev7, case2,
                  f'Read-Only user accessed critical executable evidence (attempt {i+1})',
                  result='Warning')
    for i in range(2):
        add_audit(db, 'Integrity Check', analyst, ev7, case2,
                  f'Integrity check #{i+1} — hash mismatch detected, evidence may be tampered',
                  result='Warning')

    # State change to Flagged logged in audit
    add_audit(db, 'State Change', admin, ev7, case2,
              "Evidence flagged: hash mismatch between original_hash and current_hash. "
              "Possible tampering during transfer.",
              result='Warning')
    db.session.commit()
    print('✅  EV-2026-007 — CRITICAL risk (.exe ransomware, 60 days, 8 rapid transfers, hash mismatch, 3 role warnings)')

    # ── 8. CRITICAL RISK — Keylogger DLL ──────────────────────────────────
    ev8 = EvidenceItem(
        evidence_number='EV-2026-008',
        case_id=case2.id,
        title='Keylogger DLL — Credential Harvesting Module',
        description='Dynamic link library injected into browser process. '
                    'Captures keystrokes and exfiltrates credentials to remote C2 server. '
                    'Found on 12 hospital workstations.',
        category='Other',
        lifecycle_state='Flagged',
        file_name='browserhelper.dll',
        file_path='/uploads/ev008_keylogger.dll',
        file_size=524_000,
        file_mime_type='application/x-msdownload',
        original_hash=fake_hash('browserhelper_dll_keylogger'),
        current_hash=fake_hash('browserhelper_dll_keylogger_MODIFIED'),
        uploaded_by_id=admin.id,
        current_holder_id=lead.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(65),
    )
    db.session.add(ev8)
    db.session.flush()

    # 10 rapid transfers over 5 hours
    base8 = ts(65)
    transfer_plan = [
        (admin,   None,    0,   'Upload from infected workstation image'),
        (lead,    admin,   15,  'Immediate escalation'),
        (analyst, lead,    30,  'Malware analyst'),
        (lead,    analyst, 55,  'Lead review'),
        (admin,   lead,    75,  'Admin custody'),
        (analyst, admin,   95,  'Further analysis'),
        (lead,    analyst, 120, 'Evidence committee review'),
        (admin,   lead,    145, 'Admin reclaim'),
        (analyst, admin,   165, 'Re-analysis requested'),
        (lead,    analyst, 185, 'Final lead custody'),
    ]
    for i, (to_inv, from_inv, mins, reason) in enumerate(transfer_plan):
        evt = 'Upload' if i == 0 else 'Transfer'
        log = CustodyLog(
            evidence_id=ev8.id,
            event_type=evt,
            from_investigator_id=from_inv.id if from_inv else None,
            to_investigator_id=to_inv.id,
            timestamp=base8 + timedelta(minutes=mins),
            location='Forensic Lab B',
            reason=reason,
            file_hash_at_event=ev8.original_hash,
        )
        db.session.add(log)

    # 5 role mismatch warnings + 2 duplicate entries
    for i in range(5):
        add_audit(db, 'File Access', readonly, ev8, case2,
                  f'Read-Only accessed DLL evidence — policy violation (incident {i+1})',
                  result='Warning')
    for i in range(2):
        add_audit(db, 'Integrity Check', analyst, ev8, case2,
                  f'Duplicate integrity check entry #{i+1}',
                  result='Warning')
    add_audit(db, 'State Change', admin, ev8, case2,
              "Evidence flagged: DLL hash mismatch confirmed. "
              "Evidence integrity compromised — restricted access applied.",
              result='Warning')
    db.session.commit()
    print('✅  EV-2026-008 — CRITICAL risk (.dll keylogger, 65 days, 10 rapid transfers, 5 role warnings, hash mismatch)')
    
    # ── 9. HIGH RISK — Cryptocurrency wallet export ────────────────────
    ev9 = EvidenceItem(
        evidence_number='EV-2026-009',
        case_id=case5.id,
        title='Blockchain Wallet Export — 14 Addresses',
        description='JSON export from Electrum wallet containing 14 Bitcoin '
                    'addresses with transaction history. Linked to known '
                    'ransomware payment addresses via blockchain analysis.',
        category='Database',
        lifecycle_state='Under Analysis',
        file_name='wallet_export_electrum.json',
        file_path='/uploads/ev009_wallet.json',
        file_size=38_000,
        file_mime_type='application/json',
        original_hash=fake_hash('wallet_export_electrum_btc'),
        current_hash=fake_hash('wallet_export_electrum_btc'),
        uploaded_by_id=admin.id,
        current_holder_id=analyst.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(7),
    )
    db.session.add(ev9)
    db.session.flush()

    add_custody(db, ev9, 'Upload', admin, when=ts(7),
                reason='Extracted from encrypted laptop via memory forensics')
    add_custody(db, ev9, 'Transfer', analyst, from_inv=admin,
                when=ts(5), reason='Assigned for blockchain tracing analysis')
    add_custody(db, ev9, 'Transfer', lead, from_inv=analyst,
                when=ts(3), reason='Lead review of transaction linkage findings')
    add_custody(db, ev9, 'Transfer', analyst, from_inv=lead,
                when=ts(2), reason='Continued analysis')
    add_audit(db, 'File Access', readonly, ev9, case5,
              'Read-Only user accessed Database evidence', result='Warning')
    add_audit(db, 'Integrity Check', analyst, ev9, case5,
              'Integrity check passed', result='Success')
    db.session.commit()
    print('✅  EV-2026-009 — HIGH risk (wallet .json, 7 days, 4 transfers, role warning)')

    # ── 10. CRITICAL RISK — Backdoored installer ───────────────────────
    ev10 = EvidenceItem(
        evidence_number='EV-2026-010',
        case_id=case6.id,
        title='Backdoored Software Installer — v4.2.1',
        description='Modified Windows installer (.exe) recovered from vendor '
                    'build server. Contains embedded reverse shell payload '
                    'connecting to attacker-controlled C2 infrastructure.',
        category='Other',
        lifecycle_state='Flagged',
        file_name='setup_v4.2.1_patched.exe',
        file_path='/uploads/ev010_backdoored_installer.exe',
        file_size=52_400_000,
        file_mime_type='application/x-msdownload',
        original_hash=fake_hash('setup_v421_patched_exe'),
        current_hash=fake_hash('setup_v421_patched_exe_MODIFIED'),
        uploaded_by_id=admin.id,
        current_holder_id=lead.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(3),
    )
    db.session.add(ev10)
    db.session.flush()

    base10 = ts(3)
    for i, (to_inv, from_inv, mins, reason) in enumerate([
        (admin,   None,    0,   'Upload from vendor build server image'),
        (lead,    admin,   10,  'Immediate escalation — critical evidence'),
        (analyst, lead,    25,  'Malware analyst assigned'),
        (admin,   analyst, 45,  'Admin review'),
        (lead,    admin,   60,  'Lead sign-off'),
        (analyst, lead,    80,  'Dynamic analysis environment'),
    ]):
        evt = 'Upload' if i == 0 else 'Transfer'
        log = CustodyLog(
            evidence_id=ev10.id,
            event_type=evt,
            from_investigator_id=from_inv.id if from_inv else None,
            to_investigator_id=to_inv.id,
            timestamp=base10 + timedelta(minutes=mins),
            location='Forensic Lab A',
            reason=reason,
            file_hash_at_event=ev10.original_hash,
        )
        db.session.add(log)

    for i in range(3):
        add_audit(db, 'File Access', readonly, ev10, case6,
                  f'Read-Only accessed critical installer evidence (attempt {i+1})',
                  result='Warning')
    for i in range(2):
        add_audit(db, 'Integrity Check', analyst, ev10, case6,
                  f'Hash mismatch detected on check #{i+1}', result='Warning')
    add_audit(db, 'State Change', admin, ev10, case6,
              'Evidence flagged: installer binary modified after collection',
              result='Warning')
    db.session.commit()
    print('✅  EV-2026-010 — CRITICAL risk (.exe backdoor, 3 days, 6 rapid transfers, hash mismatch)')

    # ── 11. MEDIUM RISK — USB activity log ────────────────────────────
    ev11 = EvidenceItem(
        evidence_number='EV-2026-011',
        case_id=case7.id,
        title='USB Activity Log — Suspect Workstation',
        description='Windows event log export showing USB device insertions '
                    'and file copy operations in the 48 hours before resignation. '
                    'Correlates with 4.2 GB of data movement to external drives.',
        category='Log File',
        lifecycle_state='Submitted',
        file_name='usb_activity_events.xml',
        file_path='/uploads/ev011_usb_log.xml',
        file_size=1_200_000,
        file_mime_type='application/xml',
        original_hash=fake_hash('usb_activity_events_xml'),
        current_hash=fake_hash('usb_activity_events_xml'),
        uploaded_by_id=analyst.id,
        current_holder_id=analyst.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(40),
    )
    db.session.add(ev11)
    db.session.flush()

    add_custody(db, ev11, 'Upload', analyst, when=ts(40),
                reason='Extracted from suspect workstation forensic image')
    add_custody(db, ev11, 'Transfer', lead, from_inv=analyst,
                when=ts(35), reason='Lead review for correlation analysis')
    add_audit(db, 'Integrity Check', analyst, ev11, case7,
              'Integrity check passed — file unmodified', result='Success')
    db.session.commit()
    print('✅  EV-2026-011 — MEDIUM risk (.xml log, 40 days old)')

    # ── 12. LOW RISK — Social media data package ───────────────────────
    ev12 = EvidenceItem(
        evidence_number='EV-2026-012',
        case_id=case8.id,
        title='Instagram Data Export — Victim Account',
        description='Official data export from victim Instagram account '
                    'containing message history, follower lists, and '
                    'login activity from the period of harassment.',
        category='Document',
        lifecycle_state='Collected',
        file_name='instagram_export_victim.zip',
        file_path='/uploads/ev012_instagram_export.zip',
        file_size=18_500_000,
        file_mime_type='application/zip',
        original_hash=fake_hash('instagram_export_victim_zip'),
        current_hash=fake_hash('instagram_export_victim_zip'),
        uploaded_by_id=analyst.id,
        current_holder_id=analyst.id,
        risk_score=0.0,
        risk_level='Low',
        created_at=ts(1),
    )
    db.session.add(ev12)
    db.session.flush()

    add_custody(db, ev12, 'Upload', analyst, when=ts(1),
                reason='Received from victim — official platform export')
    add_audit(db, 'Data Modification', analyst, ev12, case8,
              'Evidence received and logged', result='Success')
    db.session.commit()
    print('✅  EV-2026-012 — LOW risk (.zip social media export, 1 day old)')

    print('\n📊  Evidence summary:')
    print('    EV-001  LOW      — .txt interview notes')
    print('    EV-002  LOW      — .jpg CCTV screenshot')
    print('    EV-003  MEDIUM   — .xlsx financial records (20 days old)')
    print('    EV-004  MEDIUM   — .docm macro document (role mismatch)')
    print('    EV-005  HIGH     — .ps1 exfiltration script (6 rapid transfers)')
    print('    EV-006  HIGH     — .rar encrypted archive (55 days old)')
    print('    EV-007  CRITICAL — .exe ransomware (8 rapid transfers, hash mismatch)')
    print('    EV-008  CRITICAL — .dll keylogger (10 rapid transfers, 5 role warnings)')


if __name__ == '__main__':
    seed()
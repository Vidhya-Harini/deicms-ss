"""
Tamper-Evident Case Export
===========================
Generates a signed ZIP package for a case containing:
  - All evidence files
  - manifest.json  (SHA-256 of every file + metadata)
  - audit_trail.txt (all audit records for this case)
  - manifest_signature.hex (Ed25519 signature of manifest JSON)

The receiving party can verify authenticity by:
  1. Checking each file's SHA-256 against manifest.json
  2. Verifying manifest_signature.hex against the exporter's public key
"""
from datetime import timedelta
import hashlib
import io
import json
import os
import zipfile
from datetime import datetime, timezone

from flask import Blueprint, redirect, send_file, url_for, flash, request
from flask_login import login_required, current_user

from app import db
from app.models.audit_record import AuditRecord
from app.models.case import Case
from app.models.case_access import CaseAccess
from app.models.evidence import EvidenceItem
from app.logic.crypto import sign_payload

export_bp = Blueprint('export', __name__)


def _can_access_case(case):
    """Return True if current user may access this case."""
    if current_user.is_admin():
        return True
    access = CaseAccess.query.filter_by(
        case_id=case.id, investigator_id=current_user.id
    ).first()
    return access is not None


@export_bp.route('/cases/<int:case_id>/export')
@login_required
def export_case(case_id):
    """Generate and download a tamper-evident signed ZIP for a case."""
    case = Case.query.get_or_404(case_id)

    # Only Admin or Lead Investigator can export
    if not current_user.can_manage():
        flash('Only Admin or Lead Investigators can export a case package.', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    # Case-level access check
    if not _can_access_case(case):
        flash('You do not have access to this case.', 'danger')
        return redirect(url_for('cases.list_cases'))

    evidence_items = EvidenceItem.query.filter_by(case_id=case_id).all()
    audit_records = (
        AuditRecord.query
        .filter_by(case_id=case_id)
        .order_by(AuditRecord.timestamp.asc())
        .all()
    )

    # ── Build the manifest ───────────────────────────────────────────────
    manifest = {
        'case_number': case.case_number,
        'case_title': case.title,
        'exported_by': current_user.full_name,
        'exported_by_id': current_user.id,
        'exported_at': (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None).isoformat(),
        'evidence_count': len(evidence_items),
        'files': []
    }

    # ── Build the audit trail text ───────────────────────────────────────
    audit_lines = [
        f"DEICMS — Audit Trail Export for Case {case.case_number}",
        f"Case: {case.title}",
        f"Exported by: {current_user.full_name} at {(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None).isoformat()}",
        "=" * 70,
        ""
    ]
    for rec in audit_records:
        investigator_name = (
            rec.investigator.full_name if rec.investigator else 'System'
        )
        audit_lines.append(
            f"[{rec.timestamp.isoformat()}] "
            f"{rec.event_type} | {rec.result} | "
            f"By: {investigator_name} | "
            f"IP: {rec.ip_address or 'N/A'} | "
            f"{rec.description}"
        )
    audit_text = "\n".join(audit_lines)

    # ── Build the ZIP in memory ──────────────────────────────────────────
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:

        # Add evidence files
        for ev in evidence_items:
            file_path = ev.file_path
            if os.path.exists(file_path):
                # Decrypt the file at rest, hash the plaintext for the manifest,
                # and place the plaintext into the exported package.
                from app.logic.file_crypto import read_plaintext
                plaintext = read_plaintext(file_path)
                computed_hash = hashlib.sha256(plaintext).hexdigest()

                arc_name = f"evidence/{ev.evidence_number}_{ev.file_name}"
                zf.writestr(arc_name, plaintext)

                manifest['files'].append({
                    'evidence_number': ev.evidence_number,
                    'title': ev.title,
                    'file_name': ev.file_name,
                    'archive_path': arc_name,
                    'sha256': computed_hash,
                    'original_hash': ev.original_hash,
                    'hash_matches_original': computed_hash == ev.original_hash,
                    'lifecycle_state': ev.lifecycle_state,
                    'risk_level': ev.risk_level,
                })
            else:
                manifest['files'].append({
                    'evidence_number': ev.evidence_number,
                    'title': ev.title,
                    'file_name': ev.file_name,
                    'archive_path': None,
                    'sha256': None,
                    'original_hash': ev.original_hash,
                    'hash_matches_original': False,
                    'lifecycle_state': ev.lifecycle_state,
                    'risk_level': ev.risk_level,
                    'note': 'File not found on server'
                })

        # Add manifest.json
        manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)
        zf.writestr('manifest.json', manifest_json)

        # Add audit_trail.txt
        zf.writestr('audit_trail.txt', audit_text)

        # ── Sign the manifest ────────────────────────────────────────────
        signature_hex = None
        if current_user.private_key_encrypted:
            try:
                signature_hex = sign_payload(
                    current_user.private_key_encrypted,
                    manifest_json.encode('utf-8')
                )
                zf.writestr('manifest_signature.hex', signature_hex)
                zf.writestr(
                    'verify_signature.txt',
                    f"Verifier information\n"
                    f"Signed by: {current_user.full_name} (ID {current_user.id})\n"
                    f"Signing public key:\n{current_user.public_key}\n"
                    f"\nTo verify:\n"
                    f"  1. Load the signer's public key above.\n"
                    f"  2. Read manifest.json as bytes (UTF-8).\n"
                    f"  3. Verify the Ed25519 signature in manifest_signature.hex\n"
                    f"     against those bytes.\n"
                )
            except Exception as e:
                zf.writestr('manifest_signature.txt',
                            f'Signature generation failed: {e}')
        else:
            zf.writestr('manifest_signature.txt',
                        'No private key available for signing.')

    zip_buffer.seek(0)

    # ── Log the export ───────────────────────────────────────────────────
    audit = AuditRecord(
        event_type='File Access',
        investigator_id=current_user.id,
        case_id=case.id,
        description=(
            f'Case package exported by {current_user.full_name}. '
            f'{len(evidence_items)} evidence item(s). '
            f'Signed: {"Yes" if signature_hex else "No"}.'
        ),
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    filename = f"{case.case_number}_export_{(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.zip"
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=filename
    )

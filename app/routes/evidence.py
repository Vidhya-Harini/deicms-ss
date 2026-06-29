from datetime import timedelta
import os
import hashlib
import json
from datetime import datetime, timezone
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, current_app)
from flask_login import login_required, current_user
from app import db
from app.models.case import Case
from app.models.evidence import EvidenceItem
from app.models.custody_log import CustodyLog
from app.models.audit_record import AuditRecord
from app.models.case_access import CaseAccess
from app.logic.file_crypto import encrypt_file

evidence_bp = Blueprint('evidence', __name__)


def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in
            current_app.config['ALLOWED_EXTENSIONS'])


def compute_sha256(file_path):
    """Compute the SHA-256 hash of a file. Reads in chunks to handle large files."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


# MIME types that are never acceptable as evidence regardless of extension —
# these are the classic "renamed malware" payloads (e.g. malware.exe -> photo.jpg).
DANGEROUS_MIME_TYPES = {
    'application/x-dosexec',          # Windows PE / .exe / .dll
    'application/x-executable',       # ELF executable
    'application/x-sharedlib',        # ELF shared object
    'application/x-mach-binary',      # macOS Mach-O binary
    'application/x-msdownload',       # Windows downloadable executable
    'application/x-elf',
    'application/vnd.microsoft.portable-executable',
}


def validate_magic_bytes(file_path, filename):
    """
    Verify that a file's *real* content (read from its magic bytes) matches
    its declared extension. Prevents MIME-type spoofing where an attacker
    renames a dangerous file to a benign extension.

    Returns a tuple: (is_valid: bool, detected_mime: str, reason: str)
    """
    try:
        import magic
    except Exception:
        # python-magic / libmagic not available — skip validation gracefully
        # rather than blocking all uploads.
        return True, None, 'magic library unavailable — validation skipped'

    try:
        detected_mime = magic.from_file(file_path, mime=True)
    except Exception as e:
        return True, None, f'magic detection failed: {e}'

    # Always reject executables, whatever the extension claims.
    if detected_mime in DANGEROUS_MIME_TYPES:
        return (False, detected_mime,
                f'File content is an executable ({detected_mime}); rejected.')

    declared_ext = ''
    if '.' in filename:
        declared_ext = '.' + filename.rsplit('.', 1)[1].lower()

    mime_map = current_app.config.get('MIME_TO_EXTENSIONS', {})

    # If we recognise the detected MIME type, the declared extension must be
    # one of its legitimate extensions.
    if detected_mime in mime_map:
        allowed_exts = mime_map[detected_mime]
        if declared_ext not in allowed_exts:
            return (False, detected_mime,
                    f'File content ({detected_mime}) does not match the '
                    f'declared "{declared_ext}" extension.')
        return True, detected_mime, 'verified'

    # Unrecognised MIME type that isn't on the dangerous list — allow it but
    # record what was detected (covers exotic-but-harmless formats).
    return True, detected_mime, f'unrecognised MIME {detected_mime} — allowed'


def extract_metadata(file_path, mime_type):
    """
    Extract file metadata using Pillow for images.
    Returns a dict of metadata fields.
    """
    metadata = {
        'file_size': os.path.getsize(file_path),
        'mime_type': mime_type,
        'extracted_at': (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None).isoformat()
    }

    if mime_type and mime_type.startswith('image/'):
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(file_path)
            exif_data = img._getexif()
            if exif_data:
                exif = {}
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    if isinstance(value, bytes):
                        value = value.hex()
                    exif[tag] = str(value)
                metadata['exif'] = exif
        except Exception:
            metadata['exif'] = {}

    return metadata


def generate_evidence_number():
    """Auto-generate a unique evidence number like E-001."""
    count = EvidenceItem.query.count() + 1
    return f'E-{count:03d}'


@evidence_bp.route('/cases/<int:case_id>/evidence/upload',
                   methods=['GET', 'POST'])
@login_required
def upload_evidence(case_id):
    """Upload a new evidence file and register it in the database."""
    case = Case.query.get_or_404(case_id)

    if not CaseAccess.can_access(case_id, current_user):
        flash('You do not have access to this case.', 'danger')
        return redirect(url_for('cases.list_cases'))

    if not current_user.can_manage():
        flash('You do not have permission to upload evidence.', 'danger')
        return redirect(url_for('cases.view_case', case_id=case_id))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', 'Other')

        if not title:
            flash('Evidence title is required.', 'danger')
            return render_template('evidence/upload.html', case=case)

        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return render_template('evidence/upload.html', case=case)

        file = request.files['file']

        if file.filename == '':
            flash('No file selected.', 'danger')
            return render_template('evidence/upload.html', case=case)

        if not allowed_file(file.filename):
            flash('File type not allowed.', 'danger')
            return render_template('evidence/upload.html', case=case)

        timestamp = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')
        from werkzeug.utils import secure_filename
        safe_filename = f"{timestamp}_{secure_filename(file.filename)}"
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_filename)
        file.save(file_path)

        # ── Magic-byte validation ────────────────────────────────────────────
        # Read the file's real content type and ensure it matches the declared
        # extension. Rejects spoofed files (e.g. malware.exe renamed to .jpg).
        is_valid, detected_mime, reason = validate_magic_bytes(
            file_path, file.filename)
        if not is_valid:
            try:
                os.remove(file_path)
            except OSError:
                pass
            audit = AuditRecord(
                event_type='Failed Attempt',
                investigator_id=current_user.id,
                case_id=case_id,
                description=(f'Rejected upload "{file.filename}": {reason} '
                            f'(detected: {detected_mime})'),
                ip_address=request.remote_addr,
                result='Failure'
            )
            db.session.add(audit)
            db.session.commit()
            flash(f'Upload rejected — {reason}', 'danger')
            return render_template('evidence/upload.html', case=case)

        # Compute SHA-256 hash immediately after saving
        file_hash = compute_sha256(file_path)

        # Detect MIME type — prefer the verified magic-byte result
        mime_type = detected_mime or file.content_type or 'application/octet-stream'

        metadata = extract_metadata(file_path, mime_type)

        # Encrypt the stored evidence file at rest (AES-256-GCM). The original
        # hash above was computed on the plaintext, so integrity checks still work.
        encrypt_file(file_path)

        evidence = EvidenceItem(
            evidence_number=generate_evidence_number(),
            case_id=case_id,
            title=title,
            description=description,
            category=category,
            lifecycle_state='Collected',
            file_name=file.filename,
            file_path=file_path,
            file_size=metadata.get('file_size'),
            file_mime_type=mime_type,
            original_hash=file_hash,
            current_hash=file_hash,
            exif_metadata=json.dumps(metadata),
            uploaded_by_id=current_user.id,
            current_holder_id=current_user.id
        )
        db.session.add(evidence)
        db.session.flush()

        custody_entry = CustodyLog(
            evidence_id=evidence.id,
            event_type='Upload',
            from_investigator_id=None,
            to_investigator_id=current_user.id,
            timestamp=(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None),
            location=request.form.get('location', 'Unknown'),
            reason='Initial evidence upload',
            file_hash_at_event=file_hash,
            notes=f'File uploaded by {current_user.full_name}'
        )
        db.session.add(custody_entry)

        audit = AuditRecord(
            event_type='Data Modification',
            investigator_id=current_user.id,
            evidence_id=evidence.id,
            case_id=case_id,
            description=(f'Evidence {evidence.evidence_number} uploaded: '
                         f'{file.filename} | SHA-256: {file_hash[:16]}...'),
            ip_address=request.remote_addr,
            result='Success'
        )
        db.session.add(audit)
        db.session.commit()

        flash(f'Evidence {evidence.evidence_number} uploaded successfully. '
              f'SHA-256: {file_hash[:16]}...', 'success')
        return redirect(url_for('evidence.view_evidence',
                                case_id=case_id, evidence_id=evidence.id))

    return render_template('evidence/upload.html', case=case)


@evidence_bp.route('/cases/<int:case_id>/evidence/<int:evidence_id>')
@login_required
def view_evidence(case_id, evidence_id):
    """View a single evidence item with its full custody log."""
    case = Case.query.get_or_404(case_id)

    if not CaseAccess.can_access(case_id, current_user):
        flash('You do not have access to this case.', 'danger')
        return redirect(url_for('cases.list_cases'))

    evidence = EvidenceItem.query.get_or_404(evidence_id)
    custody_logs = (evidence.custody_logs
                    .order_by(CustodyLog.timestamp.asc())
                    .all())

    metadata = {}
    if evidence.exif_metadata:
        try:
            metadata = json.loads(evidence.exif_metadata)
        except Exception:
            metadata = {}

    audit = AuditRecord(
        event_type='File Access',
        investigator_id=current_user.id,
        evidence_id=evidence_id,
        case_id=case_id,
        description=f'{current_user.full_name} viewed evidence {evidence.evidence_number}',
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    db.session.commit()

    return render_template('evidence/view.html',
                           case=case, evidence=evidence,
                           custody_logs=custody_logs, metadata=metadata)


@evidence_bp.route('/cases/<int:case_id>/evidence/<int:evidence_id>/edit',
                   methods=['GET', 'POST'])
@login_required
def edit_evidence(case_id, evidence_id):
    """Edit evidence metadata (not the file itself)."""
    case = Case.query.get_or_404(case_id)
    evidence = EvidenceItem.query.get_or_404(evidence_id)

    if not CaseAccess.can_access(case_id, current_user):
        flash('You do not have access to this case.', 'danger')
        return redirect(url_for('cases.list_cases'))

    if not current_user.can_manage():
        flash('You do not have permission to edit evidence.', 'danger')
        return redirect(url_for('evidence.view_evidence',
                                case_id=case_id, evidence_id=evidence_id))

    if request.method == 'POST':
        evidence.title = request.form.get('title', evidence.title).strip()
        evidence.description = request.form.get('description',
                                                 evidence.description).strip()
        evidence.category = request.form.get('category', evidence.category)

        audit = AuditRecord(
            event_type='Data Modification',
            investigator_id=current_user.id,
            evidence_id=evidence_id,
            case_id=case_id,
            description=f'Metadata updated for evidence {evidence.evidence_number}',
            ip_address=request.remote_addr,
            result='Success'
        )
        db.session.add(audit)
        db.session.commit()

        flash('Evidence metadata updated successfully.', 'success')
        return redirect(url_for('evidence.view_evidence',
                                case_id=case_id, evidence_id=evidence_id))

    return render_template('evidence/edit.html', case=case, evidence=evidence)


@evidence_bp.route('/cases/<int:case_id>/evidence/<int:evidence_id>/delete',
                   methods=['POST'])
@login_required
def delete_evidence(case_id, evidence_id):
    """
    Delete an evidence item.
    Only allowed if: the evidence is in 'Collected' state AND
    the requesting investigator is Admin.
    """
    evidence = EvidenceItem.query.get_or_404(evidence_id)

    if not current_user.is_admin():
        flash('Only Admins can delete evidence items.', 'danger')
        return redirect(url_for('evidence.view_evidence',
                                case_id=case_id, evidence_id=evidence_id))

    if evidence.lifecycle_state not in ('Collected',):
        flash('Evidence can only be deleted while in Collected state.', 'danger')
        return redirect(url_for('evidence.view_evidence',
                                case_id=case_id, evidence_id=evidence_id))

    evidence_number = evidence.evidence_number
    audit = AuditRecord(
        event_type='Data Modification',
        investigator_id=current_user.id,
        case_id=case_id,
        description=f'Evidence {evidence_number} deleted by Admin.',
        ip_address=request.remote_addr,
        result='Success'
    )
    db.session.add(audit)
    evidence.is_deleted = True
    db.session.commit()

    flash(f'Evidence {evidence_number} has been deleted.', 'info')
    return redirect(url_for('cases.view_case', case_id=case_id))

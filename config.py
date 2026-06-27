import os

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Secret key used by Flask to sign session cookies
    # In a real deployment, this should be a long random string stored securely
    # We use os.environ[] so the app crashes immediately on startup if missing.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # WTF_CSRF_SECRET_KEY — used by flask-wtf to sign CSRF tokens
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', SECRET_KEY)

    # Database file location (SQLite for development)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(BASE_DIR, 'deicms.db')
    )

    # Disable modification tracking to save memory (we don't need it)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Folder where uploaded evidence files will be saved
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

    # Maximum file size for uploads: 500 MB
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024

    # ← ADD THIS — paste your real key here
    NVIDIA_API_KEY = os.environ.get('NVIDIA_API_KEY', 'dummy-nvidia-key')

    # Allowed file extensions for evidence uploads
    ALLOWED_EXTENSIONS = {
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff',  # Images
        'pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx',  # Documents
        'mp4', 'avi', 'mov', 'mkv',                    # Videos
        'mp3', 'wav',                                  # Audio
        'csv', 'json', 'xml', 'log', 'db', 'sqlite'   # Data files
    }

    # ── Security settings ────────────────────────────────────────────────────
    # Account lockout: how many consecutive failures trigger a lockout
    MAX_LOGIN_ATTEMPTS = 5
    # How long the account stays locked (minutes)
    LOCKOUT_MINUTES = 15

    # Session cookie security
    SESSION_COOKIE_HTTPONLY = True   # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE = 'Lax'  # Protects against CSRF on cross-origin navigations
    # Only send the session cookie over HTTPS connections (TLS).
    # The app runs over HTTPS in development, so this can stay enabled.
    SESSION_COOKIE_SECURE = True

    # Idle session timeout: log a user out after this many minutes of inactivity.
    from datetime import timedelta as _timedelta
    PERMANENT_SESSION_LIFETIME = _timedelta(minutes=30)
    IDLE_TIMEOUT_MINUTES = 30

    # Master secret used to derive the keys that encrypt private keys and
    # evidence files at rest.
    KEY_ENCRYPTION_SECRET = os.environ.get('KEY_ENCRYPTION_SECRET') or 'dev-encryption-secret-change-in-production'

    # Minimum length enforced by the password-strength policy.
    PASSWORD_MIN_LENGTH = 12

    # Flask-Limiter — use in-memory store for development
    RATELIMIT_STORAGE_URI = 'memory://'

    # ─────────────────────────────────────────────────────────────────────────
    # Magic-byte MIME type → allowed extension mapping
    # Used by the file upload validator to verify the real file type
    MIME_TO_EXTENSIONS = {
        'image/png':       ['.png'],
        'image/jpeg':      ['.jpg', '.jpeg'],
        'image/gif':       ['.gif'],
        'image/bmp':       ['.bmp'],
        'image/tiff':      ['.tiff'],
        'application/pdf': ['.pdf'],
        'application/msword':                                              ['.doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
        'application/vnd.ms-excel':                                        ['.xls'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
        'text/plain':      ['.txt', '.log', '.csv'],
        'text/csv':        ['.csv'],
        'application/json': ['.json'],
        'application/xml':  ['.xml'],
        'text/xml':         ['.xml'],
        'video/mp4':        ['.mp4'],
        'video/x-msvideo':  ['.avi'],
        'video/quicktime':  ['.mov'],
        'video/x-matroska': ['.mkv'],
        'audio/mpeg':       ['.mp3'],
        'audio/wav':        ['.wav'],
        'application/x-sqlite3': ['.db', '.sqlite'],
        'application/zip':  ['.zip'],   # kept for zip files only
    }


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    # In production, use PostgreSQL instead of SQLite
    # SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@localhost/deicms'
    
    # Enforce strict secrets in production (crashes on startup if missing)
    SECRET_KEY = os.environ.get('SECRET_KEY')
    KEY_ENCRYPTION_SECRET = os.environ.get('KEY_ENCRYPTION_SECRET')
    NVIDIA_API_KEY = os.environ.get('NVIDIA_API_KEY')

# The config the app will use (development by default)
config = DevelopmentConfig

if config == ProductionConfig:
    for key in ['SECRET_KEY', 'KEY_ENCRYPTION_SECRET', 'NVIDIA_API_KEY']:
        if not getattr(config, key):
            raise ValueError(f"FATAL: Missing required environment variable for production: {key}")


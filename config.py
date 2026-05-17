import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ── Secrets ─────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
    if not SECRET_KEY or len(SECRET_KEY) < 32:
        raise ValueError("FLASK_SECRET_KEY must be at least 32 characters long")

    # ── Database ────────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 10,
        'max_overflow': 20,
    }

    # ── Session Security ────────────────────────────────────────────────────
    SESSION_COOKIE_SECURE = True          # HTTPS only
    SESSION_COOKIE_HTTPONLY = True        # No JavaScript access
    SESSION_COOKIE_SAMESITE = 'Lax'       # CSRF mitigation
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 30))
    )

    # ── Upload Security ─────────────────────────────────────────────────────
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB max
    UPLOAD_FOLDER = 'static/avatars'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

    # ── CSRF Protection ─────────────────────────────────────────────────────
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # ── Security Headers ────────────────────────────────────────────────────
    SECURITY_HEADERS = {
        'X-Frame-Options': 'SAMEORIGIN',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    }
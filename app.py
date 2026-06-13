from flask import Flask, request, g, render_template
from flask_login import LoginManager, current_user
from flask_talisman import Talisman
from extensions import csrf, limiter
from models import db, User
from config import Config
import os
import logging
from datetime import datetime
from flask_migrate import Migrate


app = Flask(__name__)
app.config.from_object(Config)

# ── Security Extensions ────────────────────────────────────────────────────
csrf.init_app(app)
limiter.init_app(app)  # ✅ Just the app — config is in extensions.py

# Talisman is instantiated directly, not via init_app
talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        'img-src': ["'self'", "data:", "blob:"],
        'font-src': ["'self'", "https://cdn.jsdelivr.net"],
    },
)

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ── Upload Configuration ───────────────────────────────────────────────────
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

# ── Database ───────────────────────────────────────────────────────────────
db.init_app(app)
migrate = Migrate(app, db)

# ── Login Manager ──────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = None
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── Security Headers Middleware ────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    for header, value in Config.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

# ── Request Logging & Last Seen ────────────────────────────────────────────
@app.before_request
def before_request():
    if current_user.is_authenticated:
        now = datetime.now()
        if (
            not current_user.last_seen
            or (now - current_user.last_seen).total_seconds() > 60
        ):
            current_user.last_seen = now
            db.session.commit()

        # Log sensitive actions
        if request.endpoint in ['login', 'update_password', 'ajouter_responsable']:
            logger.info(f"User {current_user.email} accessed {request.endpoint}")

# ── Error Handling ─────────────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    logger.warning(f"403 Forbidden: {request.remote_addr} - {request.path}")
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return render_template('errors/429.html'), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"500 Error: {str(e)}")
    db.session.rollback()
    return render_template('errors/500.html'), 500


# ── Database Initialization ────────────────────────────────────────────────
with app.app_context():
    existing = {p.nom for p in Professeur.query.all()}
    new_ones = [nom for nom in PROFESSEURS_LISTE if nom not in existing]
    
    for nom in new_ones:
    db.session.add(Professeur(nom=nom, actif=True))
    
    db.session.commit()
    print(len(new_ones), new_ones)
    db.create_all()

    # Create admin if not exists
    admin_email = 'admin@yool.ma'
    admin = User.query.filter_by(role='admin').first()

    if not admin:
        from werkzeug.security import generate_password_hash
        admin_pass = os.environ.get('ADMIN_DEFAULT_PASSWORD', 'ChangeMeNow!')

        admin = User(
            email=admin_email,
            role='admin',
            nom='Admin',
            prenom='Yool',
            must_change_password=True
        )
        admin.password = generate_password_hash(admin_pass)
        db.session.add(admin)
        db.session.commit()
        logger.info(f"Admin created: {admin_email}")
        print(f"✅ Admin créé: {admin_email}")
        print(f"⚠️  MOT DE PASSE PAR DÉFAUT: {admin_pass}")
        print("🚨 CHANGEZ CE MOT DE PASSE IMMÉDIATEMENT APRÈS CONNEXION!")
    else:
        if not admin.nom:
            admin.nom = 'Admin'
        if not admin.prenom:
            admin.prenom = 'Yool'
        db.session.commit()

from routes import *

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=5000, # Ajoutez ceci
    )
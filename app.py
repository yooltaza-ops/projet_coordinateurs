from flask import Flask
from flask_login import LoginManager
from models import db, User
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = 'static/avatars'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = None

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    if not User.query.filter_by(role='admin').first():
        admin = User(email='admin@yool.ma', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin créé: admin@yool.ma / admin123")

from routes import *

if __name__ == '__main__':
    app.run(debug=True)
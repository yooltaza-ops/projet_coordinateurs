from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# Table de liaison
coordinateur_dour = db.Table('coordinateur_dour',
    db.Column('coordinateur_id', db.Integer, db.ForeignKey('coordinateur.id')),
    db.Column('dour_id', db.Integer, db.ForeignKey('dour.id'))
)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id             = db.Column(db.Integer, primary_key=True)
    email          = db.Column(db.String(150), unique=True, nullable=False)
    password       = db.Column(db.String(256), nullable=False)
    role           = db.Column(db.Enum('admin', 'responsable'), nullable=False, default='responsable')
    nom            = db.Column(db.String(100), nullable=True)
    prenom         = db.Column(db.String(100), nullable=True)
    avatar         = db.Column(db.String(200), nullable=True)
    responsable_id = db.Column(db.Integer, db.ForeignKey('responsable.id'), nullable=True)
    responsable    = db.relationship('Responsable', backref=db.backref('user', uselist=False))

    def set_password(self, pwd):
        self.password = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password, pwd)

    @property
    def is_admin(self):
        return self.role == 'admin'


class Responsable(db.Model):
    __tablename__ = 'responsable'
    id            = db.Column(db.Integer, primary_key=True)
    nom           = db.Column(db.String(100), nullable=False)
    prenom        = db.Column(db.String(100), nullable=False)
    email         = db.Column(db.String(150))
    coordinateurs = db.relationship('Coordinateur', backref='responsable', lazy=True)

    def count_coordinateurs(self):
        return sum(1 for c in self.coordinateurs if c.genre == 'M')

    def count_coordinatrices(self):
        return sum(1 for c in self.coordinateurs if c.genre == 'F')


class Dour(db.Model):
    __tablename__ = 'dour'
    id   = db.Column(db.Integer, primary_key=True)
    nom  = db.Column(db.String(100), nullable=False)
    type = db.Column(db.Enum('talib', 'taliba', 'fatat'), nullable=False)


class Coordinateur(db.Model):
    __tablename__ = 'coordinateur'
    id             = db.Column(db.Integer, primary_key=True)
    nom            = db.Column(db.String(100), nullable=False)
    prenom         = db.Column(db.String(100), nullable=False)
    genre          = db.Column(db.Enum('M', 'F'), nullable=False)
    responsable_id = db.Column(db.Integer, db.ForeignKey('responsable.id'))
    dours          = db.relationship('Dour', secondary=coordinateur_dour, lazy=True)
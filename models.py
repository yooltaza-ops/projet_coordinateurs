from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


db = SQLAlchemy()

coordinateur_dour = db.Table('coordinateur_dour',
    db.Column('coordinateur_id', db.Integer, db.ForeignKey('coordinateur.id')),
    db.Column('dour_id', db.Integer, db.ForeignKey('dour.id'))
)

# ── Listes fixes ────────────────────────────────────────────────────────────
MATIERES = [
    'Arabe',
    'Français',
    'Histoire Géographie',
    'Philo',
    'Mathématiques',
    'Éducation Islamique',
    'Éveil / Sciences',
    'SVT',
    'PC',
    'Éducation Physique',
    'Anglais',
    'Informatique',
    'Autre',
]

NIVEAUX = [
    'Collège — 1AC',
    'Collège — 2AC',
    'Collège — 3AC',
    'Lycée — Tronc commun L',
    'Lycée — Tronc commun S',
    'Lycée — 1ère Bac PC',
    'Lycée — 1ère Bac SX',
    'Lycée — 1ère Bac L',
    'Lycée — 1ère Bac SM',
    'Lycée — 2ème Bac PC',
    'Lycée — 2ème Bac SM',
    'Lycée — 2ème Bac SI',
    'Lycée — 2ème Bac L',
    'Alphabétisation',
]


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
    facebook = db.Column(db.String(300), nullable=True)
    twitter  = db.Column(db.String(300), nullable=True)
    linkedin = db.Column(db.String(300), nullable=True)
    website  = db.Column(db.String(300), nullable=True)

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
    coordinateurs = db.relationship('Coordinateur', backref='responsable', lazy=True,
                                    cascade='all, delete-orphan')

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
    seances        = db.relationship('Seance', backref='coordinateur', lazy=True,
                                     cascade='all, delete-orphan')

    def seances_mois(self, mois, annee):
        return sorted(
            [s for s in self.seances if s.mois == mois and s.annee == annee],
            key=lambda s: s.date
        )

    def total_heures_mois(self, mois, annee):
        return sum(s.nb_heures for s in self.seances_mois(mois, annee))

    def total_seances_mois(self, mois, annee):
        return len(self.seances_mois(mois, annee))


class Seance(db.Model):
    __tablename__ = 'seance'
    id              = db.Column(db.Integer, primary_key=True)
    coordinateur_id = db.Column(db.Integer, db.ForeignKey('coordinateur.id'), nullable=False)
    date            = db.Column(db.Date, nullable=False)
    mois            = db.Column(db.Integer, nullable=False)
    annee           = db.Column(db.Integer, nullable=False)
    nb_heures       = db.Column(db.Float, nullable=False, default=0)
    note            = db.Column(db.String(300), nullable=True)
    # ── NOUVEAUX CHAMPS ──────────────────────────────────────────────────────
    matiere         = db.Column(db.String(100), nullable=True)   # ex: 'Arabe'
    niveau          = db.Column(db.String(100), nullable=True)   # ex: '3ème année'
    # ─────────────────────────────────────────────────────────────────────────
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
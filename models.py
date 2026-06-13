from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import bleach
import re



db = SQLAlchemy()

# ── Allowed HTML tags for sanitization ─────────────────────────────────────
ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
ALLOWED_ATTRIBUTES = {}

# ── Tables d'association ────────────────────────────────────────────────────
coordinateur_dour = db.Table('coordinateur_dour',
    db.Column('coordinateur_id', db.Integer, db.ForeignKey('coordinateur.id')),
    db.Column('dour_id', db.Integer, db.ForeignKey('dour.id'))
)

professeur_dour = db.Table('professeur_dour',
    db.Column('professeur_id', db.Integer, db.ForeignKey('professeur.id')),
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

STATUTS_SEANCE = [
    ('passee',     'Passée'),
    ('annulee',    'Annulée'),
    ('rattrapage', 'Rattrapage'),
]

PROFESSEURS_LISTE = [
    "Rahmouni Abdessalam", "Benani Abderahim", "Yassine Hajoubi",
    "Faouzi Abdellah", "Mohamed Nouali", "Yassine Staili",
    "Guenoun Abdessamad", "Handiz Rachid", "Aziz Errachidi",
    "Akad Youssef", "Rachid Allali", "Lahcen Jaoufi",
    "Houssam Lamkadmi", "Taouil Abdelouhab", "Hajhouji Zakariat",
    "Khaoula EL AANI", "Houari Mohamed", "Charara Said",
    "Hamdach Ismail", "Jawad Himafi", "Abdelatif Barakat",
    "Hafsa Azouzi", "Said Asrou", "Abdelaziz Chemsi",
    "Zakaria Qouhafa", "El Mokhtar El Hadi", "Latifa Azour",
    "Oussama Amrani", "Baghour Mohamed", "Said Ben Rahman",
    "Zineb Sadiki", "Rachid Ayouhammou", "Agamoud Mohamed",
    "El Moussaoui Lahoussine", "El Maheni Abdellah", "Mehdi Youssefi",
    "Mustafa Jazil", "Jaoui Lahcen", "Fatim Zahra Belbass",
    "Anouar Belkacem", "Rabii Abidar", "Benaliat Abdelali",
    "Najia Gouzouli", "Omar Aroug", "Jamaa Anajjar",
    "Said Abaran", "Youssef Benchorfi", "FANAOUI Hamid",
    "Slimane Oudaoudi", "Aicha Chaguiri", "Mohamed Chouhouch",
    "Ayoub Bensaad", "Hassan Benabdi", "Hanane Daba",
    "Mohamed Alla", "Ibrahim Aadi", "Oushfa Mohamed",
    "Youssef Bouabdillah", "Mohamed Hani", "Abdelaali Himadani",
    "Wissal Rahman", "Najat Rahman", "Akassousse Abdallah",
    "Abdelaziz El Oaya", "Kamal Ryane", "Mohamed Rhazaoui",
    "Naimi Abdelouahad", "Nabil Assais", "Abdelhadi Moukabil",
    "Abderrazak Ait Hamdi", "Abdelmajid Ait Abbou", "Fatima Aadiem",
    "Salem Talhout", "Lahcen Afaadas", "Soukaina El Alaoui",
    "Yahya Elmazlouli", "Fadlo Said", "Ouchaib Brahim Laabali",
    "Lamiae Mansor", "Mbark Tizgui", "Youssef Tazavguit",
    "Imane Elgrawi", "Salma Jouroumati", "Khadija Ikhrazn",
    "Idriss Maarir", "Amina Diani", "Ayoub Bidah",
    "Idriss Zouine", "Ibrahim Salbi", "Ait Mona",
    "Salahdine Hadar", "Imane Ouchibi", "Mohamed Ghafiri",
    "Houssein Masskouri", "Kamal Chafii", "Ayoub Laaouni",
    "Latifa Bougaba", "Assia Saleh", "Meryem Bougaba",
    "Kamal Mousaid", "Maryam El Boudani", "Youssef Zahie",
    "Rachid Ghafiri", "Siham Boujoujou", "Benzayma Mohamed",
    "Fatima Gazi", "Fatim Zahra Al Idrissi", "Nawal Iflississ",
    "Mouad Aarab", "Ismail Masaad", "Youssefi Abdeljalil",
    "Mohamed Ouadou", "Lahbib Lbihi", "Kawtar Kacimi",
    "Awatif Lmalyani", "Monir Lhadad", "Taoufik Chaquir",
    "Laila Bouhouch", "ELMEHDI SALEH", "Taheri Hamid",
    "Nourdine Ahrouy", "Hicham Janih", "Khalid Morachik",
    "Ali Eladaoui", "Lhoucine Oubaadi", "Omar Habib",
    "Ahmed Soussi", "Abdelaali Tifaout", "Younes Boujenaoui",
    "Hafid Rachidi", "Abdellah lmalyani",
]

# ── Helper: Sanitize text input ────────────────────────────────────────────
def sanitize_text(text, max_length=500):
    """Sanitize user input to prevent XSS"""
    if not text:
        return None
    text = str(text).strip()
    if len(text) > max_length:
        text = text[:max_length]
    text = bleach.clean(text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)
    return text

def validate_email(email):
    """Basic email validation"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


# ── Models ──────────────────────────────────────────────────────────────────

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id             = db.Column(db.Integer, primary_key=True)
    email          = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password       = db.Column(db.String(256), nullable=False)
    role           = db.Column(db.Enum('admin', 'responsable'), nullable=False, default='responsable')
    nom            = db.Column(db.String(100), nullable=True)
    prenom         = db.Column(db.String(100), nullable=True)
    avatar         = db.Column(db.String(200), nullable=True)
    responsable_id = db.Column(db.Integer, db.ForeignKey('responsable.id'), nullable=True)
    responsable    = db.relationship('Responsable', backref=db.backref('user', uselist=False))
    facebook       = db.Column(db.String(300), nullable=True)
    twitter        = db.Column(db.String(300), nullable=True)
    linkedin       = db.Column(db.String(300), nullable=True)
    website        = db.Column(db.String(300), nullable=True)

    # Security fields
    last_seen           = db.Column(db.DateTime, nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)
    login_attempts      = db.Column(db.Integer, default=0)
    locked_until        = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, pwd):
        if len(pwd) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r'[A-Z]', pwd):
            raise ValueError("Password must contain uppercase letter")
        if not re.search(r'[a-z]', pwd):
            raise ValueError("Password must contain lowercase letter")
        if not re.search(r'\d', pwd):
            raise ValueError("Password must contain digit")
        self.password = generate_password_hash(pwd)
        self.password_changed_at = datetime.now()
        self.login_attempts = 0
        self.locked_until = None

    def check_password(self, pwd):
        return check_password_hash(self.password, pwd)

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.now():
            return True
        return False

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_online(self):
        if not self.last_seen:
            return False
        return (datetime.now() - self.last_seen).total_seconds() < 300

    @property
    def last_seen_display(self):
        if not self.last_seen:
            return "Jamais connecté"
        delta   = datetime.now() - self.last_seen
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return "À l'instant"
        elif seconds < 3600:
            mins = seconds // 60
            return f"Il y a {mins} min"
        elif seconds < 86400:
            hrs = seconds // 3600
            return f"Il y a {hrs}h"
        else:
            return self.last_seen.strftime('%d/%m à %H:%M')


class Responsable(db.Model):
    __tablename__ = 'responsable'
    id            = db.Column(db.Integer, primary_key=True)
    nom           = db.Column(db.String(100), nullable=False)
    prenom        = db.Column(db.String(100), nullable=False)
    email         = db.Column(db.String(150), index=True)
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
    professeurs = db.relationship('Professeur', secondary=professeur_dour,
                                back_populates='dours', lazy=True)


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
        return sum(s.nb_heures for s in self.seances_mois(mois, annee) if s.statut != 'annulee')

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
    matiere         = db.Column(db.String(100), nullable=True)
    niveau          = db.Column(db.String(100), nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    statut          = db.Column(db.String(20),  nullable=True, default=None)
    heure           = db.Column(db.String(5),   nullable=True)
    nb_eleves       = db.Column(db.Integer,     nullable=True)
    nb_eleves_total = db.Column(db.Integer,     nullable=True)
    remarque        = db.Column(db.String(500), nullable=True)

    dar_id = db.Column(db.Integer, db.ForeignKey('dour.id'), nullable=True)
    dar    = db.relationship('Dour', foreign_keys=[dar_id])

    prof = db.Column(db.String(200), nullable=True)

    professeur_id = db.Column(db.Integer, db.ForeignKey('professeur.id'), nullable=True)
    professeur    = db.relationship('Professeur', foreign_keys=[professeur_id],
                                    back_populates='seances')

    @property
    def statut_label(self):
        mapping = {
            'passee': 'Passée', 'annulee': 'Annulée', 'rattrapage': 'Rattrapage',
            'Passée': 'Passée', 'Annulée': 'Annulée', 'Rattrapage': 'Rattrapage',
        }
        return mapping.get(self.statut, '—')

    @property
    def statut_normalise(self):
        mapping = {
            'passee': 'passee', 'annulee': 'annulee', 'rattrapage': 'rattrapage',
            'Passée': 'passee', 'Annulée': 'annulee', 'Rattrapage': 'rattrapage',
        }
        return mapping.get(self.statut, '')

    @property
    def statut_color(self):
        mapping = {
            'passee': 'success', 'annulee': 'danger', 'rattrapage': 'warning',
        }
        return mapping.get(self.statut_normalise, 'secondary')

    @property
    def prof_nom(self):
        if self.professeur:
            return self.professeur.nom
        return self.prof or None


class Professeur(db.Model):
    __tablename__ = 'professeur'
    id    = db.Column(db.Integer, primary_key=True)
    nom   = db.Column(db.String(200), nullable=False)
    actif = db.Column(db.Boolean, default=True, nullable=False)

    dours   = db.relationship('Dour', secondary=professeur_dour,
                            back_populates='professeurs', lazy=True)
    seances = db.relationship('Seance', foreign_keys='Seance.professeur_id',
                            back_populates='professeur', lazy=True)

    def __repr__(self):
        return f'<Professeur {self.nom}>'

    def dours_actives(self):
        return list({s.dar for s in self.seances if s.dar is not None})

    def total_seances(self):
        return len(self.seances)

    def total_heures(self):
        return sum(s.nb_heures for s in self.seances)


seance_b2c_dar = db.Table('seance_b2c_dar',
    db.Column('seance_b2c_id', db.Integer, db.ForeignKey('seance_b2c.id', ondelete='CASCADE')),
    db.Column('dour_id',       db.Integer, db.ForeignKey('dour.id',       ondelete='CASCADE'))
)


class SeanceB2C(db.Model):
    __tablename__ = 'seance_b2c'
    id               = db.Column(db.Integer, primary_key=True)
    responsable_id   = db.Column(db.Integer, db.ForeignKey('responsable.id'), nullable=False)
    responsable      = db.relationship('Responsable', foreign_keys=[responsable_id],
                                       backref=db.backref('seances_b2c', lazy=True))
    date             = db.Column(db.Date, nullable=False)
    mois             = db.Column(db.Integer, nullable=False)
    annee            = db.Column(db.Integer, nullable=False)
    heure            = db.Column(db.String(5), nullable=True)
    nb_heures        = db.Column(db.Float, nullable=False, default=0)
    statut           = db.Column(db.String(20), nullable=True, default=None)
    professeur_id    = db.Column(db.Integer, db.ForeignKey('professeur.id'), nullable=True)
    professeur       = db.relationship('Professeur', foreign_keys=[professeur_id],
                                       backref=db.backref('seances_b2c', lazy=True))
    matiere          = db.Column(db.String(100), nullable=True)
    niveau           = db.Column(db.String(100), nullable=True)
    remarque         = db.Column(db.String(500), nullable=True)
    note             = db.Column(db.String(300), nullable=True)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    # ── Effectifs par segment ──────────────────────────────────────────────
    effectif_b2c_total         = db.Column(db.Integer, nullable=True)
    effectif_b2c_presents      = db.Column(db.Integer, nullable=True)
    effectif_fos_total         = db.Column(db.Integer, nullable=True)
    effectif_fos_presents      = db.Column(db.Integer, nullable=True)
    effectif_free_total        = db.Column(db.Integer, nullable=True)
    effectif_free_presents     = db.Column(db.Integer, nullable=True)
    effectif_fos_agri_total    = db.Column(db.Integer, nullable=True)
    effectif_fos_agri_presents = db.Column(db.Integer, nullable=True)
    effectif_ipse_total        = db.Column(db.Integer, nullable=True)
    effectif_ipse_presents     = db.Column(db.Integer, nullable=True)

    # ── Dar Talib — MULTI (Many-to-Many) ──────────────────────────────────
    dars = db.relationship('Dour', secondary='seance_b2c_dar', lazy=True)

    # ── Effectifs par Dar — relation vers SeanceB2CDarEffectif ────────────
    # (définie via backref dans SeanceB2CDarEffectif)

    @property
    def dar(self):
        """Compat : retourne la première dar sélectionnée (ou None)"""
        return self.dars[0] if self.dars else None

    @property
    def dar_id(self):
        """Compat legacy : premier ID"""
        return self.dars[0].id if self.dars else None

    @property
    def dar_ids(self):
        return [d.id for d in self.dars]

    @property
    def total_presents(self):
        vals = [
            self.effectif_b2c_presents,
            self.effectif_fos_presents,
            self.effectif_free_presents,
            self.effectif_fos_agri_presents,
            self.effectif_ipse_presents,
        ]
        total = sum(v for v in vals if v)
        # Ajouter les présents par dar individuellement
        for de in self.dar_effectifs:
            if de.presents:
                total += de.presents
        return total

    @property
    def total_effectif(self):
        vals = [
            self.effectif_b2c_total,
            self.effectif_fos_total,
            self.effectif_free_total,
            self.effectif_fos_agri_total,
            self.effectif_ipse_total,
        ]
        total = sum(v for v in vals if v)
        for de in self.dar_effectifs:
            if de.total:
                total += de.total
        return total

    @property
    def prof_nom(self):
        if self.professeur:
            return self.professeur.nom
        return None


class SeanceB2CDarEffectif(db.Model):
    """Effectifs par Dar Talib pour une séance B2C — un enregistrement par dar sélectionnée"""
    __tablename__ = 'seance_b2c_dar_effectif'
    id            = db.Column(db.Integer, primary_key=True)
    seance_b2c_id = db.Column(db.Integer, db.ForeignKey('seance_b2c.id', ondelete='CASCADE'), nullable=False)
    dour_id       = db.Column(db.Integer, db.ForeignKey('dour.id',       ondelete='CASCADE'), nullable=False)
    total         = db.Column(db.Integer, nullable=True)    # inscrits
    presents      = db.Column(db.Integer, nullable=True)    # présents

    seance = db.relationship('SeanceB2C', backref=db.backref('dar_effectifs', lazy=True, cascade='all, delete-orphan'))
    dour   = db.relationship('Dour')

    __table_args__ = (
        db.UniqueConstraint('seance_b2c_id', 'dour_id', name='uq_seance_dar'),
    )

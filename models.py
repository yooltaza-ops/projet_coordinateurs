from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


db = SQLAlchemy()

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
    "Ahmed Soussi", "Abdelaali Tifaout",
]


# ── Models ──────────────────────────────────────────────────────────────────

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
    facebook       = db.Column(db.String(300), nullable=True)
    twitter        = db.Column(db.String(300), nullable=True)
    linkedin       = db.Column(db.String(300), nullable=True)
    website        = db.Column(db.String(300), nullable=True)

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

    # Professeurs qui interviennent dans cette dour
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
    matiere         = db.Column(db.String(100), nullable=True)
    niveau          = db.Column(db.String(100), nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    # ── CHAMPS SUIVI PARTENARIAT ──────────────────────────────────────────
    statut    = db.Column(db.String(20),  nullable=False, default='passee')
    heure     = db.Column(db.String(5),   nullable=True)
    nb_eleves = db.Column(db.Integer,     nullable=True)
    remarque  = db.Column(db.String(500), nullable=True)

    # FK vers Dour (dar où se déroule la séance)
    dar_id = db.Column(db.Integer, db.ForeignKey('dour.id'), nullable=True)
    dar    = db.relationship('Dour', foreign_keys=[dar_id])

    # Champ legacy — conservé pour les anciennes séances saisies avant la migration FK
    prof = db.Column(db.String(200), nullable=True)

    # FK vers Professeur (nouveau champ structuré)
    professeur_id = db.Column(db.Integer, db.ForeignKey('professeur.id'), nullable=True)
    professeur    = db.relationship('Professeur', foreign_keys=[professeur_id],
                                    back_populates='seances')
    # ─────────────────────────────────────────────────────────────────────

    @property
    def statut_label(self):
        mapping = {
            'passee':     'Passée',
            'annulee':    'Annulée',
            'rattrapage': 'Rattrapage',
            'Passée':     'Passée',
            'Annulée':    'Annulée',
            'Rattrapage': 'Rattrapage',
        }
        return mapping.get(self.statut, self.statut or 'Passée')

    @property
    def statut_normalise(self):
        mapping = {
            'passee':     'passee',
            'annulee':    'annulee',
            'rattrapage': 'rattrapage',
            'Passée':     'passee',
            'Annulée':    'annulee',
            'Rattrapage': 'rattrapage',
        }
        return mapping.get(self.statut, 'passee')

    @property
    def statut_color(self):
        mapping = {
            'passee':     'success',
            'annulee':    'danger',
            'rattrapage': 'warning',
        }
        return mapping.get(self.statut_normalise, 'secondary')

    @property
    def prof_nom(self):
        """Retourne le nom du prof: via FK si dispo, sinon champ legacy string."""
        if self.professeur:
            return self.professeur.nom
        return self.prof or None


class Professeur(db.Model):
    __tablename__ = 'professeur'
    id    = db.Column(db.Integer, primary_key=True)
    nom   = db.Column(db.String(200), nullable=False)
    actif = db.Column(db.Boolean, default=True, nullable=False)

    # Dours où ce professeur intervient
    dours   = db.relationship('Dour', secondary=professeur_dour,
                               back_populates='professeurs', lazy=True)

    # Séances assurées par ce professeur
    seances = db.relationship('Seance', foreign_keys='Seance.professeur_id',
                               back_populates='professeur', lazy=True)

    def __repr__(self):
        return f'<Professeur {self.nom}>'

    def dours_actives(self):
        """Liste des dours où ce professeur a au moins une séance passée."""
        return list({s.dar for s in self.seances if s.dar is not None})

    def total_seances(self):
        return len(self.seances)

    def total_heures(self):
        return sum(s.nb_heures for s in self.seances)
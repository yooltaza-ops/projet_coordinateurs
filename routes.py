from flask import render_template, request, redirect, url_for, flash, abort, Response, session
from flask_login import login_user, logout_user, login_required, current_user
from extensions import limiter
from app import app
from models import (
    db, Responsable, Coordinateur, Dour, User, Seance, SeanceB2C, SeanceB2CDarEffectif, Professeur,
    MATIERES, NIVEAUX, STATUTS_SEANCE, sanitize_text, validate_email
)
from functools import wraps
import os
import uuid
import json
from datetime import datetime, date, timedelta
from werkzeug.utils import secure_filename

def redirect_back(fallback='index'):
    ref = request.referrer
    if ref:
        from urllib.parse import urlparse
        parsed = urlparse(ref)
        if parsed.netloc == '' or parsed.netloc == request.host:
            if parsed.scheme in ('', 'http', 'https'):
                return redirect(ref)
    return redirect(url_for(fallback))

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated

def password_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_authenticated and current_user.must_change_password:
            flash('Vous devez changer votre mot de passe avant de continuer.', 'warning')
            return redirect(url_for('change_password'))
        return f(*args, **kwargs)
    return decorated


ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def validate_image_file(file):
    if not file or file.filename == '':
        return False, "Aucun fichier sélectionné"
    if not allowed_file(file.filename):
        return False, "Format non supporté"
    
    file.seek(0)
    header = file.read(8)
    file.seek(0)
    
    magic_numbers = {
        b'\x89PNG': 'png',
        b'\xff\xd8\xff': 'jpeg',
        b'GIF87a': 'gif',
        b'GIF89a': 'gif',
        b'RIFF': 'webp',
    }
    
    valid = False
    for magic, fmt in magic_numbers.items():
        if header.startswith(magic):
            if fmt == 'webp' and b'WEBP' in header[:12]:
                valid = True
            elif fmt != 'webp':
                valid = True
            break
    
    if not valid:
        return False, "Fichier image invalide"
    return True, None


def safe_int(value, default=None, min_val=None, max_val=None):
    try:
        val = int(value)
        if min_val is not None and val < min_val:
            return default
        if max_val is not None and val > max_val:
            return default
        return val
    except (ValueError, TypeError):
        return default

def safe_float(value, default=None, min_val=0, max_val=24):
    try:
        val = float(value)
        if min_val is not None and val < min_val:
            return default
        if max_val is not None and val > max_val:
            return default
        return val
    except (ValueError, TypeError):
        return default


def normalise_statut(val):
    mapping = {
        'Passée': 'passee', 'Annulée': 'annulee', 'Rattrapage': 'rattrapage',
        'passee': 'passee', 'annulee': 'annulee', 'rattrapage': 'rattrapage',
    }
    return mapping.get((val or '').strip(), None)

def parse_professeur_id(form):
    val = form.get('professeur_id', '').strip()
    return safe_int(val)


def seance_to_dict(s):
    return {
        'id':              s.id,
        'date':            s.date.isoformat() if s.date else '',
        'heure':           s.heure or '',
        'statut':          s.statut or '',
        'matiere':         s.matiere or '',
        'niveau':          s.niveau or '',
        'prof':            s.prof_nom or '',
        'professeur_id':   s.professeur_id or '',
        'coordinateur_id': s.coordinateur_id,
        'nb_heures':       s.nb_heures or 0,
        'nb_eleves':       s.nb_eleves or 0,
        'nb_eleves_total': s.nb_eleves_total or 0,
        'remarque':        s.remarque or '',
        'note':            s.note or '',
        'dar_id':          s.dar_id or '',
    }


# ─── Auth ─────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        pwd = request.form.get('password', '')

        if not email or not pwd:
            error = 'Email et mot de passe requis.'
            return render_template('login.html', error=error)

        if not validate_email(email):
            error = 'Email invalide.'
            return render_template('login.html', error=error)

        user = User.query.filter_by(email=email).first()

        if user:
            if user.is_locked():
                error = 'Compte temporairement verrouillé. Réessayez plus tard.'
                return render_template('login.html', error=error)

            if user.check_password(pwd):
                user.login_attempts = 0
                db.session.commit()
                login_user(user)

                if user.must_change_password:
                    flash('Vous devez changer votre mot de passe par défaut.', 'warning')
                    return redirect(url_for('change_password'))

                return redirect(url_for('index'))
            else:
                user.login_attempts += 1
                if user.login_attempts >= 5:
                    user.locked_until = datetime.now() + timedelta(minutes=30)
                    error = 'Trop de tentatives. Compte verrouillé 30 minutes.'
                else:
                    remaining = 5 - user.login_attempts
                    error = f'Identifiants incorrects. {remaining} tentatives restantes.'
                db.session.commit()
        else:
            error = 'Identifiants incorrects.'

    return render_template('login.html', error=error)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_pwd = request.form.get('new_password', '')
        confirm_pwd = request.form.get('confirm_password', '')
        if new_pwd != confirm_pwd:
            flash('Les mots de passe ne correspondent pas.', 'error')
            return redirect(url_for('change_password'))
        try:
            current_user.set_password(new_pwd)
            current_user.must_change_password = False
            db.session.commit()
            flash('Mot de passe changé avec succès!', 'success')
            return redirect(url_for('index'))
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(url_for('change_password'))
    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnexion réussie.', 'info')
    return redirect(url_for('login'))


# ─── Index ────────────────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    now   = datetime.now()
    mois  = safe_int(request.args.get('mois', now.month), min_val=1, max_val=12) or now.month
    annee = safe_int(request.args.get('annee', now.year), min_val=2000, max_val=2100) or now.year
    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                'Juillet','Août','Septembre','Octobre','Novembre','Décembre']
 
    dours = Dour.query.all()
 
    if current_user.is_admin:
        all_resp = Responsable.query.all()
        responsables = [r for r in all_resp if r.user and r.user.role == 'responsable']
    else:
        resp = current_user.responsable
        responsables = [resp] if resp else []
 
    data = []
    for r in responsables:
        data.append({
            'responsable': r,
            'nb_coordinateurs':  r.count_coordinateurs(),
            'nb_coordinatrices': r.count_coordinatrices(),
            'total': len(r.coordinateurs)
        })
 
    if current_user.is_admin:
        all_seances_mois = Seance.query.filter_by(mois=mois, annee=annee).all()
    else:
        resp = current_user.responsable
        coord_ids = [c.id for c in resp.coordinateurs] if resp else []
        all_seances_mois = Seance.query.filter(
            Seance.mois == mois,
            Seance.annee == annee,
            Seance.coordinateur_id.in_(coord_ids)
        ).all()
 
    total_heures_mois    = sum(s.nb_heures for s in all_seances_mois if s.statut == 'passee')
    total_seances_mois   = sum(1 for s in all_seances_mois if s.statut == 'passee')
    total_annulees_mois  = sum(1 for s in all_seances_mois if s.statut == 'annulee')
    total_rattrapage_mois= sum(1 for s in all_seances_mois if s.statut == 'rattrapage')
 
    recap_seances = []
    if current_user.is_admin:
        all_coords = Coordinateur.query.all()
    else:
        resp = current_user.responsable
        all_coords = resp.coordinateurs if resp else []
 
    for coord in all_coords:
        seances = Seance.query.filter_by(coordinateur_id=coord.id, mois=mois, annee=annee).all()
        nb_s = len(seances)
        nb_h = sum(s.nb_heures for s in seances if s.statut == 'passee')
        nb_p = sum(1 for s in seances if s.statut == 'passee')
        nb_a = sum(1 for s in seances if s.statut == 'annulee')
        nb_r = sum(1 for s in seances if s.statut == 'rattrapage')
        if nb_s > 0:
            recap_seances.append({
                'nom': f"{coord.prenom} {coord.nom}",
                'initiales': (coord.prenom[0] + coord.nom[0]).upper() if coord.prenom and coord.nom else '?',
                'genre': coord.genre,
                'responsable': f"{coord.responsable.prenom} {coord.responsable.nom}" if coord.responsable else '',
                'nb_seances': nb_s,
                'nb_heures': nb_h,
                'nb_passees': nb_p,
                'nb_annulees': nb_a,
                'nb_rattrapages': nb_r,
            })
 
    if current_user.is_admin:
        admins = User.query.filter(
            User.role == 'admin',
            User.responsable_id == None
        ).all()
    else:
        admins = []
    nb_admins = len(admins)
 
    if current_user.is_admin:
        all_resp_all      = Responsable.query.order_by(Responsable.nom).all()
        responsables_only = [r for r in all_resp_all if r.user and r.user.role == 'responsable']
        nb_responsables   = len(responsables_only)
    else:
        resp = current_user.responsable
        nb_responsables = len(resp.coordinateurs) if resp else 0
 
    if current_user.is_admin:
        responsables_select = [r for r in Responsable.query.all() if r.user and r.user.role == 'responsable']
    else:
        resp = current_user.responsable
        responsables_select = [resp] if resp else []
 
    return render_template('index.html',
                        data=data,
                        responsables=responsables_select,
                        dours=dours,
                        total_heures_mois=total_heures_mois,
                        total_seances_mois=total_seances_mois,
                        total_annulees_mois=total_annulees_mois,
                        total_rattrapage_mois=total_rattrapage_mois,
                        mois_nom_actuel=mois_noms[mois],
                        annee_actuel=annee,
                        recap_seances=recap_seances,
                        admins=admins,
                        nb_admins=nb_admins,
                        nb_responsables=nb_responsables,
                        )


# ─── Pages dédiées ────────────────────────────────────────────────────────────
@app.route('/ajouter_responsable_page')
@login_required
@admin_required
def ajouter_responsable_page():
    return render_template('ajouter_responsable.html')


@app.route('/ajouter_coordinateur_page')
@login_required
def ajouter_coordinateur_page():
    dours = Dour.query.all()
    if current_user.is_admin:
        all_resp = Responsable.query.all()
        responsables = [r for r in all_resp if r.user and r.user.role == 'responsable']
    else:
        resp = current_user.responsable
        responsables = [resp] if resp else []
    return render_template('ajouter_coordinateur.html', dours=dours, responsables=responsables)


@app.route('/gerer_dours_page')
@login_required
@admin_required
def gerer_dours_page():
    dours = Dour.query.all()
    return render_template('gerer_dours.html', dours=dours)


@app.route('/gerer_coordinateurs')
@login_required
def gerer_coordinateurs():
    dours = Dour.query.all()
    if current_user.is_admin:
        all_resp = Responsable.query.all()
        responsables = [r for r in all_resp if r.user and r.user.role == 'responsable']
        coordinateurs = Coordinateur.query.all()
    else:
        resp = current_user.responsable
        responsables = [resp] if resp else []
        coordinateurs = resp.coordinateurs if resp else []
    return render_template('gerer_coordinateurs.html',
                        coordinateurs=coordinateurs,
                        responsables=responsables, dours=dours)


# ─── Heures / Séances ─────────────────────────────────────────────────────────
@app.route('/heures')
@login_required
@admin_required
def heures():
    now      = datetime.now()
    mois     = request.args.get('mois',  now.month, type=int)
    annee    = request.args.get('annee', now.year,  type=int)
    coord_id = request.args.get('coord_id', type=int)

    if current_user.is_admin:
        coordinateurs = Coordinateur.query.order_by(Coordinateur.nom).all()
    else:
        resp = current_user.responsable
        coordinateurs = sorted(resp.coordinateurs, key=lambda c: c.nom) if resp else []

    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                'Juillet','Août','Septembre','Octobre','Novembre','Décembre']

    if current_user.is_admin:
        all_seances_mois = Seance.query.filter_by(mois=mois, annee=annee).all()
    else:
        resp = current_user.responsable
        coord_ids = [c.id for c in resp.coordinateurs] if resp else []
        all_seances_mois = Seance.query.filter(
            Seance.mois == mois,
            Seance.annee == annee,
            Seance.coordinateur_id.in_(coord_ids)
        ).all()
    total_heures  = sum(s.nb_heures for s in all_seances_mois if s.statut != 'annulee')
    total_seances = sum(1 for s in all_seances_mois if s.statut == 'passee')

    coord_selected = None
    seances_coord  = []
    if coord_id:
        coord_selected = Coordinateur.query.get(coord_id)
        if coord_selected:
            seances_coord = sorted(coord_selected.seances_mois(mois, annee), key=lambda s: s.date)

    profs_list = Professeur.query.filter_by(actif=True).order_by(Professeur.nom).all()
    dours_ids = set()
    for coord in coordinateurs:
        for d in coord.dours:
            dours_ids.add(d.id)
    if dours_ids:
        dours_list = Dour.query.filter(Dour.id.in_(dours_ids)).order_by(Dour.nom).all()
    else:
        dours_list = []

    return render_template('heures.html',
        coordinateurs=coordinateurs,
        coord_selected=coord_selected,
        seances_coord=seances_coord,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        total_heures=total_heures,
        total_seances=total_seances,
        annees=list(range(now.year - 2, now.year + 2)),
        today=date.today().isoformat(),
        matieres=MATIERES,
        niveaux=NIVEAUX,
        profs_list=profs_list,
        dours_list=dours_list,
    )


# ─── Routes unifiées Séances ───────────────────────────────────────────────────

@app.route('/seances/ajouter', methods=['POST'])
@login_required
@password_required
def seance_ajouter():
    try:
        coord_id = safe_int(request.form.get('coordinateur_id'))
        if not coord_id:
            abort(400)

        date_str = request.form.get('date', '').strip()
        if not date_str:
            flash('Date requise.', 'error')
            return redirect_back()

        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()

        if date_obj.year < 2000 or date_obj.year > 2100:
            flash('Date invalide.', 'error')
            return redirect_back()

        nb_heures = safe_float(request.form.get('nb_heures'), min_val=0.5, max_val=12)
        if nb_heures is None:
            flash('Heures invalides (0.5 - 12).', 'error')
            return redirect_back()

        note = sanitize_text(request.form.get('note', ''), max_length=300)
        matiere = sanitize_text(request.form.get('matiere', ''), max_length=100)
        niveau = sanitize_text(request.form.get('niveau', ''), max_length=100)
        heure = sanitize_text(request.form.get('heure', ''), max_length=5)
        remarque = sanitize_text(request.form.get('remarque', ''), max_length=500)
        statut = normalise_statut(request.form.get('statut', ''))
        professeur_id = parse_professeur_id(request.form)

        nb_eleves = safe_int(request.form.get('nb_eleves'), min_val=0, max_val=1000)
        nb_eleves_total = safe_int(request.form.get('nb_eleves_total'), min_val=0, max_val=1000)
        dar_id = safe_int(request.form.get('dar_id'))

        coord = Coordinateur.query.get_or_404(coord_id)
        if not current_user.is_admin:
            if not current_user.responsable or coord.responsable_id != current_user.responsable.id:
                abort(403)

        prof_nom_legacy = None
        if professeur_id:
            p = Professeur.query.get(professeur_id)
            if p:
                prof_nom_legacy = p.nom
            else:
                professeur_id = None

        if dar_id:
            d = Dour.query.get(dar_id)
            if not d:
                dar_id = None

        s = Seance(
            coordinateur_id=coord_id,
            date=date_obj,
            mois=date_obj.month,
            annee=date_obj.year,
            nb_heures=nb_heures,
            note=note,
            matiere=matiere,
            niveau=niveau,
            statut=statut,
            heure=heure,
            prof=prof_nom_legacy,
            professeur_id=professeur_id,
            nb_eleves=nb_eleves,
            nb_eleves_total=nb_eleves_total,
            dar_id=dar_id,
            remarque=remarque,
        )
        db.session.add(s)
        db.session.commit()
        flash(f'Séance ajoutée pour {coord.prenom} {coord.nom}!', 'success')

    except ValueError as e:
        flash(f'Données invalides: {str(e)}', 'error')
        return redirect_back()

    redirect_url = request.form.get('redirect_url', '').strip()
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('heures', mois=date_obj.month, annee=date_obj.year, coord_id=coord_id))


@app.route('/seances/modifier/<int:id>', methods=['POST'])
@login_required
def seance_modifier(id):
    s = Seance.query.get_or_404(id)
    coord = s.coordinateur
    if not current_user.is_admin:
        if not current_user.responsable or coord.responsable_id != current_user.responsable.id:
            abort(403)

    redirect_url  = request.form.get('redirect_url', '').strip()
    date_obj      = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
    s.date        = date_obj
    s.mois        = date_obj.month
    s.annee       = date_obj.year
    s.nb_heures = safe_float(request.form.get('nb_heures'), min_val=0.5, max_val=12)
    if s.nb_heures is None:
        flash('Heures invalides.', 'error')
    s.note = sanitize_text(request.form.get('note', ''), max_length=300)
    s.matiere     = request.form.get('matiere',  '').strip() or None
    s.niveau      = request.form.get('niveau',   '').strip() or None
    s.heure       = request.form.get('heure',    '').strip() or None
    s.remarque    = request.form.get('remarque', '').strip() or None
    s.statut      = normalise_statut(request.form.get('statut', ''))
    s.professeur_id = parse_professeur_id(request.form)
    if s.professeur_id:
        p = Professeur.query.get(s.professeur_id)
        s.prof = p.nom if p else None
    else:
        s.prof = None

    nb_eleves_str = request.form.get('nb_eleves', '').strip()
    s.nb_eleves = int(nb_eleves_str) if nb_eleves_str.isdigit() else None

    nb_eleves_total_str = request.form.get('nb_eleves_total', '').strip()
    s.nb_eleves_total = int(nb_eleves_total_str) if nb_eleves_total_str.isdigit() else None

    dar_id_str = request.form.get('dar_id', '').strip()
    s.dar_id   = int(dar_id_str) if dar_id_str.isdigit() else None

    db.session.commit()
    flash('Séance modifiée!', 'success')

    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('heures', mois=s.mois, annee=s.annee, coord_id=coord.id))


@app.route('/seances/supprimer/<int:id>', methods=['POST'])
@login_required
def seance_supprimer(id):
    s = Seance.query.get_or_404(id)
    mois, annee, coord_id = s.mois, s.annee, s.coordinateur_id
    coord = s.coordinateur
    if not current_user.is_admin:
        if not current_user.responsable or coord.responsable_id != current_user.responsable.id:
            abort(403)

    redirect_url = request.form.get('redirect_url', '').strip()
    db.session.delete(s)
    db.session.commit()
    flash('Séance supprimée!', 'success')

    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('heures', mois=mois, annee=annee, coord_id=coord_id))


@app.route('/seances/ajouter_multiple', methods=['POST'])
@login_required
def seances_ajouter_multiple():
    coord_id     = request.form.get('coordinateur_id', type=int)
    redirect_url = request.form.get('redirect_url', '').strip()

    if not coord_id:
        flash('Coordinateur manquant.', 'error')
        if redirect_url:
            return redirect(redirect_url)
        return redirect(url_for('calendrier_coordinateurs'))

    coord = Coordinateur.query.get_or_404(coord_id)
    if not current_user.is_admin:
        if not current_user.responsable or coord.responsable_id != current_user.responsable.id:
            abort(403)

    sessions = {}
    for key, value in request.form.items():
        if key.startswith('seances['):
            try:
                idx   = key.split('[')[1].split(']')[0]
                field = key.split('[')[2].split(']')[0]
                if idx not in sessions:
                    sessions[idx] = {}
                sessions[idx][field] = value
            except (IndexError, ValueError):
                continue

    added  = 0
    errors = []

    for idx, data in sessions.items():
        date_str  = data.get('date',      '').strip()
        nb_heures = data.get('nb_heures', '').strip()
        matiere   = data.get('matiere',   '').strip() or None
        niveau    = data.get('niveau',    '').strip() or None
        note      = data.get('note',      '').strip() or None
        heure     = data.get('heure',     '').strip() or None
        remarque  = data.get('remarque',  '').strip() or None
        statut    = normalise_statut(data.get('statut', ''))

        prof_id_str   = data.get('professeur_id', '').strip()
        professeur_id = int(prof_id_str) if prof_id_str.isdigit() else None

        nb_eleves_str = data.get('nb_eleves', '').strip()
        nb_eleves = int(nb_eleves_str) if nb_eleves_str.isdigit() else None

        nb_eleves_total_str = data.get('nb_eleves_total', '').strip()
        nb_eleves_total = int(nb_eleves_total_str) if nb_eleves_total_str.isdigit() else None

        dar_id_str = data.get('dar_id', '').strip()
        dar_id = int(dar_id_str) if dar_id_str.isdigit() else None

        if not date_str or not nb_heures:
            errors.append(f'Séance {idx}: date ou heures manquantes.')
            continue

        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
            nb_h     = float(nb_heures)
            if nb_h <= 0:
                raise ValueError('Heures must be positive')
        except ValueError as e:
            errors.append(f'Séance {idx}: valeur invalide ({e}).')
            continue

        prof_nom_legacy = None
        if professeur_id:
            p = Professeur.query.get(professeur_id)
            if p:
                prof_nom_legacy = p.nom

        s = Seance(
            coordinateur_id=coord_id,
            date=date_obj,
            mois=date_obj.month,
            annee=date_obj.year,
            nb_heures=nb_h,
            matiere=matiere,
            niveau=niveau,
            note=note,
            statut=statut,
            heure=heure,
            prof=prof_nom_legacy,
            professeur_id=professeur_id,
            nb_eleves=nb_eleves,
            nb_eleves_total=nb_eleves_total,
            dar_id=dar_id,
            remarque=remarque,
        )
        db.session.add(s)
        added += 1

    if added > 0:
        db.session.commit()
        label = 'séance' if added == 1 else 'séances'
        flash(f'✅ {added} {label} ajoutée{"s" if added > 1 else ""} pour {coord.prenom} {coord.nom}!', 'success')

    for err in errors:
        flash(err, 'error')

    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('calendrier_coordinateurs'))


# ─── Routes legacy ────────────────────────────────────────────────────────────

@app.route('/heures/ajouter', methods=['POST'])
@login_required
def ajouter_seance():
    return seance_ajouter()

@app.route('/heures/modifier/<int:id>', methods=['POST'])
@login_required
def modifier_seance(id):
    return seance_modifier(id)

@app.route('/heures/supprimer/<int:id>', methods=['GET', 'POST'])
@login_required
def supprimer_seance(id):
    if request.method == 'GET':
        s = Seance.query.get_or_404(id)
        mois, annee, coord_id = s.mois, s.annee, s.coordinateur_id
        coord = s.coordinateur
        if not current_user.is_admin:
            if not current_user.responsable or coord.responsable_id != current_user.responsable.id:
                abort(403)
        db.session.delete(s)
        db.session.commit()
        flash('Séance supprimée!', 'success')
        return redirect(url_for('heures', mois=mois, annee=annee, coord_id=coord_id))
    return seance_supprimer(id)

@app.route('/heures/ajouter_multiple', methods=['POST'])
@login_required
def ajouter_seances_multiple():
    return seances_ajouter_multiple()

@app.route('/suivi_partenariat/ajouter', methods=['POST'])
@login_required
def suivi_partenariat_ajouter():
    return seance_ajouter()

@app.route('/suivi_partenariat/modifier/<int:id>', methods=['POST'])
@login_required
def suivi_partenariat_modifier(id):
    return seance_modifier(id)

@app.route('/suivi_partenariat/supprimer/<int:id>', methods=['GET', 'POST'])
@login_required
def suivi_partenariat_supprimer(id):
    if request.method == 'GET':
        s = Seance.query.get_or_404(id)
        mois, annee = s.mois, s.annee
        coord = s.coordinateur
        if not current_user.is_admin:
            if not current_user.responsable or coord.responsable_id != current_user.responsable.id:
                abort(403)
        db.session.delete(s)
        db.session.commit()
        flash('Séance supprimée!', 'success')
        return redirect(url_for('suivi_partenariat', mois=mois, annee=annee))
    return seance_supprimer(id)


# ─── Paramètres ───────────────────────────────────────────────────────────────
@app.route('/parametres')
@login_required
def parametres():
    return render_template('parametres.html')


@app.route('/update_profile', methods=['POST'])
@login_required
@password_required
def update_profile():
    nom = sanitize_text(request.form.get('nom', ''), max_length=100)
    prenom = sanitize_text(request.form.get('prenom', ''), max_length=100)
    email = request.form.get('email', '').strip().lower()

    if not validate_email(email):
        flash('Email invalide.', 'error')
        return redirect(url_for('parametres'))

    existing = User.query.filter_by(email=email).first()
    if existing and existing.id != current_user.id:
        flash('Cet email est déjà utilisé.', 'error')
        return redirect(url_for('parametres'))

    current_user.nom = nom
    current_user.prenom = prenom
    current_user.email = email
    db.session.commit()
    flash('Informations mises à jour avec succès!', 'success')
    return redirect(url_for('index'))

@app.route('/update_password', methods=['POST'])
@login_required
@password_required
def update_password():
    current_pwd = request.form.get('current_password', '')
    new_pwd = request.form.get('new_password', '')
    confirm_pwd = request.form.get('confirm_password', '')

    if not current_user.check_password(current_pwd):
        flash('Mot de passe actuel incorrect.', 'error')
        return redirect(url_for('parametres'))

    if new_pwd != confirm_pwd:
        flash('Les mots de passe ne correspondent pas.', 'error')
        return redirect(url_for('parametres'))

    try:
        current_user.set_password(new_pwd)
        db.session.commit()
        flash('Mot de passe changé avec succès!', 'success')
    except ValueError as e:
        flash(str(e), 'error')

    return redirect(url_for('index'))

@app.route('/update_avatar', methods=['POST'])
@login_required
@password_required
def update_avatar():
    file = request.files.get('avatar')
    is_valid, error_msg = validate_image_file(file)
    if not is_valid:
        flash(error_msg, 'error')
        return redirect(url_for('parametres'))

    avatar_dir = os.path.join(app.root_path, 'static', 'avatars')
    os.makedirs(avatar_dir, exist_ok=True)

    if current_user.avatar:
        old_path = os.path.join(avatar_dir, current_user.avatar)
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except OSError:
                pass

    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"user_{uuid.uuid4().hex}_{uuid.uuid4().hex[:8]}.{ext}"
    filepath = os.path.join(avatar_dir, filename)

    real_path = os.path.realpath(filepath)
    real_dir = os.path.realpath(avatar_dir)
    if not real_path.startswith(real_dir):
        flash('Chemin invalide.', 'error')
        return redirect(url_for('parametres'))

    file.save(filepath)
    current_user.avatar = filename
    db.session.commit()
    flash('Photo de profil mise à jour!', 'success')
    return redirect(url_for('index'))


# ─── Responsables ─────────────────────────────────────────────────────────────
@app.route('/ajouter_responsable', methods=['POST'])
@login_required
@admin_required
def ajouter_responsable():
    email_resp = request.form['email'].strip().lower()
    pwd        = request.form['password']
    role       = request.form.get('role', 'responsable')
    if role not in ('admin', 'responsable'):
        role = 'responsable'

    if User.query.filter_by(email=email_resp).first():
        flash('Cet email est déjà utilisé.', 'error')
        return redirect(url_for('gerer_responsables'))

    if role == 'responsable':
        r = Responsable(nom=request.form['nom'], prenom=request.form['prenom'], email=email_resp)
        db.session.add(r)
        db.session.flush()
        u = User(email=email_resp, role='responsable', responsable_id=r.id)
        u.set_password(pwd)
        db.session.add(u)
    else:
        u = User(
            email=email_resp,
            role='admin',
            nom=request.form['nom'],
            prenom=request.form['prenom'],
            responsable_id=None
        )
        u.set_password(pwd)
        db.session.add(u)

    db.session.commit()
    flash(f'{"Responsable" if role == "responsable" else "Admin"} ajouté avec succès!', 'success')
    return redirect(url_for('gerer_responsables'))


@app.route('/gerer_responsables')
@login_required
@admin_required
def gerer_responsables():
    all_resp = Responsable.query.order_by(Responsable.nom).all()
    responsables_only = [r for r in all_resp if r.user and r.user.role == 'responsable']
    admins_purs = User.query.filter_by(role='admin').filter(
                    User.responsable_id == None
                ).order_by(User.nom).all()
    total_coordinateurs = Coordinateur.query.count()
    return render_template('gerer_responsables.html',
                        responsables_only=responsables_only,
                        admins_only=[],
                        admins_purs=admins_purs,
                        total_coordinateurs=total_coordinateurs)


@app.route('/modifier_responsable/<int:id>', methods=['POST'])
@login_required
@admin_required
def modifier_responsable(id):
    r = Responsable.query.get_or_404(id)
    r.nom    = request.form['nom'].strip()
    r.prenom = request.form['prenom'].strip()
    new_email = request.form['email'].strip().lower()
    new_role  = request.form.get('role', 'responsable')
    if new_role not in ('admin', 'responsable'):
        new_role = 'responsable'

    if r.user:
        existing = User.query.filter_by(email=new_email).first()
        if existing and existing.id != r.user.id:
            flash('Cet email est déjà utilisé.', 'error')
            return redirect(url_for('gerer_responsables'))
        r.user.email = new_email
        r.user.role  = new_role
        pwd = request.form.get('password', '').strip()
        if pwd:
            r.user.set_password(pwd)

        if new_role == 'responsable':
            r.user.responsable_id = r.id
            r.email = new_email
            db.session.commit()
        else:
            u = r.user
            u.responsable_id = None
            u.nom    = r.nom
            u.prenom = r.prenom
            u.email  = new_email
            u.role   = 'admin'
            db.session.flush()
            for c in r.coordinateurs:
                Seance.query.filter_by(coordinateur_id=c.id).delete()
                db.session.execute(
                    db.text("DELETE FROM coordinateur_dour WHERE coordinateur_id = :cid"),
                    {"cid": c.id}
                )
                db.session.flush()
                db.session.delete(c)
            db.session.delete(r)
            db.session.commit()

    flash('Compte modifié avec succès!', 'success')
    return redirect(url_for('gerer_responsables'))


@app.route('/supprimer_responsable/<int:id>')
@login_required
@admin_required
def supprimer_responsable(id):
    r = Responsable.query.get_or_404(id)
    for c in r.coordinateurs:
        Seance.query.filter_by(coordinateur_id=c.id).delete()
        db.session.execute(
            db.text("DELETE FROM coordinateur_dour WHERE coordinateur_id = :cid"),
            {"cid": c.id}
        )
        db.session.flush()
        db.session.delete(c)
    if r.user:
        db.session.delete(r.user)
    db.session.delete(r)
    db.session.commit()
    flash('Responsable supprimé avec ses coordinateurs!', 'success')
    return redirect(url_for('gerer_responsables'))


# ─── Admins ───────────────────────────────────────────────────────────────────
@app.route('/ajouter_admin', methods=['POST'])
@login_required
@admin_required
def ajouter_admin():
    email = request.form['email'].strip().lower()
    if User.query.filter_by(email=email).first():
        flash('Cet email est déjà utilisé.', 'error')
        return redirect(url_for('index'))
    u = User(email=email, role='admin')
    u.nom    = request.form.get('nom', '').strip()
    u.prenom = request.form.get('prenom', '').strip()
    u.set_password(request.form['password'])
    db.session.add(u)
    db.session.commit()
    flash(f'Administrateur {u.prenom} {u.nom} ajouté!', 'success')
    return redirect(url_for('index'))


@app.route('/modifier_admin/<int:id>', methods=['POST'])
@login_required
@admin_required
def modifier_admin(id):
    u = User.query.get_or_404(id)
    new_email = request.form['email'].strip().lower()
    existing = User.query.filter_by(email=new_email).first()
    if existing and existing.id != u.id:
        flash('Email déjà utilisé.', 'error')
        return redirect(url_for('index'))

    old_role = u.role
    u.email  = new_email
    u.nom    = request.form.get('nom', '').strip()
    u.prenom = request.form.get('prenom', '').strip()

    new_role = request.form.get('role', 'admin')
    if new_role not in ('admin', 'responsable'):
        new_role = 'admin'

    safe_nom    = u.nom    or u.email.split('@')[0]
    safe_prenom = u.prenom or u.email.split('@')[0]

    if new_role == 'responsable':
        if u.responsable_id is None:
            r = Responsable(nom=safe_nom, prenom=safe_prenom, email=u.email)
            db.session.add(r)
            db.session.flush()
            u.responsable_id = r.id
        else:
            r = Responsable.query.get(u.responsable_id)
            if r:
                r.nom    = safe_nom
                r.prenom = safe_prenom
                r.email  = u.email
    elif new_role == 'admin' and old_role == 'responsable':
        u.responsable_id = None

    u.role = new_role

    pwd = request.form.get('password', '').strip()
    if pwd:
        if len(pwd) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères.', 'error')
            return redirect(url_for('index'))
        u.set_password(pwd)

    db.session.commit()
    flash('Compte modifié avec succès!', 'success')
    return redirect(url_for('index'))


@app.route('/supprimer_admin/<int:id>')
@login_required
@admin_required
def supprimer_admin(id):
    if id == current_user.id:
        flash('Impossible de supprimer votre propre compte.', 'error')
        return redirect(url_for('index'))
    u = User.query.get_or_404(id)
    db.session.delete(u)
    db.session.commit()
    flash('Admin supprimé!', 'success')
    return redirect(url_for('index'))


# ─── Coordinateurs ────────────────────────────────────────────────────────────
@app.route('/ajouter_coordinateur', methods=['POST'])
@login_required
def ajouter_coordinateur():
    resp_id = request.form['responsable_id']
    if not current_user.is_admin:
        if not current_user.responsable or str(current_user.responsable.id) != str(resp_id):
            abort(403)
    dour_ids = request.form.getlist('dours')
    c = Coordinateur(nom=request.form['nom'], prenom=request.form['prenom'],
                    genre=request.form['genre'], responsable_id=resp_id)
    for did in dour_ids:
        d = Dour.query.get(int(did))
        if d: c.dours.append(d)
    db.session.add(c)
    db.session.commit()
    flash('Coordinateur ajouté avec succès!', 'success')
    return redirect(url_for('ajouter_coordinateur_page'))


@app.route('/modifier_coordinateur/<int:id>', methods=['POST'])
@login_required
def modifier_coordinateur(id):
    c = Coordinateur.query.get_or_404(id)
    if not current_user.is_admin:
        if not current_user.responsable or c.responsable_id != current_user.responsable.id:
            abort(403)
    c.nom = request.form['nom']
    c.prenom = request.form['prenom']
    c.genre = request.form['genre']
    c.responsable_id = request.form['responsable_id']
    db.session.execute(
        db.text("DELETE FROM coordinateur_dour WHERE coordinateur_id = :cid"),
        {"cid": c.id}
    )
    db.session.flush()
    for did in request.form.getlist('dours'):
        d = Dour.query.get(int(did))
        if d: c.dours.append(d)
    db.session.commit()
    flash('Coordinateur modifié!', 'success')
    return redirect(url_for('gerer_coordinateurs'))


@app.route('/supprimer_coordinateur/<int:id>')
@login_required
def supprimer_coordinateur(id):
    c = Coordinateur.query.get_or_404(id)
    if not current_user.is_admin:
        if not current_user.responsable or c.responsable_id != current_user.responsable.id:
            abort(403)
    Seance.query.filter_by(coordinateur_id=c.id).delete()
    db.session.execute(
        db.text("DELETE FROM coordinateur_dour WHERE coordinateur_id = :cid"),
        {"cid": c.id}
    )
    db.session.flush()
    db.session.delete(c)
    db.session.commit()
    flash('Coordinateur supprimé!', 'success')
    return redirect_back()


# ─── Dours ────────────────────────────────────────────────────────────────────
@app.route('/gerer_dours', methods=['POST'])
@login_required
@admin_required
def gerer_dours():
    d = Dour(nom=request.form['nom'], type=request.form['type'])
    db.session.add(d)
    db.session.commit()
    flash('Dour ajoutée!', 'success')
    return redirect(url_for('gerer_dours_page'))


@app.route('/supprimer_dour/<int:id>')
@login_required
@admin_required
def supprimer_dour(id):
    d = Dour.query.get_or_404(id)
    db.session.delete(d)
    db.session.commit()
    flash('Dour supprimée!', 'success')
    return redirect(url_for('gerer_dours_page'))


# ─── Impression ───────────────────────────────────────────────────────────────
@app.route('/impression_seances')
@login_required
def impression_seances():
    from collections import defaultdict

    now   = datetime.now()
    mois  = request.args.get('mois',  now.month,  type=int)
    annee = request.args.get('annee', now.year,   type=int)
    filtre_matiere = request.args.get('filtre_matiere', '').strip()
    filtre_niveau  = request.args.get('filtre_niveau',  '').strip()
    filtre_coord   = request.args.get('filtre_coord',   '').strip()
    filtre_dar     = request.args.get('filtre_dar',     '').strip()

    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                'Juillet','Août','Septembre','Octobre','Novembre','Décembre']

    if current_user.is_admin:
        coordinateurs = Coordinateur.query.order_by(Coordinateur.nom).all()
    else:
        resp = current_user.responsable
        coordinateurs = sorted(resp.coordinateurs, key=lambda c: c.nom) if resp else []

    all_dours = Dour.query.order_by(Dour.nom).all()

    stats = []
    heures_par_mat = defaultdict(float)
    heures_par_niv = defaultdict(float)

    for coord in coordinateurs:
        if filtre_coord and str(coord.id) != filtre_coord:
            continue

        seances = coord.seances_mois(mois, annee)

        if filtre_dar:
            try:
                filtre_dar_int = int(filtre_dar)
                seances = [s for s in seances if s.dar_id == filtre_dar_int]
            except ValueError:
                pass

        if filtre_matiere:
            seances = [s for s in seances if s.matiere == filtre_matiere]
        if filtre_niveau:
            seances = [s for s in seances if s.niveau == filtre_niveau]

        if (filtre_dar or filtre_matiere or filtre_niveau or filtre_coord) and len(seances) == 0:
            continue

        nb_h = sum(s.nb_heures for s in seances if s.statut == 'passee')
        mats = sorted({s.matiere for s in seances if s.matiere})
        nivs = sorted({s.niveau  for s in seances if s.niveau})

        for s in seances:
            if s.matiere: heures_par_mat[s.matiere] += s.nb_heures
            if s.niveau:  heures_par_niv[s.niveau]  += s.nb_heures

        stats.append({
            'coord':          coord,
            'seances':        seances,
            'nb_seances':     len(seances),
            'nb_heures':      nb_h,
            'initiales':      (coord.prenom[0] + coord.nom[0]).upper()
                            if coord.prenom and coord.nom else '?',
            'matieres_uniq':  mats,
            'niveaux_uniq':   nivs,
            'nb_passees':     sum(1 for s in seances if s.statut == 'passee'),
            'nb_annulees':    sum(1 for s in seances if s.statut == 'annulee'),
            'nb_rattrapage':  sum(1 for s in seances if s.statut == 'rattrapage'),
            'total_eleves':   sum(s.nb_eleves for s in seances if s.nb_eleves and s.statut != 'annulee'),
        })

    stats.sort(key=lambda x: x['nb_heures'], reverse=True)

    total_heures     = sum(s['nb_heures']     for s in stats)
    total_seances    = sum(s['nb_seances']    for s in stats)
    total_coords     = sum(1 for s in stats if s['nb_seances'] > 0)
    total_passees    = sum(s['nb_passees']    for s in stats)
    total_annulees   = sum(s['nb_annulees']   for s in stats)
    total_rattrapage = sum(s['nb_rattrapage'] for s in stats)
    total_eleves     = sum(s['total_eleves']  for s in stats)

    breakdown_mat = sorted(heures_par_mat.items(), key=lambda x: x[1], reverse=True)
    breakdown_niv = sorted(heures_par_niv.items(), key=lambda x: x[1], reverse=True)
    generated_at  = now.strftime('%d/%m/%Y à %H:%M')

    return render_template('impression_seances.html',
        stats=stats,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        annees=list(range(now.year - 2, now.year + 2)),
        filtre_matiere=filtre_matiere,
        filtre_niveau=filtre_niveau,
        filtre_coord=filtre_coord,
        filtre_dar=filtre_dar,
        matieres=MATIERES,
        niveaux=NIVEAUX,
        all_coordinateurs=coordinateurs,
        all_dours=all_dours,
        total_heures=total_heures,
        total_seances=total_seances,
        total_coords=total_coords,
        total_passees=total_passees,
        total_annulees=total_annulees,
        total_rattrapage=total_rattrapage,
        total_eleves=total_eleves,
        breakdown_mat=breakdown_mat,
        breakdown_niv=breakdown_niv,
        generated_at=generated_at,
    )


# ─── Erreurs ──────────────────────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


# ─── Stats Coordinateurs ──────────────────────────────────────────────────────
@app.route('/stats_coordinateurs')
@login_required
@admin_required
def stats_coordinateurs():
    now   = datetime.now()
    mois  = request.args.get('mois',  now.month,  type=int)
    annee = request.args.get('annee', now.year,   type=int)

    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                'Juillet','Août','Septembre','Octobre','Novembre','Décembre']

    if current_user.is_admin:
        coordinateurs = Coordinateur.query.order_by(Coordinateur.nom).all()
    else:
        resp = current_user.responsable
        coordinateurs = sorted(resp.coordinateurs, key=lambda c: c.nom) if resp else []

    stats = []
    for coord in coordinateurs:
        seances = coord.seances_mois(mois, annee)
        nb_h = sum(s.nb_heures for s in seances if s.statut == 'passee')
        nb_passees   = sum(1 for s in seances if s.statut == 'passee')
        nb_annulees  = sum(1 for s in seances if s.statut == 'annulee')
        nb_rattrapage= sum(1 for s in seances if s.statut == 'rattrapage')
        total_eleves = sum(s.nb_eleves for s in seances if s.nb_eleves and s.statut != 'annulee')
        stats.append({
            'coord':         coord,
            'seances':       seances,
            'nb_seances':    len(seances),
            'nb_heures':     nb_h,
            'nb_passees':    nb_passees,
            'nb_annulees':   nb_annulees,
            'nb_rattrapage': nb_rattrapage,
            'total_eleves':  total_eleves,
            'initiales':     (coord.prenom[0] + coord.nom[0]).upper() if coord.prenom and coord.nom else '?',
        })

    stats.sort(key=lambda x: x['nb_heures'], reverse=True)

    total_heures     = sum(s['nb_heures']     for s in stats)
    total_seances    = sum(s['nb_seances']    for s in stats)
    total_passees    = sum(s['nb_passees']    for s in stats)
    total_annulees   = sum(s['nb_annulees']   for s in stats)
    total_rattrapage = sum(s['nb_rattrapage'] for s in stats)
    total_eleves     = sum(s['total_eleves']  for s in stats)
    max_heures       = max((s['nb_heures'] for s in stats), default=1) or 1

    coord_id = request.args.get('coord_id', type=int)
    coord_detail   = None
    seances_detail = []
    if coord_id:
        coord_detail = Coordinateur.query.get(coord_id)
        if coord_detail:
            if not current_user.is_admin:
                resp = current_user.responsable
                if not resp or coord_detail.responsable_id != resp.id:
                    coord_detail = None
            if coord_detail:
                seances_detail = coord_detail.seances_mois(mois, annee)

    return render_template('stats_coordinateurs.html',
        stats=stats,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        annees=list(range(now.year - 2, now.year + 2)),
        total_heures=total_heures,
        total_seances=total_seances,
        total_passees=total_passees,
        total_annulees=total_annulees,
        total_rattrapage=total_rattrapage,
        total_eleves=total_eleves,
        max_heures=max_heures,
        coord_detail=coord_detail,
        seances_detail=seances_detail,
    )


# ─── Calendrier Coordinateurs ─────────────────────────────────────────────────
@app.route('/calendrier_coordinateurs')
@login_required
def calendrier_coordinateurs():
    from collections import defaultdict

    now   = datetime.now()
    mois  = request.args.get('mois',  now.month,  type=int)
    annee = request.args.get('annee', now.year,   type=int)
    filtre_matiere = request.args.get('filtre_matiere', '').strip()
    filtre_niveau  = request.args.get('filtre_niveau',  '').strip()
    filtre_statut  = request.args.get('filtre_statut',  '').strip()
    filtre_dar     = request.args.get('filtre_dar',     '').strip()

    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                'Juillet','Août','Septembre','Octobre','Novembre','Décembre']

    dours_objs = Dour.query.order_by(Dour.nom).all()
    dours = dours_objs
    dours_json = [{'id': d.id, 'nom': d.nom, 'type': d.type} for d in dours_objs]

    if current_user.is_admin:
        coordinateurs = Coordinateur.query.order_by(Coordinateur.nom).all()
    else:
        resp = current_user.responsable
        coordinateurs = sorted(resp.coordinateurs, key=lambda c: c.nom) if resp else []

    professeurs = Professeur.query.filter_by(actif=True).order_by(Professeur.nom).all()

    stats = []
    heures_par_mat       = defaultdict(float)
    heures_par_niv       = defaultdict(float)
    matieres_actives_set = set()
    niveaux_actifs_set   = set()

    for coord in coordinateurs:
        seances = coord.seances_mois(mois, annee)

        if filtre_matiere:
            seances = [s for s in seances if s.matiere == filtre_matiere]
        if filtre_niveau:
            seances = [s for s in seances if s.niveau == filtre_niveau]
        if filtre_statut:
            seances = [s for s in seances if s.statut == filtre_statut]
        if filtre_dar:
            try:
                filtre_dar_int = int(filtre_dar)
                seances = [s for s in seances if s.dar_id == filtre_dar_int]
            except ValueError:
                pass

        nb_h = sum(s.nb_heures for s in seances if s.statut == 'passee')
        mats = sorted({s.matiere for s in seances if s.matiere})
        nivs = sorted({s.niveau  for s in seances if s.niveau})
        matieres_actives_set.update(mats)
        niveaux_actifs_set.update(nivs)

        for s in seances:
            if s.matiere: heures_par_mat[s.matiere] += s.nb_heures
            if s.niveau:  heures_par_niv[s.niveau]  += s.nb_heures

        stats.append({
            'coord':          coord,
            'seances':        seances,
            'nb_seances':     len(seances),
            'nb_heures':      nb_h,
            'initiales':      (coord.prenom[0] + coord.nom[0]).upper() if coord.prenom and coord.nom else '?',
            'matieres_uniq':  mats,
            'niveaux_uniq':   nivs,
            'nb_passees':     sum(1 for s in seances if s.statut == 'passee'),
            'nb_annulees':    sum(1 for s in seances if s.statut == 'annulee'),
            'nb_rattrapage':  sum(1 for s in seances if s.statut == 'rattrapage'),
            'total_eleves':   sum(s.nb_eleves for s in seances if s.nb_eleves and s.statut != 'annulee'),
        })

    stats.sort(key=lambda x: x['nb_heures'], reverse=True)
    breakdown_mat = sorted(heures_par_mat.items(), key=lambda x: x[1], reverse=True)
    breakdown_niv = sorted(heures_par_niv.items(), key=lambda x: x[1], reverse=True)

    total_heures     = sum(s['nb_heures']    for s in stats)
    total_seances    = sum(s['nb_seances']   for s in stats)
    total_passees    = sum(s['nb_passees']   for s in stats)
    total_annulees   = sum(s['nb_annulees']  for s in stats)
    total_rattrapage = sum(s['nb_rattrapage']for s in stats)
    total_eleves     = sum(s['total_eleves'] for s in stats)

    all_seances_flat = []
    for st in stats:
        all_seances_flat.extend(st['seances'])

    seances_json = [seance_to_dict(s) for s in all_seances_flat]

    return render_template('calendrier_coordinateurs.html',
        stats=stats,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        annees=list(range(now.year - 2, now.year + 2)),
        filtre_matiere=filtre_matiere,
        filtre_niveau=filtre_niveau,
        filtre_statut=filtre_statut,
        filtre_dar=filtre_dar,
        matieres=MATIERES,
        niveaux=NIVEAUX,
        statuts=STATUTS_SEANCE,
        dours=dours,
        dours_json=dours_json,
        professeurs=professeurs,
        seances_json=seances_json,
        total_heures=total_heures,
        total_seances=total_seances,
        total_passees=total_passees,
        total_annulees=total_annulees,
        total_rattrapage=total_rattrapage,
        total_eleves=total_eleves,
        breakdown_mat=breakdown_mat,
        breakdown_niv=breakdown_niv,
        matieres_actives=sorted(matieres_actives_set),
        niveaux_actifs=sorted(niveaux_actifs_set),
    )


@app.route('/update_social', methods=['POST'])
@login_required
def update_social():
    current_user.facebook = request.form.get('facebook', '').strip() or None
    current_user.twitter  = request.form.get('twitter',  '').strip() or None
    current_user.linkedin = request.form.get('linkedin', '').strip() or None
    current_user.website  = request.form.get('website',  '').strip() or None
    db.session.commit()
    flash('Réseaux sociaux mis à jour!', 'success')
    return redirect(url_for('parametres'))


# ─── Gestion Professeurs ──────────────────────────────────────────────────────
@app.route('/gerer_professeurs')
@login_required
@admin_required
def gerer_professeurs():
    professeurs = Professeur.query.order_by(Professeur.nom).all()
    return render_template('gerer_professeurs.html', professeurs=professeurs)


@app.route('/ajouter_professeur', methods=['POST'])
@login_required
@admin_required
def ajouter_professeur():
    nom = request.form.get('nom', '').strip()
    if not nom:
        flash('Nom obligatoire.', 'error')
        return redirect(url_for('gerer_professeurs'))
    if Professeur.query.filter_by(nom=nom).first():
        flash('Ce professeur existe déjà.', 'error')
        return redirect(url_for('gerer_professeurs'))
    db.session.add(Professeur(nom=nom))
    db.session.commit()
    flash(f'Professeur "{nom}" ajouté!', 'success')
    return redirect(url_for('gerer_professeurs'))


@app.route('/modifier_professeur/<int:id>', methods=['POST'])
@login_required
@admin_required
def modifier_professeur(id):
    p = Professeur.query.get_or_404(id)
    nom = request.form.get('nom', '').strip()
    if not nom:
        flash('Nom obligatoire.', 'error')
        return redirect(url_for('gerer_professeurs'))
    p.nom   = nom
    p.actif = request.form.get('actif', '0') == '1'
    db.session.commit()
    flash('Professeur modifié!', 'success')
    return redirect(url_for('gerer_professeurs'))


@app.route('/supprimer_professeur/<int:id>')
@login_required
@admin_required
def supprimer_professeur(id):
    p = Professeur.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    flash('Professeur supprimé!', 'success')
    return redirect(url_for('gerer_professeurs'))


@app.route('/toggle_professeur/<int:id>')
@login_required
@admin_required
def toggle_professeur(id):
    p = Professeur.query.get_or_404(id)
    p.actif = not p.actif
    db.session.commit()
    return redirect(url_for('gerer_professeurs'))


# ─── Suivi Partenariat ────────────────────────────────────────────────────────
@app.route('/suivi_partenariat')
@login_required
def suivi_partenariat():
    from collections import defaultdict

    now   = datetime.now()
    mois  = request.args.get('mois',  now.month,  type=int)
    annee = request.args.get('annee', now.year,   type=int)

    filtre_dar     = request.args.get('filtre_dar',     '').strip()
    filtre_niveau  = request.args.get('filtre_niveau',  '').strip()
    filtre_statut  = request.args.get('filtre_statut',  '').strip()
    filtre_matiere = request.args.get('filtre_matiere', '').strip()

    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                'Juillet','Août','Septembre','Octobre','Novembre','Décembre']

    if current_user.is_admin:
        coordinateurs = Coordinateur.query.order_by(Coordinateur.nom).all()
    else:
        resp = current_user.responsable
        coordinateurs = sorted(resp.coordinateurs, key=lambda c: c.nom) if resp else []

    dours_ids_set = set()
    for coord in coordinateurs:
        for d in coord.dours:
            dours_ids_set.add(d.id)
    dours = Dour.query.filter(Dour.id.in_(dours_ids_set)).order_by(Dour.nom).all()

    professeurs = Professeur.query.filter_by(actif=True).order_by(Professeur.nom).all()

    coord_ids = [c.id for c in coordinateurs]

    all_seances = Seance.query.filter(
        Seance.mois == mois,
        Seance.annee == annee,
        Seance.coordinateur_id.in_(coord_ids)
    ).order_by(Seance.date.desc()).all()

    q = Seance.query.filter(
        Seance.mois == mois,
        Seance.annee == annee,
        Seance.coordinateur_id.in_(coord_ids)
    )
    if filtre_dar:
        try:
            q = q.filter(Seance.dar_id == int(filtre_dar))
        except ValueError:
            pass
    if filtre_niveau:
        q = q.filter(Seance.niveau == filtre_niveau)
    if filtre_statut:
        q = q.filter(Seance.statut == filtre_statut)
    if filtre_matiere:
        q = q.filter(Seance.matiere == filtre_matiere)

    seances_raw  = q.order_by(Seance.date.desc()).all()
    seances_json = [seance_to_dict(s) for s in all_seances]

    par_dar  = defaultdict(list)
    sans_dar = []
    for s in seances_raw:
        if s.dar_id:
            par_dar[s.dar_id].append(s)
        else:
            sans_dar.append(s)

    dars_ids_actives = set()
    for coord in coordinateurs:
        for d in coord.dours:
            dars_ids_actives.add(d.id)

    blocs_dar = []
    for dour in dours:
        if dour.id not in dars_ids_actives:
            continue
        if filtre_dar and str(dour.id) != filtre_dar:
            continue
        seances_d = par_dar.get(dour.id, [])
        blocs_dar.append({
            'dour':          dour,
            'seances':       seances_d,
            'nb_passees':    sum(1 for s in seances_d if s.statut == 'passee'),
            'nb_annulees':   sum(1 for s in seances_d if s.statut == 'annulee'),
            'nb_rattrapage': sum(1 for s in seances_d if s.statut == 'rattrapage'),
            'total_heures':  sum(s.nb_heures for s in seances_d if s.statut == 'passee'),
            'total_eleves':  sum(s.nb_eleves for s in seances_d if s.nb_eleves and s.statut != 'annulee'),
            'niveaux_uniq':  sorted({s.niveau for s in seances_d if s.niveau}),
        })

    par_niveau = defaultdict(list)
    for s in seances_raw:
        key = s.niveau or '— Non défini —'
        par_niveau[key].append(s)

    blocs_niveau = []
    for niv, seances_n in sorted(par_niveau.items()):
        valeurs_total = [s.nb_eleves_total for s in seances_n if s.nb_eleves_total]
        effectif_total = max(valeurs_total) if valeurs_total else None

        blocs_niveau.append({
            'niveau':          niv,
            'seances':         seances_n,
            'nb_passees':      sum(1 for s in seances_n if s.statut == 'passee'),
            'nb_annulees':     sum(1 for s in seances_n if s.statut == 'annulee'),
            'nb_rattrapage':   sum(1 for s in seances_n if s.statut == 'rattrapage'),
            'total_heures':    sum(s.nb_heures for s in seances_n if s.statut == 'passee'),
            'total_eleves':    sum(s.nb_eleves for s in seances_n if s.nb_eleves and s.statut != 'annulee'),
            'effectif_total':  effectif_total,
        })

    total_passees    = sum(1 for s in all_seances if s.statut == 'passee')
    total_annulees   = sum(1 for s in all_seances if s.statut == 'annulee')
    total_rattrapage = sum(1 for s in all_seances if s.statut == 'rattrapage')
    total_heures          = sum(s.nb_heures for s in all_seances if s.statut != 'annulee')
    total_passees_heures  = sum(s.nb_heures for s in all_seances if s.statut == 'passee')
    total_eleves     = sum(s.nb_eleves for s in all_seances if s.nb_eleves and s.statut != 'annulee')

    return render_template('suivi_partenariat.html',
        blocs_dar=blocs_dar,
        blocs_niveau=blocs_niveau,
        sans_dar=sans_dar,
        seances_json=seances_json,
        dours=dours,
        coordinateurs=coordinateurs,
        professeurs=professeurs,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        annees=list(range(now.year - 2, now.year + 2)),
        filtre_dar=filtre_dar,
        filtre_niveau=filtre_niveau,
        filtre_statut=filtre_statut,
        filtre_matiere=filtre_matiere,
        matieres=MATIERES,
        niveaux=NIVEAUX,
        statuts=STATUTS_SEANCE,
        total_passees=total_passees,
        total_annulees=total_annulees,
        total_rattrapage=total_rattrapage,
        total_heures=total_heures,
        total_passees_heures=total_passees_heures,
        total_eleves=total_eleves,
        total_seances=len(all_seances),
    )

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        now = datetime.now()
        if (
            not current_user.last_seen
            or (now - current_user.last_seen).total_seconds() > 60
        ):
            current_user.last_seen = now
            db.session.commit()


@app.route('/api/statut_responsables')
@login_required
@admin_required
@limiter.limit("30 per minute")
def api_statut_responsables():
    users = User.query.all()
    data = {str(u.id): u.is_online for u in users}
    return Response(json.dumps(data), mimetype='application/json')

@app.route('/api/statut_user/<int:user_id>')
@login_required
@admin_required
@limiter.limit("30 per minute")
def api_statut_user(user_id):
    u = User.query.get_or_404(user_id)
    return Response(
        json.dumps({
            'online': u.is_online,
            'last_seen': u.last_seen.isoformat() if u.last_seen else None,
            'last_seen_fr': u.last_seen_display,
        }),
        mimetype='application/json'
    )


# ─── Suivi B2C ────────────────────────────────────────────────────────────────

@app.route('/suivi_b2c')
@login_required
@admin_required
def suivi_b2c():
    from collections import defaultdict

    now   = datetime.now()
    mois  = request.args.get('mois',  now.month,  type=int)
    annee = request.args.get('annee', now.year,   type=int)

    filtre_resp   = request.args.get('filtre_resp',   '').strip()
    filtre_statut = request.args.get('filtre_statut', '').strip()
    filtre_prof   = request.args.get('filtre_prof',   '').strip()

    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                'Juillet','Août','Septembre','Octobre','Novembre','Décembre']

    if current_user.is_admin:
        all_resp = Responsable.query.all()
        responsables = [r for r in all_resp if r.user and r.user.role == 'responsable']
    else:
        resp = current_user.responsable
        responsables = [resp] if resp else []

    resp_ids = [r.id for r in responsables]

    dours_all   = Dour.query.order_by(Dour.nom).all()
    professeurs = Professeur.query.filter_by(actif=True).order_by(Professeur.nom).all()

    q = SeanceB2C.query.filter(
        SeanceB2C.mois == mois,
        SeanceB2C.annee == annee,
        SeanceB2C.responsable_id.in_(resp_ids)
    )
    if filtre_resp:
        try:
            q = q.filter(SeanceB2C.responsable_id == int(filtre_resp))
        except ValueError:
            pass
    if filtre_statut:
        q = q.filter(SeanceB2C.statut == filtre_statut)
    if filtre_prof:
        try:
            q = q.filter(SeanceB2C.professeur_id == int(filtre_prof))
        except ValueError:
            pass

    seances = q.order_by(SeanceB2C.date.desc()).all()

    q_global = SeanceB2C.query.filter(
        SeanceB2C.mois == mois,
        SeanceB2C.annee == annee,
        SeanceB2C.responsable_id.in_(resp_ids)
    )
    if filtre_resp:
        try:
            q_global = q_global.filter(SeanceB2C.responsable_id == int(filtre_resp))
        except ValueError:
            pass

    all_seances_mois = q_global.all()

    total_passees    = sum(1 for s in all_seances_mois if s.statut == 'passee')
    total_annulees   = sum(1 for s in all_seances_mois if s.statut == 'annulee')
    total_rattrapage = sum(1 for s in all_seances_mois if s.statut == 'rattrapage')
    total_heures     = sum(s.nb_heures for s in all_seances_mois if s.statut == 'passee')
    total_presents   = sum(s.total_presents for s in all_seances_mois if s.statut != 'annulee')

    blocs_resp = []
    for resp in responsables:
        if filtre_resp and str(resp.id) != filtre_resp:
            continue

        s_resp = [s for s in seances if s.responsable_id == resp.id]

        if not s_resp:
            s_resp_all = [s for s in all_seances_mois if s.responsable_id == resp.id]
            if not s_resp_all:
                continue
            if not filtre_statut and not filtre_prof:
                s_resp = s_resp_all

        blocs_resp.append({
            'responsable':    resp,
            'seances':        s_resp,
            'nb_passees':     sum(1 for s in s_resp if s.statut == 'passee'),
            'nb_annulees':    sum(1 for s in s_resp if s.statut == 'annulee'),
            'nb_ratt':        sum(1 for s in s_resp if s.statut == 'rattrapage'),
            'total_heures':   sum(s.nb_heures for s in s_resp if s.statut == 'passee'),
            'total_presents': sum(s.total_presents for s in s_resp if s.statut != 'annulee'),
        })

    seances_pour_recap = all_seances_mois
    if filtre_prof:
        try:
            seances_pour_recap = [
                s for s in all_seances_mois
                if s.professeur_id == int(filtre_prof)
            ]
        except ValueError:
            pass

    heures_prof = defaultdict(lambda: defaultdict(float))
    for s in seances_pour_recap:
        if s.statut == 'passee' and s.professeur_id:
            heures_prof[s.responsable_id][s.professeur_id] += s.nb_heures

    recap_prof = []
    resp_visibles = [r for r in responsables if not filtre_resp or str(r.id) == filtre_resp]
    for resp in resp_visibles:
        for prof_id, heures in heures_prof[resp.id].items():
            p = Professeur.query.get(prof_id)
            if p:
                recap_prof.append({
                    'responsable': resp,
                    'professeur':  p,
                    'heures':      heures,
                })
    recap_prof.sort(key=lambda x: x['heures'], reverse=True)

    seances_json = []
    for s in all_seances_mois:
        seances_json.append({
            'id':                         s.id,
            'responsable_id':             s.responsable_id,
            'date':                       s.date.isoformat() if s.date else '',
            'heure':                      s.heure or '',
            'nb_heures':                  s.nb_heures,
            'statut':                     s.statut or '',
            'professeur_id':              s.professeur_id or '',
            'prof':                       s.prof_nom or '',
            'matiere':                    s.matiere or '',
            'niveau':                     s.niveau or '',
            'remarque':                   s.remarque or '',
            'note':                       s.note or '',
            'dar_ids':                    s.dar_ids,
            'effectif_b2c_total':         s.effectif_b2c_total or '',
            'effectif_b2c_presents':      s.effectif_b2c_presents or '',
            'effectif_fos_total':         s.effectif_fos_total or '',
            'effectif_fos_presents':      s.effectif_fos_presents or '',
            'effectif_free_total':        s.effectif_free_total or '',
            'effectif_free_presents':     s.effectif_free_presents or '',
            'effectif_fos_agri_total':    s.effectif_fos_agri_total or '',
            'effectif_fos_agri_presents': s.effectif_fos_agri_presents or '',
            'effectif_ipse_total':        s.effectif_ipse_total or '',
            'effectif_ipse_presents':     s.effectif_ipse_presents or '',
            'dar_effectifs': [
                {
                    'dour_id':  de.dour_id,
                    'total':    de.total   if de.total   is not None else '',
                    'presents': de.presents if de.presents is not None else '',
                }
                for de in s.dar_effectifs
            ],
        })

    return render_template('suivi_b2c.html',
        blocs_resp=blocs_resp,
        responsables=responsables,
        professeurs=professeurs,
        dours_all=dours_all,
        seances_json=seances_json,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        annees=list(range(now.year - 2, now.year + 2)),
        filtre_resp=filtre_resp,
        filtre_statut=filtre_statut,
        filtre_prof=filtre_prof,
        matieres=MATIERES,
        niveaux=NIVEAUX,
        statuts=STATUTS_SEANCE,
        total_passees=total_passees,
        total_annulees=total_annulees,
        total_rattrapage=total_rattrapage,
        total_heures=total_heures,
        total_presents=total_presents,
        total_seances=len(all_seances_mois),
        recap_prof=recap_prof,
    )


@app.route('/suivi_b2c/ajouter', methods=['POST'])
@login_required
@password_required
def suivi_b2c_ajouter():
    try:
        resp_id = safe_int(request.form.get('responsable_id'))
        if not resp_id:
            abort(400)

        if not current_user.is_admin:
            if not current_user.responsable or current_user.responsable.id != resp_id:
                abort(403)

        resp = Responsable.query.get_or_404(resp_id)

        date_str = request.form.get('date', '').strip()
        if not date_str:
            flash('Date requise.', 'error')
            return redirect_back()
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()

        nb_heures = safe_float(request.form.get('nb_heures'), min_val=0.5, max_val=12)
        if nb_heures is None:
            flash('Heures invalides (0.5 - 12).', 'error')
            return redirect_back()

        statut        = normalise_statut(request.form.get('statut', ''))
        professeur_id = parse_professeur_id(request.form)
        if professeur_id:
            p = Professeur.query.get(professeur_id)
            if not p:
                professeur_id = None

        def gi(field):
            return safe_int(request.form.get(field), min_val=0, max_val=10000)

        s = SeanceB2C(
            responsable_id=resp_id,
            date=date_obj,
            mois=date_obj.month,
            annee=date_obj.year,
            heure=sanitize_text(request.form.get('heure', ''), max_length=5),
            nb_heures=nb_heures,
            statut=statut,
            professeur_id=professeur_id,
            matiere=sanitize_text(request.form.get('matiere', ''), max_length=100),
            niveau=sanitize_text(request.form.get('niveau', ''), max_length=100),
            note=sanitize_text(request.form.get('note', ''), max_length=300),
            remarque=sanitize_text(request.form.get('remarque', ''), max_length=500),
            effectif_b2c_total=gi('effectif_b2c_total'),
            effectif_b2c_presents=gi('effectif_b2c_presents'),
            effectif_fos_total=gi('effectif_fos_total'),
            effectif_fos_presents=gi('effectif_fos_presents'),
            effectif_free_total=gi('effectif_free_total'),
            effectif_free_presents=gi('effectif_free_presents'),
            effectif_fos_agri_total=gi('effectif_fos_agri_total'),
            effectif_fos_agri_presents=gi('effectif_fos_agri_presents'),
            effectif_ipse_total=gi('effectif_ipse_total'),
            effectif_ipse_presents=gi('effectif_ipse_presents'),
        )
        db.session.add(s)
        db.session.flush()

        dar_ids_raw = request.form.getlist('dar_ids[]')
        for did_str in dar_ids_raw:
            did = safe_int(did_str)
            if did:
                d = Dour.query.get(did)
                if d:
                    if d not in s.dars:
                        s.dars.append(d)
                    t = safe_int(request.form.get(f'effectif_dar_total_{did}'),   min_val=0, max_val=10000)
                    p = safe_int(request.form.get(f'effectif_dar_presents_{did}'), min_val=0, max_val=10000)
                    eff = SeanceB2CDarEffectif(seance_b2c_id=s.id, dour_id=did, total=t, presents=p)
                    db.session.add(eff)

        db.session.commit()
        flash(f'Séance B2C ajoutée pour {resp.prenom} {resp.nom}!', 'success')

    except ValueError as e:
        flash(f'Données invalides: {str(e)}', 'error')
        return redirect_back()

    redirect_url = request.form.get('redirect_url', '').strip()
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('suivi_b2c', mois=date_obj.month, annee=date_obj.year))


@app.route('/suivi_b2c/modifier/<int:id>', methods=['POST'])
@login_required
def suivi_b2c_modifier(id):
    s = SeanceB2C.query.get_or_404(id)
    if not current_user.is_admin:
        if not current_user.responsable or s.responsable_id != current_user.responsable.id:
            abort(403)

    date_obj  = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
    s.date    = date_obj
    s.mois    = date_obj.month
    s.annee   = date_obj.year
    s.heure   = request.form.get('heure', '').strip() or None
    nb_heures = safe_float(request.form.get('nb_heures'), min_val=0.5, max_val=12)
    if nb_heures is not None:
        s.nb_heures = nb_heures
    s.statut        = normalise_statut(request.form.get('statut', ''))
    s.professeur_id = parse_professeur_id(request.form)
    s.matiere  = request.form.get('matiere', '').strip() or None
    s.niveau   = request.form.get('niveau',  '').strip() or None
    s.note     = sanitize_text(request.form.get('note', ''), max_length=300)
    s.remarque = sanitize_text(request.form.get('remarque', ''), max_length=500)

    def gi(field):
        return safe_int(request.form.get(field), min_val=0, max_val=10000)

    s.effectif_b2c_total          = gi('effectif_b2c_total')
    s.effectif_b2c_presents       = gi('effectif_b2c_presents')
    s.effectif_fos_total          = gi('effectif_fos_total')
    s.effectif_fos_presents       = gi('effectif_fos_presents')
    s.effectif_free_total         = gi('effectif_free_total')
    s.effectif_free_presents      = gi('effectif_free_presents')
    s.effectif_fos_agri_total     = gi('effectif_fos_agri_total')
    s.effectif_fos_agri_presents  = gi('effectif_fos_agri_presents')
    s.effectif_ipse_total         = gi('effectif_ipse_total')
    s.effectif_ipse_presents      = gi('effectif_ipse_presents')

    s.dars = []
    SeanceB2CDarEffectif.query.filter_by(seance_b2c_id=s.id).delete()
    db.session.flush()

    dar_ids_raw = request.form.getlist('dar_ids[]')
    for did_str in dar_ids_raw:
        did = safe_int(did_str)
        if did:
            d = Dour.query.get(did)
            if d:
                if d not in s.dars:
                    s.dars.append(d)
                t = safe_int(request.form.get(f'effectif_dar_total_{did}'),   min_val=0, max_val=10000)
                p = safe_int(request.form.get(f'effectif_dar_presents_{did}'), min_val=0, max_val=10000)
                eff = SeanceB2CDarEffectif(seance_b2c_id=s.id, dour_id=did, total=t, presents=p)
                db.session.add(eff)

    db.session.commit()
    flash('Séance B2C modifiée!', 'success')

    redirect_url = request.form.get('redirect_url', '').strip()
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('suivi_b2c', mois=s.mois, annee=s.annee))


@app.route('/suivi_b2c/supprimer/<int:id>', methods=['POST'])
@login_required
def suivi_b2c_supprimer(id):
    s = SeanceB2C.query.get_or_404(id)
    if not current_user.is_admin:
        if not current_user.responsable or s.responsable_id != current_user.responsable.id:
            abort(403)
    mois, annee  = s.mois, s.annee
    redirect_url = request.form.get('redirect_url', '').strip()
    db.session.delete(s)
    db.session.commit()
    flash('Séance B2C supprimée!', 'success')
    if redirect_url:
        return redirect(redirect_url)
    return redirect(url_for('suivi_b2c', mois=mois, annee=annee))


# ─── Heures Professeurs ───────────────────────────────────────────────────────
@app.route('/heures_profs')
@login_required
@admin_required
def heures_profs():
    from collections import defaultdict

    now   = datetime.now()
    mois  = request.args.get('mois',  now.month,  type=int)
    annee = request.args.get('annee', now.year,   type=int)

    filtre_resp = request.args.get('filtre_resp', '').strip()
    filtre_prof = request.args.get('filtre_prof', '').strip()

    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                 'Juillet','Août','Septembre','Octobre','Novembre','Décembre']

    # ── Périmètre responsables visibles ──────────────────────────────────────
    if current_user.is_admin:
        all_resp = Responsable.query.all()
        responsables = [r for r in all_resp if r.user and r.user.role == 'responsable']
    else:
        resp = current_user.responsable
        responsables = [resp] if resp else []

    resp_ids = [r.id for r in responsables]
    if filtre_resp:
        try:
            resp_ids_filtres = [int(filtre_resp)]
        except ValueError:
            resp_ids_filtres = resp_ids
    else:
        resp_ids_filtres = resp_ids

    professeurs = Professeur.query.filter_by(actif=True).order_by(Professeur.nom).all()

    # ══════════════════════════════════════════════════════════════════════════
    # SOURCE 1 — SeanceB2C
    # ══════════════════════════════════════════════════════════════════════════
    q_b2c = SeanceB2C.query.filter(
        SeanceB2C.mois == mois,
        SeanceB2C.annee == annee,
        SeanceB2C.statut == 'passee',
        SeanceB2C.professeur_id != None,
        SeanceB2C.responsable_id.in_(resp_ids_filtres)
    )
    if filtre_prof:
        try:
            q_b2c = q_b2c.filter(SeanceB2C.professeur_id == int(filtre_prof))
        except ValueError:
            pass
    seances_b2c = q_b2c.all()

    # ══════════════════════════════════════════════════════════════════════════
    # SOURCE 2 — Seance coordinateurs
    # ══════════════════════════════════════════════════════════════════════════
    if current_user.is_admin:
        all_coords = Coordinateur.query.all()
    else:
        resp = current_user.responsable
        all_coords = resp.coordinateurs if resp else []

    coords_visibles = [
        c for c in all_coords
        if c.responsable_id in resp_ids_filtres
    ]
    coord_ids_visibles = [c.id for c in coords_visibles]

    q_std = Seance.query.filter(
        Seance.mois == mois,
        Seance.annee == annee,
        Seance.statut == 'passee',
        Seance.professeur_id != None,
        Seance.coordinateur_id.in_(coord_ids_visibles)
    )
    if filtre_prof:
        try:
            q_std = q_std.filter(Seance.professeur_id == int(filtre_prof))
        except ValueError:
            pass
    seances_std = q_std.all()

    # ══════════════════════════════════════════════════════════════════════════
    # AGRÉGATION avec structures de données
    # ══════════════════════════════════════════════════════════════════════════
    prof_map  = {p.id: p for p in professeurs}
    resp_map  = {r.id: r for r in responsables}
    coord_map = {c.id: c for c in all_coords}

    data_by_prof_resp  = defaultdict(lambda: defaultdict(lambda: {'heures': 0.0, 'nb_seances': 0}))
    data_by_prof_coord = defaultdict(lambda: defaultdict(lambda: {'heures': 0.0, 'nb_seances': 0}))
    data_by_resp       = defaultdict(lambda: defaultdict(lambda: {'heures': 0.0, 'nb_seances': 0, 'par_coord': defaultdict(lambda: {'heures': 0.0, 'nb_seances': 0})}))
    data_by_coord      = defaultdict(lambda: defaultdict(lambda: {'heures': 0.0, 'nb_seances': 0}))

    # --- Séances B2C : pas de créneau partagé possible, on agrège directement ---
    for s in seances_b2c:
        pid = s.professeur_id
        rid = s.responsable_id
        h   = s.nb_heures or 0
        data_by_prof_resp[pid][rid]['heures']     += h
        data_by_prof_resp[pid][rid]['nb_seances'] += 1
        data_by_resp[rid][pid]['heures']           += h
        data_by_resp[rid][pid]['nb_seances']       += 1

    # --- Séances coordinateurs avec DÉDUPLICATION des créneaux partagés ---
    # Si le même prof donne une séance à plusieurs coords en même temps
    # (même date + même heure + mêmes nb_heures), on ne compte les heures
    # QU'UNE SEULE FOIS par responsable, mais on garde le lien par coord
    # pour l'affichage détaillé.
    groupes_std = defaultdict(list)
    for s in seances_std:
        # Clé d'unicité : même prof, même jour, même heure, même durée
        cle = (s.professeur_id, s.date, s.heure or '', s.nb_heures or 0, s.matiere or '', s.niveau or '')

        groupes_std[cle].append(s)

    for cle, groupe in groupes_std.items():
        pid = groupe[0].professeur_id
        h   = groupe[0].nb_heures or 0

        # On ne compte les heures au niveau resp qu'une seule fois par resp
        rids_comptabilises = set()
        
        for s in groupe:
            cid   = s.coordinateur_id
            coord = coord_map.get(cid)
            if not coord:
                continue
            rid = coord.responsable_id

            # Heures globales prof→resp : une seule fois par resp pour ce créneau
            if rid not in rids_comptabilises:
                data_by_prof_resp[pid][rid]['heures']     += h
                data_by_prof_resp[pid][rid]['nb_seances'] += 1
                data_by_resp[rid][pid]['heures']           += h
                data_by_resp[rid][pid]['nb_seances']       += 1
                rids_comptabilises.add(rid)

            # Par coordinateur
            data_by_prof_coord[pid][cid]['heures']     += h
            data_by_prof_coord[pid][cid]['nb_seances'] += 1
            data_by_coord[cid][pid]['heures']           += h
            data_by_coord[cid][pid]['nb_seances']       += 1

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCS PAR RESPONSABLE
    # ══════════════════════════════════════════════════════════════════════════
    blocs_resp = []
    for resp in responsables:
        if filtre_resp and str(resp.id) != filtre_resp:
            continue
        rid = resp.id
        prof_data = data_by_resp.get(rid, {})
        if not prof_data:
            continue

        profs_list = []
        for pid, pdata in sorted(prof_data.items(), key=lambda x: x[1]['heures'], reverse=True):
            prof = prof_map.get(pid)
            if not prof:
                continue
            par_coord_list = []
            for cid, cdata in sorted(pdata['par_coord'].items(), key=lambda x: x[1]['heures'], reverse=True):
                coord = coord_map.get(cid)
                if coord:
                    par_coord_list.append({
                        'coord':      coord,
                        'heures':     cdata['heures'],
                        'nb_seances': cdata['nb_seances'],
                    })
            profs_list.append({
                'prof':       prof,
                'heures':     pdata['heures'],
                'nb_seances': pdata['nb_seances'],
                'par_coord':  par_coord_list,
            })

        nb_coords = len({
            c.id for c in coords_visibles
            if c.responsable_id == rid
        })

        blocs_resp.append({
            'responsable':   resp,
            'profs':         profs_list,
            'total_heures':  sum(p['heures']     for p in profs_list),
            'total_seances': sum(p['nb_seances'] for p in profs_list),
            'nb_coords':     nb_coords,
        })
    blocs_resp.sort(key=lambda x: x['total_heures'], reverse=True)

    # ══════════════════════════════════════════════════════════════════════════
    # TABLEAU GLOBAL (classement par prof)
    # ══════════════════════════════════════════════════════════════════════════
    tableau_global = []
    all_prof_ids = set(data_by_prof_resp.keys()) | set(data_by_prof_coord.keys())
    for pid in all_prof_ids:
        prof = prof_map.get(pid)
        if not prof:
            continue
        total_h = sum(v['heures']     for v in data_by_prof_resp[pid].values())
        total_s = sum(v['nb_seances'] for v in data_by_prof_resp[pid].values())
        resp_names  = [resp_map[rid].prenom + ' ' + resp_map[rid].nom for rid in data_by_prof_resp[pid] if rid in resp_map]
        coord_names = [coord_map[cid].prenom + ' ' + coord_map[cid].nom for cid in data_by_prof_coord[pid] if cid in coord_map]
        tableau_global.append({
            'prof':         prof,
            'heures':       total_h,
            'nb_seances':   total_s,
            'responsables': resp_names,
            'coordinateurs': coord_names,
        })
    tableau_global.sort(key=lambda x: x['heures'], reverse=True)

    # ══════════════════════════════════════════════════════════════════════════
    # BLOCS PAR COORDINATEUR
    # ══════════════════════════════════════════════════════════════════════════
    blocs_coord = []
    for coord in coords_visibles:
        prof_data = data_by_coord.get(coord.id, {})
        if not prof_data:
            continue
        profs_list = []
        for pid, pdata in sorted(prof_data.items(), key=lambda x: x[1]['heures'], reverse=True):
            prof = prof_map.get(pid)
            if prof:
                profs_list.append({
                    'prof':       prof,
                    'heures':     pdata['heures'],
                    'nb_seances': pdata['nb_seances'],
                })
        blocs_coord.append({
            'coord':         coord,
            'profs':         profs_list,
            'total_heures':  sum(p['heures']     for p in profs_list),
            'total_seances': sum(p['nb_seances'] for p in profs_list),
        })
    blocs_coord.sort(key=lambda x: x['total_heures'], reverse=True)

    # ── KPIs globaux ─────────────────────────────────────────────────────────
    total_heures  = sum(item['heures']     for item in tableau_global)
    total_seances = sum(item['nb_seances'] for item in tableau_global)
    total_profs   = len(tableau_global)
    total_resps   = len(blocs_resp)
    total_coords  = len(blocs_coord)

    return render_template('heures_profs.html',
        blocs_resp=blocs_resp,
        blocs_coord=blocs_coord,
        tableau_global=tableau_global,
        responsables=responsables,
        professeurs=professeurs,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        annees=list(range(now.year - 2, now.year + 2)),
        filtre_resp=filtre_resp,
        filtre_prof=filtre_prof,
        total_heures=total_heures,
        total_seances=total_seances,
        total_profs=total_profs,
        total_resps=total_resps,
        total_coords=total_coords,
    )

# ─── Impression B2C ───────────────────────────────────────────────────────────
 
@app.route('/impression_b2c')
@login_required
@admin_required
def impression_b2c():
    from collections import defaultdict
 
    now   = datetime.now()
    mois  = request.args.get('mois',  now.month,  type=int)
    annee = request.args.get('annee', now.year,   type=int)
 
    filtre_resp   = request.args.get('filtre_resp',   '').strip()
    filtre_prof   = request.args.get('filtre_prof',   '').strip()
    filtre_statut = request.args.get('filtre_statut', '').strip()
 
    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                 'Juillet','Août','Septembre','Octobre','Novembre','Décembre']
 
    # ── Responsables visibles ──────────────────────────────────────────────────
    if current_user.is_admin:
        all_resp = Responsable.query.all()
        responsables = [r for r in all_resp if r.user and r.user.role == 'responsable']
    else:
        resp = current_user.responsable
        responsables = [resp] if resp else []
 
    resp_ids = [r.id for r in responsables]
    professeurs = Professeur.query.filter_by(actif=True).order_by(Professeur.nom).all()
 
    # ── Requête principale SeanceB2C ───────────────────────────────────────────
    q = SeanceB2C.query.filter(
        SeanceB2C.mois == mois,
        SeanceB2C.annee == annee,
        SeanceB2C.responsable_id.in_(resp_ids)
    )
    if filtre_resp:
        try:
            q = q.filter(SeanceB2C.responsable_id == int(filtre_resp))
        except ValueError:
            pass
    if filtre_prof:
        try:
            q = q.filter(SeanceB2C.professeur_id == int(filtre_prof))
        except ValueError:
            pass
    if filtre_statut:
        q = q.filter(SeanceB2C.statut == filtre_statut)
 
    seances = q.order_by(SeanceB2C.date.desc()).all()
 
    # ── Séances coordinateurs (source heures_profs) ───────────────────────────
    if current_user.is_admin:
        all_coords = Coordinateur.query.all()
    else:
        resp_obj = current_user.responsable
        all_coords = resp_obj.coordinateurs if resp_obj else []
 
    resp_ids_filtres = [int(filtre_resp)] if filtre_resp else resp_ids
 
    coords_visibles = [
        c for c in all_coords
        if c.responsable_id in resp_ids_filtres
    ]
    coord_ids_visibles = [c.id for c in coords_visibles]
 
    q_std = Seance.query.filter(
        Seance.mois == mois,
        Seance.annee == annee,
        Seance.professeur_id != None,
        Seance.coordinateur_id.in_(coord_ids_visibles)
    )
    if filtre_prof:
        try:
            q_std = q_std.filter(Seance.professeur_id == int(filtre_prof))
        except ValueError:
            pass
    seances_std = q_std.all()
 
    coord_map = {c.id: c for c in all_coords}
 
    # Déduplication créneaux partagés (même logique que heures_profs)
    groupes_std = defaultdict(list)
    for s in seances_std:
        cle = (s.professeur_id, s.date, s.heure or '', s.nb_heures or 0, s.matiere or '', s.niveau or '')
        groupes_std[cle].append(s)
 
    heures_std_par_prof   = defaultdict(float)   # prof_id -> heures totales
    seances_std_par_prof  = defaultdict(list)    # prof_id -> liste séances représentatives
 
    for cle, groupe in groupes_std.items():
        pid = groupe[0].professeur_id
        h   = groupe[0].nb_heures or 0
        rids_vus = set()

        # الstatut الأهم: passee > rattrapage > annulee
        def statut_priority(s):
            return {'passee': 0, 'rattrapage': 1, 'annulee': 2}.get(s.statut or '', 3)
        
        seance_representative = min(groupe, key=statut_priority)

        for s in groupe:
            coord = coord_map.get(s.coordinateur_id)
            if not coord:
                continue
            rid = coord.responsable_id
            if s.statut == 'passee' and rid not in rids_vus:
                heures_std_par_prof[pid] += h
                rids_vus.add(rid)
        
        seances_std_par_prof[pid].append(seance_representative)
 
    # ── KPIs globaux ───────────────────────────────────────────────────────────
    total_seances    = len(seances)
    total_passees    = sum(1 for s in seances if s.statut == 'passee')
    total_annulees   = sum(1 for s in seances if s.statut == 'annulee')
    total_rattrapage = sum(1 for s in seances if s.statut == 'rattrapage')
    total_heures_b2c = sum(s.nb_heures for s in seances if s.statut == 'passee')
    total_heures_std = sum(heures_std_par_prof.values())
    total_heures     = total_heures_b2c + total_heures_std
    total_presents   = sum(s.total_presents for s in seances if s.statut != 'annulee')
 
    # ══════════════════════════════════════════════════════════════════════════
    # BLOCS PAR RESPONSABLE
    # ══════════════════════════════════════════════════════════════════════════
    resp_map   = {r.id: r for r in responsables}
    blocs_resp = []
 
    for resp_r in responsables:
        if resp_r.id not in resp_ids_filtres:
            continue
        s_resp = [s for s in seances if s.responsable_id == resp_r.id]
        if not s_resp:
            continue
        blocs_resp.append({
            'responsable':    resp_r,
            'seances':        sorted(s_resp, key=lambda x: x.date, reverse=True),
            'nb_passees':     sum(1 for s in s_resp if s.statut == 'passee'),
            'nb_annulees':    sum(1 for s in s_resp if s.statut == 'annulee'),
            'nb_ratt':        sum(1 for s in s_resp if s.statut == 'rattrapage'),
            'total_heures':   sum(s.nb_heures for s in s_resp if s.statut == 'passee'),
            'total_presents': sum(s.total_presents for s in s_resp if s.statut != 'annulee'),
        })
 
    # ══════════════════════════════════════════════════════════════════════════
    # BLOCS PAR PROFESSEUR (fusion B2C + Coordinateurs)
    # ══════════════════════════════════════════════════════════════════════════
    par_prof = defaultdict(list)
    for s in seances:
        if s.professeur_id:
            par_prof[s.professeur_id].append(s)
 
    prof_map = {p.id: p for p in professeurs}
    blocs_prof = []
 
    # Union des deux sources
    all_prof_ids_imp = set(par_prof.keys()) | set(heures_std_par_prof.keys())
 
    for prof_id in all_prof_ids_imp:
        prof = prof_map.get(prof_id)
        if not prof:
            continue
        s_b2c = par_prof.get(prof_id, [])
        s_std  = seances_std_par_prof.get(prof_id, [])
        h_b2c  = sum(s.nb_heures for s in s_b2c if s.statut == 'passee')
        h_std  = heures_std_par_prof.get(prof_id, 0.0)
        blocs_prof.append({
            'professeur':       prof,
            'seances':          sorted(s_b2c, key=lambda x: x.date, reverse=True),
            'seances_std':      sorted(s_std, key=lambda x: x.date, reverse=True),
            'nb_passees':       sum(1 for s in s_b2c if s.statut == 'passee'),
            'nb_annulees':      sum(1 for s in s_b2c if s.statut == 'annulee'),
            'nb_ratt':          sum(1 for s in s_b2c if s.statut == 'rattrapage'),
            'nb_std':           len(s_std),
            'total_heures':     h_b2c + h_std,
            'total_heures_b2c': h_b2c,
            'total_heures_std': h_std,
            'total_presents':   sum(s.total_presents for s in s_b2c if s.statut != 'annulee'),
        })
 
    blocs_prof.sort(key=lambda x: x['total_heures'], reverse=True)
 
    # ── Récap global professeurs (tableau synthèse) ───────────────────────────
    recap_prof_global = []
    for bloc in blocs_prof:
        resp_names = sorted({
            resp_map[s.responsable_id].prenom + ' ' + resp_map[s.responsable_id].nom
            for s in bloc['seances']
            if s.responsable_id in resp_map
        })
        # Ajouter aussi les responsables des séances coordinateurs
        for s in bloc['seances_std']:
            coord = coord_map.get(s.coordinateur_id)
            if coord and coord.responsable_id in resp_map:
                rname = resp_map[coord.responsable_id].prenom + ' ' + resp_map[coord.responsable_id].nom
                if rname not in resp_names:
                    resp_names.append(rname)
        resp_names = sorted(resp_names)
        recap_prof_global.append({
            'professeur':       bloc['professeur'],
            'total_heures':     bloc['total_heures'],
            'total_heures_b2c': bloc['total_heures_b2c'],
            'total_heures_std': bloc['total_heures_std'],
            'total_seances':    sum(1 for s in bloc['seances'] if s.statut == 'passee') + sum(1 for s in bloc['seances_std'] if s.statut == 'passee'),
            'responsables':     resp_names,
        })
 
    nb_profs = len(blocs_prof)
    generated_at = now.strftime('%d/%m/%Y à %H:%M')
 
    return render_template('impression_b2c.html',
        blocs_resp=blocs_resp,
        blocs_prof=blocs_prof,
        recap_prof_global=recap_prof_global,
        responsables=responsables,
        professeurs=professeurs,
        statuts=STATUTS_SEANCE,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        annees=list(range(now.year - 2, now.year + 2)),
        filtre_resp=filtre_resp,
        filtre_prof=filtre_prof,
        filtre_statut=filtre_statut,
        total_seances=total_seances,
        total_passees=total_passees,
        total_annulees=total_annulees,
        total_rattrapage=total_rattrapage,
        total_heures=total_heures,
        total_heures_b2c=total_heures_b2c,
        total_heures_std=total_heures_std,
        total_presents=total_presents,
        nb_profs=nb_profs,
        generated_at=generated_at,
    )
from flask import render_template, request, redirect, url_for, flash, abort
from flask_login import login_user, logout_user, login_required, current_user
from app import app
from models import db, Responsable, Coordinateur, Dour, User, Seance
from functools import wraps
import os, uuid
from datetime import datetime, date
from werkzeug.utils import secure_filename


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated

ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT


# ─── Auth ─────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        pwd   = request.form['password']
        user  = User.query.filter_by(email=email).first()
        if user and user.check_password(pwd):
            login_user(user)
            return redirect(url_for('index'))
        error = 'Email aw mot de passe khata.'
    return render_template('login.html', error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ─── Index ────────────────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    dours = Dour.query.all()
    if current_user.is_admin:
        responsables = Responsable.query.all()
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
    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin','Juillet','Août','Septembre','Octobre','Novembre','Décembre']
    now = datetime.now()
    all_s = Seance.query.filter_by(mois=now.month, annee=now.year).all()
    total_seances_mois = len(all_s)
    total_heures_mois  = sum(s.nb_heures for s in all_s)
    recap_seances = []
    for coord in Coordinateur.query.order_by(Coordinateur.nom).all():
        nb_s = coord.total_seances_mois(now.month, now.year)
        nb_h = coord.total_heures_mois(now.month, now.year)
        if nb_s > 0:
            recap_seances.append({'nom': coord.prenom+' '+coord.nom, 'genre': coord.genre, 'initiales': coord.prenom[0].upper()+coord.nom[0].upper(), 'responsable': (coord.responsable.prenom+' '+coord.responsable.nom) if coord.responsable else '', 'nb_seances': nb_s, 'nb_heures': nb_h})
    return render_template('index.html', data=data,
                           responsables=responsables, dours=dours,
                           total_seances_mois=total_seances_mois,
                           total_heures_mois=total_heures_mois,
                           mois_nom_actuel=mois_noms[now.month],
                           annee_actuel=now.year,
                           recap_seances=recap_seances)


# ─── Pages dédiées ────────────────────────────────────────────────────────────
@app.route('/ajouter_coordinateur_page')
@login_required
def ajouter_coordinateur_page():
    dours = Dour.query.all()
    if current_user.is_admin:
        responsables = Responsable.query.all()
    else:
        resp = current_user.responsable
        responsables = [resp] if resp else []
    return render_template('ajouter_coordinateur.html', dours=dours, responsables=responsables)


@app.route('/ajouter_responsable_page')
@login_required
@admin_required
def ajouter_responsable_page():
    return render_template('ajouter_responsable.html')


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
        responsables = Responsable.query.all()
        coordinateurs = Coordinateur.query.all()
    else:
        resp = current_user.responsable
        responsables = [resp] if resp else []
        coordinateurs = resp.coordinateurs if resp else []
    return render_template('gerer_coordinateurs.html',
                           coordinateurs=coordinateurs,
                           responsables=responsables, dours=dours)


# ─── Séances / Heures ─────────────────────────────────────────────────────────
@app.route('/heures')
@login_required
def heures():
    now   = datetime.now()
    mois  = request.args.get('mois',  now.month, type=int)
    annee = request.args.get('annee', now.year,  type=int)
    coord_id = request.args.get('coord_id', type=int)

    if current_user.is_admin:
        coordinateurs = Coordinateur.query.order_by(Coordinateur.nom).all()
    else:
        resp = current_user.responsable
        coordinateurs = sorted(resp.coordinateurs, key=lambda c: c.nom) if resp else []

    mois_noms = ['','Janvier','Février','Mars','Avril','Mai','Juin',
                 'Juillet','Août','Septembre','Octobre','Novembre','Décembre']

    all_seances_mois = Seance.query.filter_by(mois=mois, annee=annee).all()
    total_heures  = sum(s.nb_heures for s in all_seances_mois)
    total_seances = len(all_seances_mois)

    coord_selected = None
    seances_coord  = []
    if coord_id:
        coord_selected = Coordinateur.query.get(coord_id)
        if coord_selected:
            seances_coord = sorted(
                coord_selected.seances_mois(mois, annee),
                key=lambda s: s.date
            )

    return render_template('heures.html',
        coordinateurs=coordinateurs,
        coord_selected=coord_selected,
        seances_coord=seances_coord,
        mois=mois, annee=annee,
        mois_noms=mois_noms,
        total_heures=total_heures,
        total_seances=total_seances,
        annees=list(range(now.year - 2, now.year + 2)),
        today=date.today().isoformat()
    )


@app.route('/heures/ajouter', methods=['POST'])
@login_required
def ajouter_seance():
    coord_id  = int(request.form['coordinateur_id'])
    date_str  = request.form['date']
    nb_heures = float(request.form['nb_heures'])
    note      = request.form.get('note', '').strip()

    coord = Coordinateur.query.get_or_404(coord_id)
    if not current_user.is_admin:
        if not current_user.responsable or coord.responsable_id != current_user.responsable.id:
            abort(403)

    date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
    s = Seance(
        coordinateur_id=coord_id,
        date=date_obj,
        mois=date_obj.month,
        annee=date_obj.year,
        nb_heures=nb_heures,
        note=note
    )
    db.session.add(s)
    db.session.commit()
    flash(f'Séance ajoutée pour {coord.prenom} {coord.nom}!', 'success')
    return redirect(url_for('heures', mois=date_obj.month, annee=date_obj.year, coord_id=coord_id))


@app.route('/heures/modifier/<int:id>', methods=['POST'])
@login_required
def modifier_seance(id):
    s = Seance.query.get_or_404(id)
    coord = s.coordinateur
    if not current_user.is_admin:
        if not current_user.responsable or coord.responsable_id != current_user.responsable.id:
            abort(403)
    date_obj    = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
    s.date      = date_obj
    s.mois      = date_obj.month
    s.annee     = date_obj.year
    s.nb_heures = float(request.form['nb_heures'])
    s.note      = request.form.get('note', '').strip()
    db.session.commit()
    flash('Séance modifiée!', 'success')
    return redirect(url_for('heures', mois=s.mois, annee=s.annee, coord_id=coord.id))


@app.route('/heures/supprimer/<int:id>')
@login_required
def supprimer_seance(id):
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


# ─── Paramètres ───────────────────────────────────────────────────────────────
@app.route('/parametres')
@login_required
def parametres():
    return render_template('parametres.html')


@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    nom    = request.form.get('nom', '').strip()
    prenom = request.form.get('prenom', '').strip()
    email  = request.form.get('email', '').strip().lower()
    existing = User.query.filter_by(email=email).first()
    if existing and existing.id != current_user.id:
        flash('Cet email est déjà utilisé.', 'error')
        return redirect(url_for('parametres'))
    current_user.nom    = nom
    current_user.prenom = prenom
    current_user.email  = email
    db.session.commit()
    flash('Informations mises à jour avec succès!', 'success')
    return redirect(url_for('parametres'))


@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    current_pwd = request.form.get('current_password', '')
    new_pwd     = request.form.get('new_password', '')
    confirm_pwd = request.form.get('confirm_password', '')
    if not current_user.check_password(current_pwd):
        flash('Mot de passe actuel incorrect.', 'error')
        return redirect(url_for('parametres'))
    if new_pwd != confirm_pwd:
        flash('Les mots de passe ne correspondent pas.', 'error')
        return redirect(url_for('parametres'))
    if len(new_pwd) < 6:
        flash('Le mot de passe doit contenir au moins 6 caractères.', 'error')
        return redirect(url_for('parametres'))
    current_user.set_password(new_pwd)
    db.session.commit()
    flash('Mot de passe changé avec succès!', 'success')
    return redirect(url_for('parametres'))


@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    file = request.files.get('avatar')
    if not file or file.filename == '':
        flash('Aucun fichier sélectionné.', 'error')
        return redirect(url_for('parametres'))
    if not allowed_file(file.filename):
        flash('Format non supporté.', 'error')
        return redirect(url_for('parametres'))
    avatar_dir = os.path.join(app.root_path, 'static', 'avatars')
    os.makedirs(avatar_dir, exist_ok=True)
    if current_user.avatar:
        old_path = os.path.join(avatar_dir, current_user.avatar)
        if os.path.exists(old_path):
            os.remove(old_path)
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"user_{uuid.uuid4().hex[:8]}.{ext}"
    file.save(os.path.join(avatar_dir, filename))
    current_user.avatar = filename
    db.session.commit()
    flash('Photo de profil mise à jour!', 'success')
    return redirect(url_for('parametres'))


# ─── Responsables ─────────────────────────────────────────────────────────────
@app.route('/ajouter_responsable', methods=['POST'])
@login_required
@admin_required
def ajouter_responsable():
    email_resp = request.form['email'].strip().lower()
    pwd        = request.form['password']
    r = Responsable(nom=request.form['nom'], prenom=request.form['prenom'], email=email_resp)
    db.session.add(r)
    db.session.flush()
    u = User(email=email_resp, role='responsable', responsable_id=r.id)
    u.set_password(pwd)
    db.session.add(u)
    db.session.commit()
    flash(f'Responsable {r.prenom} {r.nom} ajouté!', 'success')
    return redirect(url_for('index'))


@app.route('/supprimer_responsable/<int:id>')
@login_required
@admin_required
def supprimer_responsable(id):
    r = Responsable.query.get_or_404(id)
    if r.user:
        db.session.delete(r.user)
    for c in r.coordinateurs:
        c.dours = []
        db.session.delete(c)
    db.session.delete(r)
    db.session.commit()
    flash('Responsable supprimé!', 'success')
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
    return redirect(url_for('index'))


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
    c.dours = []
    for did in request.form.getlist('dours'):
        d = Dour.query.get(int(did))
        if d: c.dours.append(d)
    db.session.commit()
    flash('Coordinateur modifié!', 'success')
    return redirect(url_for('index'))


@app.route('/supprimer_coordinateur/<int:id>')
@login_required
def supprimer_coordinateur(id):
    c = Coordinateur.query.get_or_404(id)
    if not current_user.is_admin:
        if not current_user.responsable or c.responsable_id != current_user.responsable.id:
            abort(403)
    c.dours = []
    db.session.delete(c)
    db.session.commit()
    flash('Coordinateur supprimé!', 'success')
    return redirect(url_for('index'))


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
def supprimer_dour(id):
    d = Dour.query.get_or_404(id)
    db.session.delete(d)
    db.session.commit()
    flash('Dour supprimée!', 'success')
    return redirect(url_for('gerer_dours_page'))


# ─── Erreurs ──────────────────────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403
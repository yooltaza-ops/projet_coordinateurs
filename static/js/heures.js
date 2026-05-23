// ── Edit modal ────────────────────────────────────────────────────────────────
function openEdit(id, date, heures, note, matiere, niveau) {
    document.getElementById('edit-form').action = '/heures/modifier/' + id;
    document.getElementById('edit-date').value = date;
    document.getElementById('edit-heures').value = heures;
    document.getElementById('edit-note').value = note || '';

    var selMat = document.getElementById('edit-matiere');
    for (var i = 0; i < selMat.options.length; i++)
        selMat.options[i].selected = (selMat.options[i].value === matiere);

    var selNiv = document.getElementById('edit-niveau');
    for (var i = 0; i < selNiv.options.length; i++)
        selNiv.options[i].selected = (selNiv.options[i].value === niveau);

    document.getElementById('edit-modal').classList.add('active');
}

function closeModal() {
    document.getElementById('edit-modal').classList.remove('active');
}

document.getElementById('edit-modal').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
});

// ── Confirm Delete ────────────────────────────────────────────────────────────
var _confirmDeleteUrl = null;

function confirmDelete(url, info) {
    _confirmDeleteUrl = url;
    document.getElementById('confirm-seance-info').textContent = '📅 ' + info;
    document.getElementById('confirm-overlay').classList.add('open');
}

function confirmCancel() {
    _confirmDeleteUrl = null;
    document.getElementById('confirm-overlay').classList.remove('open');
}

function confirmOk() {
    if (_confirmDeleteUrl) window.location.href = _confirmDeleteUrl;
    document.getElementById('confirm-overlay').classList.remove('open');
}

document.getElementById('confirm-overlay').addEventListener('click', function(e) {
    if (e.target === this) confirmCancel();
});

/* ══════════════════════════════════════════
   heures.js — Séances de Travail — Yool
   ══════════════════════════════════════════

   Variables injectées par le template Jinja avant ce script :
     SP_PROFS         — liste des profs  [{ id, nom }, ...]
     SP_SEANCES       — dict des séances { id: { ...champs } }
     SP_COORD_DOURS   — dict des dars par coord { coord_id: [{ id, nom }] }
     SP_ADD_URL       — url_for('ajouter_seance')
     SP_TODAY         — date du jour ISO (ex: "2025-01-15")
*/

/* ══ Lock Dar Talib selon coordinateur ══ */
function spLockDar(coordId) {
    var darSelect = document.getElementById('spDar');
    var darHidden = document.getElementById('spDarHidden');
    var darBadge = document.getElementById('spDarLockedBadge');
    var dours = SP_COORD_DOURS[coordId] || [];

    /* Reconstruire les options */
    darSelect.innerHTML = '';

    if (dours.length === 0) {
        /* Aucun dar → vide + verrouillé */
        var opt = document.createElement('option');
        opt.value = '';
        opt.textContent = '— Aucune —';
        darSelect.appendChild(opt);
        darHidden.value = '';
        darSelect.disabled = true;
        darBadge.style.display = 'none';
        return;
    }

    if (dours.length === 1) {
        /* Un seul dar → pré-sélectionné + verrouillé */
        var opt = document.createElement('option');
        opt.value = dours[0].id;
        opt.textContent = dours[0].nom;
        opt.selected = true;
        darSelect.appendChild(opt);
        darHidden.value = String(dours[0].id);
        darSelect.disabled = true;
        darBadge.style.display = 'flex';
    } else {
        /* Plusieurs dars → dropdown limité aux dars du coord */
        var emptyOpt = document.createElement('option');
        emptyOpt.value = '';
        emptyOpt.textContent = '— Aucune —';
        darSelect.appendChild(emptyOpt);

        dours.forEach(function(d) {
            var opt = document.createElement('option');
            opt.value = d.id;
            opt.textContent = d.nom;
            darSelect.appendChild(opt);
        });

        darHidden.value = '';
        darSelect.disabled = false;
        darBadge.style.display = 'none';

        /* Sync hidden à chaque changement */
        darSelect.onchange = function() { darHidden.value = darSelect.value; };
    }
}

/* ══ Stepper heures ══ */
function spChgH(d) {
    var el = document.getElementById('spHeures');
    var v = parseFloat(el.value) || 2;
    v = Math.min(12, Math.max(0.5, v + d));
    el.value = (v % 1 === 0) ? v : v.toFixed(1);
}

/* ══ Statut pills ══ */
function spSetStatut(val) {
    document.querySelectorAll('input[name="statut"]').forEach(function(r) {
        r.checked = (r.value === val);
    });
}

/* ══ Prof search dropdown ══ */
var spProfSearch, spProfDrop, spProfHidden;

function spInitProfSearch() {
    spProfSearch = document.getElementById('spProfSearch');
    spProfDrop = document.getElementById('spProfDrop');
    spProfHidden = document.getElementById('spProfHidden');

    spProfSearch.addEventListener('focus', function() {
        spRenderProfs(spProfSearch.value);
        spProfDrop.classList.add('open');
    });
    spProfSearch.addEventListener('input', function() {
        spRenderProfs(spProfSearch.value);
        spProfDrop.classList.add('open');
        spProfHidden.value = '';
    });
    spProfSearch.addEventListener('blur', function() {
        setTimeout(function() { spProfDrop.classList.remove('open'); }, 150);
    });
}

function spRenderProfs(filter) {
    var lower = (filter || '').toLowerCase();
    var list = SP_PROFS.filter(function(p) { return p.nom.toLowerCase().includes(lower); });
    spProfDrop.innerHTML = '';

    /* option vide */
    var empty = document.createElement('div');
    empty.className = 'sp-prof-opt';
    empty.textContent = '— Aucun prof —';
    empty.dataset.value = '';
    empty.dataset.nom = '';
    spProfDrop.appendChild(empty);

    list.forEach(function(p) {
        var opt = document.createElement('div');
        opt.className = 'sp-prof-opt' + (String(p.id) === spProfHidden.value ? ' selected' : '');
        opt.textContent = p.nom;
        opt.dataset.value = String(p.id);
        opt.dataset.nom = p.nom;
        spProfDrop.appendChild(opt);
    });

    spProfDrop.querySelectorAll('.sp-prof-opt').forEach(function(opt) {
        opt.addEventListener('mousedown', function(e) {
            e.preventDefault();
            spProfHidden.value = opt.dataset.value;
            spProfSearch.value = opt.dataset.nom || '';
            spProfDrop.classList.remove('open');
        });
    });
}

/* ══ Modal open / close ══ */
var spModal;

function spOpenAdd(coordId, defaultDate) {
    document.getElementById('spModalTitle').textContent = 'Ajouter une séance';
    document.getElementById('spModalSub').textContent = 'Séances de travail';
    document.getElementById('sp-form').action = SP_ADD_URL;
    document.getElementById('spSubmitBtn').textContent = '💾 Ajouter';
    document.getElementById('sp-form').reset();

    spProfHidden.value = '';
    spProfSearch.value = '';
    document.getElementById('spCoordId').value = coordId;
    document.getElementById('spDate').value = defaultDate || new Date().toISOString().slice(0, 10);
    document.getElementById('spHeures').value = '2';
    document.getElementById('spRedirectUrl').value = window.location.href;

    spLockDar(coordId);
    spModal.classList.add('show');
}

function spOpenEdit(id) {
    var s = SP_SEANCES[id];
    if (!s) { console.warn('Séance introuvable:', id); return; }

    document.getElementById('spModalTitle').textContent = 'Modifier la séance';
    document.getElementById('spModalSub').textContent = 'Séances de travail';
    document.getElementById('sp-form').action = '/heures/modifier/' + id;
    document.getElementById('spSubmitBtn').textContent = '💾 Enregistrer';

    document.getElementById('spCoordId').value = s.coordinateur_id;
    document.getElementById('spDate').value = s.date;
    document.getElementById('spHeure').value = s.heure;
    document.getElementById('spHeures').value = s.nb_heures;
    document.getElementById('spMatiere').value = s.matiere;
    document.getElementById('spNiveau').value = s.niveau;
    document.getElementById('spEleves').value = s.nb_eleves || '';
    document.getElementById('spElevesTotal').value = s.nb_eleves_total || '';
    document.getElementById('spNote').value = s.note;
    document.getElementById('spRemarque').value = s.remarque;
    document.getElementById('spRedirectUrl').value = window.location.href;

    spProfHidden.value = s.professeur_id ? String(s.professeur_id) : '';
    spProfSearch.value = s.prof || '';

    if (s.statut) spSetStatut(s.statut);

    spLockDar(s.coordinateur_id);

    /* Après lock, forcer la valeur sauvegardée de la séance */
    var darSelect = document.getElementById('spDar');
    var darHidden = document.getElementById('spDarHidden');
    if (s.dar_id) {
        darSelect.value = String(s.dar_id);
        darHidden.value = String(s.dar_id);
    }

    spModal.classList.add('show');
}

function spCloseModal() {
    spModal.classList.remove('show');
    var darSelect = document.getElementById('spDar');
    darSelect.disabled = false;
    document.getElementById('spDarLockedBadge').style.display = 'none';
}

/* ══ Init au chargement ══ */
document.addEventListener('DOMContentLoaded', function() {
    spModal = document.getElementById('sp-modal');
    spInitProfSearch();

    spModal.addEventListener('click', function(e) {
        if (e.target === spModal) spCloseModal();
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') spCloseModal();
    });
});
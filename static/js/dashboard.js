// ── Panels ───────────────────────────────────────────────────────────────────
function openPanel(id) {
    closeAllPanels();
    const panel = document.getElementById(id);
    if (panel) {
        panel.classList.add('active');
        document.getElementById('overlay').classList.add('active');
    }
}

function closeAllPanels() {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const ov = document.getElementById('overlay');
    if (ov) ov.classList.remove('active');
}

// ── Modifier Coordinateur ─────────────────────────────────────────────────────
function openModifier(id, nom, prenom, genre, respId, dourIds) {
    document.getElementById('form-modifier').action = '/modifier_coordinateur/' + id;
    document.getElementById('mod-nom').value = nom;
    document.getElementById('mod-prenom').value = prenom;
    document.getElementById('mod-genre').value = genre;
    document.getElementById('mod-resp').value = respId;
    const sel = document.getElementById('mod-dours');
    for (let opt of sel.options) {
        opt.selected = dourIds.includes(parseInt(opt.value));
    }
    openPanel('panel-modifier');
}

// ── Modifier Admin ────────────────────────────────────────────────────────────
function selectAdminRole(role) {
    document.getElementById('madm-card-admin').classList.toggle('selected', role === 'admin');
    document.getElementById('madm-card-responsable').classList.toggle('selected', role === 'responsable');
    document.getElementById('madm-role').value = role;
}

function openModifierAdmin(id, nom, prenom, email, role) {
    document.getElementById('form-modifier-admin').action = '/modifier_admin/' + id;
    document.getElementById('madm-nom').value = nom;
    document.getElementById('madm-prenom').value = prenom;
    document.getElementById('madm-email').value = email;
    selectAdminRole(role || 'admin');
    openPanel('panel-modifier-admin');
}

// ── Confirm Modal ─────────────────────────────────────────────────────────────
// Usage: confirmDelete(url, nomElement, typeElement)
// typeElement: 'admin' | 'responsable' | 'coordinateur' | 'dour'

var _confirmUrl = null;

function confirmDelete(url, nom, type) {
    _confirmUrl = url;

    var messages = {
        admin: 'Toutes les données de cet administrateur seront définitivement supprimées.',
        responsable: 'Tous les coordinateurs associés à ce responsable seront également supprimés.',
        coordinateur: 'Toutes les séances et présences de ce coordinateur seront supprimées.',
        dour: 'Ce dour sera définitivement supprimé de la plateforme.',
    };

    var icons = {
        admin: '👑',
        responsable: '👤',
        coordinateur: '👥',
        dour: '🏠',
    };

    document.getElementById('confirm-element-name').textContent = (icons[type] || '🗑️') + ' ' + nom;
    document.getElementById('confirm-warn-msg').textContent = messages[type] || 'Cette action est irréversible.';
    document.getElementById('confirm-overlay').classList.add('open');
}

function confirmCancel() {
    _confirmUrl = null;
    document.getElementById('confirm-overlay').classList.remove('open');
}

function confirmOk() {
    if (_confirmUrl) {
        window.location.href = _confirmUrl;
    }
    document.getElementById('confirm-overlay').classList.remove('open');
}

// Fermer si click sur overlay (pas sur la box)
document.addEventListener('DOMContentLoaded', function() {
    var overlay = document.getElementById('confirm-overlay');
    if (overlay) {
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) confirmCancel();
        });
    }
});
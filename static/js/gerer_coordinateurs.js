/* ═══════════════════════════════════════════════
   coordinateurs.js — Gérer Coordinateurs
   ═══════════════════════════════════════════════ */

// ── Panel helpers ─────────────────────────────────────────────────────────────
function openPanel(id) {
    var el = document.getElementById(id);
    if (el) {
        el.classList.add('active');
        document.getElementById('overlay').classList.add('active');
    }
}

function closeAllPanels() {
    document.querySelectorAll('.panel').forEach(function(p) {
        p.classList.remove('active');
    });
    var ov = document.getElementById('overlay');
    if (ov) ov.classList.remove('active');
}

// ── Modifier coordinateur ─────────────────────────────────────────────────────
function openModifier(id, nom, prenom, genre, respId, dourIds) {
    document.getElementById('form-modifier').action = '/modifier_coordinateur/' + id;
    document.getElementById('mod-nom').value = nom;
    document.getElementById('mod-prenom').value = prenom;
    document.getElementById('mod-genre').value = genre;
    document.getElementById('mod-resp').value = respId;

    var sel = document.getElementById('mod-dours');
    for (var i = 0; i < sel.options.length; i++) {
        sel.options[i].selected = dourIds.includes(parseInt(sel.options[i].value));
    }

    openPanel('panel-modifier');
}

// ── Confirm Delete Modal ──────────────────────────────────────────────────────
var _confirmDeleteUrl = null;

function confirmDelete(url, nom) {
    _confirmDeleteUrl = url;
    document.getElementById('confirm-coord-name').textContent = '👥 ' + nom;
    document.getElementById('confirm-overlay').classList.add('open');
}

function confirmCancel() {
    _confirmDeleteUrl = null;
    document.getElementById('confirm-overlay').classList.remove('open');
}

function confirmOk() {
    if (_confirmDeleteUrl) {
        window.location.href = _confirmDeleteUrl;
    }
    document.getElementById('confirm-overlay').classList.remove('open');
}

// ── Fermer confirm si click en dehors de la box ───────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
    var overlay = document.getElementById('confirm-overlay');
    if (overlay) {
        overlay.addEventListener('click', function(e) {
            if (e.target === this) confirmCancel();
        });
    }
});
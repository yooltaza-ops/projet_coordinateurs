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
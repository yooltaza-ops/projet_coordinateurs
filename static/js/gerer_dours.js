var _confirmDeleteUrl = null;

function confirmDelete(url, nom) {
    _confirmDeleteUrl = url;
    document.getElementById('confirm-dour-name').textContent = '🏠 ' + nom;
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
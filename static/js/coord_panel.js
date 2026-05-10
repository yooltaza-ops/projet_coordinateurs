// ══ ACCORDION RESPONSABLE ════════════════════════════════════════════════════

function toggleAcc(respId) {
    var block = document.getElementById('acc-' + respId);
    if (!block) return;

    var isOpen = block.classList.contains('open');

    // Fermer tous les autres
    document.querySelectorAll('.acc-block.open').forEach(function(b) {
        b.classList.remove('open');
    });

    // Toggle ce bloc
    if (!isOpen) {
        block.classList.add('open');
    }
}
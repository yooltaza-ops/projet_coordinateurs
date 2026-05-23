function filterCoords(q) {
    var lq = q.toLowerCase().trim();
    document.querySelectorAll('.coord-row').forEach(function(row) {
        row.style.display = (!lq || row.dataset.name.includes(lq)) ? '' : 'none';
    });
}
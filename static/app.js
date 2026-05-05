/* ══════════════════════════════════════════════════════
   app.js — Yool Base JavaScript
   ══════════════════════════════════════════════════════ */

// ── Navbar dropdown ──────────────────────────────────────────────────────────
function toggleDropdown() {
    document.getElementById('dropdownMenu').classList.toggle('open');
}
document.addEventListener('click', function(e) {
    var dd = document.getElementById('userDropdown');
    if (dd && !dd.contains(e.target)) {
        document.getElementById('dropdownMenu').classList.remove('open');
    }
});

// ── Sidebar collapse (desktop) ───────────────────────────────────────────────
(function() {
    try {
        var version = localStorage.getItem('sb_ver');
        if (version !== '2') {
            localStorage.removeItem('sb_collapsed');
            localStorage.setItem('sb_ver', '2');
        } else if (localStorage.getItem('sb_collapsed') === 'true' && window.innerWidth > 768) {
            var sb = document.getElementById('sidebar');
            var btn = document.getElementById('toggle-btn');
            if (sb) sb.classList.add('collapsed');
            if (btn) btn.textContent = '›';
        }
    } catch (e) {}
})();

function toggleSidebar() {
    if (window.innerWidth <= 768) return;
    var sb = document.getElementById('sidebar');
    var btn = document.getElementById('toggle-btn');
    var isCollapsed = sb.classList.toggle('collapsed');
    btn.textContent = isCollapsed ? '›' : '‹';
    try { localStorage.setItem('sb_collapsed', isCollapsed); } catch (e) {}
}

// ── Mobile sidebar ───────────────────────────────────────────────────────────
function toggleMobSidebar() {
    var sb = document.getElementById('sidebar');
    var ov = document.getElementById('mob-overlay');
    var btn = document.getElementById('mob-menu-btn');
    var open = sb.classList.toggle('mob-open');
    ov.classList.toggle('active', open);
    btn.textContent = open ? '✕' : '☰';
    btn.style.background = open ? '#e74c3c' : '#1a3a6b';
}

function closeMobSidebar() {
    var sb = document.getElementById('sidebar');
    var ov = document.getElementById('mob-overlay');
    var btn = document.getElementById('mob-menu-btn');
    sb.classList.remove('mob-open');
    ov.classList.remove('active');
    btn.textContent = '☰';
    btn.style.background = '#1a3a6b';
}

document.querySelectorAll('.sidebar .nav-item').forEach(function(item) {
    item.addEventListener('click', function() {
        if (window.innerWidth <= 768) closeMobSidebar();
    });
});

// ── Panel helpers ────────────────────────────────────────────────────────────
function openPanel(id) {
    closeAllPanels();
    var el = document.getElementById(id);
    if (el) {
        el.classList.add('active');
        var ov = document.getElementById('overlay');
        if (ov) ov.classList.add('active');
    }
}

function closeAllPanels() {
    document.querySelectorAll('.panel').forEach(function(p) {
        p.classList.remove('active');
    });
    var ov = document.getElementById('overlay');
    if (ov) ov.classList.remove('active');
}
document.addEventListener('click', function(e) {
  const el = e.target.closest('[data-confirm]');
  if (el) {
    const msg = el.getAttribute('data-confirm') || 'Are you sure?';
    if (!confirm(msg)) {
      e.preventDefault();
    }
  }
});

// Theme toggle
(function() {
  const root = document.documentElement;
  const key = 'sassycode-theme';
  function apply(theme) {
    if (theme === 'dark') root.setAttribute('data-theme', 'dark');
    else root.removeAttribute('data-theme');
  }
  const saved = localStorage.getItem(key);
  if (saved) apply(saved);
  document.addEventListener('click', function(e) {
    const btn = e.target.closest('[data-theme-toggle]');
    if (!btn) return;
    const current = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem(key, next);
    apply(next);
  });
})();

// Unique findings search/sort
(function() {
  function sevRank(s) {
    const order = { 'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3 };
    return order[s] ?? 0;
  }
  const table = document.getElementById('uniqTable');
  if (!table) return;
  const rows = Array.from(table.querySelectorAll('tbody tr'));
  const search = document.getElementById('uniqSearch');
  const sortSel = document.getElementById('uniqSort');

  function apply() {
    const q = (search?.value || '').toLowerCase();
    let filtered = rows;
    if (q) {
      filtered = rows.filter(r => r.textContent.toLowerCase().includes(q));
    }
    const mode = sortSel?.value || 'last_seen_desc';
    filtered.sort((a, b) => {
      if (mode === 'last_seen_desc' || mode === 'last_seen_asc') {
        const av = a.dataset.lastseen || '';
        const bv = b.dataset.lastseen || '';
        return (mode === 'last_seen_desc' ? -1 : 1) * av.localeCompare(bv);
      }
      if (mode === 'severity_desc' || mode === 'severity_asc') {
        const av = sevRank(a.dataset.severity || 'LOW');
        const bv = sevRank(b.dataset.severity || 'LOW');
        return (mode === 'severity_desc' ? -1 : 1) * (av - bv);
      }
      if (mode === 'occ_desc' || mode === 'occ_asc') {
        const av = parseInt(a.dataset.occ || '0', 10);
        const bv = parseInt(b.dataset.occ || '0', 10);
        return (mode === 'occ_desc' ? -1 : 1) * (av - bv);
      }
      if (mode === 'file_asc') {
        return (a.dataset.file || '').localeCompare(b.dataset.file || '');
      }
      return 0;
    });
    const tbody = table.querySelector('tbody');
    tbody.innerHTML = '';
    filtered.forEach(r => tbody.appendChild(r));
  }
  search?.addEventListener('input', apply);
  sortSel?.addEventListener('change', apply);
})();



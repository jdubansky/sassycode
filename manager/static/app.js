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



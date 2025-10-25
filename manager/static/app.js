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
      if (mode === 'status_asc' || mode === 'status_desc') {
        const av = (a.querySelector('td:nth-child(3)')?.textContent || '').trim().toLowerCase();
        const bv = (b.querySelector('td:nth-child(3)')?.textContent || '').trim().toLowerCase();
        return (mode === 'status_desc' ? -1 : 1) * av.localeCompare(bv);
      }
      if (mode === 'status_asc' || mode === 'status_desc') {
        const av = (a.querySelector('td:nth-child(3)')?.textContent || '').trim().toLowerCase();
        const bv = (b.querySelector('td:nth-child(3)')?.textContent || '').trim().toLowerCase();
        return (mode === 'status_desc' ? -1 : 1) * av.localeCompare(bv);
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

// Column resizing with persistence
(function(){
  function enableTableResize(table){
    const key = table.getAttribute('data-resize-key') || 'table-default';
    const colgroup = table.querySelector('colgroup');
    if (!colgroup) return;
    const cols = Array.from(colgroup.querySelectorAll('col'));
    const headerRow = table.querySelector('thead tr');
    if (!headerRow) return;
    const headers = Array.from(headerRow.children);

    // Apply saved widths
    try {
      const saved = JSON.parse(localStorage.getItem('colwidth:'+key) || '[]');
      saved.forEach((w, i) => { if (cols[i] && w) cols[i].style.width = w; });
    } catch {}

    headers.forEach((th, i) => {
      if (i === headers.length - 1) return; // skip last column
      const resizer = document.createElement('div');
      resizer.className = 'col-resizer';
      th.appendChild(resizer);
      let startX = 0; let startWidth = 0;
      function onMove(e){
        const dx = (e.touches? e.touches[0].clientX : e.clientX) - startX;
        const newW = Math.max(60, startWidth + dx);
        if (cols[i]) cols[i].style.width = newW + 'px';
      }
      function onUp(){
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        document.removeEventListener('touchmove', onMove);
        document.removeEventListener('touchend', onUp);
        // persist widths
        const widths = cols.map(c => c.style.width || '');
        try { localStorage.setItem('colwidth:'+key, JSON.stringify(widths)); } catch {}
      }
      resizer.addEventListener('mousedown', (e)=>{
        startX = e.clientX; startWidth = th.offsetWidth; e.preventDefault();
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      });
      resizer.addEventListener('touchstart', (e)=>{
        startX = e.touches[0].clientX; startWidth = th.offsetWidth; e.preventDefault();
        document.addEventListener('touchmove', onMove, {passive:false});
        document.addEventListener('touchend', onUp);
      }, {passive:false});
    });
  }
  document.addEventListener('DOMContentLoaded', function(){
    document.querySelectorAll('table.uniq-table[data-resize-key]')
      .forEach(enableTableResize);
  });
})();

// Unique finding see-more drawer
(function(){
  const table = document.getElementById('uniqTable');
  if (!table) return;
  table.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-see-more]');
    if (!btn) return;
    const ufId = btn.getAttribute('data-see-more');
    const row = btn.closest('tr');
    const next = row.nextElementSibling;
    if (next && next.classList.contains('details-row')) {
      next.remove();
      return;
    }
    const res = await fetch(`/unique_findings/${ufId}/details.json`, { cache: 'no-store' });
    if (!res.ok) return;
    const data = await res.json();
    const d = data.details || {};
    const wrap = document.createElement('tr');
    wrap.className = 'details-row';
    const td = document.createElement('td');
    td.colSpan = row.children.length;
    td.innerHTML = `
      <div class="panel" style="margin:8px 0;">
        <div class="muted" style="margin-bottom:6px;">
          <strong>CWE:</strong> ${data.unique.cwe || '-'} •
          <strong>Occurrences:</strong> ${data.unique.occurrences || 1} •
          <strong>Last seen:</strong> ${data.unique.last_seen_at || '-'}
        </div>
        <form method="post" action="/unique_findings/${ufId}/status" class="toolbar" style="margin:8px 0;">
          <label class="muted">Status</label>
          <select name="status">
            <option value="open" ${data.unique.status==='open'?'selected':''}>Open</option>
            <option value="triaging" ${data.unique.status==='triaging'?'selected':''}>Triaging</option>
            <option value="false_positive" ${data.unique.status==='false_positive'?'selected':''}>False Positive</option>
            <option value="fixed" ${data.unique.status==='fixed'?'selected':''}>Fixed</option>
          </select>
          <button class="btn-primary" type="submit">Update</button>
          <span style="flex:1"></span>
          <button class="btn-danger" formmethod="post" formaction="/unique_findings/${ufId}/delete" type="submit" onclick="return confirm('Delete this unique finding?');">Delete</button>
        </form>
        ${d.explanation ? `<div><strong>Explanation:</strong> ${d.explanation}</div>` : ''}
        ${d.impact ? `<div><strong>Impact:</strong> ${d.impact}</div>` : ''}
        ${data.finding && data.finding.root_cause ? `<div><strong>Root cause:</strong> ${data.finding.root_cause}</div>` : ''}
        ${data.finding && data.finding.recommendation ? `<div><strong>Remediation:</strong> ${data.finding.recommendation}</div>` : ''}
        ${data.finding && data.finding.function_name ? `<div><strong>Function:</strong> <code>${data.finding.function_name}</code></div>` : ''}
        ${data.finding && data.finding.entrypoint ? `<div><strong>Entrypoint:</strong> <code>${data.finding.entrypoint}</code></div>` : ''}
        ${data.finding && data.finding.arguments ? `<div><strong>Arguments:</strong> ${data.finding.arguments}</div>` : ''}
        ${d.fix_suggestion ? `<div><strong>Fix suggestion:</strong> ${d.fix_suggestion}</div>` : ''}
        ${Array.isArray(d.references) && d.references.length ? `<div><strong>References:</strong> ${d.references.map(r=>`<a href=\"${r}\" target=\"_blank\" rel=\"noreferrer\">${r}</a>`).join(', ')}</div>` : ''}
        ${d.evidence && d.evidence.snippet ? `<div style=\"margin-top:8px;\"><strong>Evidence (lines ${d.evidence.start_line||''}-${d.evidence.end_line||''}):</strong><pre>${d.evidence.snippet}</pre></div>` : ''}
      </div>
    `;
    wrap.appendChild(td);
    row.insertAdjacentElement('afterend', wrap);
  });
})();



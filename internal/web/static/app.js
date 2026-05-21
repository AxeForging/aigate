const state = {
  refreshTimer: null,
  events: [],
  filters: {
    query: '',
    kind: '',
    rule: '',
    source: '',
  },
};

const labels = {
  deny_read: 'protected reads',
  deny_exec: 'blocked commands',
  allow_net: 'network boundary',
};

const colors = {
  deny_read: 'oklch(68% 0.13 246)',
  deny_exec: 'oklch(67% 0.19 28)',
  allow_net: 'oklch(72% 0.15 157)',
};

function text(selector, value) {
  const el = document.querySelector(selector);
  if (!el) return;
  if (el.textContent !== String(value)) {
    el.textContent = value;
    el.animate([
      { transform: 'translateY(6px)', opacity: 0.55 },
      { transform: 'translateY(0)', opacity: 1 },
    ], { duration: 260, easing: 'cubic-bezier(0.16, 1, 0.3, 1)' });
  }
}

function list(selector, items, empty) {
  const el = document.querySelector(selector);
  if (!el) return;
  const values = items && items.length ? items : [empty];
  el.innerHTML = values.map((item, index) => {
    const cls = items && items.length ? '' : ' class="muted"';
    return `<li${cls}>${escapeHtml(item)}</li>`;
  }).join('');
}

function renderBars(counters) {
  const el = document.querySelector('[data-field="bars"]');
  if (!el) return;
  const entries = Object.entries(counters.by_rule || {});
  const max = Math.max(1, ...entries.map(([, value]) => value));
  el.innerHTML = entries.map(([key, value], index) => {
    const width = Math.max(4, Math.round((value / max) * 100));
    return `
      <div class="bar-row" style="animation-delay:${index * 55}ms">
        <div class="bar-meta">
          <span>${escapeHtml(labels[key] || key)}</span>
          <strong>${value}</strong>
        </div>
        <div class="bar-track"><div class="bar-fill" style="--value:${width}%; --bar-color:${colors[key] || 'oklch(68% 0.21 41)'}"></div></div>
      </div>
    `;
  }).join('');
}

function renderLatest(event) {
  const el = document.querySelector('[data-field="latest-block"]');
  if (!el) return;
  if (!event) {
    el.innerHTML = '<strong>quiet</strong><span>No blocked sandbox activity has been captured yet.</span><small>Run commands through aigate and this panel will fill in.</small>';
    return;
  }
  el.innerHTML = `
    <strong>${escapeHtml(event.rule || 'blocked')}</strong>
    <span>${escapeHtml(event.command || 'unknown command')}</span>
    <small>${escapeHtml(event.detail || event.source || '')}</small>
  `;
}

function renderEvents(events) {
  const el = document.querySelector('[data-list="events"]');
  if (!el) return;
  if (!events || !events.length) {
    const hasFilters = Object.values(state.filters).some(Boolean);
    const message = hasFilters
      ? 'No events match the active filters.'
      : '`aigate run -- ...` will start populating this view.';
    el.innerHTML = `<div class="empty-state"><strong>No audit events shown.</strong><span>${escapeHtml(message)}</span></div>`;
    updateFilterCount(0, state.events.length);
    return;
  }
  el.innerHTML = events.map((event, index) => `
    <article class="event-row rule-${escapeHtml(event.rule || '')}" style="animation-delay:${Math.min(index * 24, 220)}ms">
      <time>${formatTime(event.time)}</time>
      <strong>${escapeHtml(event.kind || '')}</strong>
      <span>${escapeHtml(event.rule || event.source || '')}</span>
      <p>
        <b>${escapeHtml(event.command || event.detail || '')}</b>
        ${event.detail ? `<small>${escapeHtml(event.detail)}</small>` : ''}
      </p>
    </article>
  `).join('');
  updateFilterCount(events.length, state.events.length);
}

function applyFilters() {
  const query = state.filters.query.toLowerCase();
  const filtered = state.events.filter((event) => {
    if (state.filters.kind && event.kind !== state.filters.kind) return false;
    if (state.filters.rule && event.rule !== state.filters.rule) return false;
    if (state.filters.source && event.source !== state.filters.source) return false;
    if (!query) return true;
    const haystack = [
      event.kind,
      event.rule,
      event.source,
      event.command,
      event.detail,
      event.work_dir,
    ].filter(Boolean).join(' ').toLowerCase();
    return haystack.includes(query);
  });
  renderEvents(filtered);
}

function updateFilterCount(shown, total) {
  const el = document.querySelector('[data-field="filter-count"]');
  if (!el) return;
  el.textContent = `${shown} shown / ${total} total`;
}

function renderSourceOptions(events) {
  const el = document.querySelector('[data-filter="source"]');
  if (!el) return;
  const current = el.value;
  const sources = [...new Set(events.map((event) => event.source).filter(Boolean))].sort();
  el.innerHTML = '<option value="">Any source</option>' + sources.map((source) => (
    `<option value="${escapeHtml(source)}">${escapeHtml(source)}</option>`
  )).join('');
  if (sources.includes(current)) {
    el.value = current;
  } else {
    state.filters.source = '';
  }
}

async function refresh() {
  const res = await fetch('/api/overview', { headers: { accept: 'application/json' } });
  if (!res.ok) return;
  const data = await res.json();
  text('[data-field="blocked-total"]', data.counters.blocked_total);
  text('[data-field="blocked-today"]', data.counters.blocked_today);
  text('[data-field="runs-total"]', data.counters.runs_total);
  text('[data-field="rule-read"]', data.rules.deny_read.length);
  text('[data-field="rule-exec"]', data.rules.deny_exec.length);
  text('[data-field="rule-net"]', data.rules.allow_net.length);
  list('[data-list="deny-read"]', data.rules.deny_read, 'none');
  list('[data-list="deny-exec"]', data.rules.deny_exec, 'none');
  list('[data-list="allow-net"]', data.rules.allow_net, 'all outbound allowed');
  renderBars(data.counters);
  renderLatest(data.last_blocked);
  state.events = data.events || [];
  renderSourceOptions(state.events);
  applyFilters();
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

document.querySelector('[data-action="refresh"]')?.addEventListener('click', refresh);
document.querySelector('[data-action="clear-filters"]')?.addEventListener('click', () => {
  state.filters = { query: '', kind: '', rule: '', source: '' };
  document.querySelectorAll('[data-filter]').forEach((control) => {
    control.value = '';
  });
  applyFilters();
});
document.querySelectorAll('[data-filter]').forEach((control) => {
  control.addEventListener('input', () => {
    state.filters[control.dataset.filter] = control.value;
    applyFilters();
  });
});
renderBars({
  by_rule: {
    deny_read: 0,
    deny_exec: 0,
    allow_net: 0,
  },
});
refresh();
state.refreshTimer = setInterval(refresh, 5000);

const state = {
  refreshTimer: null,
  syncTimer: null,
  lastSync: null,
  events: [],
  filters: {
    query: '',
    kind: '',
    rule: '',
    source: '',
  },
};

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

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

// countUp tweens a numeric field from its current value to the target so the
// hero counter feels alive instead of snapping.
function countUp(selector, target) {
  const el = document.querySelector(selector);
  if (!el) return;
  const from = parseInt(el.textContent.replace(/\D/g, ''), 10) || 0;
  const to = Number(target) || 0;
  if (from === to) return;
  if (reducedMotion) {
    el.textContent = to;
    return;
  }
  const start = performance.now();
  const duration = Math.min(900, 240 + Math.abs(to - from) * 40);
  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const frame = (now) => {
    const t = Math.min(1, (now - start) / duration);
    el.textContent = Math.round(from + (to - from) * ease(t));
    if (t < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

function markSynced() {
  state.lastSync = Date.now();
  renderSyncNote();
}

function renderSyncNote() {
  const el = document.querySelector('[data-field="sync-note"]');
  if (!el || !state.lastSync) return;
  const seconds = Math.max(0, Math.round((Date.now() - state.lastSync) / 1000));
  el.textContent = seconds < 2 ? 'synced just now' : `synced ${seconds}s ago`;
  el.classList.toggle('is-stale', seconds > 15);
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

// renderSpark draws a mini bar chart of daily activity (blocked vs runs) for
// the last 14 days from the event feed.
function renderSpark(events) {
  const el = document.querySelector('[data-field="spark"]');
  if (!el) return;
  const days = [];
  const byDay = new Map();
  for (let i = 13; i >= 0; i -= 1) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    days.push(key);
    byDay.set(key, { blocked: 0, runs: 0 });
  }
  (events || []).forEach((event) => {
    const key = String(event.time || '').slice(0, 10);
    const bucket = byDay.get(key);
    if (!bucket) return;
    if (event.kind === 'blocked') bucket.blocked += 1;
    else if (event.kind === 'run_started') bucket.runs += 1;
  });
  const max = Math.max(1, ...days.map((key) => byDay.get(key).blocked + byDay.get(key).runs));
  el.innerHTML = days.map((key, index) => {
    const { blocked, runs } = byDay.get(key);
    const blockedPct = Math.round((blocked / max) * 100);
    const runsPct = Math.round((runs / max) * 100);
    const label = `${key}: ${blocked} blocked, ${runs} runs`;
    return `
      <div class="spark-col" style="animation-delay:${index * 26}ms" title="${escapeHtml(label)}">
        <div class="spark-runs" style="height:${Math.max(runs ? 6 : 0, runsPct)}%"></div>
        <div class="spark-blocked" style="height:${Math.max(blocked ? 6 : 0, blockedPct)}%"></div>
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
  const button = document.querySelector('[data-action="refresh"]');
  button?.classList.add('is-syncing');
  try {
    const res = await fetch('/api/overview', { headers: { accept: 'application/json' } });
    if (!res.ok) return;
    const data = await res.json();
    countUp('[data-field="blocked-total"]', data.counters.blocked_total);
    countUp('[data-field="blocked-today"]', data.counters.blocked_today);
    countUp('[data-field="runs-total"]', data.counters.runs_total);
    text('[data-field="rule-read"]', data.rules.deny_read.length);
    text('[data-field="rule-exec"]', data.rules.deny_exec.length);
    text('[data-field="rule-net"]', data.rules.allow_net.length);
    text('[data-field="rule-scope"]', (data.rules.allowed_paths || []).length);
    list('[data-list="deny-read"]', data.rules.deny_read, 'none');
    list('[data-list="deny-exec"]', data.rules.deny_exec, 'none');
    list('[data-list="allow-net"]', data.rules.allow_net, 'all outbound allowed');
    list('[data-list="allowed-paths"]', data.rules.allowed_paths, 'scope off — $HOME fully accessible');
    renderBars(data.counters);
    renderLatest(data.last_blocked);
    state.events = data.events || [];
    renderSpark(state.events);
    renderSourceOptions(state.events);
    applyFilters();
    markSynced();
  } finally {
    button?.classList.remove('is-syncing');
  }
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
state.syncTimer = setInterval(renderSyncNote, 1000);

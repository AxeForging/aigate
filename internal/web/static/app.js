const state = {
  refreshTimer: null,
  syncTimer: null,
  lastSync: null,
  events: [],
  decisions: [],
  filters: {
    query: '',
    kind: '',
    layer: '',
    identity: '',
  },
};

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const labels = {
  deny_read: 'protected reads',
  deny_exec: 'blocked commands',
  allow_net: 'network boundary',
  judge: 'judge verdicts',
};

const colors = {
  deny_read: 'oklch(68% 0.13 246)',
  deny_exec: 'oklch(67% 0.19 28)',
  allow_net: 'oklch(72% 0.15 157)',
  judge: 'oklch(74% 0.14 85)',
};

// kindLabel turns a decision into the short word a person would use.
function kindLabel(d) {
  switch (d.kind) {
    case 'judge_decision':
      if (d.outcome === 'ask') return 'judge asked you';
      if (d.outcome === 'deny') return 'judge denied';
      return 'judge: no objection';
    case 'judge_override':
      if ((d.reason || '').startsWith('session started with --judge=off')) return 'judge off (session)';
      if ((d.reason || '').startsWith('allow-once granted')) return 'allow-once granted';
      return 'allowed once';
    case 'judge_fallback': return 'judge fallback';
    default: return 'blocked';
  }
}

// byLabel names who decided in plain words.
function byLabel(by) {
  if (by === 'rules') return 'local rules';
  if (by.startsWith('clef') || by === 'jev') return `${by} model`;
  return by.replace('_', ' ');
}

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

function renderEvents(decisions) {
  const el = document.querySelector('[data-list="events"]');
  if (!el) return;
  if (!decisions || !decisions.length) {
    const hasFilters = Object.values(state.filters).some(Boolean);
    const message = hasFilters
      ? 'No decisions match the active filters.'
      : '`aigate run -- ...` will start populating this view.';
    el.innerHTML = `<div class="empty-state"><strong>No decisions shown.</strong><span>${escapeHtml(message)}</span></div>`;
    updateFilterCount(0, state.decisions.length);
    return;
  }
  // Allow-once overrides, by call id, so a denial can point at its override.
  const overrides = new Map(state.decisions
    .filter((o) => o.kind === 'judge_override' && o.call_id && !(o.reason || '').startsWith('allow-once granted'))
    .map((o) => [o.call_id, o]));
  el.innerHTML = decisions.map((d, index) => {
    const later = d.kind === 'judge_decision' && d.call_id ? overrides.get(d.call_id) : null;
    const laterNote = later
      ? `<small class="override-who">→ later allowed once by ${escapeHtml(later.os_user || 'a person')}${later.reason ? `: ${escapeHtml(later.reason.replace('allowed once by the user: ', ''))}` : ''}</small>` : '';
    const scores = d.scores ? 'model scores (0–1): ' + Object.entries(d.scores)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k.replace('action_', 'chose ')} ${v}`).join(' · ') : '';
    const who = d.kind === 'judge_override'
      ? `<small class="override-who">by ${escapeHtml(d.os_user || 'unknown user')}${d.call_id ? ` · call ${escapeHtml(d.call_id)}` : ''}</small>` : '';
    return `
    <article class="event-row decision-row layer-${escapeHtml(d.layer || '')} kind-${escapeHtml(d.kind || '')}" style="animation-delay:${Math.min(index * 24, 220)}ms">
      <time datetime="${escapeHtml(d.time || '')}">${formatTime(d.time)}</time>
      <strong>${escapeHtml(kindLabel(d))}${later ? ' <span class="overridden">(overridden)</span>' : ''}</strong>
      <span class="chips">
        <span class="chip chip-layer" title="layer that decided">${escapeHtml(d.layer || '')}</span>
        ${d.identity ? `<span class="chip chip-identity" title="identity (account)">${escapeHtml(d.identity)}</span>` : ''}
        ${d.by ? `<span class="chip" title="decided by">${escapeHtml(byLabel(d.by))}</span>` : ''}
      </span>
      <p>
        <b>${escapeHtml(d.what || d.reason || '')}</b>
        ${d.what && d.reason ? `<small>${escapeHtml(d.reason)}</small>` : ''}
        ${scores ? `<small class="scores">${escapeHtml(scores)}</small>` : ''}
        ${who}
        ${laterNote}
      </p>
    </article>`;
  }).join('');
  updateFilterCount(decisions.length, state.decisions.length);
}

function applyFilters() {
  const query = state.filters.query.toLowerCase();
  const filtered = state.decisions.filter((d) => {
    if (state.filters.kind && d.kind !== state.filters.kind) return false;
    if (state.filters.layer && d.layer !== state.filters.layer) return false;
    if (state.filters.identity && d.identity !== state.filters.identity) return false;
    if (!query) return true;
    return [d.kind, d.layer, d.identity, d.by, d.what, d.reason, d.work_dir, d.os_user]
      .filter(Boolean).join(' ').toLowerCase().includes(query);
  });
  renderEvents(filtered);
}

function updateFilterCount(shown, total) {
  const el = document.querySelector('[data-field="filter-count"]');
  if (!el) return;
  el.textContent = `${shown} shown / ${total} total`;
}

function renderIdentityOptions(identities) {
  const el = document.querySelector('[data-filter="identity"]');
  if (!el) return;
  const current = el.value;
  const names = [...new Set([...identities.map((i) => i.name), ...state.decisions.map((d) => d.identity)].filter(Boolean))].sort();
  el.innerHTML = '<option value="">Any identity</option>' + names.map((n) => (
    `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`
  )).join('');
  if (names.includes(current)) el.value = current;
  else state.filters.identity = '';
}

function copyButton(command) {
  return `<button type="button" class="copy-btn" data-copy="${escapeHtml(command)}" aria-label="Copy: ${escapeHtml(command)}"><code>${escapeHtml(command)}</code><span aria-hidden="true">copy</span></button>`;
}

function renderIdentities(data) {
  const el = document.querySelector('[data-list="identities"]');
  if (!el) return;
  const ids = data.identities || [];
  if (!ids.length) {
    el.innerHTML = `<div class="empty-state"><strong>No identities yet.</strong><span>Each identity keeps its own Claude and GitHub logins, git author and ssh key.</span>${copyButton('aigate identity add work')}</div>`;
    return;
  }
  el.innerHTML = ids.map((i) => {
    const problems = (i.problems || []).map((p) => `
      <li class="${p.fatal ? 'is-fatal' : ''}">${escapeHtml(p.message)}${p.fix ? copyButton(p.fix) : ''}</li>`).join('');
    return `
    <article class="identity-card${(i.problems || []).some((p) => p.fatal) ? ' has-problem' : ''}">
      <header>
        <h3>${escapeHtml(i.name)}</h3>
        ${i.default ? '<span class="chip chip-default">default</span>' : ''}
      </header>
      <dl>
        <div><dt>git</dt><dd>${escapeHtml(i.git || '—')}</dd></div>
        <div><dt>claude</dt><dd>${escapeHtml(i.claude_dir)}</dd></div>
        <div><dt>github</dt><dd>${escapeHtml(i.gh_dir)}</dd></div>
        <div><dt>ssh key</dt><dd>${escapeHtml(i.ssh_key || 'none configured')}</dd></div>
        <div><dt>folders</dt><dd>${escapeHtml((i.folders || []).join(', ') || 'none bound')}</dd></div>
        <div><dt>last used</dt><dd>${i.last_used ? `${relativeTime(i.last_used)} <small>(${formatTime(i.last_used)})</small>` : 'never'}</dd></div>
      </dl>
      <details>
        <summary>What a session can reach (${(i.reach || []).length})</summary>
        <ul>${(i.reach || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
      </details>
      ${problems ? `<ul class="problems" aria-label="Problems">${problems}</ul>` : ''}
      <div class="fixes">${(i.fixes || []).map(copyButton).join('')}</div>
    </article>`;
  }).join('');
}

async function getJSON(url) {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return res.json();
}

async function refresh() {
  const button = document.querySelector('[data-action="refresh"]');
  button?.classList.add('is-syncing');
  try {
    const [data, decisions, identities] = await Promise.all([
      getJSON('/api/overview'), getJSON('/api/decisions'), getJSON('/api/identities'),
    ]);
    countUp('[data-field="blocked-total"]', data.counters.blocked_total);
    countUp('[data-field="blocked-today"]', data.counters.blocked_today);
    countUp('[data-field="runs-total"]', data.counters.runs_total);
    text('[data-field="rule-read"]', (data.rules.deny_read || []).length);
    text('[data-field="rule-exec"]', (data.rules.deny_exec || []).length);
    text('[data-field="rule-net"]', (data.rules.allow_net || []).length);
    text('[data-field="rule-scope"]', (data.rules.allowed_paths || []).length);
    list('[data-list="deny-read"]', data.rules.deny_read || [], 'none');
    list('[data-list="deny-exec"]', data.rules.deny_exec || [], 'none');
    list('[data-list="allow-net"]', data.rules.allow_net || [], 'all outbound allowed');
    list('[data-list="allowed-paths"]', data.rules.allowed_paths, 'scope off — $HOME fully accessible');
    renderBars(data.counters);
    renderLatest(data.last_blocked);
    state.events = data.events || [];
    renderSpark(state.events);
    state.decisions = decisions.decisions || [];
    renderIdentities(identities);
    renderIdentityOptions(identities.identities || []);
    applyFilters();
    markSynced();
  } catch (err) {
    console.error('aigate dashboard refresh failed:', err);
    const note = document.querySelector('[data-field="sync-note"]');
    if (note) {
      note.textContent = err instanceof TypeError && /fetch/i.test(err.message)
        ? 'sync failed — is aigate serve still running?'
        : `display error: ${err.message} (see browser console)`;
      note.classList.add('is-stale');
    }
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

function relativeTime(value) {
  const secs = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (!Number.isFinite(secs)) return '';
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)} h ago`;
  return `${Math.round(secs / 86400)} days ago`;
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
  state.filters = { query: '', kind: '', layer: '', identity: '' };
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
document.addEventListener('click', async (event) => {
  const btn = event.target.closest('[data-copy]');
  if (!btn) return;
  const value = btn.dataset.copy;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const area = document.createElement('textarea');
    area.value = value;
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }
  const label = btn.querySelector('span');
  if (label) {
    label.textContent = 'copied';
    setTimeout(() => { label.textContent = 'copy'; }, 1400);
  }
});
renderBars({
  by_rule: {
    deny_read: 0,
    deny_exec: 0,
    allow_net: 0,
    judge: 0,
  },
});
refresh();
state.refreshTimer = setInterval(refresh, 5000);
state.syncTimer = setInterval(renderSyncNote, 1000);

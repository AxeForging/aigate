const state = {
  lastSync: null,
  decisions: [],
  filters: { query: '', kind: '', layer: '', identity: '' },
};

const ruleLabels = {
  deny_read: 'Hidden files',
  deny_exec: 'Blocked commands',
  allow_net: 'Network',
  judge: 'Judge',
};

const layerLabels = { sandbox: 'Sandbox', rule: 'Rule', identity: 'Identity', judge: 'Judge' };

// kindLabel turns a decision into the short phrase a person would use.
function kindLabel(d) {
  switch (d.kind) {
    case 'judge_decision':
      if (d.outcome === 'ask') return 'Judge asked you';
      if (d.outcome === 'deny') return 'Judge denied';
      return 'Judge: no objection';
    case 'judge_override':
      if ((d.reason || '').startsWith('session started with --judge=off')) return 'Judge off (session)';
      if ((d.reason || '').startsWith('allow-once granted')) return 'Allow-once granted';
      return 'Allowed once';
    case 'judge_fallback': return 'Judge fallback';
    default: return 'Blocked';
  }
}

// outcomeClass picks the badge colour: red stopped, amber asked/degraded,
// green let through, blue a person overrode.
function outcomeClass(d) {
  switch (d.kind) {
    case 'judge_decision':
      if (d.outcome === 'deny') return 'deny';
      if (d.outcome === 'ask') return 'ask';
      return 'ok';
    case 'judge_override': return 'override';
    case 'judge_fallback': return 'fallback';
    default: return 'deny';
  }
}

// byLabel names who decided in plain words.
function byLabel(by) {
  if (by === 'rules') return 'local rules';
  if (by.startsWith('clef') || by === 'jev') return `${by} model`;
  return by.replace('_', ' ');
}

// setNumber updates a counter and flashes it only when the value changed.
function setNumber(selector, value) {
  const el = document.querySelector(selector);
  if (!el) return;
  const next = String(Number(value) || 0);
  if (el.textContent === next) return;
  el.textContent = next;
  el.classList.remove('is-updated');
  void el.offsetWidth; // restart the animation
  el.classList.add('is-updated');
}

function setText(selector, value) {
  const el = document.querySelector(selector);
  if (el && el.textContent !== String(value)) el.textContent = value;
}

function markSynced() {
  state.lastSync = Date.now();
  renderSyncNote();
}

function renderSyncNote() {
  const el = document.querySelector('[data-field="sync-note"]');
  if (!el || !state.lastSync) return;
  const seconds = Math.max(0, Math.round((Date.now() - state.lastSync) / 1000));
  el.textContent = seconds < 3 ? 'Updated just now' : `Updated ${seconds}s ago`;
  el.classList.toggle('is-stale', seconds > 15);
}

function list(selector, items, empty) {
  const el = document.querySelector(selector);
  if (!el) return;
  el.innerHTML = items && items.length
    ? items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')
    : `<li class="muted">${escapeHtml(empty)}</li>`;
}

function renderBars(byRule) {
  const el = document.querySelector('[data-field="bars"]');
  if (!el) return;
  const entries = Object.keys(ruleLabels).map((key) => [key, (byRule || {})[key] || 0]);
  const total = entries.reduce((sum, [, v]) => sum + v, 0);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  el.innerHTML = entries.map(([key, value]) => `
    <div class="bar-row">
      <div class="bar-meta"><span>${escapeHtml(ruleLabels[key])}</span><strong>${value}</strong></div>
      <div class="bar-track"><div class="bar-fill" style="--value:${value ? Math.max(3, Math.round((value / max) * 100)) : 0}%"></div></div>
    </div>`).join('') + (total ? '' : '<p class="bars-note">No blocks yet.</p>');
}

// renderSpark draws daily sessions and blocks for the last 14 days.
function renderSpark(events) {
  const el = document.querySelector('[data-field="spark"]');
  if (!el) return;
  const days = [];
  const byDay = new Map();
  for (let i = 13; i >= 0; i -= 1) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = localDay(d);
    days.push({ key, date: d });
    byDay.set(key, { blocked: 0, runs: 0 });
  }
  (events || []).forEach((event) => {
    const t = new Date(event.time);
    if (Number.isNaN(t.getTime())) return;
    const bucket = byDay.get(localDay(t));
    if (!bucket) return;
    if (event.kind === 'blocked') bucket.blocked += 1;
    else if (event.kind === 'run_started') bucket.runs += 1;
  });
  const max = Math.max(1, ...days.map(({ key }) => byDay.get(key).blocked + byDay.get(key).runs));
  el.innerHTML = days.map(({ key, date }) => {
    const { blocked, runs } = byDay.get(key);
    const label = `${date.toLocaleDateString([], { month: 'short', day: 'numeric' })}: ${runs} sessions, ${blocked} blocks`;
    return `
      <div class="spark-col${blocked + runs ? '' : ' is-empty'}" title="${escapeHtml(label)}">
        <div class="spark-runs" style="height:${runs ? Math.max(3, Math.round((runs / max) * 100)) : 0}%"></div>
        <div class="spark-blocked" style="height:${blocked ? Math.max(3, Math.round((blocked / max) * 100)) : 0}%"></div>
      </div>`;
  }).join('');
  const axis = document.querySelector('[data-field="spark-axis"]');
  if (axis) {
    // A label every 4 days, ending on today.
    axis.innerHTML = days.map(({ date }, i) => {
      if (i === days.length - 1) return '<span>Today</span>';
      const show = (days.length - 1 - i) % 4 === 0 && i < days.length - 2;
      return `<span>${show ? escapeHtml(date.toLocaleDateString([], { month: 'short', day: 'numeric' })) : ''}</span>`;
    }).join('');
  }
}

function localDay(d) {
  return `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
}

function renderLatest(event) {
  const el = document.querySelector('[data-field="latest-block"]');
  if (!el) return;
  const badge = document.querySelector('[data-field="latest-badge"]');
  if (badge) badge.hidden = !event;
  if (!event) {
    el.innerHTML = '<p class="muted">Nothing blocked yet. Blocks from <code>aigate run</code> sessions show up here.</p>';
    return;
  }
  const why = [ruleLabels[event.rule] || event.rule, event.detail].filter(Boolean).join(' · ');
  el.innerHTML = `
    <code class="latest-what">${escapeHtml(event.command || 'unknown command')}</code>
    <p class="latest-why">${escapeHtml(why)}</p>
    <time datetime="${escapeHtml(event.time || '')}">${escapeHtml(relativeTime(event.time))} · ${escapeHtml(formatTime(event.time))}</time>`;
}

function renderEvents(decisions) {
  const el = document.querySelector('[data-list="events"]');
  if (!el) return;
  if (!decisions.length) {
    const filtered = Object.values(state.filters).some(Boolean);
    el.innerHTML = filtered
      ? '<div class="empty"><strong>No decisions match these filters.</strong><button type="button" class="btn btn-quiet" data-action="clear-filters">Clear filters</button></div>'
      : '<div class="empty"><strong>No decisions yet.</strong><span>Start a session with <code>aigate run -- claude</code>; blocks and judge verdicts appear here.</span></div>';
    updateFilterCount(0, state.decisions.length);
    return;
  }
  // Allow-once overrides by call id, so a denial can point at its override.
  const overrides = new Map(state.decisions
    .filter((o) => o.kind === 'judge_override' && o.call_id && !(o.reason || '').startsWith('allow-once granted'))
    .map((o) => [o.call_id, o]));
  el.innerHTML = decisions.map((d, index) => {
    const later = d.kind === 'judge_decision' && d.call_id ? overrides.get(d.call_id) : null;
    const meta = [
      d.layer ? `<span title="Layer that decided">${escapeHtml(layerLabels[d.layer] || d.layer)}</span>` : '',
      d.identity ? `<span title="Identity">identity ${escapeHtml(d.identity)}</span>` : '',
      d.by ? `<span title="Decided by">${escapeHtml(byLabel(d.by))}</span>` : '',
      d.kind === 'judge_override' ? `<span>by ${escapeHtml(d.os_user || 'unknown user')}</span>` : '',
    ].filter(Boolean).join('');
    const scores = d.scores ? 'Model scores (0–1): ' + Object.entries(d.scores)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k.replace('action_', '')} ${v}`).join(' · ') : '';
    const laterNote = later
      ? `Later allowed once by ${later.os_user || 'a person'}${later.reason ? `: ${later.reason.replace('allowed once by the user: ', '')}` : ''}` : '';
    const what = d.what || d.reason || '';
    return `
    <article class="decision" style="animation-delay:${Math.min(index * 18, 180)}ms">
      <time datetime="${escapeHtml(d.time || '')}" title="${escapeHtml(formatTime(d.time))}">${escapeHtml(formatTime(d.time))}</time>
      <span class="outcome outcome-${outcomeClass(d)}">${escapeHtml(kindLabel(d))}</span>
      <div class="decision-body">
        ${what ? `<div class="decision-what">${escapeHtml(what)}</div>` : ''}
        ${d.what && d.reason ? `<div class="decision-why">${escapeHtml(d.reason)}</div>` : ''}
        ${meta ? `<div class="decision-meta">${meta}</div>` : ''}
        ${scores ? `<div class="decision-scores">${escapeHtml(scores)}</div>` : ''}
        ${laterNote ? `<div class="decision-note">${escapeHtml(laterNote)} <span class="overridden">(overridden)</span></div>` : ''}
      </div>
    </article>`;
  }).join('');
  updateFilterCount(decisions.length, state.decisions.length);
}

function applyFilters() {
  const query = state.filters.query.trim().toLowerCase();
  const filtered = state.decisions.filter((d) => {
    if (state.filters.kind && d.kind !== state.filters.kind) return false;
    if (state.filters.layer && d.layer !== state.filters.layer) return false;
    if (state.filters.identity && d.identity !== state.filters.identity) return false;
    if (!query) return true;
    return [kindLabel(d), d.layer, d.identity, d.by, d.what, d.reason, d.work_dir, d.os_user]
      .filter(Boolean).join(' ').toLowerCase().includes(query);
  });
  renderEvents(filtered);
}

function updateFilterCount(shown, total) {
  setText('[data-field="filter-count"]', shown === total ? `${total} decisions` : `${shown} of ${total} decisions`);
}

function renderIdentityOptions(identities) {
  const el = document.querySelector('[data-filter="identity"]');
  if (!el) return;
  const current = el.value;
  const names = [...new Set([...identities.map((i) => i.name), ...state.decisions.map((d) => d.identity)].filter(Boolean))].sort();
  el.innerHTML = '<option value="">All identities</option>' + names.map((n) => (
    `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`
  )).join('');
  if (names.includes(current)) el.value = current;
  else state.filters.identity = '';
}

function copyButton(command) {
  return `<button type="button" class="copy" data-copy="${escapeHtml(command)}" aria-label="Copy command: ${escapeHtml(command)}"><code>${escapeHtml(command)}</code><span aria-hidden="true">Copy</span></button>`;
}

function renderIdentities(data) {
  const el = document.querySelector('[data-list="identities"]');
  if (!el) return;
  const ids = data.identities || [];
  if (!ids.length) {
    el.innerHTML = `<div class="card empty"><strong>No identities yet.</strong><span>Sessions use your normal logins. Add an identity to keep separate Claude and GitHub logins, git author and ssh key per account.</span>${copyButton('aigate identity add work')}</div>`;
    return;
  }
  el.innerHTML = ids.map((i) => {
    const problems = (i.problems || []).map((p) => `
      <li class="${p.fatal ? 'is-fatal' : ''}"><span>${escapeHtml(p.message)}</span>${p.fix ? copyButton(p.fix) : ''}</li>`).join('');
    return `
    <article class="card identity${(i.problems || []).some((p) => p.fatal) ? ' has-problem' : ''}">
      <header>
        <h3>${escapeHtml(i.name)}</h3>
        ${i.default ? '<span class="tag tag-default">default</span>' : ''}
      </header>
      <dl class="kv">
        <div><dt>Git author</dt><dd>${escapeHtml(i.git || '—')}</dd></div>
        <div><dt>Claude</dt><dd>${escapeHtml(i.claude_dir)}</dd></div>
        <div><dt>GitHub CLI</dt><dd>${escapeHtml(i.gh_dir)}</dd></div>
        <div><dt>SSH key</dt><dd>${escapeHtml(i.ssh_key || 'none')}</dd></div>
        <div><dt>Folders</dt><dd>${escapeHtml((i.folders || []).join(', ') || 'none bound')}</dd></div>
        <div><dt>Last used</dt><dd>${i.last_used ? `${escapeHtml(relativeTime(i.last_used))} <small>${escapeHtml(formatTime(i.last_used))}</small>` : 'never'}</dd></div>
      </dl>
      ${problems ? `<ul class="problems" aria-label="Problems">${problems}</ul>` : ''}
      <details>
        <summary>What a session can reach (${(i.reach || []).length})</summary>
        <ul>${(i.reach || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
      </details>
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
    const rules = data.rules || {};
    setNumber('[data-field="blocked-total"]', data.counters.blocked_total);
    setNumber('[data-field="blocked-today"]', data.counters.blocked_today);
    setNumber('[data-field="runs-total"]', data.counters.runs_total);
    setText('[data-field="rule-read"]', (rules.deny_read || []).length);
    setText('[data-field="rule-exec"]', (rules.deny_exec || []).length);
    setText('[data-field="rule-net"]', (rules.allow_net || []).length);
    setText('[data-field="rule-scope"]', (rules.allowed_paths || []).length);
    list('[data-list="deny-read"]', rules.deny_read, 'none');
    list('[data-list="deny-exec"]', rules.deny_exec, 'none');
    list('[data-list="allow-net"]', rules.allow_net, 'any host (no allow_net)');
    list('[data-list="allowed-paths"]', rules.allowed_paths, 'scope off — all of $HOME is reachable');
    renderBars(data.counters.by_rule);
    renderLatest(data.last_blocked);
    renderSpark(data.events || []);
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
        ? 'Can’t reach aigate serve — is it still running?'
        : `Display error: ${err.message} (see browser console)`;
      note.classList.add('is-stale');
    }
  } finally {
    button?.classList.remove('is-syncing');
  }
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function relativeTime(value) {
  const secs = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (!Number.isFinite(secs)) return '';
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)} h ago`;
  const days = Math.round(secs / 86400);
  return days === 1 ? 'yesterday' : `${days} days ago`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function clearFilters() {
  state.filters = { query: '', kind: '', layer: '', identity: '' };
  document.querySelectorAll('[data-filter]').forEach((control) => { control.value = ''; });
  applyFilters();
}

// Highlight the tab of the section in view.
function watchSections() {
  const tabs = new Map([...document.querySelectorAll('.tabs a')].map((a) => [a.getAttribute('href').slice(1), a]));
  const visible = new Map();
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((e) => visible.set(e.target.id, e.isIntersecting ? e.intersectionRatio : 0));
    const atBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
    const top = atBottom ? [...tabs.keys()].pop() : [...tabs.keys()].find((id) => (visible.get(id) || 0) > 0);
    setActiveTab(tabs, top);
  }, { rootMargin: '-120px 0px -55% 0px', threshold: [0, 0.01] });
  tabs.forEach((_, id) => {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  });
  window.addEventListener('scroll', () => {
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) setActiveTab(tabs, [...tabs.keys()].pop());
  }, { passive: true });
  tabs.forEach((a, id) => a.addEventListener('click', () => setActiveTab(tabs, id)));
}

function setActiveTab(tabs, active) {
  if (!active) return;
  tabs.forEach((a, id) => {
    a.classList.toggle('is-active', id === active);
    if (id === active) a.setAttribute('aria-current', 'location');
    else a.removeAttribute('aria-current');
  });
}



document.querySelector('[data-action="refresh"]')?.addEventListener('click', refresh);
document.querySelectorAll('[data-filter]').forEach((control) => {
  control.addEventListener('input', () => {
    state.filters[control.dataset.filter] = control.value;
    applyFilters();
  });
});
document.addEventListener('click', async (event) => {
  if (event.target.closest('[data-action="clear-filters"]')) {
    clearFilters();
    return;
  }
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
  btn.classList.add('is-copied');
  if (label) label.textContent = 'Copied';
  setTimeout(() => {
    btn.classList.remove('is-copied');
    if (label) label.textContent = 'Copy';
  }, 1400);
});

// Drop the bottom fade once the decisions list is scrolled to its end.
function watchDecisionsEnd() {
  const el = document.querySelector('[data-list="events"]');
  if (!el) return;
  const update = () => el.classList.toggle('is-end', el.scrollTop + el.clientHeight >= el.scrollHeight - 4);
  el.addEventListener('scroll', update, { passive: true });
  new MutationObserver(update).observe(el, { childList: true });
  update();
}

renderBars({});
watchSections();
watchDecisionsEnd();
refresh();
setInterval(refresh, 5000);
setInterval(renderSyncNote, 1000);

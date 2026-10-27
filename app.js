// Proditor - multiOTP-Verwaltung
'use strict';

const state = {
  csrf: '',
  users: [],
  filter: 'all',
  query: '',
  selected: null,
};

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

async function api(action, body, params = {}) {
  const url = new URL('api.php', location.href);
  url.searchParams.set('action', action);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  const opts = { credentials: 'same-origin', headers: {} };
  if (body !== undefined) {
    opts.method = 'POST';
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['X-CSRF-Token'] = state.csrf;
    opts.body = JSON.stringify(body);
  }
  let res, data;
  try {
    res = await fetch(url, opts);
    data = await res.json();
  } catch {
    throw new Error('Keine Antwort vom Server. Prüfe die Verbindung und lade neu.');
  }
  if (res.status === 401 && action !== 'login') {
    showLogin();
  }
  if (!data.ok) throw new Error(data.error || 'Unbekannter Fehler.');
  return data;
}

function toast(text, bad = false) {
  const t = el('div', { class: 'toast' + (bad ? ' bad' : ''), role: bad ? 'alert' : 'status', text });
  $('#toasts').append(t);
  setTimeout(() => t.remove(), bad ? 7000 : 3500);
}

async function busy(button, fn) {
  button.disabled = true;
  try { return await fn(); } finally { button.disabled = false; }
}

/* ---------- Anmeldung ---------- */

function showLogin() {
  $('#versions').hidden = true;
  $('#view-app').hidden = true;
  $('#bar-actions').hidden = true;
  $('#view-login').hidden = false;
  $('#login-password').value = '';
  $('#login-password').focus();
}

async function showVersions() {
  const d = await api('session');
  const box = $('#versions');
  box.replaceChildren(
    el('span', { class: 'ver' }, el('span', { class: 'ver-k', text: 'multiOTP' }), el('span', { class: 'ver-v', text: d.multiotp })),
    el('span', { class: 'ver' }, el('span', { class: 'ver-k', text: 'PHP' }), el('span', { class: 'ver-v', text: d.php })));
  box.hidden = !d.multiotp;
}

async function showApp() {
  showVersions().catch(() => {});
  $('#view-login').hidden = true;
  $('#view-app').hidden = false;
  $('#bar-actions').hidden = false;
  await loadUsers();
  const linked = decodeURIComponent((location.hash.match(/^#u=(.+)$/) || [])[1] || '');
  if (linked && state.users.some((u) => u.user === linked)) select(linked);
  else $('#search').focus();
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error');
  err.textContent = '';
  await busy(e.submitter || $('#login-form button'), async () => {
    try {
      const d = await api('login', { password: $('#login-password').value });
      state.csrf = d.csrf;
      await showApp();
    } catch (ex) {
      err.textContent = ex.message;
      $('#login-password').select();
    }
  });
});

$('#logout').addEventListener('click', async () => {
  try { await api('logout', {}); } catch { /* egal */ }
  const d = await api('session');
  state.csrf = d.csrf;
  state.selected = null;
  showLogin();
});

/* ---------- Liste ---------- */

const isDual = (u) => u.user.includes('#2');
const ALGO = { hotp: 'HOTP', totp: 'TOTP', without2fa: 'Without2FA' };
const stickName = (serial) => (serial ? `Proditor ${serial}` : '–');
const serialLabel = (u) => (u.algorithm === 'hotp' ? stickName(u.serial) : (u.serial || '–'));
const algoLabel = (u) => ALGO[u.algorithm] || (u.algorithm || '–').toUpperCase();
const nextCounter = (u) => u.last_event + 1;

function matches(u) {
  switch (state.filter) {
    case 'hotp': if (u.algorithm !== 'hotp') return false; break;
    case 'totp': if (u.algorithm !== 'totp') return false; break;
    case 'without2fa': if (u.algorithm !== 'without2fa') return false; break;
    case 'dual': if (!isDual(u)) return false; break;
    case 'locked': if (!u.locked) return false; break;
  }
  if (!state.query) return true;
  const q = state.query.toLowerCase();
  return [u.user, u.description, u.display_name, u.serial && serialLabel(u), u.email].some((v) => v && v.toLowerCase().includes(q));
}

function statusTags(u) {
  const tags = [];
  if (isDual(u)) tags.push(el('span', { class: 'tag', text: 'Dual-Token' }));
  if (u.locked) tags.push(el('span', { class: 'tag tag-locked', text: 'Gesperrt' }));
  if (!u.active) tags.push(el('span', { class: 'tag tag-off', text: 'Deaktiviert' }));
  if (u.synced) tags.push(el('span', { class: 'tag', text: 'AD/LDAP' }));
  return tags;
}

function renderCounts() {
  const c = { all: 0, hotp: 0, totp: 0, without2fa: 0, dual: 0, locked: 0 };
  for (const u of state.users) {
    c.all++;
    if (u.algorithm === 'hotp') c.hotp++;
    if (u.algorithm === 'totp') c.totp++;
    if (u.algorithm === 'without2fa') c.without2fa++;
    if (isDual(u)) c.dual++;
    if (u.locked) c.locked++;
  }
  for (const [k, v] of Object.entries(c)) $(`[data-count="${k}"]`).textContent = v;
}

function renderList() {
  const rows = $('#user-rows');
  const list = state.users.filter(matches);
  rows.replaceChildren(...list.map((u) => {
    const tr = el('tr', { tabindex: '0', 'data-user': u.user, 'aria-selected': String(u.user === state.selected) },
      el('td', {}, el('div', { class: 'u-name', text: u.user }), u.description ? el('div', { class: 'u-desc', text: u.description }) : null),
      el('td', {}, el('span', { class: 'tag' + (u.algorithm === 'hotp' ? ' tag-hotp' : ''), text: algoLabel(u) })),
      el('td', { class: 'mono', text: serialLabel(u) }),
      el('td', { class: 'num', text: u.algorithm === 'hotp' ? String(nextCounter(u)) : '' }),
      el('td', { class: 'num' }, u.errors > 0 ? el('span', { class: 'errors', text: String(u.errors) }) : null),
      el('td', {}, ...statusTags(u)),
    );
    return tr;
  }));
  const empty = $('#empty');
  empty.hidden = list.length > 0;
  empty.textContent = state.users.length === 0 ? 'Es sind noch keine Benutzer angelegt.' : 'Kein Benutzer passt zur Suche oder zum Filter.';
}

async function loadUsers() {
  const d = await api('users');
  state.users = d.users;
  renderCounts();
  renderList();
  if (state.selected) {
    const u = state.users.find((x) => x.user === state.selected);
    if (u) renderDetail(u); else clearDetail();
  }
}

function replaceUser(u) {
  const i = state.users.findIndex((x) => x.user === u.user);
  if (i >= 0) state.users[i] = u; else state.users.push(u);
  renderCounts();
  renderList();
}

$('#user-rows').addEventListener('click', (e) => {
  const tr = e.target.closest('tr[data-user]');
  if (tr) select(tr.dataset.user);
});
$('#user-rows').addEventListener('keydown', (e) => {
  const tr = e.target.closest('tr[data-user]');
  if (!tr) return;
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(tr.dataset.user); }
  if (e.key === 'ArrowDown') { e.preventDefault(); tr.nextElementSibling?.focus(); }
  if (e.key === 'ArrowUp') { e.preventDefault(); tr.previousElementSibling?.focus(); }
});

$('#search').addEventListener('input', (e) => { state.query = e.target.value.trim(); renderList(); });

$('#filters').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-filter]');
  if (!b) return;
  state.filter = b.dataset.filter;
  for (const x of $('#filters').children) x.setAttribute('aria-checked', String(x === b));
  renderList();
});

/* ---------- Details ---------- */

function clearDetail() {
  state.selected = null;
  history.replaceState(null, '', location.pathname);
  $('#detail').replaceChildren(el('div', { class: 'detail-empty' },
    el('p', { text: 'Wähle links einen Benutzer aus.' }),
    el('p', { class: 'muted', text: 'Bei HOTP-Sticks kannst du hier den Zählerstand direkt setzen.' })));
}

function select(name) {
  state.selected = name;
  history.replaceState(null, '', `#u=${encodeURIComponent(name)}`);
  for (const tr of $('#user-rows').children) tr.setAttribute('aria-selected', String(tr.dataset.user === name));
  const u = state.users.find((x) => x.user === name);
  if (u) renderDetail(u);
  if (window.matchMedia('(max-width: 900px)').matches) $('#detail').scrollIntoView({ behavior: 'smooth' });
}

function formatDate(ts) {
  if (!ts) return 'noch nie';
  return new Date(ts * 1000).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
}

// Zaehlwerk: jede Ziffer ist eine Walze, die beim Aendern auf den neuen Wert rollt
function renderOdometer(box, value, animateFrom) {
  const text = String(value).padStart(6, '0');
  const from = animateFrom == null ? text : String(animateFrom).padStart(text.length, '0');
  const firstSignificant = text.search(/[1-9]/);
  box.replaceChildren(...[...text].map((ch, i) => {
    const reel = el('div', { class: 'reel' }, ...Array.from({ length: 10 }, (_, n) => el('span', { text: String(n) })));
    reel.style.transform = `translateY(-${Number(from[i] ?? 0) * 10}%)`;
    const lead = firstSignificant === -1 ? i < text.length - 1 : i < firstSignificant;
    return el('div', { class: 'digit' + (lead ? ' lead' : '') }, reel);
  }));
  box.setAttribute('aria-label', `Nächster Zählerstand ${value}`);
  if (animateFrom != null) {
    requestAnimationFrame(() => requestAnimationFrame(() => {
      [...box.children].forEach((d, i) => { d.firstChild.style.transform = `translateY(-${Number(text[i]) * 10}%)`; });
    }));
  }
}

function renderDetail(u, previousNext = null) {
  const node = $('#tpl-detail').content.firstElementChild.cloneNode(true);
  const f = (name) => node.querySelector(`[data-f="${name}"]`);

  f('user').textContent = u.user;
  f('description').textContent = u.description || u.display_name || '';
  f('chips').replaceChildren(
    el('span', { class: 'tag' + (u.algorithm === 'hotp' ? ' tag-hotp' : ''), text: `${algoLabel(u)}${u.digits && u.algorithm !== 'without2fa' ? `, ${u.digits}-stellig` : ''}` }),
    ...statusTags(u));

  const facts = [
    [u.algorithm === 'hotp' ? 'Stick' : 'Seriennummer', serialLabel(u)],
    ['Letzte Anmeldung', formatDate(u.last_login)],
    ['Fehlversuche', String(u.errors)],
    ['E-Mail', u.email || '–'],
    ['Gruppe', u.group || '–'],
  ];
  f('facts').replaceChildren(...facts.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })]));

  // HOTP-Zaehler
  if (u.algorithm === 'hotp') {
    f('counter-block').hidden = false;
    const current = nextCounter(u);
    renderOdometer(f('odometer'), current, previousNext);
    const form = f('counter-form');
    const input = form.elements.next;
    const hint = f('counter-hint');
    input.value = current;
    const updateHint = () => {
      const v = Number(input.value);
      hint.classList.remove('warn');
      if (!input.value || !Number.isInteger(v) || v < 1) { hint.textContent = 'Gib eine ganze Zahl ab 1 ein.'; return; }
      if (v < current) {
        hint.classList.add('warn');
        hint.textContent = `Niedriger als bisher (${current}). Codes zwischen ${v} und ${current - 1} werden dadurch wieder gültig.`;
      } else if (v === current) {
        hint.textContent = 'Entspricht dem aktuellen Stand.';
      } else {
        hint.textContent = `Codes unter ${v} werden ungültig.`;
      }
    };
    input.addEventListener('input', updateHint);
    updateHint();
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const v = Number(input.value);
      if (!Number.isInteger(v) || v < 1) { input.focus(); return; }
      if (v < current && !confirm(`Den Zähler von ${current} auf ${v} zurücksetzen? Bereits benutzte Codes werden dann wieder angenommen.`)) return;
      await busy(form.querySelector('button'), async () => {
        try {
          const d = await api('counter', { user: u.user, next: v });
          replaceUser(d.user);
          renderDetail(d.user, current);
          toast(`Zähler von ${u.user} auf ${v} gesetzt.`);
        } catch (ex) { toast(ex.message, true); }
      });
    });
  }

  if (u.algorithm === 'without2fa') {
    for (const t of node.querySelectorAll('.tool')) t.remove();
  }

  // Code pruefen
  const check = f('check-form');
  check.addEventListener('submit', async (e) => {
    e.preventDefault();
    await busy(check.querySelector('button'), async () => {
      try {
        const d = await api('check', { user: u.user, otp: check.elements.otp.value });
        check.elements.otp.value = '';
        replaceUser(d.user);
        renderDetail(d.user, u.algorithm === 'hotp' ? nextCounter(u) : null);
        toast(d.valid ? `Code für ${u.user} ist gültig.` : `Code für ${u.user} abgelehnt: ${d.message}`, !d.valid);
      } catch (ex) { toast(ex.message, true); }
    });
  });

  // Resync
  const resync = f('resync-form');
  resync.addEventListener('submit', async (e) => {
    e.preventDefault();
    await busy(resync.querySelector('button'), async () => {
      try {
        const d = await api('resync', { user: u.user, otp1: resync.elements.otp1.value, otp2: resync.elements.otp2.value });
        replaceUser(d.user);
        renderDetail(d.user, u.algorithm === 'hotp' ? nextCounter(u) : null);
        toast(`${u.user} ist synchronisiert.`);
      } catch (ex) { toast(ex.message, true); }
    });
  });

  // Sperren / Entsperren
  const lock = f('lock');
  lock.textContent = u.locked ? 'Entsperren' : 'Sperren';
  if (u.locked) lock.classList.add('btn-primary');
  lock.addEventListener('click', () => busy(lock, async () => {
    try {
      const d = await api(u.locked ? 'unlock' : 'lock', { user: u.user });
      replaceUser(d.user);
      renderDetail(d.user);
      toast(d.user.locked ? `${u.user} ist gesperrt.` : `${u.user} ist entsperrt.`);
    } catch (ex) { toast(ex.message, true); }
  }));

  // QR-Code nur fuer App-Tokens ohne Hardware-Seriennummer
  const qr = f('qr');
  if (u.algorithm !== 'totp') qr.remove();
  else qr.href = `api.php?action=qr&user=${encodeURIComponent(u.user)}`;

  f('delete').addEventListener('click', () => openDelete(u.user));

  $('#detail').replaceChildren(node);
}

/* ---------- Anlegen ---------- */

const dlgCreate = $('#dlg-create');
const createForm = $('#create-form');

let freeSticks = [];

function renderSticks() {
  const q = $('#stick-filter').value.trim().toLowerCase();
  const sel = $('#stick-select');
  const keep = sel.value;
  const list = freeSticks.filter((t) => stickName(t).toLowerCase().includes(q));
  sel.replaceChildren(...list.map((t) => el('option', { value: t, text: stickName(t) })));
  if (list.includes(keep)) sel.value = keep;
  else if (list.length === 1) sel.value = list[0];
  $('#stick-count').textContent = freeSticks.length === 0
    ? '(keine frei, neue Sticks in der alten Konsole importieren)'
    : list.length === freeSticks.length ? `(${freeSticks.length} frei)` : `(${list.length} von ${freeSticks.length})`;
}

async function loadSticks() {
  $('#stick-count').textContent = '(wird geladen …)';
  try {
    freeSticks = (await api('tokens')).tokens;
    renderSticks();
  } catch (ex) { $('#stick-count').textContent = ex.message; }
}

// Nicht benoetigte Felder bleiben sichtbar, werden aber abgedunkelt und gesperrt
function setOff(container, off) {
  container.classList.toggle('is-off', off);
  container.setAttribute('aria-disabled', String(off));
  for (const c of container.querySelectorAll('input, select')) c.disabled = off;
}

function updateKind() {
  const kind = createForm.elements.kind.value;
  setOff($('#stick-field'), kind !== 'stick');
  $('#stick-select').required = kind === 'stick';
  for (const n of createForm.querySelectorAll('.pin-only')) setOff(n, kind === 'without2fa');
}

$('#new-user').addEventListener('click', () => {
  createForm.reset();
  $('#create-error').textContent = '';
  $('#stick-filter').value = '';
  updateKind();
  loadSticks();
  dlgCreate.showModal();
  createForm.elements.user.focus();
});

createForm.addEventListener('change', (e) => { if (e.target.name === 'kind') updateKind(); });
$('#stick-filter').addEventListener('input', renderSticks);
$('#stick-filter').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown') { e.preventDefault(); const s = $('#stick-select'); s.focus(); if (!s.value && s.options.length) s.selectedIndex = 0; }
  if (e.key === 'Enter') e.preventDefault();
});

createForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(createForm);
  const body = Object.fromEntries(fd.entries());
  if (body.kind === 'stick' && !body.serial) {
    $('#create-error').textContent = 'Wähle einen Proditor-Stick aus der Liste.';
    $('#stick-filter').focus();
    return;
  }
  // QR-Fenster sofort oeffnen, sonst blockiert der Browser das Popup nach dem Warten
  const qrWin = body.kind === 'totp' ? window.open('', '_blank') : null;
  await busy(createForm.querySelector('[type=submit]'), async () => {
    try {
      const d = await api('create', body);
      dlgCreate.close();
      replaceUser(d.user);
      state.users.sort((a, b) => a.user.localeCompare(b.user, 'de', { numeric: true, sensitivity: 'base' }));
      renderList();
      select(d.user.user);
      if (qrWin) qrWin.location = `api.php?action=qr&user=${encodeURIComponent(d.user.user)}`;
      toast(body.kind === 'stick' ? `${d.user.user} ist angelegt, ${stickName(d.user.serial)} zugeordnet.` : `${d.user.user} ist angelegt.`);
    } catch (ex) {
      qrWin?.close();
      $('#create-error').textContent = ex.message;
    }
  });
});

/* ---------- Loeschen ---------- */

const dlgDelete = $('#dlg-delete');
const deleteForm = $('#delete-form');
let deleteTarget = null;

function openDelete(name) {
  deleteTarget = name;
  deleteForm.reset();
  $('#delete-name').textContent = name;
  $('#delete-error').textContent = '';
  dlgDelete.showModal();
  deleteForm.elements.confirm.focus();
}

deleteForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (deleteForm.elements.confirm.value !== deleteTarget) {
    $('#delete-error').textContent = 'Der Name stimmt nicht überein.';
    return;
  }
  await busy(deleteForm.querySelector('[type=submit]'), async () => {
    try {
      await api('delete', { user: deleteTarget, confirm: deleteForm.elements.confirm.value });
      dlgDelete.close();
      state.users = state.users.filter((u) => u.user !== deleteTarget);
      renderCounts();
      renderList();
      clearDetail();
      toast(`${deleteTarget} ist gelöscht.`);
    } catch (ex) { $('#delete-error').textContent = ex.message; }
  });
});

for (const b of document.querySelectorAll('dialog [data-close]')) {
  b.addEventListener('click', () => b.closest('dialog').close());
}

/* ---------- Start ---------- */

(async () => {
  try {
    const d = await api('session');
    state.csrf = d.csrf;
    $('#host').textContent = `auf ${d.host}`;
    if (d.logged) await showApp(); else showLogin();
  } catch (ex) {
    showLogin();
    $('#login-error').textContent = ex.message;
  }
})();

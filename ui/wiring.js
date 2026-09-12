/* Startup: fetch, render, and the controls in the header. */

/* ---------- wiring ---------- */

var lastGenerated = 0;
var refreshDeadline = 0;
var connectionLost = false;
var freshnessState = '';
var loadingState = false;

function load() {
  if (loadingState) return Promise.resolve();
  loadingState = true;
  return fetch('/api/state', {signal: AbortSignal.timeout(15000)}).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }).then(function (s) {
    connectionLost = false;
    state = s;
    lastGenerated = s.generated || 0;
    render();
    updateFreshness();
    refreshHostSheet();
    refreshManagementView();
  }).catch(function (e) {
    connectionLost = true;
    document.getElementById('summary').textContent = 'Нет связи с дашбордом. Повторяем подключение…';
    updateFreshness();
  }).finally(function () { loadingState = false; });
}

/* A poll takes twenty seconds on a good day and much longer when something is
   wedged, and until now the only sign of it was a button that said "опрашиваю…"
   for an unknown length of time. This asks a deliberately tiny endpoint — the
   snapshot itself is three quarters of a megabyte — for how far the cycle has
   got, and reloads the page's data the moment a new one lands. */
function tickProgress() {
  return fetch('/api/progress', {signal: AbortSignal.timeout(10000)}).then(function (r) { return r.json(); }).then(function (p) {
    var bar = document.getElementById('pollbar');
    var btn = document.getElementById('btn-refresh');
    var pct = p.total ? Math.round((p.done || 0) * 100 / p.total) : 0;
    if (p.polling) {
      bar.classList.remove('hidden');
      bar.querySelector('i').style.width = pct + '%';
      bar.querySelector('span').textContent =
        (p.phase || 'опрашиваю') + (p.total ? ' · ' + (p.done || 0) + ' из ' + p.total : '');
      if (btn.disabled) btn.textContent = 'опрашиваю ' + (p.done || 0) + '/' + p.total;
    } else {
      bar.classList.add('hidden');
    }
    if (p.generated && p.generated > lastGenerated) {
      lastGenerated = p.generated;
      done();
      return load();
    }
    /* The poll outlived any sane cycle; stop pretending it is still coming. */
    if (btn.disabled && refreshDeadline && Date.now() > refreshDeadline) {
      btn.textContent = 'опрос не ответил';
      setTimeout(done, 3000);
    }
  }).catch(function () { /* a missed tick is not worth a message */ });
}

function done() {
  var btn = document.getElementById('btn-refresh');
  refreshDeadline = 0;
  btn.disabled = false;
  btn.textContent = 'Обновить данные';
}

function refresh() {
  if (state && state.demo) { load(); return; }
  /* Nothing to poll for here any more: the progress ticker knows when a new
     snapshot lands and puts the button back itself. */
  var btn = document.getElementById('btn-refresh');
  btn.disabled = true;
  btn.textContent = 'опрашиваю…';
  refreshDeadline = Date.now() + 180000;
  fetch('/api/refresh', { method: 'POST', headers: actionHeaders() })
    .then(function (r) { return r.json(); }).then(function (res) { if (res.error) { if (!actionFailed(res)) alert(res.error); done(); return; } tickProgress(); })
    .catch(function () { done(); });
}

document.addEventListener('DOMContentLoaded', function () {
  var saved = localStorage.getItem('hz-theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);

  function toggleTheme() {
    var now = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', now);
    localStorage.setItem('hz-theme', now);
  }
  document.getElementById('btn-theme').addEventListener('click', toggleTheme);
  document.getElementById('btn-theme-mobile').addEventListener('click', toggleTheme);
  document.getElementById('btn-refresh').addEventListener('click', refresh);
  var problemsBtn = document.getElementById('btn-problems');
  problemsBtn.addEventListener('click', function () {
    if (onlyProblems || fleetFilter !== 'all') setFleetFilter('all');
    else setFleetFilter('problems');
  });
  document.getElementById('search').addEventListener('input', function (e) {
    searchText = e.target.value.trim();
    render();
  });
  document.getElementById('btn-upgrade-all').addEventListener('click', function () { showView('updates'); });

  /* The chosen tab survives a reload: the page reloads itself every thirty
     seconds, and a view that jumped back to the fleet each time would be
     unusable for reading anything longer than that. */
  document.querySelectorAll('.sidebar [data-view]').forEach(function (tab) {
    tab.addEventListener('click', function () { showView(tab.dataset.view); });
  });
  showView(window.location.hash.slice(1) || localStorage.getItem('hz-view') || 'fleet', true);
  window.addEventListener('popstate', function () { showView(window.location.hash.slice(1) || 'fleet', true); });
  window.addEventListener('hashchange', function () { showView(window.location.hash.slice(1) || 'fleet', true); });
  window.addEventListener('beforeunload', function (event) {
    if (settingsDirty || (suppressionDraft && suppressionDraft.dirty)) { event.preventDefault(); event.returnValue = ''; }
  });

  document.querySelectorAll('[data-close]').forEach(function (el) {
    el.addEventListener('click', function () {
      el.closest('.modal').classList.add('hidden');
    });
  });
  document.querySelectorAll('.modal').forEach(function (m) {
    m.addEventListener('click', function (e) { if (e.target === m) m.classList.add('hidden'); });
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') document.querySelectorAll('.modal').forEach(function (m) { m.classList.add('hidden'); });
  });

  load();
  tickProgress();
  setInterval(tickProgress, 2000);
  // A safety net: if the ticker never sees a new cycle (a hub restart resets
  // the counter), the page still refreshes itself.
  setInterval(load, 60000);
  setInterval(updateFreshness, 5000);
  wireDialogs();
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && !document.querySelector('.modal:not(.hidden)')) { e.preventDefault(); showView('fleet'); document.getElementById('search').focus(); }
  });
});

var currentView = 'fleet';
var viewScroll = {};
function showView(name, fromHistory) {
  var titles = {fleet:'Обзор сети',network:'Сеть',journal:'Журнал',updates:'Обновления',sites:'Сервисы',suppressions:'Исключения',settings:'Настройки'};
  if (name === 'egress' || name === 'topology') { networkTab = name; name = 'network'; }
  if (!Object.prototype.hasOwnProperty.call(titles, name)) name = 'fleet';
  var changed = currentView !== name;
  if (changed) {
    viewScroll[currentView] = window.scrollY;
    document.querySelectorAll('.modal').forEach(function (modal) { modal.classList.add('hidden'); });
    if (name === 'settings' && !settingsDirty) settingsLoaded = false;
  }
  currentView = name;
  document.querySelectorAll('.sidebar [data-view]').forEach(function (tab) { tab.classList.toggle('active', tab.dataset.view === name); tab.setAttribute('aria-current',tab.dataset.view === name ? 'page' : 'false'); });
  Object.keys(titles).forEach(function (view) { document.getElementById(view).classList.toggle('hidden', view !== name); });
  document.getElementById('fleet-toolbar').classList.toggle('hidden',name !== 'fleet');
  document.getElementById('overview').classList.toggle('hidden',name !== 'fleet');
  document.getElementById('fleet-alert').classList.toggle('hidden',name !== 'fleet');
  document.getElementById('view-title').textContent = titles[name];
  document.getElementById('view-crumb').textContent = titles[name].toUpperCase();
  document.title = 'health-zoo · ' + titles[name];
  localStorage.setItem('hz-view',name);
  if (window.location.hash !== '#' + name) {
    window.history[fromHistory ? 'replaceState' : 'pushState'](null, '', '#' + name);
  }
  refreshManagementView();
  if (changed) window.scrollTo(0, viewScroll[name] || 0);
}
function refreshManagementView() {
  if (currentView === 'sites') renderServices();
  if (currentView === 'network') renderNetwork();
  if (currentView === 'journal') renderJournal();
  if (currentView === 'updates') renderUpdates();
  if (currentView === 'suppressions') renderSuppressionReview();
  // Keep the mounted form (and its unsaved values) through polling and tabs.
  if (currentView === 'settings') {
    if (settingsLoaded && !settingsDirty && !settingsObservedGeneration && state && state.generated) settingsLoaded = false;
    renderSettings();
  }
}
function updateFreshness() {
  refreshServiceFreshness();
  var age = snapshotAge();
  var current = String(connectionLost) + age.level;
  var label = document.getElementById('connection-label');
  label.textContent = connectionLost ? 'Нет связи с дашбордом' : !state ? 'Подключение…' : age.level !== 'ok' ? 'Данные устарели' : 'Данные обновляются';
  if (current !== freshnessState && state) { freshnessState = current; renderAlert(state.hosts || []); }
}
function wireDialogs() {
  var returnFocus = null;
  var previousHost = null;
  document.querySelectorAll('.modal').forEach(function (modal) {
    var wasOpen = false;
    new MutationObserver(function () {
      var open = !modal.classList.contains('hidden');
      if (open && !wasOpen) { returnFocus = document.activeElement; previousHost = returnFocus && returnFocus.dataset.host; modal.querySelector('[data-close]').focus(); }
      if (!open && wasOpen) {
        if (returnFocus && returnFocus.isConnected) returnFocus.focus();
        else if (previousHost) { var target = Array.from(document.querySelectorAll('[data-host]')).find(function (e) {return e.dataset.host === previousHost;}); if (target) target.focus(); }
        else document.getElementById('btn-refresh').focus();
      }
      wasOpen = open;
    }).observe(modal,{attributes:true,attributeFilter:['class']});
    modal.addEventListener('keydown',function(e){
      if(e.key !== 'Tab') return;
      var controls = Array.from(modal.querySelectorAll('button,a[href],input,select,textarea,[tabindex="0"]')).filter(function(x){return !x.disabled && x.getClientRects().length;});
      var first=controls[0],last=controls[controls.length-1];
      if(e.shiftKey && document.activeElement === first){e.preventDefault();last.focus();}
      else if(!e.shiftKey && document.activeElement === last){e.preventDefault();first.focus();}
    });
  });
}
function refreshHostSheet() {
  if (!currentHostId || document.getElementById('modal').classList.contains('hidden') || !document.getElementById('modal').classList.contains('host-sheet')) return;
  var host = (state.hosts || []).find(function(x){return x.id === currentHostId;});
  if (host) showHost(host, true);
}

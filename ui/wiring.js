/* Startup: fetch, render, and the controls in the header. */

/* ---------- wiring ---------- */

var lastGenerated = 0;
var refreshDeadline = 0;

function load() {
  return fetch('/api/state').then(function (r) { return r.json(); }).then(function (s) {
    state = s;
    lastGenerated = s.generated || 0;
    render();
  }).catch(function (e) {
    document.getElementById('summary').textContent = 'не удалось получить данные: ' + e;
  });
}

/* A poll takes twenty seconds on a good day and much longer when something is
   wedged, and until now the only sign of it was a button that said "опрашиваю…"
   for an unknown length of time. This asks a deliberately tiny endpoint — the
   snapshot itself is three quarters of a megabyte — for how far the cycle has
   got, and reloads the page's data the moment a new one lands. */
function tickProgress() {
  return fetch('/api/progress').then(function (r) { return r.json(); }).then(function (p) {
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
  /* Nothing to poll for here any more: the progress ticker knows when a new
     snapshot lands and puts the button back itself. */
  var btn = document.getElementById('btn-refresh');
  btn.disabled = true;
  btn.textContent = 'опрашиваю…';
  refreshDeadline = Date.now() + 180000;
  fetch('/api/refresh', { method: 'POST', headers: actionHeaders() })
    .then(function () { tickProgress(); })
    .catch(function () { done(); });
}

document.addEventListener('DOMContentLoaded', function () {
  var saved = localStorage.getItem('hz-theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);

  document.getElementById('btn-theme').addEventListener('click', function () {
    var now = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', now);
    localStorage.setItem('hz-theme', now);
  });
  document.getElementById('btn-refresh').addEventListener('click', refresh);
  var problemsBtn = document.getElementById('btn-problems');
  function syncProblemsBtn() {
    problemsBtn.classList.toggle('btn-primary', onlyProblems);
    problemsBtn.textContent = onlyProblems ? 'Показаны проблемы' : 'Только проблемы';
  }
  syncProblemsBtn();
  problemsBtn.addEventListener('click', function () {
    onlyProblems = !onlyProblems;
    localStorage.setItem('hz-only-problems', onlyProblems ? '1' : '0');
    syncProblemsBtn();
    render();
  });
  document.getElementById('search').addEventListener('input', function (e) {
    searchText = e.target.value.trim();
    render();
  });
  document.getElementById('btn-sites').addEventListener('click', showSites);
  document.getElementById('btn-suppressions').addEventListener('click', showSuppressions);
  document.getElementById('btn-settings').addEventListener('click', showSettings);
  document.getElementById('btn-upgrade-all').addEventListener('click', function () { startUpdate([]); });

  /* The chosen tab survives a reload: the page reloads itself every thirty
     seconds, and a view that jumped back to the fleet each time would be
     unusable for reading anything longer than that. */
  function showView(name) {
    document.querySelectorAll('.view-tabs .tab').forEach(function (tab) {
      tab.classList.toggle('active', tab.dataset.view === name);
    });
    ['fleet', 'egress'].forEach(function (view) {
      document.getElementById(view).classList.toggle('hidden', view !== name);
    });
    localStorage.setItem('hz-view', name);
  }
  document.querySelectorAll('.view-tabs .tab').forEach(function (tab) {
    tab.addEventListener('click', function () { showView(tab.dataset.view); });
  });
  showView(localStorage.getItem('hz-view') || 'fleet');

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
});

/* Startup: fetch, render, and the controls in the header. */

/* ---------- wiring ---------- */

function load() {
  return fetch('/api/state').then(function (r) { return r.json(); }).then(function (s) {
    state = s;
    render();
  }).catch(function (e) {
    document.getElementById('summary').textContent = 'не удалось получить данные: ' + e;
  });
}

function refresh() {
  /* Wait for the snapshot to actually change, not for a fixed number of
     seconds. A timer either lies (the button frees up while the old data is
     still on screen) or wastes time; the generated timestamp says exactly when
     the new poll landed. */
  var btn = document.getElementById('btn-refresh');
  var was = (state && state.generated) || 0;
  var deadline = Date.now() + 120000;
  btn.disabled = true;
  btn.textContent = 'опрашиваю…';

  function done() {
    btn.disabled = false;
    btn.textContent = 'Обновить данные';
  }

  function poll() {
    load().then(function () {
      if (state && state.generated > was) { done(); return; }
      if (Date.now() > deadline) {
        // The poll outlived any sane cycle; stop pretending it is still coming.
        btn.textContent = 'опрос не ответил';
        setTimeout(done, 3000);
        return;
      }
      setTimeout(poll, 1500);
    });
  }

  fetch('/api/refresh', { method: 'POST', headers: actionHeaders() })
    .then(function () { setTimeout(poll, 1200); })
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
  setInterval(load, 30000);
});

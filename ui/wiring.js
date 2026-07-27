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
  var btn = document.getElementById('btn-refresh');
  btn.disabled = true;
  btn.textContent = 'опрашиваю…';
  fetch('/api/refresh', { method: 'POST', headers: actionHeaders() }).then(function () {
    // The hub polls asynchronously; give it a moment before re-reading.
    setTimeout(function () {
      load().then(function () {
        btn.disabled = false;
        btn.textContent = 'Обновить данные';
      });
    }, 4000);
  });
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
  document.getElementById('btn-upgrade-all').addEventListener('click', function () { startUpdate([]); });

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

/* Everything that changes something: suppressions, updates, reboots,
   service actions, and the job log they all report into. */

/* ---------- suppressions ---------- */

function suppressIssue(host, issue) {
  var reason = prompt(
    'Исключить проверку для ' + host.name + ':\n«' + issue.text + '»\n\n' +
    'Проверка продолжит выполняться, но перестанет красить карточку и слать\n' +
    'алерты. Причина будет показана рядом с проверкой.\n\n' +
    'Причина (обязательно):');
  if (reason === null) return;
  if (reason.trim().length < 3) { alert('Без причины исключение бессмысленно.'); return; }

  var days = prompt('На сколько дней? Пусто — бессрочно.\n' +
                    'Срок помогает потом понять, нужно ли исключение ещё.', '90');
  if (days === null) return;

  fetch('/api/suppress', {
    method: 'POST', headers: actionHeaders(),
    body: JSON.stringify({ host: host.id, key: issue.key, reason: reason.trim(),
                           days: days.trim() ? parseInt(days, 10) : null })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    document.getElementById('modal').classList.add('hidden');
    load();
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}

function unsuppress(id, onDone) {
  if (!confirm('Снять исключение? Проверка снова будет влиять на статус и алерты.')) return;
  fetch('/api/suppress/remove', {
    method: 'POST', headers: actionHeaders(), body: JSON.stringify({ id: id })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    load();
    if (onDone) onDone();
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}

function showSuppressions() {
  var list = (state && state.suppressions) || [];
  document.getElementById('modal-title').textContent = 'Исключения (' + list.length + ')';
  var root = document.getElementById('modal-body');
  root.innerHTML = '';

  if (!list.length) {
    root.appendChild(h('p', { class: 'checks-intro', text:
      'Исключений нет — дашборд показывает всё, что находит.' }));
    document.getElementById('modal').classList.remove('hidden');
    return;
  }

  var stale = list.filter(function (s) { return !s.still_firing; }).length;
  root.appendChild(h('p', { class: 'checks-intro', text:
    'Проверки продолжают выполняться; исключение лишь снимает влияние на статус и алерты.' +
    (stale ? ' У ' + stale + ' исключений проблема уже не воспроизводится — их можно снять.' : '') }));

  root.appendChild(table(['хост', 'проверка', 'обоснование', 'возраст', 'состояние', ''],
    list.map(function (s) {
      return h('tr', null, [
        h('td', { text: s.host_name }),
        h('td', { class: 'mono', text: s.key }),
        h('td', { text: s.reason }),
        h('td', { class: 'mono right', text: Math.round(s.age_days) + ' сут' +
                  (s.days_left !== null ? ' / ещё ' + Math.round(s.days_left) : '') }),
        h('td', null, [
          h('span', { class: 'dot ' + (s.still_firing ? 'warn' : 'ok') }),
          h('span', { text: s.still_firing ? 'скрывает проблему' : 'проблемы больше нет' })
        ]),
        h('td', { class: 'right' }, [h('button', {
          class: 'btn btn-sm', text: 'снять',
          onclick: function () { unsuppress(s.id, showSuppressions); }
        })])
      ]);
    })));
  document.getElementById('modal').classList.remove('hidden');
}

/* ---------- service actions ---------- */

function serviceAction(host, svc, action) {
  var name = svc.name.replace(/\.service$/, '');
  if (!confirm('Перезапустить «' + name + '» на ' + host.name + '?')) return;

  fetch('/api/service/action', {
    method: 'POST', headers: actionHeaders(),
    body: JSON.stringify({ host: host.id, unit: svc.name, action: action })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    document.getElementById('modal').classList.add('hidden');
    openJobLog();
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}

/* ---------- service removal ---------- */

/* Units that would cut off access to the host itself, or take the box down with
   them. The hub refuses these as well — this only hides the button early. */
function isProtected(name) {
  var base = name.replace(/\.(service|timer)$/, '');
  return /^(ssh|sshd|dropbear|network|networking|systemd-networkd|systemd-resolved|dbus|firewall|cron|rpcd|log|health-zoo)$/.test(base) ||
         base.indexOf('systemd-') === 0;
}

function removeService(host, svc) {
  var name = svc.name.replace(/\.service$/, '');
  var typed = prompt(
    'Удалить сервис «' + name + '» с ' + host.name + '?\n\n' +
    'Сервис будет остановлен, отключён из автозапуска, а его unit-файл удалён.\n' +
    'Это необратимо.\n\n' +
    'Для подтверждения введите имя сервиса:');
  if (typed === null) return;
  if (typed.trim() !== name) { alert('Имя не совпало — ничего не удалено.'); return; }

  fetch('/api/service/remove', {
    method: 'POST',
    headers: actionHeaders(),
    body: JSON.stringify({ host: host.id, unit: svc.name })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    document.getElementById('modal').classList.add('hidden');
    openJobLog();
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}

/* ---------- updates ---------- */

/* When the hub is configured with an action_token, mutating calls carry it in
   a header. Kept in localStorage so it is typed once per browser. */
function actionHeaders() {
  var headers = { 'Content-Type': 'application/json' };
  if (state && state.needs_token) {
    var token = localStorage.getItem('hz-token');
    if (!token) {
      token = prompt('Введите токен доступа (задан в /etc/health-zoo.json):') || '';
      if (token) localStorage.setItem('hz-token', token);
    }
    headers['X-Health-Zoo-Token'] = token;
  }
  return headers;
}

function actionFailed(res) {
  if (res && res.error && /token/i.test(res.error)) {
    localStorage.removeItem('hz-token');
    alert('Токен не подошёл — введите заново при следующей попытке.');
    return true;
  }
  return false;
}

function startUpdate(ids) {
  var what = ids && ids.length ? ids.join(', ') : 'все серверы';
  if (!confirm('Обновить пакеты: ' + what + '?\n\nЭто выполнит apt-get upgrade. Хост дашборда обновится последним.')) return;

  fetch('/api/update', {
    method: 'POST',
    headers: actionHeaders(),
    body: JSON.stringify({ hosts: ids || [] })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    document.getElementById('modal').classList.add('hidden');
    openJobLog();
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}

function openJobLog() {
  jobTab = '';
  document.getElementById('joblog').classList.remove('hidden');
  pollJob();
  if (jobTimer) clearInterval(jobTimer);
  jobTimer = setInterval(pollJob, 1500);
}

var jobTab = '';

/* Log colouring. apt output is dense and mostly uninteresting; what the
   operator is scanning for is which packages moved, what failed, and whether
   a reboot is now required. Line-level classification is enough for that —
   a real tokeniser would add weight for no extra answer. */
var LOG_RULES = [
  { re: /^===\s/,                                   cls: 'log-head' },
  { re: /\b(E:|error|failed|cannot|unable to)\b/i, cls: 'log-error' },
  { re: /REBOOT-REQUIRED|reboot required/i,          cls: 'log-reboot' },
  { re: /\b(W:|warning|warn)\b/i,                  cls: 'log-warn' },
  { re: /^(Setting up|Unpacking|Preparing to unpack|Installing|Upgrading)\b/, cls: 'log-act' },
  { re: /^(Get:|Hit:|Ign:|Fetched|Reading|Building|Calculating|Selecting)\b/, cls: 'log-noise' },
  { re: /^\s*\d+ upgraded|newly installed|to remove/,  cls: 'log-summary' },
  { re: /^(Processing triggers|Created symlink|Removed)\b/, cls: 'log-act' },
  { re: /^\s*(алерты|команда|через|переопрос)/,      cls: 'log-note' }
];

function renderLog(container, lines) {
  container.innerHTML = '';
  var fragment = document.createDocumentFragment();
  lines.forEach(function (line) {
    var cls = '';
    for (var i = 0; i < LOG_RULES.length; i++) {
      if (LOG_RULES[i].re.test(line)) { cls = LOG_RULES[i].cls; break; }
    }
    var row = h('div', { class: 'log-line ' + cls });
    // Package names and versions are the part worth finding at a glance.
    var match = line.match(/^(Setting up|Unpacking|Preparing to unpack|Get:\d+|Removed)\s+(\S+)(.*)$/);
    if (match) {
      row.appendChild(document.createTextNode(match[1] + ' '));
      row.appendChild(h('b', { class: 'log-pkg', text: match[2] }));
      row.appendChild(document.createTextNode(match[3]));
    } else {
      row.textContent = line;
    }
    fragment.appendChild(row);
  });
  container.appendChild(fragment);
}

function pollJob() {
  fetch('/api/job').then(function (r) { return r.json(); }).then(function (job) {
    if (!job || job.state === 'idle') {
      document.getElementById('job-status').textContent = 'нет активных заданий';
      return;
    }
    var done = job.state === 'done';
    var hosts = job.hosts || {};
    var ids = job.targets || Object.keys(hosts);

    /* One tab per host, coloured by outcome: amber while running, green when
       that host is finished, red if it failed. Parallel updates otherwise
       interleave four apt runs into one unreadable stream. */
    var tabs = document.getElementById('job-tabs');
    tabs.innerHTML = '';
    var finished = 0;
    ids.forEach(function (id) {
      var entry = hosts[id] || { name: id, state: 'pending', log: [] };
      if (entry.state === 'ok' || entry.state === 'failed' ||
          entry.state === 'partial') finished++;
      if (!jobTab || !hosts[jobTab]) jobTab = id;
      var mark = { ok: '✓', partial: '!', failed: '✕',
                   running: '…', pending: '·' }[entry.state] || '·';
      var tab = h('button', {
        class: 'job-tab ' + entry.state + (id === jobTab ? ' active' : ''),
        text: mark + ' ' + (entry.name || id),
        onclick: function () { jobTab = id; pollJob(); }
      });
      tabs.appendChild(tab);
    });

    /* "partial" is its own outcome: apt finished cleanly but left packages
       that need a removal to install. Folding it into "ok" is what made a run
       look successful while the card kept its update count. */
    var failed = ids.filter(function (id) {
      var st = (hosts[id] || {}).state;
      return st === 'failed' || st === 'partial';
    });
    var status = (done ? 'готово' : 'идёт параллельно: ' + (ids.length - finished) + ' из ' + ids.length) +
      ' · завершено ' + finished + '/' + ids.length +
      (job.current ? ' · последним: ' + ((hosts[job.current] || {}).name || job.current) : '');
    var statusEl = document.getElementById('job-status');
    statusEl.innerHTML = '';
    statusEl.appendChild(document.createTextNode(status));
    failed.forEach(function (id) {
      var entry = hosts[id];
      statusEl.appendChild(h('div', {
        class: entry.state === 'partial' ? 'job-partial' : 'job-fail',
        text: (entry.state === 'partial' ? '! ' : '✕ ') + entry.name + ': ' +
              (entry.reason || 'подробности в логе') }));
    });

    var out = document.getElementById('job-output');
    var atBottom = out.scrollTop + out.clientHeight >= out.scrollHeight - 30;
    var lines = (hosts[jobTab] || {}).log || job.log || [];
    renderLog(out, lines);
    if (atBottom) out.scrollTop = out.scrollHeight;

    if (done && jobTimer) {
      clearInterval(jobTimer);
      jobTimer = null;
      // The hub re-polls each target as its step finishes, so the snapshot is
      // already current — just re-read it instead of triggering a full sweep.
      load();
    }
  }).catch(function () { /* keep polling */ });
}


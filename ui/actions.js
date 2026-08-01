/* Everything that changes something: suppressions, updates, reboots,
   service actions, and the job log they all report into. */

/* ---------- suppressions ---------- */

function suppressIssue(host, issue) {
  suppressKey(host, issue.key, '«' + issue.text + '»');
}

/* Accepting a finding must not require catching it in the act. Air occupancy
   and retransmissions come and go with the evening, and the moment somebody
   decides "this is fine here" is rarely the moment the chip is on screen — so
   a check can be accepted by its key, firing or not. */
function suppressKey(host, key, what) {
  var reason = prompt(
    'Исключить проверку для ' + host.name + ':\n' + what + '\n\n' +
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
    body: JSON.stringify({ host: host.id, key: key, reason: reason.trim(),
                           days: days.trim() ? parseInt(days, 10) : null })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    document.getElementById('modal').classList.add('hidden');
    load();
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}

/* One click, no prompt, no record to review: the finding is read and goes
   quiet until the fact behind it changes. Anything worth explaining in writing
   is a suppression instead. */
function ackIssue(host, issue) {
  fetch('/api/ack', {
    method: 'POST', headers: actionHeaders(),
    body: JSON.stringify({ host: host.id, key: issue.key })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    load();
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}

function unack(id) {
  fetch('/api/ack/remove', {
    method: 'POST', headers: actionHeaders(), body: JSON.stringify({ id: id })
  }).then(function (r) { return r.json(); }).then(function () { load(); })
    .catch(function (e) { alert('Ошибка запроса: ' + e); });
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

  /* Stale means "has had nothing to hide for a fortnight", not "is quiet right
     now": a finding that fires for twenty minutes a day would otherwise be
     offered for removal for the remaining twenty-three hours. */
  var stale = list.filter(function (s) {
    return !s.still_firing && (s.quiet_days === null || s.quiet_days >= 14);
  }).length;
  root.appendChild(h('p', { class: 'checks-intro', text:
    'Проверки продолжают выполняться; исключение лишь снимает влияние на статус и алерты.' +
    (stale ? ' У ' + stale + ' исключений проблема не воспроизводилась две недели — их можно снять.' : '') }));

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
          h('span', { text: s.still_firing ? 'скрывает проблему'
            : s.quiet_days === null ? 'пока не срабатывало'
            : s.quiet_days < 14 ? 'срабатывало ' + (s.quiet_days < 1
                ? Math.round(s.quiet_days * 24) + ' ч назад'
                : Math.round(s.quiet_days) + ' сут назад')
            : 'проблемы больше нет' })
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


/* ---------- settings ---------- */

/* Thresholds are decisions, and decisions get revised while looking at the
   dashboard — not while editing a file over ssh. Only the values that were
   actually changed are stored, so a later change to a default still applies to
   everything nobody has overridden. */
function showSettings() {
  document.getElementById('modal-title').textContent = 'Настройки';
  var root = document.getElementById('modal-body');
  root.innerHTML = '';
  root.appendChild(h('p', { class: 'checks-intro', text: 'Загружаю…' }));
  document.getElementById('modal').classList.remove('hidden');

  fetch('/api/settings').then(function (r) { return r.json(); }).then(function (cfg) {
    root.innerHTML = '';
    var inputs = {};

    root.appendChild(h('p', { class: 'checks-intro', text:
      'Пороги применяются ко всем хостам. У некоторых ролей значения свои: NAS с ' +
      'видеоархивом заполнен под завязку по назначению, а не от беды. Такие ' +
      'исключения перечислены ниже.' }));

    var groups = [];
    cfg.fields.forEach(function (f) {
      if (groups.indexOf(f.group) < 0) groups.push(f.group);
    });
    groups.forEach(function (group) {
      var rows = cfg.fields.filter(function (f) { return f.group === group; })
        .map(function (f) {
          var overridden = cfg.overridden.indexOf(f.key) >= 0;
          var input = h('input', {
            class: 'set-input', type: 'number', value: cfg.values[f.key],
            min: f.min, max: f.max
          });
          inputs[f.key] = input;
          return h('tr', null, [
            h('td', null, [
              h('div', { text: f.label }),
              f.hint ? h('div', { class: 'set-hint', text: f.hint }) : null
            ]),
            h('td', { class: 'right nowrap' }, [
              input,
              h('span', { class: 'set-unit', text: f.unit || '' })
            ]),
            h('td', { class: 'right nowrap' }, [
              // The default is shown, not hidden behind a reset button: the
              // useful question is "what would this be if I left it alone".
              h('span', { class: 'set-default' + (overridden ? ' changed' : ''),
                          text: 'по умолчанию ' + cfg.defaults[f.key] }),
              overridden ? h('button', {
                class: 'btn btn-sm', text: '↺', title: 'вернуть значение по умолчанию',
                onclick: function () { input.value = cfg.defaults[f.key]; }
              }) : null
            ])
          ]);
        });
      root.appendChild(section(group, table(['проверка', 'значение', ''], rows)));
    });

    var roles = Object.keys(cfg.by_role || {});
    if (roles.length) {
      root.appendChild(section('Свои пороги по ролям',
        table(['роль', 'что переопределено'], roles.map(function (role) {
          var over = cfg.by_role[role];
          return h('tr', null, [
            h('td', { text: ROLE_NAME[role] || role }),
            h('td', { class: 'mono', text: Object.keys(over).map(function (k) {
              return k + ' = ' + over[k];
            }).join(', ') })
          ]);
        }))));
    }

    /* No vendor feed to check, so the newest published build is written down
       here — and the dashboard says "есть новее" only when this says so. */
    var fwInputs = {};
    if ((cfg.models || []).length) {
      root.appendChild(section('Свежие прошивки камер',
        table(['модель', 'версия', 'сборка (ггммдд)', 'ссылка'],
          cfg.models.map(function (model) {
            var known = (cfg.firmware || {})[model] || {};
            var version = h('input', { class: 'set-input set-wide', type: 'text',
                                       value: known.version || '', placeholder: 'V5.7.210' });
            var built = h('input', { class: 'set-input', type: 'text',
                                     value: known.built || '', placeholder: '260402' });
            var url = h('input', { class: 'set-input set-wide', type: 'text',
                                   value: known.url || '', placeholder: 'откуда скачать' });
            fwInputs[model] = { version: version, built: built, url: url };
            return h('tr', null, [
              h('td', { class: 'mono', text: model }),
              h('td', null, [version]),
              h('td', null, [built]),
              h('td', null, [url])
            ]);
          }))));
      root.appendChild(h('p', { class: 'set-hint', text:
        'Пусто — значит новее неизвестна, и дашборд промолчит. Возраст сборки ' +
        'сам по себе не повод ругаться: у камеры, которую производитель больше ' +
        'не обновляет, четырёхлетняя прошивка и есть последняя.' }));
    }

    /* One silence threshold cannot fit every camera: a street camera quiet
       for six hours is broken, a garage quiet for two days is a garage nobody
       entered. Empty means "follow the fleet-wide value above". */
    var camInputs = {};
    if ((cfg.cameras || []).length) {
      root.appendChild(section('Тишина детекции по камерам',
        table(['камера', 'сейчас без событий', 'предупреждение, ч', 'проблема, ч'],
          cfg.cameras.map(function (cam) {
            var warnInput = h('input', { class: 'set-input', type: 'number', min: 1, max: 336,
              value: cam.limits && cam.limits.warn !== undefined ? cam.limits.warn : '',
              placeholder: String(cfg.values.camera_quiet_warn_hours) });
            var badInput = h('input', { class: 'set-input', type: 'number', min: 1, max: 336,
              value: cam.limits && cam.limits.bad !== undefined ? cam.limits.bad : '',
              placeholder: String(cfg.values.camera_quiet_bad_hours) });
            camInputs[cam.key] = { warn: warnInput, bad: badInput };
            var quiet = cam.quiet_hours;
            return h('tr', null, [
              h('td', null, [h('div', { text: cam.name }),
                             h('div', { class: 'set-hint', text: cam.host })]),
              h('td', { class: 'mono right',
                        text: quiet === null || quiet === undefined ? '' : Math.round(quiet) + ' ч' }),
              h('td', { class: 'right' }, [warnInput]),
              h('td', { class: 'right' }, [badInput])
            ]);
          }))));
    }

    /* Rebooting on its own is the one setting here that acts rather than
       measures, so it says exactly what it will do and when. */
    var auto = cfg.auto_reboot || {};
    var enabled = h('input', { type: 'checkbox' });
    enabled.checked = !!auto.enabled;
    var fromHour = h('input', { class: 'set-input', type: 'number', min: 0, max: 23,
                                value: auto.from_hour });
    var toHour = h('input', { class: 'set-input', type: 'number', min: 0, max: 23,
                              value: auto.to_hour });
    var excludeBoxes = {};
    var excludeList = h('div', { class: 'set-exclude' },
      (cfg.hosts || []).map(function (host) {
        var box = h('input', { type: 'checkbox' });
        box.checked = (auto.exclude || []).indexOf(host.id) >= 0;
        excludeBoxes[host.id] = box;
        return h('label', { class: 'set-check' }, [box, h('span', { text: host.name })]);
      }));

    var cleanup = h('input', { type: 'checkbox' });
    cleanup.checked = !(cfg.auto_cleanup && cfg.auto_cleanup.enabled === false);
    root.appendChild(section('Чистка ненужных пакетов', h('div', { class: 'set-block' }, [
      h('label', { class: 'set-check' }, [cleanup,
        h('span', { text: 'убирать пакеты, которые больше никому не нужны (apt autoremove)' })]),
      h('p', { class: 'set-hint', text:
        'Выполняется вместе с обновлением пакетов, а не отдельно: чистка — это ' +
        'следствие обновления. apt сохраняет работающее ядро и всё, от чего ' +
        'что-то зависит, поэтому в отличие от перезагрузки это безопасно и ' +
        'включено по умолчанию.' })
    ])));

    root.appendChild(section('Автоматическая перезагрузка', h('div', { class: 'set-block' }, [
      h('label', { class: 'set-check' }, [enabled,
        h('span', { text: 'перезагружать хост, когда он сам просит перезагрузку' })]),
      h('p', { class: 'set-hint', text:
        'Только те хосты, которые сами сообщают о необходимости перезагрузки (после ' +
        'обновления ядра), и только в указанные часы. Один хост за цикл, не чаще раза ' +
        'в сутки, и никогда — хост с самим дашбордом: он бы оборвал собственный отчёт. ' +
        'Перед каждой перезагрузкой уходит сообщение в Telegram.' }),
      h('div', { class: 'set-row' }, [
        h('span', { text: 'окно, часы:' }), fromHour, h('span', { text: '—' }), toHour
      ]),
      h('div', { class: 'set-row' }, [h('span', { text: 'никогда не перезагружать:' })]),
      excludeList
    ])));

    var status = h('span', { class: 'set-status' });
    root.appendChild(h('div', { class: 'set-actions' }, [
      h('button', { class: 'btn btn-primary', text: 'Сохранить', onclick: function () {
        var thresholds = {};
        Object.keys(inputs).forEach(function (key) {
          thresholds[key] = inputs[key].value === '' ? null : Number(inputs[key].value);
        });
        var exclude = Object.keys(excludeBoxes).filter(function (id) {
          return excludeBoxes[id].checked;
        });
        status.textContent = 'сохраняю…';
        fetch('/api/settings', {
          method: 'POST', headers: actionHeaders(),
          body: JSON.stringify({
            thresholds: thresholds,
            firmware: Object.keys(fwInputs).reduce(function (acc, model) {
              acc[model] = {
                version: fwInputs[model].version.value.trim(),
                built: fwInputs[model].built.value.trim(),
                url: fwInputs[model].url.value.trim()
              };
              return acc;
            }, {}),
            cameras: Object.keys(camInputs).reduce(function (acc, key) {
              acc[key] = {
                warn: camInputs[key].warn.value === '' ? null : Number(camInputs[key].warn.value),
                bad: camInputs[key].bad.value === '' ? null : Number(camInputs[key].bad.value)
              };
              return acc;
            }, {}),
            auto_cleanup: { enabled: cleanup.checked },
            auto_reboot: { enabled: enabled.checked, from_hour: Number(fromHour.value),
                           to_hour: Number(toHour.value), exclude: exclude }
          })
        }).then(function (r) { return r.json(); }).then(function (res) {
          if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
          status.textContent = 'сохранено — пороги применены к текущему снимку';
          load();
        }).catch(function (e) { alert('Ошибка запроса: ' + e); });
      } }),
      status
    ]));
  }).catch(function (e) {
    root.innerHTML = '';
    root.appendChild(h('p', { class: 'checks-intro', text: 'не удалось загрузить настройки: ' + e }));
  });
}

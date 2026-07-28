/* The detail view: facts, tables, sparklines and the checks tab. */

/* ---------- host detail ---------- */

/* Wrapped so a wide table (mount points, SMART attributes) scrolls inside its
   own box instead of widening the page — on a phone that used to push the last
   columns past the right edge with no way to reach them. */
function table(headers, rows) {
  return h('div', { class: 'table-wrap' }, [
    h('table', { class: 'list' }, [
      h('thead', null, [h('tr', null, headers.map(function (t) { return h('th', { text: t }); }))]),
      h('tbody', null, rows)
    ])
  ]);
}

function section(title, node) {
  return node ? h('div', { class: 'section' }, [h('h3', { text: title }), node]) : null;
}

/* The detail view has two tabs: what the host looks like now, and what is
   being checked on it at all. The second answers the question a findings-only
   dashboard leaves open — "is this fine, or simply not watched?" */
function showHost(host) {
  document.getElementById('modal-title').textContent = host.name + ' · ' + host.addr;
  var root = document.getElementById('modal-body');
  root.innerHTML = '';

  var body = h('div', { class: 'tab-page' }, []);
  var checksPage = h('div', { class: 'tab-page hidden' }, []);
  renderChecks(host, checksPage);

  var tabState = h('button', { class: 'tab active', text: 'Состояние' });
  var checksCount = (host.checks || []).filter(function (c) { return c.status !== 'n/a'; }).length;
  var tabChecks = h('button', { class: 'tab', text: 'Проверки (' + checksCount + ')' });
  tabState.addEventListener('click', function () {
    tabState.classList.add('active'); tabChecks.classList.remove('active');
    body.classList.remove('hidden'); checksPage.classList.add('hidden');
  });
  tabChecks.addEventListener('click', function () {
    tabChecks.classList.add('active'); tabState.classList.remove('active');
    checksPage.classList.remove('hidden'); body.classList.add('hidden');
  });

  root.appendChild(h('div', { class: 'tabs' }, [tabState, tabChecks]));
  root.appendChild(body);
  root.appendChild(checksPage);

  var facts = [];
  function fact(label, value) {
    if (value === undefined || value === null || value === '') return;
    facts.push(h('dt', { text: label }), h('dd', { text: String(value) }));
  }
  fact('состояние', host.reachable ? 'на связи' : 'не отвечает: ' + (host.error || '—'));
  fact('система', host.os_name);
  fact('модель', host.model);
  fact('ядро', host.kernel);
  fact('процессор', host.cpu_model);
  fact('аптайм', host.uptime ? duration(host.uptime) : null);
  fact('нагрузка', host.load1 !== undefined ? host.load1 + ' / ' + host.load5 + ' / ' + host.load15 : null);
  fact('память', host.mem_total ? bytes(host.mem_used) + ' из ' + bytes(host.mem_total) + ' (' + host.mem_pct + '%)' : null);
  fact('swap', host.swap_total ? bytes(host.swap_used) + ' из ' + bytes(host.swap_total) + ' (' + host.swap_pct + '%)' : null);
  fact('ping', host.rtt_ms !== null && host.rtt_ms !== undefined ? host.rtt_ms + ' мс' : null);
  fact('опрос', (host.probe_ms || 0) + ' мс');
  if (host.agent === 'meshtastic') {
    fact('эфир', host.channel_utilization + '% (tx ' + host.tx_utilization + '%)');
    fact('перезагрузок', host.reboot_counter);
    fact('wifi RSSI', host.wifi_rssi + ' дБм');
    fact('частота', host.frequency + ' МГц');
    fact('питание', host.battery_percent !== undefined ? host.battery_percent + '%' : host.power_source);
  }
  if (host.firmware_latest) fact('доступна прошивка', host.firmware_latest);
  if (host.zm_events_count) {
    fact('событий ZoneMinder', host.zm_events_count + ' (' + bytes(host.zm_events_bytes) + ')');
    fact('последнее событие', ago(host.zm_last_event));
  }
  // Everything summarised on the card is explained here; a chip with no
  // expansion leaves the reader guessing what it counted.
  if ((host.roles || []).length > 1) {
    fact('роли', host.roles.map(function (r) { return ROLE_NAME[r] || r; }).join(' + '));
  }
  if (host.power_recovery !== null && host.power_recovery !== undefined) {
    fact('автостарт после сбоя питания', host.power_recovery ? 'включён' : 'ВЫКЛЮЧЕН');
  }
  // Only where there is actually a radio: a speaker reporting "0 Wi-Fi
  // clients" is noise, not information.
  if ((host.radios || host.radioiws || []).length) {
    fact('клиентов Wi-Fi', host.wifi_clients);
  }
  if (host.unifi_state !== undefined) {
    fact('в контроллере', host.unifi_state === 2 ? 'управляется' : 'не управляется (' + host.unifi_state + ')');
  }
  fact('зона', host.zone);
  if (host.os_name && host.role === 'camera') {
    fact('прошивка', host.os_name +
         (host.firmware_age_days ? ' — сборке ' + host.firmware_age_days + ' сут' : '') +
         '; версию прочитал ' + (host.firmware_source || 'рекордер') +
         ', у него есть учётные данные камеры');
    var known = host.firmware_known;
    if (known && known.version) {
      fact('доступна версия', known.version +
           (known.built ? ', сборка ' + known.built : '') +
           (host.firmware_outdated ? ' — новее установленной' : ' — та же, что стоит'));
      if (known.url) {
        fact('где взять', known.url);
      }
    } else {
      fact('новее не известна',
           'производитель не публикует машиночитаемый список версий; ' +
           'известную свежую сборку можно вписать в настройках');
    }
  }
  if (host.link) {
    fact('подключение', host.link === 'ethernet' ? 'кабелем'
         : 'по Wi-Fi' + (host.wifi_band ? ', ' + host.wifi_band + ' ГГц' : '') +
           (host.wifi_channel ? ', канал ' + host.wifi_channel : '') +
           (host.wifi_freq ? ' (' + host.wifi_freq + ' МГц)' : ''));
  }
  (host.wifi_crowded_by || []).forEach(function (c) {
    fact('канал занят', c.ap + ' вещает на канале ' + c.channel + ' и занимает ' +
                        c.airtime + '% эфира — это тот же участок диапазона');
  });
  if (host.volume !== undefined) {
    fact('громкость', host.volume + '%' + (host.muted ? ' — звук заглушен' : ''));
  }
  if (host.group) fact('группа', host.group.join(' + '));
  if (host.track) fact('сейчас играет', host.track);
  if (host.behind_extender) fact('через репитер', 'колонка подключена не напрямую к точке');
  fact('воспроизведение', host.playback === 'PLAYING' ? 'играет'
       : host.playback === 'STOPPED' ? 'ничего не играет — колонка на связи и свободна'
       : host.playback === 'PAUSED_PLAYBACK' ? 'на паузе'
       : host.playback === 'TRANSITIONING' ? 'переключает дорожку'
       : host.playback);
  fact('версия железа', host.hardware);
  fact('серийный номер', host.serial);
  if (host.recorded_by) {
    fact('пишет', host.recorded_by +
      (host.camera_fps ? ', ' + Number(host.camera_fps).toFixed(1) + ' к/с' : ''));
    fact('статус записи', host.camera_status);
    if (host.only_via_recorder) {
      fact('видимость', 'из сети дашборда недоступна — статус берётся у рекордера');
    }
  }
  if ((host.backs_up_to || []).length) fact('бэкапится на', host.backs_up_to.join(', '));
  if ((host.receives_from || []).length) fact('принимает бэкапы от', host.receives_from.join(', '));
  if (host.note) fact('заметка', host.note);
  body.appendChild(section('Общее', h('dl', { class: 'kv' }, facts)));

  if (host.reachable) {
    body.appendChild(section('Действия', h('div', { class: 'card-foot' }, [
      host.updatable && host.agent === 'linux' ? h('button', {
        class: 'btn btn-sm btn-warn', text: 'обновить пакеты',
        onclick: function () { startUpdate([host.id]); }
      }) : null,
      h('button', {
        class: 'btn btn-sm', text: 'перезагрузить хост',
        onclick: function () { rebootHost(host); }
      })
    ])));
  }

  var issues = hostIssues(host).filter(function (i) { return i.level !== 'ok'; });
  if (issues.length) {
    body.appendChild(section('Замечания', table(['', 'что', 'решение'],
      issues.map(function (i) {
        return h('tr', null, [
          h('td', null, [h('span', { class: 'dot ' + (i.suppressed ? '' : i.level) })]),
          h('td', null, [
            h('div', { text: i.text }),
            i.suppressed ? h('div', { class: 'check-rule',
              text: 'исключено: ' + i.suppress_reason }) : null
          ]),
          h('td', { class: 'right' }, [
            i.suppressed
              ? h('button', { class: 'btn btn-sm', text: 'вернуть',
                  onclick: function () { unsuppress(host.id + '/' + i.key); } })
              : h('button', { class: 'btn btn-sm', text: 'исключить',
                  title: 'принять как известное — с причиной',
                  onclick: function () { suppressIssue(host, i); } })
          ])
        ]);
      }))));
  }

  if ((host.disks || []).length) {
    body.appendChild(section('Диски', table(['точка', 'устройство', 'занято', 'всего', '%'],
      host.disks.map(function (d) {
        return h('tr', null, [
          h('td', { text: d.mount }),
          h('td', { class: 'mono', text: d.fs }),
          h('td', { class: 'mono', text: bytes(d.used) }),
          h('td', { class: 'mono', text: bytes(d.total) }),
          h('td', { class: 'mono right ' + diskClass(d.pct, host), text: d.pct + '%' })
        ]);
      }))));
  }

  if (host.reachable) {
    var trends = h('div', { class: 'trends' }, []);
    body.appendChild(section('Динамика за 2 недели', trends));
    loadHistory(host, trends);
  }

  var allRadios = (host.radios || []).concat(host.radioiws || []);
  if (allRadios.length) {
    body.appendChild(section('Радио (' + (host.wifi_clients || 0) + ' клиентов)',
      table(['радио', 'канал', 'клиентов', 'эфир: всего', 'свой', 'чужой', 'повторы', 'качество'],
        allRadios.map(function (r) {
          var dead = !r.disabled && (r.channel === 0 || r.freq === 0);
          var band = r.band ? r.band + ' ГГц' : (r.name || r.dev || '');
          var warnAir = r.band === '2.4' ? 40 : 60;
          var warnRetry = r.band === '2.4' ? 35 : 45;
          return h('tr', null, [
            h('td', null, [h('span', { class: 'dot ' + (dead ? 'bad' : r.disabled ? '' : 'ok') }),
                           h('span', { text: band + (r.ssid ? ' · ' + r.ssid : '') })]),
            h('td', { class: 'mono right' + (r.overlaps_with ? ' warn' : ''),
                      title: r.overlaps_with ? 'перекрывается с ' + r.overlaps_with.join(', ') : '',
                      text: (r.channel === null || r.channel === undefined ? '' : String(r.channel)) +
                            (r.overlaps_with ? ' ⚠' : '') }),
            h('td', { class: 'mono right', text: r.clients === undefined ? '' : String(r.clients) }),
            h('td', { class: 'mono right' + (r.utilization >= warnAir ? ' warn' : ''),
                      text: r.utilization === undefined || r.utilization === null ? '' : r.utilization + '%' }),
            h('td', { class: 'mono right', text: r.own_utilization === undefined ? '' : r.own_utilization + '%' }),
            // Foreign airtime is the number that decides whether changing
            // channel would help: our own load moves with us, theirs does not.
            h('td', { class: 'mono right', text: r.foreign_utilization === undefined || r.foreign_utilization === null ? '' : r.foreign_utilization + '%' }),
            /* Retries answer a question airtime cannot: the channel can read
               half empty while our own frames keep going out twice. */
            h('td', { class: 'mono right' + (r.retries >= warnRetry ? ' warn' : ''),
                      text: r.retries === undefined || r.retries === null ? '' : r.retries + '%' }),
            h('td', { class: 'mono right', text: r.satisfaction === undefined || r.satisfaction === null ? '' : r.satisfaction + '%' })
          ]);
        }))));
  }

  /* Every chip on the card is explained here. The SSID chips say "ferretclub
     2.4: 60%"; this is where that 60% is broken down — which band it is on,
     how many clients see it, and what signal they average. */
  if ((host.ssids || []).length) {
    body.appendChild(section('Сети Wi-Fi (SSID)',
      table(['сеть', 'диапазон', 'канал', 'клиентов', 'сигнал', 'качество'],
        host.ssids.map(function (net) {
          var sat = net.satisfaction;
          var poor = typeof sat === 'number' && sat > 0 && sat < 80;
          return h('tr', null, [
            h('td', null, [h('span', { class: 'dot ' + (net.up ? 'ok' : 'bad') }),
                           h('span', { text: net.essid + (net.guest ? ' (гостевая)' : '') })]),
            h('td', { class: 'mono right', text: net.band + ' ГГц' }),
            h('td', { class: 'mono right', text: net.channel === null || net.channel === undefined ? '' : String(net.channel) }),
            h('td', { class: 'mono right', text: String(net.clients || 0) }),
            // Average client signal: -60 dBm is comfortable, -75 is the edge.
            h('td', { class: 'mono right' + (net.signal && net.signal < -72 ? ' warn' : ''),
                      text: net.signal ? net.signal + ' dBm' : '' }),
            h('td', { class: 'mono right' + (poor ? ' warn' : ''),
                      text: typeof sat === 'number' && sat > 0 ? sat + '%' : '' })
          ]);
        }))));
  }

  /* Forwards and tunnels: the configuration that stops working without
     saying so. The verdict column is the point of the table. */
  if ((host.orphans || []).length) {
    body.appendChild(section('Ненужные пакеты (' + host.orphans.length + ')',
      h('div', { class: 'scroll-y' }, [table(['пакет'],
        host.orphans.map(function (o) {
          return h('tr', null, [h('td', { class: 'mono', text: o.pkg })]);
        }))])));
  }

  if ((host.forwards || []).length) {
    var VERDICT = {
      'ok': ['есть кому ответить', 'ok'],
      'no-listener': ['ведёт в никуда', 'bad'],
      'host-down': ['хост не отвечает', 'bad'],
      'disabled': ['выключено', ''],
      'unknown': ['цель вне парка', '']
    };
    body.appendChild(section('Пробросы портов',
      table(['правило', 'снаружи', 'куда', 'состояние', 'прошло байт'],
        host.forwards.map(function (rule) {
          var verdict = VERDICT[rule.verdict] || VERDICT.unknown;
          return h('tr', null, [
            h('td', { text: rule.comment || rule.action }),
            h('td', { class: 'mono right', text: rule.port || '' }),
            h('td', { class: 'mono', text: (rule.to || 'сам роутер') +
                      (rule.to_port ? ':' + rule.to_port : '') }),
            h('td', { class: verdict[1] === 'bad' ? 'warn' : '', text: verdict[0] }),
            // Zero bytes on a live rule is not a fault by itself — a forward
            // for a service used twice a year is legitimately idle — but next
            // to "ведёт в никуда" it is the confirmation.
            h('td', { class: 'mono right', text: bytes(rule.bytes || 0) })
          ]);
        }))));
  }

  if ((host.ipsec || []).length) {
    body.appendChild(section('Туннели IPsec',
      table(['откуда', 'куда', 'состояние'],
        host.ipsec.map(function (policy) {
          var up = policy.state === 'established';
          return h('tr', null, [
            h('td', null, [h('span', { class: 'dot ' + (policy.disabled ? '' : up ? 'ok' : 'bad') }),
                           h('span', { class: 'mono', text: policy.src })]),
            h('td', { class: 'mono', text: policy.dst }),
            h('td', { class: !policy.disabled && !up ? 'warn' : '',
                      text: policy.disabled ? 'выключен'
                            : (policy.state || 'не поднят') })
          ]);
        }))));
  }

  if ((host.smarts || []).length) {
    body.appendChild(section('Здоровье дисков', table(
      ['', 'устройство', 'модель', 'темп.', 'наработка', 'износ', 'realloc/pending'],
      host.smarts.map(function (d) {
        return h('tr', null, [
          h('td', null, [h('span', { class: 'dot ' + (d.failing ? 'bad' : 'ok') })]),
          h('td', { class: 'mono', text: d.dev }),
          h('td', { text: d.model || '' }),
          h('td', { class: 'mono right', text: d.temp ? d.temp + ' °C' : '' }),
          h('td', { class: 'mono right', text: d.hours ? Math.round(d.hours / 24) + ' сут' : '' }),
          h('td', { class: 'mono right', text: (d.wear || d.wear === 0) ? d.wear + '%' : '' }),
          h('td', { class: 'mono right', text: (d.realloc || 0) + ' / ' + (d.pending || 0) })
        ]);
      }))));
  }

  if ((host.raid || []).length) {
    body.appendChild(section('RAID', table(['массив', 'уровень', 'состояние'],
      host.raid.map(function (r) {
        var bad = r.state.indexOf('_') >= 0;
        return h('tr', null, [
          h('td', { class: 'mono', text: r.dev }),
          h('td', { text: r.level }),
          h('td', null, [h('span', { class: 'dot ' + (bad ? 'bad' : 'ok') }), h('span', { text: r.state })])
        ]);
      }))));
  }

  /* Two groups, because they answer different questions. "Did my service
     break" is what the operator opens this view for; "is systemd-udevd
     running" is background noise until it is not, so it stays available but
     out of the way — and off the card entirely. */
  function serviceRows(list) {
    // Removal only makes sense where we manage units: systemd and OpenWrt init.
    var removable = host.agent === 'linux' || host.agent === 'openwrt';
    return list.map(function (s) {
      var failed = (s.state || '').indexOf('failed') >= 0;
      var running = (s.state || '').indexOf('running') >= 0 || s.state === 'active/exited';
      return h('tr', null, [
        h('td', null, [h('span', { class: 'dot ' + (failed ? 'bad' : running ? 'ok' : '') })]),
        h('td', { text: s.name.replace(/\.service$/, ''), title: s.desc || '' }),
        h('td', { class: 'mono', text: s.state }),
        h('td', { class: 'mono', text: s.version || '' }),
        h('td', { class: 'right nowrap' }, [
          // Restart first: a crashed service usually needs starting again,
          // not removing. Removal stays available but is not the default.
          removable ? h('button', {
            class: 'btn btn-sm', text: '↻', title: 'перезапустить сервис',
            onclick: function (e) { e.stopPropagation(); serviceAction(host, s, 'restart'); }
          }) : null,
          removable && !isProtected(s.name) ? h('button', {
            class: 'btn btn-sm btn-danger', text: '✕', title: 'удалить сервис с хоста',
            onclick: function (e) { e.stopPropagation(); removeService(host, s); }
          }) : null
        ])
      ]);
    });
  }

  var byName = function (a, b) {
    var af = (a.state || '').indexOf('failed') >= 0 ? 0 : 1;
    var bf = (b.state || '').indexOf('failed') >= 0 ? 0 : 1;
    return af - bf || a.name.localeCompare(b.name);
  };
  var allServices = (host.services || []).slice().sort(byName);
  var ownServices = allServices.filter(function (s) { return s.scope !== 'system'; });
  var sysServices = allServices.filter(function (s) { return s.scope === 'system'; });

  if (ownServices.length) {
    body.appendChild(section('Сервисы (' + ownServices.length + ')',
      h('div', { class: 'scroll-y' }, [table(['', 'сервис', 'состояние', 'версия', ''],
        serviceRows(ownServices))])));
  }
  if (sysServices.length) {
    // Collapsed: present when needed, silent otherwise. A failed one is the
    // exception — it opens by itself, since that is the case worth seeing.
    var brokenSys = sysServices.some(function (s) {
      return (s.state || '').indexOf('failed') >= 0;
    });
    var details = h('details', { class: 'sys-services' }, [
      h('summary', { text: 'Системные сервисы (' + sysServices.length + ')' +
                           (brokenSys ? ' — есть упавшие' : '') }),
      h('div', { class: 'scroll-y' }, [table(['', 'сервис', 'состояние', 'версия', ''],
        serviceRows(sysServices))])
    ]);
    if (brokenSys) details.open = true;
    body.appendChild(h('div', { class: 'section' }, [details]));
  }

  if ((host.timers || []).length) {
    body.appendChild(section('Таймеры', table(['таймер', 'состояние'],
      host.timers.map(function (t) {
        return h('tr', null, [
          h('td', { text: t.name.replace(/\.timer$/, ''), title: t.desc || '' }),
          h('td', { class: 'mono', text: t.state })
        ]);
      }))));
  }

  if ((host.containers || []).length) {
    body.appendChild(section('Контейнеры', table(['имя', 'образ', 'состояние'],
      host.containers.map(function (c) {
        return h('tr', null, [
          h('td', null, [h('span', { class: 'dot ' + (c.state === 'running' ? 'ok' : 'bad') }), h('span', { text: c.name })]),
          h('td', { class: 'mono', text: c.image }),
          h('td', { class: 'mono', text: c.status })
        ]);
      }))));
  }

  if ((host.cameras || []).length) {
    body.appendChild(section('Камеры', table(
      ['камера', 'адрес', 'состояние', 'fps', 'событий/сут', 'молчит', 'архив'],
      host.cameras.map(function (c) {
        var live = c.status === 'Connected' || c.status === 'recording';
        var quiet = c.quiet_hours;
        return h('tr', null, [
          h('td', null, [h('span', { class: 'dot ' + (live ? 'ok' : 'bad') }), h('span', { text: c.name })]),
          h('td', { class: 'mono', text: c.addr || '' }),
          h('td', { class: 'mono', text: c.status || '' }),
          h('td', { class: 'mono right', text: c.fps ? Number(c.fps).toFixed(1) : '' }),
          h('td', { class: 'mono right', text: c.day_count === undefined ? '' : String(c.day_count) }),
          h('td', { class: 'mono right' + (quiet >= 12 ? ' warn' : ''),
                    text: quiet === undefined || quiet === null ? '' : quiet + ' ч' }),
          h('td', { class: 'mono right', text: c.archive_days ? Math.round(c.archive_days) + ' сут' : '' })
        ]);
      }))));
  }

  if ((host.repos || []).length) {
    body.appendChild(section('Репозитории', table(['путь', 'ветка', 'версия', 'коммит'],
      host.repos.map(function (r) {
        return h('tr', null, [
          h('td', { class: 'mono', text: r.path }),
          h('td', { class: 'mono', text: r.branch }),
          h('td', { class: 'mono', text: r.describe }),
          h('td', { class: 'mono', text: ago(Number(r.committed)) })
        ]);
      }))));
  }

  if ((host.backups || []).length || (host.backuprepos || []).length ||
      (host.receives_from || []).length) {
    var rows = (host.backups || []).map(function (b) {
      return h('tr', null, [
        h('td', { text: b.name || b.task }),
        h('td', { text: '→ ' + (b.dest_name || b.dest || '?') + (b.share ? ' / ' + b.share : '') }),
        h('td', { class: 'mono', text: b.folders || '' })
      ]);
    });
    (host.backuprepos || []).forEach(function (r) {
      var stale = r.age_days !== null && r.age_days > 2;
      rows.push(h('tr', null, [
        h('td', null, [h('span', { class: 'dot ' + (stale ? 'bad' : 'ok') }), h('span', { text: r.name })]),
        h('td', { text: '← принимает' }),
        h('td', { class: 'mono' + (stale ? ' warn' : ''),
                  text: (r.age_days === null ? '' : r.age_days + ' сут назад') +
                        (r.size ? ' · ' + bytes(r.size * 1024) : '') })
      ]));
    });
    body.appendChild(section('Бэкапы', table(['что', 'направление', 'детали'], rows)));
  }

  if ((host.updates || []).length) {
    var upd = host.updates.slice().sort(function (a, b) {
      return (b.security === '1') - (a.security === '1') || a.pkg.localeCompare(b.pkg);
    });
    var head = h('div', { class: 'section' }, [
      h('h3', { text: 'Доступные обновления (' + upd.length + ')' }),
      host.updatable ? h('div', { class: 'card-foot' }, [
        h('button', {
          class: 'btn btn-sm btn-primary', text: 'обновить ' + host.name,
          onclick: function () { startUpdate([host.id]); }
        })
      ]) : null,
      h('div', { class: 'scroll-y' }, [table(['пакет', 'было', 'станет', ''],
        upd.map(function (u) {
          return h('tr', null, [
            h('td', { text: u.pkg }),
            h('td', { class: 'mono', text: u.old }),
            h('td', { class: 'mono', text: u.new }),
            h('td', null, [u.security === '1' ? chip('sec', 'warn') : null])
          ]);
        }))])
    ]);
    body.appendChild(head);
  }

  if ((host.web || []).length) {
    body.appendChild(section('Веб-интерфейсы', h('div', { class: 'chips' },
      host.web.map(function (link) {
        var name = link.title ? ' — ' + link.title : (link.label ? ' — ' + link.label : '');
        var cert = link.cert && link.cert.days_left !== undefined
          ? ' · сертификат ' + Math.round(link.cert.days_left) + ' сут' : '';
        name += cert;
        if (link.local) {
          return h('span', {
            class: 'btn btn-sm btn-local',
            text: '⌂ localhost:' + link.port + name +
                  (link.served_by ? ' — открыт как ' + link.served_by
                                  : ' (только локально)')
          });
        }
        return h('a', {
          class: 'btn btn-sm btn-link', target: '_blank', rel: 'noopener',
          href: webUrl(host, link), text: '⧉ ' + webUrl(host, link) + name
        });
      }))));
  }

  if ((host.external || []).length) {
    body.appendChild(section('Доступность снаружи', table(['что', 'откуда проверено', 'результат'],
      host.external.map(function (c) {
        return h('tr', null, [
          h('td', { text: c.label || ('порт ' + c.port) }),
          h('td', { text: c.from }),
          h('td', null, [h('span', { class: 'dot ' + (c.open ? 'ok' : 'bad') }),
                         h('span', { text: c.open ? 'открыт' : 'недоступен' })])
        ]);
      }))));
  }

  if ((host.endpoints || []).length) {
    body.appendChild(section('Публикует наружу', table(['порт', 'протокол', 'сервис'],
      host.endpoints.map(function (ep) {
        return h('tr', null, [
          h('td', { class: 'mono', text: String(ep.port) }),
          h('td', { class: 'mono', text: ep.proto }),
          h('td', { text: ep.label || ep.process || '' })
        ]);
      }))));
  }

  if ((host.ports || null) && Object.keys(host.ports).length) {
    body.appendChild(section('Порты', h('div', { class: 'chips' },
      Object.keys(host.ports).map(function (p) {
        return chip(p + (host.ports[p] ? ' открыт' : ' закрыт'), host.ports[p] ? 'ok' : 'bad');
      }))));
  }

  document.getElementById('modal').classList.remove('hidden');
}

function renderChecks(host, container) {
  var checks = host.checks || [];
  if (!checks.length) {
    container.appendChild(h('div', { class: 'role-head', text: 'нет данных о проверках' }));
    return;
  }

  var titles = {};
  ((state && state.check_categories) || []).forEach(function (pair) { titles[pair[0]] = pair[1]; });

  var byCategory = {};
  checks.forEach(function (c) { (byCategory[c.category] = byCategory[c.category] || []).push(c); });

  var active = checks.filter(function (c) { return c.status !== 'n/a'; }).length;
  container.appendChild(h('p', { class: 'checks-intro', text:
    'На этом хосте выполняется ' + active + ' из ' + checks.length + ' проверок. ' +
    'Остальные не применимы — под каждой написано почему.' }));

  Object.keys(byCategory).forEach(function (category) {
    var rows = byCategory[category].map(function (c) {
      var mark = { ok: '✓', bad: '✕', warn: '!', info: 'i', muted: '⊘', 'n/a': '—' }[c.status];
      var reasons = (c.suppressed || []).map(function (s) {
        return h('div', { class: 'check-rule muted-reason' }, [
          h('span', { text: 'исключено: ' + s.reason }),
          h('button', {
            class: 'link-btn', text: 'вернуть',
            onclick: function () { unsuppress(host.id + '/' + s.key); }
          })
        ]);
      });
      return h('tr', { class: c.status === 'n/a' ? 'check-na' : '' }, [
        h('td', { class: 'check-mark ' + c.status, text: mark }),
        h('td', null, [h('div', { class: 'check-name', text: c.name }),
                       h('div', { class: 'check-rule', text: c.rule })].concat(reasons)),
        h('td', { class: 'check-detail' + (c.status === 'bad' ? ' bad' : c.status === 'warn' ? ' warn' : ''),
                  text: c.detail || (c.status === 'ok' ? 'в норме' : '') })
      ]);
    });
    container.appendChild(section(titles[category] || category,
      h('table', { class: 'list checks' }, [h('tbody', null, rows)])));
  });
}

/* ---------- history sparklines ---------- */

function sparkline(series, width, height) {
  /* A tiny inline SVG: enough to see "climbing steadily" versus "flat", which
     is the whole point of keeping history. */
  width = width || 150; height = height || 28;
  if (!series || series.length < 2) return null;
  var values = series.map(function (p) { return p[1]; });
  var min = Math.min.apply(null, values), max = Math.max.apply(null, values);
  var span = (max - min) || 1;
  var t0 = series[0][0], t1 = series[series.length - 1][0];
  var tspan = (t1 - t0) || 1;

  var points = series.map(function (p) {
    var x = ((p[0] - t0) / tspan) * (width - 2) + 1;
    var y = height - 1 - ((p[1] - min) / span) * (height - 2);
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');

  var ns = 'http://www.w3.org/2000/svg';
  var svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
  svg.setAttribute('width', width);
  svg.setAttribute('height', height);
  svg.setAttribute('class', 'spark');
  var line = document.createElementNS(ns, 'polyline');
  line.setAttribute('points', points);
  svg.appendChild(line);
  return svg;
}

function trendText(trend, metric) {
  if (!trend) return 'данных пока мало';
  var per = trend.slope_per_day;
  var unit = metric.indexOf('disk') === 0 || metric.indexOf('_pct') > 0 ? '%' :
             metric === 'temp_max' ? '°' : '';
  var dir = Math.abs(per) < 0.01 ? 'ровно'
          : (per > 0 ? '+' : '') + per.toFixed(2) + unit + '/сут';
  if (trend.days_to_full !== undefined) {
    dir += ' · заполнится за ' + Math.round(trend.days_to_full) + ' сут';
  }
  return dir;
}

function loadHistory(host, container) {
  /* Which series are worth showing depends on the host: a router has no
     disks worth trending, a mesh node has no temperature sensor. */
  var wanted = [];
  var disk = biggestDisk(host);
  if (disk) wanted.push({ metric: 'disk:' + disk.mount, label: 'диск ' + disk.mount });
  if ((host.temps || []).length) wanted.push({ metric: 'temp_max', label: 'температура' });
  if (host.mem_pct !== undefined) wanted.push({ metric: 'mem_pct', label: 'память' });
  if (host.update_count) wanted.push({ metric: 'update_count', label: 'обновления' });

  wanted.forEach(function (item) {
    fetch('/api/history/' + encodeURIComponent(host.id) + '/' +
          encodeURIComponent(item.metric) + '?days=14')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var chart = sparkline(data.series);
        var row = h('div', { class: 'trend-row' }, [
          h('span', { class: 'trend-label', text: item.label }),
          chart || h('span', { class: 'trend-empty', text: '—' }),
          h('span', { class: 'trend-value', text: trendText(data.trend, item.metric) })
        ]);
        container.appendChild(row);
      })
      .catch(function () { /* history is optional */ });
  });
}

/* ---------- every web UI in the fleet ---------- */

function showSites() {
  var hosts = (state && state.hosts) || [];
  document.getElementById('modal-title').textContent = 'Веб-интерфейсы парка';
  var body = document.getElementById('modal-body');
  body.innerHTML = '';

  var rows = [];
  hosts.forEach(function (host) {
    (host.web || []).forEach(function (link) {
      var url = webUrl(host, link);
      rows.push(h('tr', null, [
        h('td', null, [
          h('span', { class: 'dot ' + (host.reachable ? 'ok' : 'bad') }),
          h('span', { text: host.name })
        ]),
        h('td', null, [link.local
          ? h('span', { class: 'sitelink local', text: 'localhost:' + link.port })
          : h('a', { class: 'sitelink', href: url, target: '_blank', rel: 'noopener', text: url })]),
        h('td', { text: (link.title || link.label || '') + (link.local ? ' · только локально' : '') })
      ]));
    });
  });

  if (!rows.length) {
    body.appendChild(h('div', { class: 'role-head', text: 'веб-интерфейсов не найдено' }));
  } else {
    body.appendChild(section('Найдено ' + rows.length,
      table(['хост', 'адрес', 'что это'], rows)));
  }
  document.getElementById('modal').classList.remove('hidden');
}

/* ---------- reboot ---------- */

function rebootHost(host) {
  var self = host.local ? '\n\nЭТО ХОСТ САМОГО ДАШБОРДА — страница станет недоступна ' +
                          'до его возвращения.' : '';
  var typed = prompt(
    'Перезагрузить ' + host.name + ' (' + host.addr + ')?' + self +
    '\n\nАлерты по хосту будут молчать, пока он поднимается.' +
    '\n\nДля подтверждения введите имя хоста:');
  if (typed === null) return;
  if (typed.trim() !== host.name) { alert('Имя не совпало — перезагрузка отменена.'); return; }

  fetch('/api/reboot', {
    method: 'POST', headers: actionHeaders(),
    body: JSON.stringify({ host: host.id })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    document.getElementById('modal').classList.add('hidden');
    openJobLog();
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}

/* Firmware upgrades go through the controller too — the AP itself takes no
   orders from us. */
function upgradeAccessPoint(host) {
  if (!confirm('Обновить прошивку ' + host.name + '?\n\n' +
               'Точка перезагрузится, клиенты переподключатся к соседней.')) return;
  fetch('/api/unifi/upgrade', {
    method: 'POST', headers: actionHeaders(),
    body: JSON.stringify({ host: host.id })
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (res.error) { if (!actionFailed(res)) alert('Не вышло: ' + res.error); return; }
    alert('Команда отправлена контроллеру — обновление идёт в фоне.');
  }).catch(function (e) { alert('Ошибка запроса: ' + e); });
}


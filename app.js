/* health-zoo dashboard.
   Reads /api/state (a whole-fleet snapshot) and renders it grouped by subnet.
   The hub does the arithmetic; this file only decides how things look. */

'use strict';

var ROLE_ICON = {
  router: '🛜', server: '🖥️', nas: '💽', camera: '📷', mesh: '📡', other: '📦'
};
var ROLE_ORDER = { router: 0, server: 1, nas: 2, camera: 3, mesh: 4, other: 5 };

/* Thresholds shared by the bars and the card's overall colour.
   Temperatures are tuned for the low-power x86 boxes this watches: a Celeron
   N5105 transcoding video sits in the 80s by design (Tjmax is 105), so warning
   below that would mean a permanently amber dashboard. */
/* `load` is load-average expressed as a percentage of core count (100% = one
   busy core per core), `cpu` is a plain 0-100 utilisation figure. Mixing the
   two is what made an idle 0.04 load render red. */
var WARN = { disk: 90, mem: 90, swap: 60, temp: 88, load: 150, cpu: 85 };
var BAD = { disk: 96, mem: 97, swap: 90, temp: 96, load: 300, cpu: 96 };

/* A NAS recording video is *supposed* to run near-full: the archive grows until
   rotation starts overwriting the oldest footage. Flagging that as a problem
   would mean a permanently amber dashboard, so surveillance volumes only
   complain when they are genuinely out of room. */
var DISK_BY_ROLE = {
  nas:    { warn: 96, bad: 99 },
  router: { warn: 90, bad: 96 }
};

function diskLimits(host) {
  return DISK_BY_ROLE[host.role] || { warn: WARN.disk, bad: BAD.disk };
}

function diskClass(pct, host) {
  var lim = diskLimits(host);
  if (pct >= lim.bad) return 'bad';
  if (pct >= lim.warn) return 'warn';
  return '';
}

var state = null;
var jobTimer = null;

/* ---------- helpers ---------- */

function h(tag, attrs, children) {
  var el = document.createElement(tag);
  if (attrs) Object.keys(attrs).forEach(function (k) {
    if (k === 'class') el.className = attrs[k];
    else if (k === 'text') el.textContent = attrs[k];
    else if (k === 'html') el.innerHTML = attrs[k];
    else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), attrs[k]);
    else if (attrs[k] !== null && attrs[k] !== undefined) el.setAttribute(k, attrs[k]);
  });
  (children || []).forEach(function (c) {
    if (c === null || c === undefined) return;
    el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  });
  return el;
}

function bytes(n) {
  if (!n && n !== 0) return '—';
  var units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'], i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)) + ' ' + units[i];
}

function duration(sec) {
  if (!sec && sec !== 0) return '—';
  sec = Math.floor(sec);
  var d = Math.floor(sec / 86400), hrs = Math.floor((sec % 86400) / 3600),
      m = Math.floor((sec % 3600) / 60);
  if (d > 0) return d + ' д ' + hrs + ' ч';
  if (hrs > 0) return hrs + ' ч ' + m + ' мин';
  return m + ' мин';
}

function ago(ts) {
  if (!ts) return '—';
  return duration(Date.now() / 1000 - ts) + ' назад';
}

function webUrl(host, link) {
  var port = link.port;
  var std = (link.scheme === 'http' && port === 80) || (link.scheme === 'https' && port === 443);
  /* Some consoles live one path down from a distro's placeholder root ("/zm/",
     "/admin/"); the probe records where it actually found the page. */
  return link.scheme + '://' + host.addr + (std ? '' : ':' + port) + (link.path || '');
}

function shortMount(path) {
  /* Deep mount points ("/System/Volumes/Update/SFR/mnt1") would blow the card
     apart; the tail is the identifying part. */
  if (!path || path.length <= 18) return path || '';
  var parts = path.split('/').filter(Boolean);
  return '…/' + parts.slice(-2).join('/');
}

function pctClass(value, kind) {
  if (value >= BAD[kind]) return 'bad';
  if (value >= WARN[kind]) return 'warn';
  return '';
}

/* ---------- per-host severity ---------- */

function hostIssues(host) {
  var issues = [];
  if (!host.reachable) { issues.push({ level: 'bad', text: host.error || 'не отвечает' }); return issues; }

  // Alive on the network but the agent could not run: half-known is not healthy,
  // otherwise a router with no SSH key would sit there looking perfectly fine.
  if (host.error) issues.push({ level: 'warn', text: 'нет доступа: ' + host.error });

  (host.disks || []).forEach(function (d) {
    var cls = diskClass(d.pct, host);
    if (cls) issues.push({ level: cls, text: 'диск ' + d.mount + ' ' + d.pct + '%' });
  });
  if (host.mem_pct >= BAD.mem) issues.push({ level: 'bad', text: 'память ' + host.mem_pct + '%' });
  if (host.swap_pct >= WARN.swap) issues.push({ level: 'warn', text: 'swap ' + host.swap_pct + '%' });

  // Only the hottest sensor: a quad-core reports one reading per core plus a
  // package total, and six identical "82°" chips say nothing extra.
  var hot = hottest(host);
  if (hot && hot.c >= WARN.temp) {
    issues.push({
      level: hot.c >= BAD.temp ? 'bad' : 'warn',
      text: 'нагрев ' + hot.c + '° (' + hot.label + ')'
    });
  }

  (host.services || []).forEach(function (s) {
    var state = s.state || '';
    var name = s.name.replace(/\.service$/, '');
    if (state.indexOf('failed') >= 0) {
      issues.push({ level: 'bad', text: name + ' упал' });
    } else if (host.agent === 'linux' && /^enabled/.test(s.enabled || '') &&
               state.indexOf('running') < 0 && state.indexOf('exited') < 0) {
      // systemd only: OpenWrt's init scripts report a coarse running/stopped
      // where one-shot boot scripts legitimately sit at "stopped" forever.
      // Enabled but not running is "supposed to work and doesn't" — quieter
      // than a crash, but the dashboard used to swallow it entirely.
      issues.push({ level: 'warn', text: name + ' включён, но не запущен' });
    }
  });
  (host.degraded_raid || []).forEach(function (r) {
    issues.push({ level: 'bad', text: 'RAID ' + r.dev + ' ' + r.state });
  });
  (host.failing_disks || []).forEach(function (d) {
    var why = d.health && d.health.toUpperCase() !== 'PASSED' ? 'SMART ' + d.health
      : (d.pending ? d.pending + ' pending-секторов' : d.realloc + ' переназначенных секторов');
    issues.push({ level: 'bad', text: 'диск ' + d.dev + ': ' + why });
  });
  (host.cameras || []).forEach(function (c) {
    if (c.enabled === '1' && c.status && c.status !== 'Connected' && c.status !== 'recording') {
      issues.push({ level: 'bad', text: 'камера ' + c.name + ': ' + c.status });
    }
  });
  if (host.reboot_required) issues.push({ level: 'warn', text: 'нужна перезагрузка' });
  if (host.security_count > 0) {
    issues.push({
      level: 'warn',
      text: host.security_count + ' ' +
        plural(host.security_count, 'security-обновление', 'security-обновления', 'security-обновлений')
    });
  }
  return issues;
}

function hostLevel(host) {
  var issues = hostIssues(host);
  if (!host.reachable) return 'off';
  if (issues.some(function (i) { return i.level === 'bad'; })) return 'bad';
  if (issues.some(function (i) { return i.level === 'warn'; })) return 'warn';
  return 'ok';
}

/* ---------- card ---------- */

function bar(label, pct, kind, valueText, cls) {
  var fill = h('i', { class: cls === undefined ? pctClass(pct, kind) : cls });
  fill.style.width = Math.max(0, Math.min(100, pct)) + '%';
  return h('div', { class: 'metric' }, [
    h('span', { class: 'metric-label', text: label }),
    h('div', { class: 'bar' }, [fill]),
    h('span', { class: 'metric-value', text: valueText })
  ]);
}

function biggestDisk(host) {
  var disks = (host.disks || []).filter(function (d) { return d.total > 0; });
  if (!disks.length) return null;
  return disks.reduce(function (a, b) { return b.pct > a.pct ? b : a; });
}

function hottest(host) {
  var temps = host.temps || [];
  if (!temps.length) return null;
  return temps.reduce(function (a, b) { return b.c > a.c ? b : a; });
}

function chip(text, cls) { return h('span', { class: 'chip ' + (cls || ''), text: text }); }

function hostCard(host) {
  var level = hostLevel(host);
  var chips = [];

  if (host.update_count > 0) {
    chips.push(chip('↑ ' + host.update_count + ' обновл.' +
      (host.security_count ? ' · ' + host.security_count + ' security' : ''),
      host.security_count ? 'warn' : 'info'));
  }
  if (host.reachable && host.error) chips.push(chip('нет доступа', 'warn'));
  if (host.recorded_by) {
    chips.push(chip(host.camera_live ? 'пишется: ' + host.recorded_by : 'запись стоит: ' + host.recorded_by,
      host.camera_live ? 'ok' : 'bad'));
  }
  var failed = (host.services || []).filter(function (s) { return (s.state || '').indexOf('failed') >= 0; });
  if (failed.length) chips.push(chip('✕ ' + failed.length + ' упало', 'bad'));
  var running = (host.services || []).filter(function (s) {
    return (s.state || '').indexOf('running') >= 0 || s.state === 'active/exited';
  });
  if (running.length) chips.push(chip('⚙ ' + running.length, ''));
  if ((host.containers || []).length) chips.push(chip('🐳 ' + host.containers.length, ''));
  if ((host.cameras || []).length) chips.push(chip('📷 ' + host.cameras.length, ''));
  if (host.reboot_required) chips.push(chip('⟳ перезагрузка', 'warn'));
  (host.degraded_raid || []).forEach(function (r) { chips.push(chip('RAID ' + r.state, 'bad')); });
  if ((host.failing_disks || []).length) {
    chips.push(chip('⚠ диск: ' + host.failing_disks[0].dev, 'bad'));
  } else if ((host.smarts || []).length) {
    chips.push(chip('SMART ok', 'ok'));
  }
  if (host.agent === 'meshtastic' && host.channel_utilization !== undefined) {
    chips.push(chip('эфир ' + host.channel_utilization + '%', host.channel_utilization > 25 ? 'warn' : ''));
  }
  if (host.role === 'camera' && host.ports) {
    var rtsp = host.ports['554'];
    if (rtsp) chips.push(chip('RTSP жив', 'ok'));
    else if (host.only_via_recorder) chips.push(chip('не видна отсюда', ''));
    else chips.push(chip('RTSP молчит', 'bad'));
  }
  if (host.camera_fps) chips.push(chip(Number(host.camera_fps).toFixed(1) + ' к/с', ''));

  var metrics = [];
  if (host.reachable) {
    if (host.load1 !== undefined && host.cpus) {
      var loadPct = (host.load1 / host.cpus) * 100;
      metrics.push(bar('CPU', loadPct, 'load', host.load1 + ' / ' + host.cpus));
    } else if (host.cpu_load_pct !== undefined) {
      metrics.push(bar('CPU', host.cpu_load_pct, 'cpu', host.cpu_load_pct + '%'));
    }
    if (host.mem_pct !== undefined) {
      metrics.push(bar('ОЗУ', host.mem_pct, 'mem',
        bytes(host.mem_used) + ' / ' + bytes(host.mem_total)));
    }
    var disk = biggestDisk(host);
    if (disk) {
      metrics.push(bar('диск', disk.pct, 'disk', disk.pct + '% ' + shortMount(disk.mount),
        diskClass(disk.pct, host)));
    }
    var temp = hottest(host);
    if (temp) metrics.push(bar('темп.', temp.c, 'temp', temp.c + ' °C'));
  }

  var subtitle;
  if (!host.reachable) {
    subtitle = host.error || 'нет ответа';
  } else if (host.only_via_recorder) {
    subtitle = 'запись идёт через ' + host.recorded_by +
      (host.camera_resolution ? ' · ' + host.camera_resolution : '');
  } else {
    subtitle = (host.os_name || host.model || host.note || '') +
      (host.uptime ? ' · ' + duration(host.uptime) : '');
  }

  var footer = [];
  // Appliances answer on several ports where all but one are redirect stubs or
  // distro default pages; if anything identified itself as a real service, show
  // only those on the card. The full list lives behind the "Сайты" button.
  var named = (host.web || []).filter(function (l) { return (l.title || l.label) && !l.stub; });
  // One service often answers on several ports (Pi-hole on :443 and :8080); the
  // card wants a button per service, not per port. Links are sorted 80/443
  // first, so the survivor is the address a person would type.
  var seenName = {};
  named = named.filter(function (l) {
    var name = (l.title || l.label) + (l.path || '');
    if (seenName[name]) return false;
    seenName[name] = true;
    return true;
  });
  (named.length ? named : (host.web || [])).slice(0, 6).forEach(function (link) {
    footer.push(h('a', {
      class: 'btn btn-sm btn-link', target: '_blank', rel: 'noopener',
      href: webUrl(host, link),
      title: (link.title || link.label || 'веб-интерфейс') + ' — ' + webUrl(host, link),
      text: '⧉ ' + (link.title || link.label || (link.port === 80 || link.port === 443 ? 'веб' : link.port)),
      onclick: function (e) { e.stopPropagation(); }
    }));
  });
  if (host.updatable && host.update_count > 0) {
    footer.push(h('button', {
      class: 'btn btn-sm btn-warn', text: 'обновить',
      onclick: function (e) { e.stopPropagation(); startUpdate([host.id]); }
    }));
  }

  return h('div', {
    class: 'card state-' + level,
    onclick: function () { showHost(host); }
  }, [
    h('div', { class: 'card-head' }, [
      h('span', { class: 'card-role', text: ROLE_ICON[host.role] || ROLE_ICON.other }),
      h('span', { class: 'card-name', text: host.name }),
      h('span', { class: 'card-addr', text: host.addr })
    ]),
    h('div', { class: 'card-os', text: subtitle }),
    h('div', { class: 'metrics' }, metrics),
    chips.length ? h('div', { class: 'chips' }, chips) : null,
    footer.length ? h('div', { class: 'card-foot' }, footer) : null
  ]);
}

/* ---------- fleet, drawn as the actual network tree ---------- */

var ROLE_TITLE = {
  router: 'Роутеры', server: 'Серверы', nas: 'NAS', camera: 'Камеры',
  mesh: 'Меш-ноды', other: 'Прочее'
};

function roleGroups(hosts) {
  /* Split a subnet's hosts into per-type buckets, in a fixed order. */
  var order = ['router', 'server', 'nas', 'camera', 'mesh', 'other'];
  var buckets = {};
  hosts.forEach(function (host) {
    var role = ROLE_ORDER[host.role] === undefined ? 'other' : host.role;
    (buckets[role] = buckets[role] || []).push(host);
  });
  return order.filter(function (r) { return buckets[r]; }).map(function (r) {
    buckets[r].sort(function (a, b) { return a.name.localeCompare(b.name); });
    return { role: r, hosts: buckets[r] };
  });
}

function subnetSection(node, depth) {
  var hosts = node.hosts;
  var down = hosts.filter(function (x) { return !x.reachable; }).length;
  var groups = roleGroups(hosts);

  var children = [];
  groups.forEach(function (group) {
    // With a single kind of device the type heading is just noise.
    if (groups.length > 1) {
      children.push(h('div', { class: 'role-head', text: ROLE_TITLE[group.role] }));
    }
    children.push(h('div', { class: 'cards' }, group.hosts.map(hostCard)));
  });

  var kids = (node.children || []).map(function (child) {
    return subnetSection(child, depth + 1);
  });

  return h('section', {
    class: 'subnet depth-' + Math.min(depth, 3) + (kids.length ? ' has-children' : '')
  }, [
    h('div', { class: 'subnet-head' }, [
      h('span', { class: 'subnet-pipe', text: depth ? '└' : '' }),
      h('h2', { text: node.def.name || node.def.cidr }),
      node.def.cidr && node.def.cidr !== '0.0.0.0/0'
        ? h('span', { class: 'subnet-cidr', text: node.def.cidr }) : null,
      node.def.router ? h('span', { class: 'subnet-cidr', text: '⇢ ' + node.def.router }) : null,
      h('span', {
        class: 'subnet-count',
        text: hosts.length ? hosts.length + ' устройств' + (down ? ' · ' + down + ' не отвечает' : '') : ''
      })
    ]),
    h('div', { class: 'subnet-body' }, children.concat(kids))
  ]);
}

function buildTree(subnets, hosts) {
  /* Subnets declare their parent, so the dashboard mirrors the real topology:
     uplink router -> site router -> the camera segment behind it. */
  var nodes = {};
  subnets.forEach(function (s) { nodes[s.cidr] = { def: s, hosts: [], children: [] }; });

  var orphans = { def: { cidr: '', name: 'Прочее' }, hosts: [], children: [] };
  hosts.forEach(function (host) {
    (nodes[host.subnet] || orphans).hosts.push(host);
  });

  var roots = [];
  subnets.forEach(function (s) {
    var node = nodes[s.cidr];
    if (s.parent && nodes[s.parent]) nodes[s.parent].children.push(node);
    else roots.push(node);
  });
  if (orphans.hosts.length) roots.push(orphans);

  // Drop empty branches that carry no devices anywhere beneath them.
  function prune(node) {
    node.children = node.children.filter(prune);
    return node.hosts.length > 0 || node.children.length > 0;
  }
  return roots.filter(prune);
}

function plural(n, one, few, many) {
  var mod10 = n % 10, mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few;
  return many;
}

function renderAlert(hosts) {
  /* One banner for the whole fleet: red if anything is actually broken,
     amber for things that merely want attention, green when all clear. */
  var box = document.getElementById('alert');
  var bad = [], warn = [];

  hosts.forEach(function (host) {
    hostIssues(host).forEach(function (issue) {
      (issue.level === 'bad' ? bad : warn).push({ host: host, text: issue.text });
    });
  });

  var level = bad.length ? 'bad' : (warn.length ? 'warn' : 'ok');
  box.className = 'alert ' + level;

  var title;
  if (level === 'ok') {
    title = '✓ Всё в порядке — проблем не обнаружено';
  } else {
    var parts = [];
    if (bad.length) parts.push(bad.length + ' ' + plural(bad.length, 'проблема', 'проблемы', 'проблем'));
    if (warn.length) parts.push(warn.length + ' ' + plural(warn.length, 'замечание', 'замечания', 'замечаний'));
    title = (level === 'bad' ? '✕ ' : '⚠ ') + parts.join(' · ');
  }

  var items = bad.concat(warn).slice(0, 40).map(function (entry) {
    var isBad = bad.indexOf(entry) >= 0;
    return h('span', {
      class: 'alert-item ' + (isBad ? 'bad' : 'warn'),
      onclick: function () { showHost(entry.host); }
    }, [h('b', { text: entry.host.name }), document.createTextNode(': ' + entry.text)]);
  });

  box.innerHTML = '';
  box.appendChild(h('div', { class: 'alert-title', text: title }));
  if (items.length) box.appendChild(h('div', { class: 'alert-list' }, items));
  box.classList.remove('hidden');
}

function render() {
  if (!state) return;
  var root = document.getElementById('fleet');
  root.innerHTML = '';

  if (!state.generated) {
    // First poll after a restart takes a few seconds; say so instead of
    // showing an empty page that looks like a dead fleet.
    root.appendChild(h('div', { class: 'role-head', text: 'идёт первый опрос…' }));
    document.getElementById('summary').textContent = 'опрашиваю хосты…';
    setTimeout(load, 3000);
    return;
  }

  buildTree(state.subnets || [], state.hosts || []).forEach(function (node) {
    root.appendChild(subnetSection(node, 0));
  });

  renderAlert(state.hosts || []);

  var hosts = state.hosts || [];
  var totalUpdates = hosts.reduce(function (a, x) { return a + (x.update_count || 0); }, 0);
  var offline = hosts.filter(function (x) { return !x.reachable; }).length;
  document.getElementById('summary').textContent =
    hosts.length + ' устройств · ' + (offline ? offline + ' не отвечает · ' : 'все на связи · ') +
    totalUpdates + ' обновлений · снимок ' + ago(state.generated);

  var updatable = hosts.filter(function (x) { return x.updatable && x.update_count > 0; });
  var btn = document.getElementById('btn-upgrade-all');
  btn.disabled = updatable.length === 0;
  btn.textContent = updatable.length ? 'Обновить всё (' + updatable.length + ')' : 'Всё обновлено';

  document.getElementById('foot-note').textContent =
    'опрос занял ' + ((state.duration_ms || 0) / 1000).toFixed(1) + ' с · ' +
    'автообновление каждые ' + Math.round((state.poll_interval || 180) / 60) + ' мин';
}

/* ---------- host detail ---------- */

function table(headers, rows) {
  return h('table', { class: 'list' }, [
    h('thead', null, [h('tr', null, headers.map(function (t) { return h('th', { text: t }); }))]),
    h('tbody', null, rows)
  ]);
}

function section(title, node) {
  return node ? h('div', { class: 'section' }, [h('h3', { text: title }), node]) : null;
}

function showHost(host) {
  document.getElementById('modal-title').textContent = host.name + ' · ' + host.addr;
  var body = document.getElementById('modal-body');
  body.innerHTML = '';

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
  if (host.note) fact('заметка', host.note);
  body.appendChild(section('Общее', h('dl', { class: 'kv' }, facts)));

  var issues = hostIssues(host).filter(function (i) { return i.level !== 'ok'; });
  if (issues.length) {
    body.appendChild(section('Замечания', h('div', { class: 'chips' }, issues.map(function (i) {
      return chip(i.text, i.level);
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

  var services = (host.services || []).slice().sort(function (a, b) {
    var af = (a.state || '').indexOf('failed') >= 0 ? 0 : 1;
    var bf = (b.state || '').indexOf('failed') >= 0 ? 0 : 1;
    return af - bf || a.name.localeCompare(b.name);
  });
  if (services.length) {
    // Removal only makes sense where we manage units: systemd and OpenWrt init.
    var removable = host.agent === 'linux' || host.agent === 'openwrt';
    body.appendChild(section('Сервисы (' + services.length + ')',
      h('div', { class: 'scroll-y' }, [table(['', 'сервис', 'состояние', 'версия', ''],
        services.map(function (s) {
          var failed = (s.state || '').indexOf('failed') >= 0;
          var running = (s.state || '').indexOf('running') >= 0 || s.state === 'active/exited';
          return h('tr', null, [
            h('td', null, [h('span', { class: 'dot ' + (failed ? 'bad' : running ? 'ok' : '') })]),
            h('td', { text: s.name.replace(/\.service$/, ''), title: s.desc || '' }),
            h('td', { class: 'mono', text: s.state }),
            h('td', { class: 'mono', text: s.version || '' }),
            h('td', { class: 'right' }, [
              removable && !isProtected(s.name) ? h('button', {
                class: 'btn btn-sm btn-danger', text: '✕', title: 'удалить сервис с хоста',
                onclick: function (e) { e.stopPropagation(); removeService(host, s); }
              }) : null
            ])
          ]);
        }))])));
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
    body.appendChild(section('Камеры', table(['камера', 'адрес', 'состояние', 'fps'],
      host.cameras.map(function (c) {
        var live = c.status === 'Connected' || c.status === 'recording';
        return h('tr', null, [
          h('td', null, [h('span', { class: 'dot ' + (live ? 'ok' : 'bad') }), h('span', { text: c.name })]),
          h('td', { class: 'mono', text: c.addr || '' }),
          h('td', { class: 'mono', text: c.status || '' }),
          h('td', { class: 'mono right', text: c.fps ? Number(c.fps).toFixed(1) : '' })
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

  if ((host.backups || []).length) {
    body.appendChild(section('Бэкапы', table(['задача', 'последний запуск'],
      host.backups.map(function (b) {
        return h('tr', null, [
          h('td', { text: b.name || b.task }),
          h('td', { class: 'mono', text: b.last })
        ]);
      }))));
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
        return h('a', {
          class: 'btn btn-sm btn-link', target: '_blank', rel: 'noopener',
          href: webUrl(host, link),
          text: '⧉ ' + webUrl(host, link) +
            (link.title ? ' — ' + link.title : (link.label ? ' — ' + link.label : ''))
        });
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
        h('td', null, [h('a', {
          class: 'sitelink', href: url, target: '_blank', rel: 'noopener', text: url
        })]),
        h('td', { text: link.title || link.label || '' })
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
  document.getElementById('joblog').classList.remove('hidden');
  pollJob();
  if (jobTimer) clearInterval(jobTimer);
  jobTimer = setInterval(pollJob, 1500);
}

function pollJob() {
  fetch('/api/job').then(function (r) { return r.json(); }).then(function (job) {
    if (!job || job.state === 'idle') {
      document.getElementById('job-status').textContent = 'нет активных заданий';
      return;
    }
    var done = job.state === 'done';
    var results = Object.keys(job.results || {}).map(function (k) {
      return k + ': ' + job.results[k];
    }).join(' · ');
    document.getElementById('job-status').textContent =
      (done ? 'готово' : 'идёт: ' + (job.current || '…')) +
      ' · цели: ' + (job.targets || []).join(', ') +
      (results ? ' · ' + results : '');

    var out = document.getElementById('job-output');
    var atBottom = out.scrollTop + out.clientHeight >= out.scrollHeight - 30;
    out.textContent = (job.log || []).join('\n');
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
  document.getElementById('btn-sites').addEventListener('click', showSites);
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

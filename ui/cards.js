/* Cards and the subnet tree — how the fleet is laid out on screen. */

/* ---------- card ---------- */

function bar(label, pct, kind, valueText, cls, host) {
  var fill = h('i', { class: cls === undefined ? pctClass(pct, kind, host) : cls });
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

function chip(text, cls, title) {
  return h('span', { class: 'chip ' + (cls || ''), text: text, title: title || null });
}

/* A labelled line of chips. The label is what makes a card readable once
   nothing is abbreviated away: without it "docker" and "SSH:22" sit in the
   same soup, and the eye has to parse every chip to find the one it wants. */
function chipRow(label, chips) {
  if (!chips.length) return null;
  return h('div', { class: 'chiprow' },
    [label ? h('span', { class: 'chiprow-label', text: label }) : null].concat(chips));
}

/* A chip repeats what a check found, so it has to respect the same decisions.
   Accepting "не бэкапится никуда" on the record turned the host green while
   its chip stayed red — the card contradicted itself, and the exception looked
   like it had not applied. A suppressed finding keeps its chip (the fact is
   still true) but loses the colour and says it was accepted. */
function suppressedIssue(host, key) {
  var found = null;
  (host.issues || []).forEach(function (i) {
    if (i.suppressed && (i.key === key || (key.slice(-1) === ':' && i.key.indexOf(key) === 0))) found = i;
  });
  return found;
}

function chipFor(host, key, text, cls) {
  var muted = suppressedIssue(host, key);
  if (!muted) return chip(text, cls);
  var node = chip(text + ' · принято', 'muted');
  node.title = muted.suppress_reason || 'исключение без причины';
  return node;
}

function hostCard(host) {
  var level = hostLevel(host);
  var chips = [];

  if (host.reachable && host.error) chips.push(chip('нет доступа', 'warn'));
  if (host.recorded_by) {
    chips.push(chip(host.camera_live ? 'пишется: ' + host.recorded_by : 'запись стоит: ' + host.recorded_by,
      host.camera_live ? 'ok' : 'bad'));
  }
  var failed = (host.services || []).filter(function (s) { return (s.state || '').indexOf('failed') >= 0; });
  if (failed.length) {
    var stillLoud = failed.filter(function (s) { return !suppressedIssue(host, 'svc:' + s.name); });
    chips.push(stillLoud.length
      ? chip('✕ ' + stillLoud.length + ' упало', 'bad')
      : chip('✕ ' + failed.length + ' упало · принято', 'muted'));
  }
  /* The card names the operator's own services. A count said nothing — "⚙ 41"
     looked identical on every host — and counting systemd's units made it
     worse. Names answer "what does this machine do" at a glance; the full
     list, base system included, is in the detail view. */
  var running = (host.services || []).filter(function (s) {
    return s.scope !== 'system' &&
      ((s.state || '').indexOf('running') >= 0 || s.state === 'active/exited');
  });
  /* One chip per name, and every name. Packing them into a single chip meant a
     character budget, and a budget means "+ ещё 6" — the six that were cut are
     exactly the ones nobody remembers running. Separate chips wrap by
     themselves and cost nothing to read. */
  var svcChips = running.map(function (s) {
    return chip(s.name.replace(/\.service$/, ''), '');
  }).sort(function (a, b) { return a.textContent.localeCompare(b.textContent); });

  var boxChips = (host.containers || []).map(function (c) {
    return chip(c.name, c.state === 'running' ? '' : 'bad');
  });
  if ((host.cameras || []).length) chips.push(chip('📷 ' + host.cameras.length, ''));
  (host.degraded_raid || []).forEach(function (r) {
    chips.push(chipFor(host, 'raid:' + r.dev, 'RAID ' + r.state, 'bad'));
  });
  if ((host.failing_disks || []).length) {
    chips.push(chipFor(host, 'smart:' + host.failing_disks[0].dev,
      '⚠ диск: ' + host.failing_disks[0].dev, 'bad'));
  } else if ((host.smarts || []).length) {
    chips.push(chip('SMART ok', 'ok'));
  }
  if (host.agent === 'meshtastic' && host.channel_utilization !== undefined) {
    chips.push(chip('эфир ' + host.channel_utilization + '%', host.channel_utilization > 25 ? 'warn' : ''));
  }
  /* Published services that are not web pages — VPN endpoints, proxies, RTSP.
     One process on three ports is one service, so group by name: "telemt:443,
     2053, 8443" instead of three separate chips saying the same thing.
     Reachable from the internet is a different question from listening, and it
     gets its own row: a chip there means the chain of forwards from a public
     address ends at this port, not that a rule exists somewhere. */
  var lanChips = [], wanChips = [];
  var byService = {};
  (host.endpoints || []).forEach(function (ep) {
    var key = [ep.label || ep.process || '', ep.proto === 'udp' ? 'udp' : 'tcp',
               ep.exposed ? 'wan' : 'lan'].join('\u0000');
    (byService[key] = byService[key] || []).push(ep);
  });
  Object.keys(byService).sort().forEach(function (key) {
    var group = byService[key].sort(function (a, b) { return a.port - b.port; });
    var parts = key.split('\u0000');
    var tail = parts[1] === 'udp' ? '/udp' : '';
    var name = parts[0];
    if (parts[2] === 'wan') {
      // The number a stranger types is the one on the edge; the port inside is
      // worth showing only when the forward changes it.
      var outside = group.map(function (ep) {
        return ep.exposed.wan_port +
          (String(ep.exposed.wan_port) === String(ep.port) ? '' : ' → ' + ep.port);
      }).join(', ');
      var seen = group[0].exposed;
      wanChips.push(chip('🌍 ' + (name ? name + ': ' : 'порт ') + outside + tail,
        seen.verified === false ? '' : 'warn',
        seen.addr + ':' + seen.wan_port +
        (seen.via ? ' через ' + seen.via : '') +
        (seen.verified === true ? '. Проверено снаружи'
          : seen.verified === false ? '. Снаружи не подтверждено — UDP или фильтр' : '')));
    } else {
      var ports = group.map(function (ep) { return ep.port; }).join(', ');
      lanChips.push(chip('⇄ ' + (name ? name + ':' : 'порт ') + ports + tail, ''));
    }
  });
  // A device with more than one job says so: "роутер + точка доступа".
  if ((host.roles || []).length > 1) {
    chips.push(chip(host.roles.map(function (r) { return ROLE_NAME[r] || r; }).join(' + '), ''));
  }
  (host.backs_up_to || []).forEach(function (dest) {
    chips.push(chip('💾 → ' + dest, 'ok'));
  });
  if ((host.receives_from || []).length) {
    chips.push(chip('💾 ← ' + host.receives_from.join(', '), 'ok'));
  }
  /* Money is a fact about the host like any other, and the only one that turns
     a working server off on a schedule. Shown whenever it is known — not only
     when it is nearly out — because "paid until when?" is a question people
     ask long before it is a problem. */
  var money = host.billing || {};
  if (typeof money.days_left === 'number') {
    var left = Math.round(money.days_left);
    chips.push(chipFor(host, 'balance', '💳 денег на ' + left +
      plural(left, ' день', ' дня', ' дней'),
      left <= 3 ? 'bad' : left <= 10 ? 'warn' : ''));
    chips[chips.length - 1].title = 'по расчёту провайдера средств хватает до ' +
      money.forecast + (money.balance && money.balance.real !== undefined
        ? '; на счету ' + money.balance.real : '');
  } else if (money.error) {
    chips.push(chip('💳 биллинг: ' + money.error, ''));
  }
  if (host.paid_until) {
    var days = Math.round((Date.parse(host.paid_until) - Date.now()) / 86400000);
    chips.push(chipFor(host, 'paid', '💳 оплачен на ' + days +
      plural(days, ' день', ' дня', ' дней'),
      days <= 2 ? 'bad' : days <= 7 ? 'warn' : ''));
    chips[chips.length - 1].title = 'оплачен до ' + host.paid_until;
  }
  if (host.backup_orphan) chips.push(chipFor(host, 'no_backup', '💾 без бэкапа', 'bad'));
  if (host.orphan_count) {
    chips.push(chipFor(host, 'orphans', '🧹 лишних пакетов: ' + host.orphan_count, 'warn'));
  }
  /* What the box hands on to somebody else. A router's forwards appeared on the
     card only when one of them was already broken, which is late: the ports it
     listens on say nothing about the ports it passes through, and the rules
     nobody sees are the rules nobody revisits. The globe marks the ones the
     internet can actually use — the rest are plumbing behind a NAT that looks
     identical in the configuration. */
  var fwdChips = [];
  (host.forwards || []).forEach(function (rule) {
    if (rule.disabled) return;
    var dead = rule.verdict === 'no-listener' || rule.verdict === 'host-down' ||
      rule.verdict === 'no-answer';
    var sameName = String(rule.to_port || rule.port) === String(rule.port);
    var text = (rule.public_addr ? '🌍 ' : '↦ ') + rule.port +
      (rule.proto ? '/' + rule.proto : '') + ' → ' +
      (rule.to_name || rule.to || 'сюда же') + (sameName ? '' : ':' + rule.to_port);
    /* Answered from outside is a fact; a rule that did not answer may be UDP,
       or filtered, or genuinely shut — the chip says which of those we know. */
    var checked = rule.verified === true ? '. Проверено снаружи'
      : rule.public_addr ? '. Снаружи не подтверждено — UDP или фильтр' : '';
    checked += rule.live === true ? '. Сервис отвечает'
      : rule.live === false ? '. Сервис не принимает соединение'
      : rule.live_by ? '. Порт держит ' + rule.live_by : '';
    var why = (rule.comment ? rule.comment + '. ' : '') +
      (rule.public_addr ? 'снаружи как ' + rule.public_addr + ':' + rule.wan_port
                        : 'доступен только изнутри периметра') + checked +
      (dead ? '. За пробросом никто не слушает' : '');
    fwdChips.push(dead
      ? chipFor(host, 'fwd:' + rule.port, text, 'warn')
      : chip(text, rule.verified === true ? 'warn' : '', why));
  });
  var downTunnels = (host.ipsec || []).filter(function (p) {
    return !p.disabled && p.state !== 'established';
  });
  if (downTunnels.length) {
    chips.push(chipFor(host, 'ipsec:' + downTunnels[0].dst,
      '🔒 туннель не поднят: ' + downTunnels[0].dst, 'warn'));
  }
  /* An access point is judged by the networks people join, not by its radios:
     "ferretclub 2.4: 60%" is a complaint waiting to happen, "клиентов: 7" is
     trivia. The controller's own satisfaction score is used as-is. */
  (host.ssids || []).forEach(function (net) {
    if (!net.up) { chips.push(chip('📵 ' + net.essid + ' выключена', 'warn')); return; }
    var sat = net.satisfaction;
    var text = '📶 ' + net.essid + ' ' + net.band + ' ГГц';
    if (typeof sat === 'number' && sat > 0) text += ': ' + sat + '%';
    if (net.clients) text += ' · ' + net.clients;
    chips.push(chipFor(host, 'ssidsat:' + net.essid + '/' + net.band, text,
      typeof sat === 'number' && sat > 0 && sat < 80 ? 'warn' : sat >= 90 ? 'ok' : ''));
  });
  if (!(host.ssids || []).length && host.wifi_clients !== undefined &&
      (host.radios || host.radioiws || []).length) {
    chips.push(chip('📶 клиентов: ' + host.wifi_clients, ''));
  }
  if (host.link) {
    chips.push(chipFor(host, 'wifi_crowded',
      host.link === 'ethernet' ? '🔌 кабель'
        : '📶 Wi-Fi ' + (host.wifi_band ? host.wifi_band + ' ГГц' : '') +
          (host.wifi_channel ? ', канал ' + host.wifi_channel : ''),
      host.wifi_crowded_by ? 'warn' : ''));
  }
  if (host.volume !== undefined) {
    chips.push(chip((host.muted ? '🔇 ' : '🔊 ') + host.volume + '%' +
                    (host.muted ? ' (заглушено)' : ''), host.muted ? 'warn' : ''));
  }
  if (host.group) {
    chips.push(chip('⛓ группа: ' + host.group.join(' + '), ''));
  }
  if (host.track) chips.push(chip('♪ ' + host.track, ''));
  if (host.playback) {
    // "тишина" was a riddle: it read as a fault rather than as "the speaker is
    // idle, which is what a speaker is most of the time".
    var PLAYBACK = {
      'PLAYING': '▶ играет',
      'PAUSED_PLAYBACK': '⏸ на паузе',
      'TRANSITIONING': '⏵ переключается',
      'STOPPED': '⏹ ничего не играет'
    };
    chips.push(chip(PLAYBACK[host.playback] || '⏹ ' + host.playback, ''));
  }
  if (host.role === 'camera' && host.ports) {
    var rtsp = host.ports['554'];
    if (rtsp) chips.push(chip('RTSP жив', 'ok'));
    else if (host.only_via_recorder) chips.push(chip('не видна отсюда', ''));
    else chips.push(chipFor(host, 'cam:', 'RTSP молчит', 'bad'));
  }
  if (host.camera_fps) chips.push(chip(Number(host.camera_fps).toFixed(1) + ' к/с', ''));
  if (host.os_name && host.role === 'camera') {
    /* Age on its own is not a verdict: the newest build a vendor ever shipped
       can be four years old. The chip turns amber only when a newer one is
       known to exist. */
    var known = host.firmware_known || {};
    chips.push(chipFor(host, 'firmware_age',
      '⚙ прошивка ' + host.os_name +
      (host.firmware_outdated ? ' → есть ' + (known.version || 'новее') : ' · последняя известная'),
      host.firmware_outdated ? 'warn' : 'ok'));
  }

  var metrics = [];
  if (host.reachable) {
    /* The bar shows busy time where it is known — that is the number with a
       ceiling, and the one the threshold is set on. Load average keeps its
       place beside it: it says how much work is queued, which busy time cannot
       tell you once the processor is full. */
    if (host.cpu_load_pct !== undefined) {
      metrics.push(bar('CPU', host.cpu_load_pct, 'cpu',
        host.cpu_load_pct + '%' +
        /* Waiting on a disk is not work: shown next to the number, never
           folded into it. */
        (host.cpu_iowait_pct >= 20 ? ' · ждёт диск ' + host.cpu_iowait_pct + '%' : '') +
        (host.cpu_steal_pct >= 5 ? ' · украдено ' + host.cpu_steal_pct + '%' : '') +
        (host.load1 !== undefined && host.cpus
          ? ' · ' + host.load1 + ' / ' + host.cpus : ''), undefined, host));
    } else if (host.load1 !== undefined && host.cpus) {
      var loadPct = (host.load1 / host.cpus) * 100;
      metrics.push(bar('CPU', loadPct, 'load', host.load1 + ' / ' + host.cpus,
        undefined, host));
    }
    if (host.mem_pct !== undefined) {
      metrics.push(bar('ОЗУ', host.mem_pct, 'mem',
        bytes(host.mem_used) + ' / ' + bytes(host.mem_total), undefined, host));
    }
    var disk = biggestDisk(host);
    if (disk) {
      metrics.push(bar('диск', disk.pct, 'disk', disk.pct + '% ' + shortMount(disk.mount),
        diskClass(disk.pct, host), host));
    }
    var temp = hottest(host);
    if (temp) metrics.push(bar('темп.', temp.c, 'temp', temp.c + ' °C', undefined, host));
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
  /* Loopback services stay in the detail view, where there is room to say
     "only from the host itself" — as a card button they are a link
     that opens nothing. */
  var named = (host.web || []).filter(function (l) {
    return (l.title || l.label) && !l.stub && !l.local;
  });
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
  (named.length ? named : (host.web || [])).forEach(function (link) {
    footer.push(h('a', {
      class: 'btn btn-sm btn-link', target: '_blank', rel: 'noopener',
      href: webUrl(host, link),
      title: (link.title || link.label || 'веб-интерфейс') + ' — ' + webUrl(host, link),
      text: '⧉ ' + (link.title || link.label || (link.port === 80 || link.port === 443 ? 'веб' : link.port)),
      onclick: function (e) { e.stopPropagation(); }
    }));
  });
  if (host.agent === 'unifi' && host.update_count > 0) {
    footer.push(h('button', {
      class: 'btn btn-sm btn-warn', text: 'прошивка',
      title: 'обновить прошивку точки через контроллер',
      onclick: function (e) { e.stopPropagation(); upgradeAccessPoint(host); }
    }));
  }
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
      // Pending work belongs next to the host's identity, not mixed in with
      // the chips describing what it runs.
      // Spelled out: a lone glyph reads as decoration, not as "this box is
      // waiting for you to do something".
      host.update_count ? h('span', {
        class: 'head-badge ' + (host.security_count ? 'warn' : 'info'),
        title: host.update_count + ' доступных обновлений' +
          (host.security_count ? ', из них ' + host.security_count + ' security' : ''),
        text: host.update_count + ' обновл.' + (host.security_count ? ' ⚠' : '')
      }) : null,
      // "Up to date" is worth a word: without it a card with no update badge
      // is indistinguishable from one where nothing was ever checked — and
      // those are opposite answers.
      (!host.update_count && host.updates_checked) ? h('span', {
        class: 'head-badge ok',
        title: 'установленная версия совпадает с последней доступной',
        text: '✓ актуально'
      }) : null,
      host.reboot_required ? h('span', {
        class: 'head-badge warn',
        title: 'после обновлений нужна перезагрузка',
        text: 'нужен ребут'
      }) : null,
      h('span', { class: 'card-addr', text: host.addr }),
      host.reachable ? h('button', {
        class: 'head-action', title: 'перезагрузить ' + host.name, text: '↻',
        onclick: function (e) { e.stopPropagation(); rebootHost(host); }
      }) : null
    ]),
    h('div', { class: 'card-os', text: subtitle }),
    h('div', { class: 'metrics' }, metrics),
    chipRow('', chips),
    chipRow('сервисы', svcChips),
    chipRow('контейнеры', boxChips),
    chipRow('из интернета', wanChips),
    chipRow('пробросы', fwdChips),
    chipRow('в локальной сети', lanChips),
    footer.length ? h('div', { class: 'card-foot' }, footer) : null
  ]);
}

/* ---------- fleet, drawn as the actual network tree ---------- */

var ROLE_TITLE = {
  router: 'Роутеры', ap: 'Точки доступа', server: 'Серверы', nas: 'NAS',
  camera: 'Камеры', mesh: 'Меш-ноды', media: 'Аудио', other: 'Прочее'
};

function roleGroups(hosts) {
  /* Split a subnet's hosts into per-type buckets, in a fixed order. */
  // Derived from ROLE_ORDER, not repeated: a hard-coded list here silently
  // dropped whole device types (access points, speakers) the moment a new
  // role was added — they had cards built and never rendered.
  var order = Object.keys(ROLE_ORDER).sort(function (a, b) {
    return ROLE_ORDER[a] - ROLE_ORDER[b];
  });
  if (order.indexOf('other') < 0) order.push('other');
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

function snapshotAge() {
  /* How stale the data is. A collector that has hung shows a page full of
     green cards that were true an hour ago — the one way this dashboard can
     actively mislead, so it outranks everything else in the banner. */
  if (!state || !state.generated) return { seconds: 0, level: 'ok' };
  var seconds = Math.max(0, Date.now() / 1000 - state.generated);
  var interval = state.poll_interval || 180;
  if (seconds > interval * 5) return { seconds: seconds, level: 'bad' };
  if (seconds > interval * 2) return { seconds: seconds, level: 'warn' };
  return { seconds: seconds, level: 'ok' };
}

function renderAlert(hosts) {
  /* One banner for the whole fleet: red if anything is actually broken,
     amber for things that merely want attention, green when all clear. */
  var box = document.getElementById('alert');
  var bad = [], warn = [];

  hosts.forEach(function (host) {
    hostIssues(host).forEach(function (issue) {
      // A suppressed finding keeps its place in the host's own list, with the
      // reason next to it — but it has been accepted, so the fleet banner is
      // exactly where it must not appear. It carries level "info", and
      // "anything not bad is a warning" quietly put it back on the banner.
      if (issue.suppressed) return;
      // The issue travels with the row: the dismiss button needs to name the
      // finding it is dismissing, not the text it happens to show.
      if (issue.level === 'bad') bad.push({ host: host, text: issue.text, issue: issue });
      else if (issue.level === 'warn') warn.push({ host: host, text: issue.text, issue: issue });
    });
  });

  var age = snapshotAge();
  var level = age.level === 'bad' ? 'bad'
            : (bad.length ? 'bad'
            : ((warn.length || age.level === 'warn') ? 'warn' : 'ok'));
  box.className = 'alert ' + level;

  var title;
  if (age.level !== 'ok') {
    title = (age.level === 'bad' ? '✕ ДАННЫЕ УСТАРЕЛИ' : '⚠ данные устаревают') +
      ' — последний успешный опрос ' + duration(age.seconds) + ' назад,' +
      ' ожидается каждые ' + Math.round((state.poll_interval || 180) / 60) + ' мин.' +
      ' Показанное ниже может уже не соответствовать действительности.';
  } else if (level === 'ok') {
    title = '✓ Всё в порядке — проблем не обнаружено';
  } else {
    var parts = [];
    if (bad.length) parts.push(bad.length + ' ' + plural(bad.length, 'проблема', 'проблемы', 'проблем'));
    if (warn.length) parts.push(warn.length + ' ' + plural(warn.length, 'замечание', 'замечания', 'замечаний'));
    title = (level === 'bad' ? '✕ ' : '⚠ ') + parts.join(' · ');
  }

  var items = bad.concat(warn).slice(0, 40).map(function (entry) {
    var isBad = bad.indexOf(entry) >= 0;
    /* Read-and-move-on belongs where the finding is read, not three clicks
       away inside the host. One press, no reason asked: it comes back when the
       finding says something different. */
    /* Only where there is a next time. A port that negotiated 100 Mbit will go
       on saying so until somebody changes the cable, and a button that hides it
       "until it happens again" would hide it for good. Those take a reason, in
       the host's own list. */
    var dismiss = entry.issue && entry.issue.episodic ? h('button', {
      class: 'alert-dismiss', text: '✓',
      title: 'принято — скрыть до следующего раза; вернётся, если изменится',
      onclick: function (e) { e.stopPropagation(); ackIssue(entry.host, entry.issue); }
    }) : null;
    return h('span', {
      class: 'alert-item ' + (isBad ? 'bad' : 'warn'),
      onclick: function () { showHost(entry.host); }
    }, [h('b', { text: entry.host.name }),
        document.createTextNode(': ' + entry.text), dismiss]);
  });

  box.innerHTML = '';
  box.appendChild(h('div', { class: 'alert-title', text: title }));
  if (items.length) {
    // Collapsed by default on narrow screens (CSS decides): the banner must
    // not push the fleet below the fold on a phone.
    var list = h('div', { class: 'alert-list collapsed' }, items);
    box.appendChild(list);
    if (items.length > 4) {
      var more = h('button', {
        class: 'alert-more', text: 'показать все (' + items.length + ')',
        onclick: function () {
          var collapsed = list.classList.toggle('collapsed');
          more.textContent = collapsed ? 'показать все (' + items.length + ')' : 'свернуть';
        }
      });
      box.appendChild(more);
    }
  }
  box.classList.remove('hidden');
}

function renderUnmanaged(root, devices) {
  /* Everything the routers' DHCP tables know about that the config does not.
     Two uses: hardware worth adding to the dashboard, and anything on the
     network that has no business being there. */
  if (!devices.length) return;

  var open = localStorage.getItem('hz-unmanaged-open') === '1';
  var list = h('div', { class: 'cards' }, devices.map(function (d) {
    return h('div', { class: 'card state-off unmanaged' }, [
      h('div', { class: 'card-head' }, [
        h('span', { class: 'card-role', text: '❔' }),
        h('span', { class: 'card-name', text: d.name || d.vendor || 'без имени' }),
        h('span', { class: 'card-addr', text: d.addr })
      ]),
      h('div', { class: 'card-os', text: (d.vendor ? d.vendor + ' · ' : '') + (d.mac || '') })
    ]);
  }));
  list.style.display = open ? '' : 'none';

  var toggle = h('button', {
    class: 'btn btn-sm',
    text: (open ? 'скрыть' : 'показать') + ' (' + devices.length + ')',
    onclick: function () {
      open = !open;
      list.style.display = open ? '' : 'none';
      toggle.textContent = (open ? 'скрыть' : 'показать') + ' (' + devices.length + ')';
      localStorage.setItem('hz-unmanaged-open', open ? '1' : '0');
    }
  });

  root.appendChild(h('section', { class: 'subnet' }, [
    h('div', { class: 'subnet-head' }, [
      h('h2', { text: 'Обнаружено в сети' }),
      h('span', { class: 'subnet-cidr', text: 'нет в конфиге, взято из DHCP роутеров' }),
      h('span', { class: 'subnet-count' }, [toggle])
    ]),
    list
  ]));
}

var onlyProblems = localStorage.getItem('hz-only-problems') === '1';
var searchText = '';

function hostMatches(host) {
  if (onlyProblems && (host.level === 'ok' || !host.level)) return false;
  if (!searchText) return true;
  var needle = searchText.toLowerCase();
  return (host.name || '').toLowerCase().indexOf(needle) >= 0 ||
         (host.addr || '').indexOf(needle) >= 0 ||
         (host.os_name || '').toLowerCase().indexOf(needle) >= 0 ||
         (host.note || '').toLowerCase().indexOf(needle) >= 0;
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

  var visible = (state.hosts || []).filter(hostMatches);
  buildTree(state.subnets || [], visible).forEach(function (node) {
    root.appendChild(subnetSection(node, 0));
  });
  if (!visible.length) {
    root.appendChild(h('div', { class: 'role-head', text:
      onlyProblems ? 'проблемных хостов нет' : 'ничего не найдено' }));
  }

  renderUnmanaged(root, state.unmanaged || []);

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

  /* The dashboard watches every service in the house except itself. Saying
     which commit is running — and whether the repository has moved on since —
     is the smallest version of watching itself that is worth anything. */
  var version = state.version || {};
  var build = version.commit && version.commit !== 'unknown'
    ? ' · версия ' + version.commit +
      (version.dirty ? ' (с правками вне коммита)' : '') +
      (version.behind ? ', отстала на ' + version.behind +
        plural(version.behind, ' коммит', ' коммита', ' коммитов') : '')
    : '';
  document.getElementById('foot-note').textContent =
    'опрос занял ' + ((state.duration_ms || 0) / 1000).toFixed(1) + ' с · ' +
    'автообновление каждые ' + Math.round((state.poll_interval || 180) / 60) + ' мин' +
    build;
}


/* health-zoo — "Схема": what is plugged into what.

   The fleet view is a list and the outside view is a tree of services; neither
   answers the question you ask while standing in front of the rack with a cable
   in your hand. A cable is the one part of this network that no configuration
   file describes: the switch learns it from the frames it forwards, the access
   point learns it from the clients that associate, and until now nobody asked
   either of them.

   So this is drawn from what the hardware knows — the bridge's address table
   and the registration tables — rather than from anything somebody wrote down
   and then stopped updating. A port with nothing behind it says so; a device
   nobody can name is shown by its vendor and its address, because "unknown
   thing on ether7" is exactly the row worth seeing. */

'use strict';

/* Everything the snapshot knows about who owns a MAC, in one lookup. Leases
   give the address and the name the device calls itself, the fleet gives the
   name we call it, and the unmanaged list carries the vendor for the ones that
   are neither. */
function whoIs(state) {
  var byMac = {};
  /* Merging must never overwrite something known with something empty: the
     wireless tables carry a MAC and a signal and nothing else, and assigning
     their blank address over the one the lease gave turned every known client
     into "неизвестное устройство". */
  function put(mac, fields) {
    if (!mac) return;
    var key = mac.toLowerCase();
    var entry = byMac[key] || (byMac[key] = {});
    Object.keys(fields).forEach(function (field) {
      if (fields[field]) entry[field] = fields[field];
    });
  }
  (state.hosts || []).forEach(function (host) {
    (host.leases || []).forEach(function (lease) {
      put(lease.mac, { addr: lease.addr, hostname: lease.name || '' });
    });
  });
  (state.unmanaged || []).forEach(function (device) {
    put(device.mac, { addr: device.addr || '', hostname: device.name || '',
                      vendor: device.vendor || '' });
  });
  var byAddr = {};
  (state.hosts || []).forEach(function (host) { byAddr[host.addr] = host; });
  (state.hosts || []).forEach(function (host) {
    (host.wireless || []).forEach(function (client) {
      put(client.mac, { addr: client.addr || '', hostname: client.name || '' });
    });
  });
  return { mac: byMac, addr: byAddr };
}

function nameFor(known, mac) {
  var seen = known.mac[(mac || '').toLowerCase()] || {};
  var host = seen.addr ? known.addr[seen.addr] : null;
  if (host) {
    return { text: host.name, addr: host.addr, role: host.role, known: true,
             level: host.level };
  }
  var label = seen.hostname || seen.vendor || 'неизвестное устройство';
  return { text: label, addr: seen.addr || '', known: false };
}

function deviceLine(known, mac, note) {
  var who = nameFor(known, mac);
  return h('div', { class: 'tree-leaf' }, [
    h('span', { class: 'wire-dot ' + (who.known ? (who.level || 'ok') : 'unknown') }),
    h('span', { class: 'tree-name', text: (who.known ? ROLE_ICON[who.role] + ' ' : '') + who.text }),
    who.addr ? h('span', { class: 'tree-target', text: who.addr }) : null,
    note ? h('span', { class: 'tree-where', text: note }) : null,
    h('span', { class: 'tree-evidence mono', text: mac })
  ]);
}

function speedOf(link) {
  if (!link || link.state !== 'up') return 'нет линка';
  var mbit = link.speed >= 1000 ? (link.speed / 1000) + ' Гбит/с' : link.speed + ' Мбит/с';
  return mbit + (link.duplex === 'half' ? ', полудуплекс' : '');
}

/* A port and everything the switch has seen behind it. More than one device
   means another switch down there — worth showing as such rather than as a
   list of strangers. */
function portNode(known, link, sitting) {
  var slow = link && link.state === 'up' && link.speed_best && link.speed < link.speed_best;
  var head = h('div', { class: 'tree-leaf' }, [
    h('span', { class: 'tree-name mono', text: link ? link.name : '—' }),
    h('span', { class: slow ? 'tree-target warn' : 'tree-target', text: speedOf(link) }),
    sitting.length > 1
      ? h('span', { class: 'tree-where', text: 'через свитч, устройств ' + sitting.length })
      : null
  ]);
  var kids = sitting.map(function (mac) { return h('li', null, [deviceLine(known, mac)]); });
  if (!kids.length && link && link.state === 'up') {
    // Either the uplink (its far end is not on our bridge) or something that
    // has not spoken since the switch last forgot it.
    kids = [h('li', { class: 'tree-label' },
      [h('span', { text: 'линк есть, за ним никого не видно — аплинк или молчун' })])];
  }
  return h('li', null, [head].concat(kids.length ? [h('ul', { class: 'tree' }, kids)] : []));
}

function radioNode(known, radio, clients) {
  var title = (radio.ssid || radio.name || 'радио') +
    (radio.band ? ' · ' + radio.band + ' ГГц' : '') +
    (radio.channel ? ' · канал ' + radio.channel : '');
  var head = h('div', { class: 'tree-leaf' }, [
    h('span', { class: 'tree-name', text: '📶 ' + title }),
    h('span', { class: 'tree-where', text: clients.length + ' устр.' })
  ]);
  var kids = clients.map(function (client) {
    return h('li', null, [deviceLine(known, client.mac,
      (client.signal ? client.signal + ' дБм' : '') +
      (client.ssid && !radio.ssid ? ' · ' + client.ssid : ''))]);
  });
  return h('li', null, [head].concat(kids.length ? [h('ul', { class: 'tree' }, kids)] : []));
}

function switchBlock(known, host) {
  var sitting = {};
  (host.behind || []).forEach(function (entry) {
    (sitting[entry.port] = sitting[entry.port] || []).push(entry.mac);
  });
  var items = [];

  (host.links || []).forEach(function (link) {
    if (link.state !== 'up' && !(sitting[link.name] || []).length) return;
    items.push(portNode(known, link, sitting[link.name] || []));
  });

  /* Wireless clients grouped by the radio they sit on. RouterOS names the
     virtual access point, the UniFi controller names the band; both end up as
     one branch per thing a device can be associated to. */
  var byRadio = {};
  (host.wireless || []).forEach(function (client) {
    var key = client.radio || client.ssid || client.band || 'радио';
    (byRadio[key] = byRadio[key] || []).push(client);
  });
  Object.keys(byRadio).sort().forEach(function (key) {
    var clients = byRadio[key];
    var radio = (host.radios || []).filter(function (r) {
      return r.name === key || r.ssid === key;
    })[0] || { name: key, ssid: clients[0].ssid, band: clients[0].band };
    items.push(radioNode(known, radio, clients));
  });

  var ports = (host.links || []).filter(function (l) { return l.state === 'up'; }).length;
  return h('section', { class: 'egress-block' }, [
    h('div', { class: 'egress-head' }, [
      h('span', { class: 'egress-title', text: (ROLE_ICON[host.role] || '') + ' ' + host.name }),
      h('span', { class: 'egress-sub', text: host.addr })
    ]),
    h('div', { class: 'egress-note', text:
      'портов в работе ' + ports + ' · устройств за портами ' + (host.behind || []).length +
      ' · по радио ' + (host.wireless || []).length }),
    items.length ? h('ul', { class: 'tree' }, items)
      : h('div', { class: 'egress-note', text: 'ничего не подключено' })
  ]);
}

function renderTopology() {
  var root = document.getElementById('topology');
  if (!root || !state) return;
  root.innerHTML = '';

  var known = whoIs(state);
  /* Anything that other devices hang off: a router, a switch, an access point.
     Ordered by subnet so the drawing follows the house rather than the config
     file. */
  var carriers = (state.hosts || []).filter(function (host) {
    return (host.behind || []).length || (host.wireless || []).length;
  }).sort(function (a, b) {
    return (a.subnet || '').localeCompare(b.subnet || '') ||
           (a.name || '').localeCompare(b.name || '');
  });

  if (!carriers.length) {
    root.appendChild(h('div', { class: 'role-head', text:
      'ни один коммутатор пока не рассказал, что к нему подключено' }));
    return;
  }

  var site = '';
  carriers.forEach(function (host) {
    if ((host.subnet || '') !== site) {
      site = host.subnet || '';
      var named = (state.subnets || []).filter(function (s) { return s.cidr === site; })[0];
      root.appendChild(h('div', { class: 'role-head', text: (named && named.name) || site }));
    }
    root.appendChild(switchBlock(known, host));
  });
}

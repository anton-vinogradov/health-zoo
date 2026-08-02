/* health-zoo — "Наружу": how each service reaches the internet.

   The fleet view answers "is this host healthy". This one answers a question
   that has no home anywhere else: through what does a given service leave the
   house. That knowledge is currently spread across a curl option in one file,
   a JSON key in another, a tunnel configuration in a third — and after a few
   months nobody remembers which of them applies to what. Grouped by the way
   out rather than by service, so both directions of the question are answered
   at once: what does this service use, and what else rides the same tunnel. */

'use strict';

function exitKey(listen) {
  return (listen || '').trim();
}

/* A "via" as written by whoever configured it ("socks5://10.0.0.1:1081") next
   to an exit as the host reports it ("10.0.0.1:1081"). */
function viaMatchesExit(via, listen) {
  if (!via || !listen) return false;
  return via.indexOf(listen) >= 0;
}

function tunnelLine(ex) {
  var parts = [];
  if (ex.tunnel) parts.push(ex.tunnel === 'amneziawg' ? 'AmneziaWG' : 'WireGuard');
  if (ex.endpoint) parts.push('→ ' + ex.endpoint);
  return parts.join(' ');
}

function outboundRow(item) {
  /* The evidence is the point: a claim about where traffic goes is worth what
     the file behind it says, and the file is what you edit to change it. */
  return h('tr', null, [
    h('td', { class: 'egress-who', text: item.who }),
    h('td', { text: item.target || '' }),
    h('td', { class: 'egress-note', text: item.evidence || '' })
  ]);
}

function exitBlock(ex, users) {
  var head = h('div', { class: 'egress-head' }, [
    h('span', { class: 'egress-title', text: ex.listen + ' · ' + (ex.kind || 'proxy') }),
    h('span', { class: 'egress-sub', text: tunnelLine(ex) })
  ]);
  var meta = [];
  if (ex.unit) meta.push(ex.unit);
  if (ex.state) meta.push(ex.state === 'active' ? 'работает' : ex.state);
  if (ex.inside) meta.push('адрес внутри туннеля ' + ex.inside);
  if (ex.host) meta.push('на ' + ex.host);

  return h('section', { class: 'egress-block' }, [
    head,
    h('div', { class: 'egress-note', text: meta.join(' · ') }),
    users.length
      ? h('table', { class: 'egress-table' }, [h('tbody', null, users.map(outboundRow))])
      : h('div', { class: 'egress-note', text: 'через этот выход сейчас никто не ходит' })
  ]);
}

function directBlock(hosts, direct) {
  /* Everything nobody routed anywhere. Worth showing next to the tunnels
     precisely because it is the default: a service is direct not by decision
     but by nobody having decided. */
  var byHost = {};
  direct.forEach(function (item) {
    (byHost[item.host] = byHost[item.host] || []).push(item);
  });
  var blocks = Object.keys(byHost).sort().map(function (name) {
    var host = hosts.filter(function (x) { return x.name === name || x.id === name; })[0];
    /* Only the site's edge is measured from outside, so only it can name the
       address the world sees. Printing "unknown" against every other host
       would be true and useless; the measured exits are listed once above. */
    var seen = host && host.egress_addr ? 'выход ' + host.egress_addr : 'через роутер площадки';
    return h('section', { class: 'egress-block' }, [
      h('div', { class: 'egress-head' }, [
        h('span', { class: 'egress-title', text: name }),
        h('span', { class: 'egress-sub', text: seen })
      ]),
      h('table', { class: 'egress-table' }, [h('tbody', null, byHost[name].map(outboundRow))])
    ]);
  });
  return blocks;
}

function renderEgress() {
  var root = document.getElementById('egress');
  if (!root || !state) return;
  root.innerHTML = '';

  var hosts = state.hosts || [];
  var exits = [];
  var outbound = [];
  hosts.forEach(function (host) {
    (host.exits || []).forEach(function (ex) {
      exits.push(Object.assign({}, ex, { host: host.name || host.id }));
    });
    (host.outbounds || []).forEach(function (item) {
      outbound.push(Object.assign({}, item, { host: host.name || host.id }));
    });
  });

  if (!exits.length && !outbound.length) {
    root.appendChild(h('div', { class: 'role-head', text:
      'ни один хост пока не рассказал, как он ходит наружу' }));
    return;
  }

  /* Two identical tunnels on two hosts are two ways out, not one: they exit
     through the same endpoint but a service can only use the one on its own
     host, and that difference is exactly what somebody debugging needs. */
  var used = {};
  exits.forEach(function (ex) {
    var users = outbound.filter(function (item) {
      return item.host === ex.host && viaMatchesExit(item.via, exitKey(ex.listen));
    });
    users.forEach(function (item) { used[item.host + '|' + item.who + '|' + item.target] = true; });
    root.appendChild(exitBlock(ex, users));
  });

  var direct = outbound.filter(function (item) {
    return !used[item.host + '|' + item.who + '|' + item.target];
  });
  if (direct.length) {
    /* What the internet sees when nothing is tunnelled. Measured, not read off
       an interface: a provider can hand out a private address and map a public
       one onto it, which is exactly what happens here. */
    var edges = hosts.filter(function (x) { return x.egress_addr; })
      .map(function (x) { return x.egress_addr + ' (' + (x.name || x.id) + ')'; });
    root.appendChild(h('div', { class: 'role-head', text:
      'напрямую, без туннеля' + (edges.length ? ' — снаружи это ' + edges.join(', ') : '') }));
    directBlock(hosts, direct).forEach(function (block) { root.appendChild(block); });
  }
}

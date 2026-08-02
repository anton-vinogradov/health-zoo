/* health-zoo — "Наружу": how each service reaches the internet.

   The fleet view answers "is this host healthy". This one answers a question
   that has no home anywhere else: through what does a given service leave the
   house. That knowledge is currently spread across a curl option in one file,
   a JSON key in another, a tunnel configuration in a third — and after a few
   months nobody remembers which of them applies to what.

   A tree of services, not a list of hosts. The same service usually runs in
   more than one place and takes the same road out of each, so the road is the
   branch and the host is a detail on the leaf. Where one service reaches the
   internet through another — everything here sends its notifications by
   handing them to telegram.sh — it hangs under it, because that is the shape
   of the thing: one exit, one script, and a dozen users behind it. */

'use strict';

/* Two hosts running the same tunnel to the same endpoint are one way out, seen
   twice. Grouping by the endpoint answers "what rides this tunnel" across the
   whole fleet, which is the question a list per host cannot answer. */
function exitGroupKey(ex) {
  return (ex.tunnel || 'proxy') + ' ' + (ex.endpoint || ex.listen || '');
}

function exitGroupTitle(ex) {
  var kind = ex.tunnel === 'amneziawg' ? 'AmneziaWG'
           : ex.tunnel === 'wireguard' ? 'WireGuard' : (ex.kind || 'прокси');
  return 'через туннель · ' + kind + (ex.endpoint ? ' → ' + ex.endpoint : '');
}

/* The road spelled out end to end. The branch used to name the tunnel and the
   leaf its destination, leaving the reader to guess whether the service talked
   to the tunnel or to the destination — which is the one thing this view is
   for. Written as a chain, there is nothing left to assemble. */
function chainOf(exits) {
  var listens = exits.map(function (ex) { return ex.listen; }).join(' / ');
  var far = exits[0] && exits[0].endpoint ? exits[0].endpoint : 'узел на той стороне';
  return 'сервис → SOCKS5 ' + listens + ' → туннель → ' + far + ' → адрес назначения';
}

function leaf(name, targets, hosts, evidence, children) {
  var line = h('div', { class: 'tree-leaf' }, [
    h('span', { class: 'tree-name', text: name }),
    targets.length ? h('span', { class: 'tree-target', text: '→ ' + targets.join(', ') }) : null,
    hosts.length ? h('span', { class: 'tree-where', text: hosts.join(', ') }) : null,
    evidence ? h('span', { class: 'tree-evidence', text: evidence }) : null
  ]);
  return h('li', null, [line].concat(children && children.length
    ? [h('ul', { class: 'tree' }, children)] : []));
}

/* One service, however many rows and hosts it came from. */
function collect(rows) {
  var byName = {};
  rows.forEach(function (row) {
    /* A service can appear twice on the same road for different reasons — once
       because it hands its messages to another service, once because its own
       configuration names the proxy. Merging those two would lose whichever
       was read second, and the second one is usually the setting somebody is
       looking for. */
    var carried = (row.evidence || '').indexOf('через ') === 0;
    var key = row.who + (carried ? ' ↑' : '');
    var entry = byName[key] || (byName[key] = {
      who: row.who, targets: {}, hosts: {}, evidence: {}, viaScript: carried
    });
    if (row.target) entry.targets[row.target] = true;
    if (row.host) entry.hosts[row.host] = true;
    if (row.evidence) entry.evidence[row.evidence] = true;
  });
  return Object.keys(byName).sort().map(function (k) {
    var e = byName[k];
    return {
      who: e.who,
      targets: Object.keys(e.targets).sort(),
      hosts: Object.keys(e.hosts).sort(),
      evidence: Object.keys(e.evidence).sort().join(', '),
      viaScript: e.viaScript
    };
  });
}

/* Services that reach the internet by handing the job to another service hang
   under it. Anything else stands on its own. */
function nest(services) {
  var carriers = {}, out = [];
  services.forEach(function (s) { if (!s.viaScript) carriers[s.who] = { service: s, kids: [] }; });
  services.forEach(function (s) {
    if (!s.viaScript) return;
    var host = null;
    Object.keys(carriers).forEach(function (name) {
      if (s.evidence.indexOf(name) >= 0) host = carriers[name];
    });
    (host ? host.kids : out).push(s);
  });
  Object.keys(carriers).sort().forEach(function (name) {
    out.push(carriers[name].service);
    carriers[name].service.kids = carriers[name].kids;
  });
  return out.sort(function (a, b) { return a.who.localeCompare(b.who); });
}

function serviceNodes(services) {
  return nest(services).map(function (s) {
    /* A child inherits its parent's destination — it is the same traffic, one
       hand-off earlier. Repeating the address on every child is noise; saying
       nothing at all is what made the tree unreadable, so the branch says it
       once, in words. */
    var kids = (s.kids || []).map(function (k) {
      return leaf(k.who, [], k.hosts, '', []);
    });
    if (kids.length) {
      kids = [h('li', { class: 'tree-label' },
        [h('span', { text: 'шлют через ' + s.who + ', адрес тот же:' })])].concat(kids);
    }
    return leaf(s.who, s.targets, s.hosts, s.evidence, kids);
  });
}

function branch(title, meta, services) {
  return h('section', { class: 'egress-block' }, [
    h('div', { class: 'egress-head' }, [h('span', { class: 'egress-title', text: title })]),
    meta ? h('div', { class: 'egress-note', text: meta }) : null,
    services.length
      ? h('ul', { class: 'tree' }, serviceNodes(services))
      : h('div', { class: 'egress-note', text: 'этой дорогой сейчас никто не ходит' })
  ]);
}

function renderEgress() {
  var root = document.getElementById('egress');
  if (!root || !state) return;
  root.innerHTML = '';

  var hosts = state.hosts || [];
  var exits = [], outbound = [];
  hosts.forEach(function (host) {
    var where = host.name || host.id;
    (host.exits || []).forEach(function (ex) {
      exits.push({ host: where, kind: ex.kind, listen: ex.listen, unit: ex.unit,
                   state: ex.state, tunnel: ex.tunnel, endpoint: ex.endpoint,
                   inside: ex.inside });
    });
    (host.outbounds || []).forEach(function (item) {
      outbound.push({ host: where, who: item.who, target: item.target,
                      via: item.via, evidence: item.evidence });
    });
  });

  if (!exits.length && !outbound.length) {
    root.appendChild(h('div', { class: 'role-head', text:
      'ни один хост пока не рассказал, как он ходит наружу' }));
    return;
  }

  var groups = {}, order = [];
  exits.forEach(function (ex) {
    var key = exitGroupKey(ex);
    if (!groups[key]) { groups[key] = { title: exitGroupTitle(ex), exits: [] }; order.push(key); }
    groups[key].exits.push(ex);
  });

  var taken = {};
  order.forEach(function (key) {
    var group = groups[key];
    var rows = outbound.filter(function (item) {
      return group.exits.some(function (ex) {
        return item.host === ex.host && item.via && ex.listen &&
               item.via.indexOf(ex.listen) >= 0;
      });
    });
    rows.forEach(function (item) { taken[item.host + '|' + item.who + '|' + item.target] = true; });
    var meta = chainOf(group.exits) + '\n' + group.exits.map(function (ex) {
      return ex.listen + ' на ' + ex.host + ' (' + ex.unit +
             (ex.state === 'active' ? ', работает' : ', ' + ex.state) + ')';
    }).join(' · ');
    root.appendChild(branch(group.title, meta, collect(rows)));
  });

  var direct = outbound.filter(function (item) {
    return !taken[item.host + '|' + item.who + '|' + item.target];
  });
  if (direct.length) {
    /* Measured, not read off an interface: a provider can hand out a private
       address and map a public one onto it, which is what happens here. */
    var edges = hosts.filter(function (x) { return x.egress_addr; })
      .map(function (x) { return x.egress_addr + ' (' + (x.name || x.id) + ')'; });
    root.appendChild(branch('напрямую, без туннеля',
      edges.length ? 'снаружи это ' + edges.join(', ') : '', collect(direct)));
  }
}

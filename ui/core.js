/* health-zoo — shared state, helpers and severity.
   Loaded first: everything else assumes h(), bytes(), duration() and
   the threshold tables exist. */

/* health-zoo dashboard.
   Reads /api/state (a whole-fleet snapshot) and renders it grouped by subnet.
   The hub does the arithmetic; this file only decides how things look. */

'use strict';

var ROLE_ICON = {
  router: '🛜', ap: '📶', server: '🖥️', nas: '💽', camera: '📷', mesh: '📡',
  media: '🔊', other: '📦'
};
var ROLE_ORDER = { router: 0, ap: 1, server: 2, nas: 3, camera: 4, mesh: 5, media: 6, other: 7 };
var ROLE_NAME = {
  router: 'роутер', ap: 'точка доступа', server: 'сервер', nas: 'NAS',
  camera: 'камера', mesh: 'меш-нода', media: 'колонка', other: 'устройство'
};

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
  var t = host.thresholds;
  if (t && t.disk_warn) return { warn: t.disk_warn, bad: t.disk_bad };
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
  /* The hub computes these (collector/issues.py) so the banner, the card
     colours and the Telegram alerts cannot drift apart. */
  return host.issues || [];
}

function hostLevel(host) {
  return host.level || 'ok';
}


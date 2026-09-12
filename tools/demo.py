#!/usr/bin/env python3
"""Read-only demo from the anonymous fixture; never probes or controls devices."""
import argparse
import copy
import json
import sys
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'collector'))
import hub
import issues
import settings

DEMO_STARTED = int(time.time()) - 7200


def journal_entries():
    host = snapshot()['hosts'][0]
    return [dict(id=i + 1, ts=DEMO_STARTED + i * 90, kind='actions' if i % 3 == 0 else 'events',
                 event='demo', severity=['ok', 'warn', 'info'][i % 3],
                 host_id=host['id'], host_name=host['name'],
                 title=['Обновление пакетов завершено', 'Мало свободного места', 'Сервис снова отвечает'][i % 3],
                 detail='Пример записи в демонстрации.', job_id='') for i in range(65)]


def snapshot():
    fixture = json.loads((ROOT / 'tests/fixtures/fleet.json').read_text())
    hosts = copy.deepcopy(fixture['hosts'])
    cfg = fixture.get('cfg', {})
    issues.annotate(hosts, cfg, None)
    issues.annotate_checks(hosts, cfg)
    subnets = [{'cidr': s, 'name': 'Сегмент ' + str(i + 1), 'parent': None}
               for i, s in enumerate(dict.fromkeys(h.get('subnet', '') for h in hosts))]
    return {'hosts': hosts, 'subnets': subnets, 'generated': int(time.time()),
            'poll_interval': 180, 'duration_ms': 2300, 'demo': True,
            'actions_enabled': False, 'check_categories': issues.CHECK_CATEGORIES,
            'version': {'commit': 'demo'}, 'suppressions': [], 'acks': []}


class Demo(hub.Handler):
    def do_GET(self):
        path = self.path.split('?')[0]
        if path == '/api/state':
            self._json(snapshot())
        elif path == '/api/progress':
            self._json({'polling': False})
        elif path == '/api/settings':
            self._json({'fields': settings.FIELDS, 'values': issues.DEFAULT_THRESHOLDS,
                'defaults': issues.DEFAULT_THRESHOLDS, 'overridden': [], 'by_role': issues.ROLE_THRESHOLDS,
                'auto_reboot': settings.AUTO_REBOOT_DEFAULT, 'auto_security': settings.AUTO_SECURITY_DEFAULT,
                'auto_cleanup': settings.AUTO_CLEANUP_DEFAULT, 'hosts':snapshot()['hosts'], 'cameras': [], 'firmware': {}})
        elif path == '/api/job':
            self._json({'state': 'idle'})
        elif path == '/api/journal':
            q = parse_qs(self.path.partition('?')[2])
            kind = q.get('kind', ['all'])[0]
            host = q.get('host', [''])[0]
            since = int(q.get('since', ['0'])[0])
            before = int(q.get('before', ['99999'])[0])
            entries = [e for e in reversed(journal_entries()) if e['id'] < before
                       and e['ts'] >= since and (kind == 'all' or e['kind'] == kind)
                       and (not host or e['host_id'] == host)]
            self._json({'entries': entries[:50], 'started_at': DEMO_STARTED,
                        'next_before': entries[49]['id'] if len(entries) > 50 else None})
        elif path.startswith('/api/history/'):
            self._json({'series': [], 'trend': None})
        elif path.startswith('/api/metrics/'):
            self._json({'metrics': []})
        elif path.startswith('/api/'):
            self._json({'error': 'В демонстрации настройки недоступны.'}, 409)
        else:
            super().do_GET()

    def do_POST(self):
        self.close_connection = True
        self._json({'error': 'Демонстрация: управление устройствами отключено.'}, 403)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8817)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Demo)
    print(f'health-zoo demo: http://127.0.0.1:{args.port}', flush=True)
    server.serve_forever()

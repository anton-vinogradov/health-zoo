#!/usr/bin/env python3
"""Read-only demo from the anonymous fixture; never probes or controls devices."""
import argparse
import copy
import json
import sys
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'collector'))
import hub
import issues
import settings


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

#!/usr/bin/env python3
"""Exercise the real Ruby/curl API client against a loopback-only fake controller."""
import http.server
import json
import os
import subprocess
import tempfile
import threading
import urllib.parse

SECRET = 'test-"\\key'
TARGET = 'example-antigravity'
CID = '11111111-2222-3333-4444-555555555555'
deletes = []
unauthorized = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, code, payload=None):
        self.send_response(code)
        self.end_headers()
        if payload is not None:
            self.wfile.write(json.dumps(payload, ensure_ascii=False).encode())

    def authorized(self):
        ok = self.headers.get('Authorization') == 'Bearer ' + SECRET
        if not ok:
            unauthorized.append(True)
            self.respond(401)
        return ok

    def do_GET(self):
        if not self.authorized():
            return
        path = urllib.parse.unquote(self.path)
        if path == '/proxies/' + TARGET:
            self.respond(200, {'type': 'Selector', 'now': 'fallback', 'all': ['fallback']})
        elif path == '/proxies/fallback':
            self.respond(200, {'type': 'Fallback', 'now': 'node-new', 'all': ['node-new']})
        elif path == '/proxies/node-new':
            self.respond(404, {'message': 'provider-only node'})
        elif path == '/connections':
            flows = [] if deletes else [{
                'id': CID, 'metadata': {'host': 'aicode.googleapis.com',
                    'sourceIP': '192.0.2.10', 'sourcePort': '41234', 'network': 'tcp'},
                'chains': ['node-old', TARGET], 'upload': 42, 'download': 64,
            }]
            self.respond(200, {'connections': flows})
        else:
            self.respond(404)

    def do_DELETE(self):
        if not self.authorized():
            return
        deletes.append(self.path)
        self.respond(204)


server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory() as tmp:
        config = os.path.join(tmp, 'config.yaml')
        with open(config, 'w', encoding='utf-8') as f:
            f.write('external-controller: "127.0.0.1:%s"\n' % server.server_port)
            f.write('secret: ' + json.dumps(SECRET) + '\n')
        code = '''
require './antigravity_connection_guard'
api = AntigravityRouterAPI.new(ARGV.fetch(0))
raise 'nested node resolution failed' unless api.current_leaf == 'node-new'
time = [0]
feed = -> { { identities: [['192.0.2.10','41234']], region_error: false,
              tasks_idle: true, idle_for: 1000, reporter_id: 'a' * 32, activity_epoch: 0 } }
guard = AntigravityConnectionGuard.new(api, feed, -> { time[0] })
raise 'initial scan failed' unless guard.tick == :observing
time[0] = 45
raise 'targeted close failed' unless guard.tick == :closed
'''
        subprocess.run(['ruby', '-e', code, config], check=True, timeout=15)
    assert deletes == ['/connections/' + CID], deletes
    assert not unauthorized, unauthorized
    print('loopback controller integration passed: exact authenticated DELETE')
finally:
    server.shutdown()
    server.server_close()

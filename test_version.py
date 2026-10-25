import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import URLError
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from php_version import assess, classify_headers, parse_url, scan


class Tests(unittest.TestCase):
    def test_fixed_boundaries(self):
        for branch, first in [('8.2', 35), ('8.3', 36), ('8.4', 27), ('8.5', 12)]:
            for patch, expected in [(first - 1, 'potentially_affected'),
                                    (first, 'upstream_fix_level_observed'),
                                    (first + 1, 'upstream_fix_level_observed')]:
                with self.subTest(branch=branch, patch=patch):
                    self.assertEqual(assess(f'{branch}.{patch}')['status'], expected)

    def test_legacy_and_unknown(self):
        for v in ['5.4.0', '5.6.40', '7.4.33', '8.0.30', '8.1.34']:
            self.assertEqual(assess(v)['status'], 'potentially_affected')
        for v in [None, '', '8.2', '8.2.35RC1', '8.2.35-dev',
                  '8.2.34-1ubuntu1', '8.6.0', '5.3.29', '6.0.0']:
            self.assertEqual(assess(v)['status'], 'unknown')

    def test_headers_and_conflicts(self):
        h = Message()
        h['X-Powered-By'] = 'PHP/8.3.35'
        h['Set-Cookie'] = 'PHPSESSID=SECRET; HttpOnly'
        r = classify_headers(h)
        self.assertEqual(r['status'], 'potentially_affected')
        self.assertNotIn('SECRET', json.dumps(r))
        h['Server'] = 'Apache PHP/8.3.36'
        self.assertEqual(classify_headers(h)['status'], 'unknown')
        self.assertEqual(classify_headers(Message())['status'], 'unknown')

    def test_url_validation(self):
        for url in ['file:///etc/passwd', 'http://a:b@localhost/',
                    'http://localhost/?secret=x', 'http://localhost/#x',
                    'http://localhost:99999/', 'http://localhost:0/',
                    'http://local host/', 'http://a\\b/']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                parse_url(url)

    def test_scope(self):
        with self.assertRaises(ValueError):
            scan('http://localhost:9/', ['http://localhost:8'], 'lab')
        with self.assertRaises(ValueError):
            scan('http://localhost:9/', ['http://localhost:9'], '')

    def test_network_error_is_not_negative_finding(self):
        with patch('urllib.request.OpenerDirector.open', side_effect=URLError('offline')):
            result = scan('http://localhost:9/', ['http://localhost:9'], 'lab')
        self.assertEqual(result['status'], 'error')
        self.assertFalse(result['rce_confirmed'])

    def test_http_without_redirect_or_body_download(self):
        visited = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                visited.append(self.path)
                status = {'/redirect': 302, '/error': 500}.get(self.path, 200)
                self.send_response(status)
                if self.path != '/hidden':
                    self.send_header('X-Powered-By', 'PHP/8.4.26')
                if status == 302:
                    self.send_header('Location', '/never-follow')
                self.end_headers()

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                for path in ['/', '/redirect', '/error']:
                    result = scan(base + path, [base], 'unit-test')
                    self.assertEqual(result['status'], 'potentially_affected')
                    self.assertEqual(result['request_count'], 1)
                    self.assertFalse(result['rce_confirmed'])
                self.assertEqual(scan(base + '/hidden', [base], 'unit-test')['status'], 'unknown')
                self.assertEqual(visited, ['/', '/redirect', '/error', '/hidden'])
            finally:
                server.shutdown()
                thread.join()


if __name__ == '__main__':
    unittest.main(verbosity=2)

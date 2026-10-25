"""rc6 behaviour: TLS policy, endpoint suitability, timeout classes, recovery,
runtime-evidence validation, and report-structure parity across profiles."""
import datetime
import hashlib
import hmac
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import template_method
from scanner import canonical, load_attestation, run_chain


def serve(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f'http://127.0.0.1:{server.server_port}'


class EndpointSuitability(unittest.TestCase):
    def test_login_redirect_control_is_unsuitable_and_classified(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(303)
                self.send_header('Location', '/login?user=&direct=1')
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *a):
                pass
        server, t, base = serve(Handler)
        try:
            out = template_method.check(base + '/login', timeout=5)
            self.assertEqual(out['kind'], 'inconclusive')
            self.assertEqual(out['control_request_status'], 303)
            self.assertEqual(out['redirect_classification'], 'authentication_redirect')
            self.assertEqual(out['endpoint_suitability'], 'authentication_required')
            self.assertEqual(out['request_count'], 1)  # stops after an unsuitable control
        finally:
            server.shutdown(); t.join()


class TimeoutClassification(unittest.TestCase):
    def test_read_stage_timeout_is_named(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                time.sleep(2)  # exceed the 1s read timeout
                self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
            def log_message(self, *a):
                pass
        server, t, base = serve(Handler)
        try:
            out = template_method.check(base + '/', timeout=1)
            self.assertEqual(out['kind'], 'inconclusive')
            self.assertEqual(out['failure_stage'], 'read')
            self.assertEqual(out['timeout_category'], 'read_timeout')
        finally:
            server.shutdown(); t.join()


class RecoveryRecording(unittest.TestCase):
    def test_recovery_checks_recorded_separately_from_findings(self):
        class Handler(BaseHTTPRequestHandler):
            def _ok(self):
                self.send_response(200)
                self.send_header('X-Powered-By', 'PHP/8.3.36')
                self.send_header('Content-Length', '2')
                self.end_headers(); self.wfile.write(b'OK')
            def do_GET(self):
                self._ok()
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', '0'))); self._ok()
            def log_message(self, *a):
                pass
        server, t, base = serve(Handler)
        try:
            report = run_chain(base + '/index.php', [base], 'rc6-recovery', timeout=5,
                               active_methods=('template',), profile='lab')
            self.assertTrue(report['recovery_checks'])
            check = report['recovery_checks'][0]
            self.assertTrue(check['recovered'])
            self.assertEqual(check['http_status'], 200)
            self.assertFalse(report['active_stopped_after_recovery_failure'])
            # recovery is not a finding
            self.assertFalse(report['findings'][0]['rce_confirmed'])
        finally:
            server.shutdown(); t.join()


class RuntimeEvidence(unittest.TestCase):
    KEY = 'k' * 32

    def _signed(self, payload):
        return {'payload': payload, 'hmac_sha256':
                hmac.new(self.KEY.encode(), canonical(payload), hashlib.sha256).hexdigest()}

    def _payload(self, **over):
        base = {'target': 'https://lab.test/', 'source': 'trusted-web-runtime-agent',
                'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'runtimes': [{'runtime_id': 'fpm', 'version': '8.3.36',
                              'package_revision': '8.3.36-1', 'vendor_advisory': 'DSA-1',
                              'active_workers_verified': True,
                              'cve_status': {'CVE-2026-109618': 'fixed', 'CVE-2026-109619': 'fixed'}}]}
        base.update(over)
        return base

    def _write(self, tmpdir, payload):
        path = Path(tmpdir) / 'attestation.json'
        path.write_text(json.dumps(self._signed(payload)))
        return str(path)

    def test_incomplete_runtime_inventory_is_rejected(self):
        bad = self._payload()
        del bad['runtimes'][0]['package_revision']  # missing required field
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'package revision'):
                load_attestation(self._write(tmp, bad), 'https://lab.test/', self.KEY)

    def test_unverified_workers_are_rejected(self):
        bad = self._payload()
        bad['runtimes'][0]['active_workers_verified'] = False
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'Active workers'):
                load_attestation(self._write(tmp, bad), 'https://lab.test/', self.KEY)


class ReportStructure(unittest.TestCase):
    PASSIVE = {'target': 'https://lab.test/', 'http_status': 200,
               'status': 'potentially_affected', 'version': '8.3.10'}

    def test_active_methods_empty_when_none_execute(self):
        with patch('scanner.scan', return_value=dict(self.PASSIVE)):
            report = run_chain('https://lab.test/', ['https://lab.test'], 'rc6-none')
        self.assertEqual(report['active_methods_executed'], [])
        self.assertEqual(report['findings'][0]['evidence_provenance']['active_methods'], [])
        self.assertEqual(report['active_validation_status'], 'not_performed')
        self.assertEqual(report['tls_verification'], 'enabled')

    def test_production_and_lab_reports_share_structure(self):
        with patch('scanner.scan', return_value=dict(self.PASSIVE)):
            prod = run_chain('https://lab.test/', ['https://lab.test'], 'rc6-prod', profile='production')
            lab = run_chain('https://lab.test/', ['https://lab.test'], 'rc6-lab', profile='lab')
        self.assertEqual(sorted(prod), sorted(lab))
        self.assertEqual(prod['schema_version'], '3.2')
        for finding in prod['findings']:
            self.assertEqual(sorted(finding), sorted(lab['findings'][0]))


if __name__ == '__main__':
    unittest.main(verbosity=2)

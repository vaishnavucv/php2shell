import datetime as dt
import hashlib
import hmac
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from scanner import CVES, active_signals, canonical, decide, load_attestation, run_active, run_chain


def passive(status='unknown'):
    return [{'status': status}]


def attestation(status='fixed', covered=True):
    return {'target': 'http://127.0.0.1:8080/index.php',
            'source': 'trusted-web-runtime-agent',
            'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'all_backends_covered': covered,
            'runtimes': [{'runtime_id': 'fpm-pool-1', 'version': '8.3.36',
                          'package_revision': 'vendor-package-revision',
                          'vendor_advisory': 'vendor-advisory-covering-both-CVEs',
                          'active_workers_verified': True,
                          'cve_status': {c: status for c in CVES}}]}


class VerdictTests(unittest.TestCase):
    def result(self, p, a=(), evidence=None):
        return decide(p, a, evidence)[0]

    def test_old_banner_is_not_confirmed_rce(self):
        r = self.result(passive('potentially_affected'))
        self.assertEqual(r['status'], 'potentially_affected')
        self.assertFalse(r['rce_confirmed'])

    def test_fixed_banner_is_not_verified_patch(self):
        self.assertEqual(self.result(passive('upstream_fix_level_observed'))['status'], 'fix_level_advertised')

    def test_no_signal_is_inconclusive_even_if_upstream_says_false(self):
        signals = active_signals({'results': [{'vulnerable': False, 'verdict': 'NO SIGNAL'}]})
        self.assertEqual(self.result(passive(), signals)['status'], 'inconclusive')

    def test_patched_empty_500_regression(self):
        upstream = {'results': [{'vulnerable': True, 'verdict': 'VULNERABLE',
                                 'reason': 'request handler crashed: HTTP 500 with an empty body',
                                 'probes': [{'status_code': 500}]}]}
        signals = active_signals(upstream)
        self.assertEqual(self.result(passive(), signals)['status'], 'suspicious_behavior')
        r = self.result(passive(), signals, attestation())
        self.assertEqual(r['status'], 'patch_verified')
        self.assertTrue(r['anomaly_requires_separate_triage'])

    def test_gateway_errors_never_confirm_cve(self):
        for status in (502, 503, 504):
            signals = active_signals({'results': [{'verdict': 'VULNERABLE',
                'probes': [{'status_code': status}]}]})
            r = self.result(passive(), signals)
            self.assertEqual(r['status'], 'suspicious_behavior')
            self.assertFalse(r['rce_confirmed'])

    def test_memory_error_never_confirms_cve(self):
        signals = active_signals({'results': [{'verdict': 'VULNERABLE', 'reason': 'memory exhausted in Unknown'}]})
        self.assertEqual(self.result(passive(), signals)['status'], 'suspicious_behavior')

    def test_upstream_boolean_alone_does_not_verify(self):
        signals = active_signals({'results': [{'vulnerable': True, 'verdict': 'VULNERABLE'}]})
        self.assertEqual(self.result(passive(), signals)['confidence_basis'], 'behavioral_signal_only')

    def test_active_version_fallback(self):
        signals = active_signals({'results': [{'verdict': 'VULNERABLE',
            'reason': 'no crash observed; old version', 'powered_by': '8.3.35'}]})
        self.assertEqual(self.result(passive(), signals)['status'], 'potentially_affected')

    def test_verified_affected_and_per_cve_verdicts(self):
        a = attestation('affected')
        a['runtimes'][0]['cve_status'][CVES[1]] = 'fixed'
        findings = decide(passive(), [], a)
        self.assertEqual(findings[0]['status'], 'affected_runtime_verified')
        self.assertEqual(findings[1]['status'], 'patch_verified')

    def test_partial_backend_inventory_cannot_clear(self):
        self.assertEqual(self.result(passive(), evidence=attestation(covered=False))['status'], 'inconclusive')

    def test_old_banner_conflicts_with_verified_patch(self):
        self.assertEqual(self.result(passive('potentially_affected'), evidence=attestation())['status'], 'evidence_conflict')

    def test_any_affected_backend_is_reported(self):
        a = attestation()
        affected = dict(a['runtimes'][0], cve_status={c: 'affected' for c in CVES})
        a['runtimes'].append(affected)
        self.assertEqual(self.result(passive(), evidence=a)['status'], 'affected_runtime_verified')

    def test_invalid_upstream_schema(self):
        for x in ([], {}, {'results': [None]}):
            with self.assertRaises(ValueError):
                active_signals(x)


class AttestationTests(unittest.TestCase):
    key = 'test-only-key-not-for-production-123456789'

    def load(self, payload, signature=None, target=None):
        sig = signature or hmac.new(self.key.encode(), canonical(payload), hashlib.sha256).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'evidence.json'
            path.write_text(json.dumps({'payload': payload, 'hmac_sha256': sig}))
            return load_attestation(path, target or payload['target'], self.key)

    def test_valid_attestation(self):
        self.assertTrue(self.load(attestation())['all_backends_covered'])

    def test_tampered_and_wrong_target(self):
        with self.assertRaises(ValueError):
            self.load(attestation(), signature='0' * 64)
        with self.assertRaises(ValueError):
            self.load(attestation(), target='http://another-tenant/')

    def test_expired_and_incomplete_worker_evidence(self):
        a = attestation()
        a['observed_at'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)).isoformat()
        with self.assertRaises(ValueError):
            self.load(a)
        a = attestation()
        a['runtimes'][0]['active_workers_verified'] = False
        with self.assertRaises(ValueError):
            self.load(a)


class ChainTests(unittest.TestCase):
    def test_modified_upstream_script_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / 'scanner.py'
            script.write_text('raise RuntimeError("must not run")')
            with self.assertRaises(ValueError):
                run_active(script, 'http://127.0.0.1:8080/', 5)

    def test_scope_rejected_before_requests(self):
        with patch('scanner.scan') as mocked:
            with self.assertRaises(ValueError):
                run_chain('http://localhost:8080/', ['http://localhost:9090'], 'lab')
            mocked.assert_not_called()

    def test_live_http_chain(self):
        visited = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                visited.append(self.path)
                self.send_response(200)
                if self.path == '/index.php':
                    self.send_header('X-Powered-By', 'PHP/8.3.35')
                self.end_headers()
            def log_message(self, *args):
                pass
        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                report = run_chain(base + '/', [base], 'test-lab', ['/index.php', '/index.php'])
                self.assertEqual(visited, ['/', '/index.php'])
                self.assertEqual(report['findings'][0]['status'], 'potentially_affected')
                self.assertFalse(report['accuracy']['measured'])
            finally:
                server.shutdown()
                t.join()

    def test_active_budget_and_baseline_skip(self):
        with patch('scanner.scan', return_value={'http_status': 403, 'target': 'http://localhost:8080/', 'status': 'unknown'}), patch('scanner.run_active') as active:
            r = run_chain('http://localhost:8080/', ['http://localhost:8080'], 'lab', active_script='unused', profile='lab')
            active.assert_not_called()
            self.assertEqual(r['active_evidence'][0]['kind'], 'inconclusive')


if __name__ == '__main__':
    unittest.main(verbosity=2)

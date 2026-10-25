"""rc7: baseline-vs-active suitability separation, staged method execution,
dynamic remediation, build identity, and contradictory-field invariants."""
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from scanner import run_chain


def serve(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f'http://127.0.0.1:{server.server_port}'


class LoginRedirectHandler(BaseHTTPRequestHandler):
    """GET /login is 200 (reachable), POST /login 303 -> auth (unsuitable)."""
    def do_GET(self):
        self.send_response(200)
        self.send_header('X-Powered-By', 'PHP/8.5.10')
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.send_response(303)
        self.send_header('Location', '/login?user=&direct=1')
        self.send_header('Content-Length', '0')
        self.end_headers()
    def log_message(self, *a):
        pass


class SuitabilitySeparation(unittest.TestCase):
    def _run(self):
        server, t, base = serve(LoginRedirectHandler)
        try:
            return run_chain(base + '/login', [base], 'rc7-login', timeout=5,
                             active_methods=('template', 'assetnote'), profile='lab')
        finally:
            server.shutdown(); t.join()

    def test_baseline_reachable_but_active_endpoint_unsuitable(self):
        r = self._run()
        # The two dimensions are reported separately and are NOT contradictory.
        self.assertEqual(r['baseline_reachability'], 'reachable')
        self.assertEqual(r['active_endpoint_suitability'], 'authentication_required')
        self.assertEqual(r['active_validation_status'], 'inconclusive')

    def test_control_only_runs_are_not_completed_validation(self):
        r = self._run()
        for item in r['active_evidence']:
            self.assertTrue(item['execution']['method_invoked'])
            self.assertFalse(item['execution']['control_completed'])        # 303, not 2xx
            self.assertFalse(item['execution']['active_validation_completed'])
            self.assertFalse(item['execution']['vulnerability_confirmed'])
            self.assertEqual(item['execution_status'], 'control_blocked')
        self.assertEqual(r['active_methods_invoked'], ['template', 'assetnote'])
        self.assertEqual(r['active_methods_validated'], [])  # nothing actually validated

    def test_no_contradiction_between_suitability_and_confirmation(self):
        r = self._run()
        # Invariant: if the active endpoint is not suitable, nothing may be
        # validated or confirmed, and version evidence stays the only basis.
        if r['active_endpoint_suitability'] != 'suitable':
            self.assertIn(r['active_validation_status'], ('inconclusive', 'not_performed'))
            self.assertEqual(r['active_methods_validated'], [])
        for f in r['findings']:
            self.assertFalse(f['rce_confirmed'])
            self.assertEqual(f['confidence_basis'], 'version_evidence')

    def test_redirect_evidence_preserved(self):
        r = self._run()
        tmpl = next(x for x in r['active_evidence'] if x.get('method') == 'template')
        self.assertEqual(tmpl['control_request_status'], 303)
        self.assertEqual(tmpl['redirect_location'], '/login?user=&direct=1')
        self.assertEqual(tmpl['redirect_classification'], 'authentication_redirect')

    def test_remediation_is_derived_from_observed_failure(self):
        r = self._run()
        joined = ' '.join(r['remediation_recommendations']).lower()
        self.assertIn('--active-endpoint', joined)
        self.assertTrue(any('authentication' in x.lower() or 'redirect' in x.lower()
                            for x in r['remediation_recommendations']))


class BuildIdentity(unittest.TestCase):
    def test_build_block_present(self):
        passive = {'target': 'https://lab.test/', 'http_status': 200,
                   'status': 'potentially_affected', 'version': '8.5.10'}
        with patch('scanner.scan', return_value=dict(passive)):
            r = run_chain('https://lab.test/', ['https://lab.test'], 'rc7-build')
        self.assertEqual(r['build']['scanner_version'], '1.0.0-rc7')
        self.assertIn('source_commit', r['build'])
        self.assertTrue(r['build']['assetnote_blob'])
        self.assertTrue(r['build']['template_blob'])
        self.assertEqual(r['active_endpoint_suitability'], 'not_assessed')
        self.assertEqual(r['active_methods_invoked'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)

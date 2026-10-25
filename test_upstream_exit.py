import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from scanner import run_active


class UpstreamExitTests(unittest.TestCase):
    def test_exit_status_and_report_validity_are_evaluated_together(self):
        valid = {'results': [{'verdict': 'VULNERABLE', 'reason': 'HTTP 500 with an empty body',
                              'probes': [{'status_code': 500}]}]}
        cases = [(0, valid, 'completed'), (1, valid, 'completed'),
                 (1, None, 'failed'), (2, valid, 'failed'),
                 (0, 'invalid-json', 'failed'), (0, {'results': []}, 'failed')]
        script = Path(__file__).parent / 'vendor' / 'assetnote_scanner.py'
        for code, document, expected in cases:
            def fake_run(argv, **kwargs):
                out = Path(argv[argv.index('-o') + 1])
                if document is not None:
                    out.write_text(document if isinstance(document, str) else json.dumps(document))
                return subprocess.CompletedProcess(argv, code)
            with self.subTest(code=code, document=document), patch('scanner.subprocess.run', side_effect=fake_run):
                result = run_active(script, 'http://127.0.0.1:8080/', 5)
                self.assertEqual(result[0]['execution_status'], expected)
                self.assertEqual(result[0]['upstream_exit_code'], code)


if __name__ == '__main__':
    unittest.main(verbosity=2)

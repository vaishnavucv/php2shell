"""Exact-endpoint safety adapter around the unchanged, pinned Assetnote algorithm."""
import argparse
import importlib.util
import json
from pathlib import Path

from http_diagnostics import request_once
from template_method import MAX_RESPONSE_BYTES
from php_version import classify_headers


def check(script, url, timeout, insecure_tls=False, ca_cert=None):
    from scanner import active_signals
    spec = importlib.util.spec_from_file_location('sigil_assetnote', script)
    upstream = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their module through sys.modules.
    import sys
    sys.modules[spec.name] = upstream
    spec.loader.exec_module(upstream)
    observations = []

    class StopAssessment(Exception):
        pass

    def send(target, body, boundary, custom_headers, request_timeout, verify_ssl,
             follow_redirects=False):
        if target != url or follow_redirects or len(observations) >= 4:
            raise StopAssessment('Upstream requested an unapproved endpoint or exceeded request budget.')
        role = 'control' if not observations else 'probe'
        record, headers, content = request_once(url, 'POST', timeout, body,
            upstream.request_headers(custom_headers, boundary), MAX_RESPONSE_BYTES,
            insecure_tls=insecure_tls, ca_cert=ca_cert)
        if headers is not None:
            record.update(classify_headers(headers))
        observations.append(dict(record, role=role, request_body_bytes=len(body)))
        status = record.get('http_status')
        if (record.get('error') or status is None or not 200 <= status < 300):
            raise StopAssessment('Transport failed or response redirected/rejected/unhealthy; no active verdict possible.')
        if len(content) > MAX_RESPONSE_BYTES:
            raise StopAssessment('Response capture limit exceeded; assessment inconclusive.')
        response = upstream.HTTPResult()
        response.status_code = status
        response.headers = dict(headers.items())
        response.body = content
        response.bytes_sent = len(body)
        return response

    upstream.send_post = send
    try:
        doc = upstream.check_url(url, url, timeout, True, {}, 'auto', False)
        result = active_signals({'results': [doc]})[0]
    except StopAssessment as exc:
        result = {'kind': 'inconclusive', 'reason': str(exc)}
    result.update(observations=observations, request_count=len(observations),
                  source_commit='052b56ef4f9bf674aa31ac645068144747bade3d',
                  source_blob='287e97898ab759f6692c698f83d9a30d81db4fbb',
                  control_request_status=observations[0]['http_status'] if observations else None,
                  rce_confirmed=False)
    for observation in observations:
        for key in ('failure_stage', 'timeout_category', 'redirect_location',
                    'redirect_classification', 'endpoint_suitability'):
            if observation.get(key) is not None:
                result[key] = observation[key]
    versions = {x['version'] for x in observations if x.get('version')}
    result['advertised_version'] = next(iter(versions)) if len(versions) == 1 else None
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script', required=True)
    parser.add_argument('--url', required=True)
    parser.add_argument('--timeout', type=float, required=True)
    parser.add_argument('--insecure-tls', action='store_true')
    parser.add_argument('--ca-cert')
    args = parser.parse_args()
    print(json.dumps(check(Path(args.script), args.url, args.timeout,
                           args.insecure_tls, args.ca_cert)))

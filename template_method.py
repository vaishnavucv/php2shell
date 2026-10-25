#!/usr/bin/env python3
"""Python adaptation of ProjectDiscovery's PHP2Shell Nuclei method.

Derived from CVE-2026-109618.yaml, git blob
9d89d77dbd5f269dd0039534f204c16389911f46.
Authors: lcfr_hax, assetnote, princechaddha, s4e-io.
MIT, Copyright (c) 2025 ProjectDiscovery, Inc.
Full license: vendor/PROJECTDISCOVERY-LICENSE.txt.
No Nuclei runtime is required. See METHOD_REFERENCE.md for adaptations.
"""
import argparse
import http.client
import json
import time
import urllib.error
import urllib.request

from php_version import NoRedirect, assess, classify_headers, parse_url

SOURCE_URL = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-109618.yaml'
SOURCE_BLOB = '9d89d77dbd5f269dd0039534f204c16389911f46'
PROBES = ((1, 4000), (8, 1020), (20, 1020))
REJECTED = {400, 403, 411, 413, 414, 417, 422, 429, 431}
MAX_RESPONSE_BYTES = 262144


def build_probe(size_mib, parts):
    """Port of the template's buildProbe, retaining its LF multipart bytes."""
    size = size_mib * 1048576
    nested = b'[a]' * 62
    part = b'--\nContent-Disposition:name=a[]' + nested + b';filename=\n\n'
    base = part * parts
    filler_count = (size - len(base)) // 3
    if filler_count < 0:
        raise ValueError('Probe size is too small for the requested parts.')
    body = b'--\n' + b'x:\n' * filler_count + base[3:]
    return body[:-1]


def exchange(url, body, boundary, timeout):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(url, data=body, method='POST', headers={
        'Content-Type': 'multipart/form-data; boundary=' + boundary,
        'User-Agent': 'SIGiL-PHP2Shell-TemplateMethod/1.0', 'Connection': 'close'})
    started = time.monotonic()
    try:
        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
            headers = classify_headers(response.headers)
            return {'http_status': response.code, 'version': headers['version'],
                    'response_bytes_captured': min(len(content), MAX_RESPONSE_BYTES),
                    'response_truncated': len(content) > MAX_RESPONSE_BYTES,
                    'memory_error_signature': all(x in content[:MAX_RESPONSE_BYTES] for x in
                        (b'Allowed memory size of', b'bytes exhausted', b'Unknown')),
                    'elapsed_seconds': round(time.monotonic() - started, 4)}
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        return {'error': type(exc).__name__, 'elapsed_seconds': round(time.monotonic() - started, 4)}


def check(url, timeout=5):
    parse_url(url)
    if not 0 < timeout <= 30:
        raise ValueError('Timeout must be between 0 and 30 seconds.')
    out = {'method': 'projectdiscovery_python_adaptation',
           'evidence_family': 'multipart_oom_behavior',
           'source_url': SOURCE_URL, 'source_blob': SOURCE_BLOB,
           'target': url, 'kind': 'inconclusive', 'request_count': 0,
           'request_body_bytes': 0, 'rce_confirmed': False, 'observations': []}
    control_body = b'--x\nContent-Disposition:name=a;filename=\n'

    def send(body, boundary, role):
        out['request_count'] += 1
        out['request_body_bytes'] += len(body)
        record = exchange(url, body, boundary, timeout)
        out['observations'].append(dict(record, role=role, request_body_bytes=len(body)))
        return record

    control = send(control_body, 'x', 'control')
    if control.get('error') or control.get('http_status', 0) not in range(200, 300):
        out['reason'] = 'Control failed, redirected or was rejected; no active verdict possible.'
        return out
    versions = set()
    if control.get('version'):
        versions.add(control['version'])
    for size_mib, parts in PROBES:
        probe = send(build_probe(size_mib, parts), '', f'probe_{size_mib}MiB')
        if probe.get('version'):
            versions.add(probe['version'])
        out['observed_versions'] = sorted(versions)
        out['advertised_version'] = next(iter(versions)) if len(versions) == 1 else None
        if probe.get('error'):
            out['reason'] = 'Probe failed; a transport error is not proof of vulnerability.'
            return out
        if probe.get('memory_error_signature'):
            out['kind'] = 'ambiguous_runtime_anomaly'
            out['reason'] = 'Template memory-exhaustion matcher observed; patched PHP can also produce OOM errors.'
            return out
        status = probe.get('http_status', 0)
        if status in REJECTED or 300 <= status < 400:
            out['reason'] = 'Probe was rejected or redirected; no negative security verdict is possible.'
            return out
        if status >= 500:
            out['kind'] = 'ambiguous_runtime_anomaly'
            out['reason'] = 'Server error observed; source attribution to a PHP CVE is unverified.'
            return out
        if len(versions) == 1 and assess(next(iter(versions)))['status'] == 'upstream_fix_level_observed':
            break
    if len(versions) > 1:
        out['reason'] = 'Conflicting version banners across requests; inspect backend routing.'
    elif versions:
        out['kind'] = 'version_only'
        out['reason'] = 'No specific vulnerability proved; version fallback evaluated locally.'
    else:
        out['kind'] = 'no_signal'
        out['reason'] = 'No distinguishing signal or exact PHP version; this does not establish a patch.'
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url', required=True)
    p.add_argument('--timeout', type=int, default=5)
    a = p.parse_args()
    print(json.dumps(check(a.url, a.timeout)))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""One-target PHP2Shell assessment chain, with conservative evidence fusion."""
import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit

from php_version import CVES, WARNINGS, assess, parse_url, scan
from template_method import SOURCE_BLOB, SOURCE_URL

ASSETNOTE_COMMIT = '052b56ef4f9bf674aa31ac645068144747bade3d'
ASSETNOTE_BLOB = '287e97898ab759f6692c698f83d9a30d81db4fbb'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def load_attestation(path, target, key):
    """Only backend/agent assertions authenticated with a private runner key count."""
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise ValueError('Attestation exceeds 64 KiB.')
    doc = json.loads(raw)
    if not isinstance(doc, dict):
        raise ValueError('Attestation must be a JSON object.')
    payload = doc.get('payload')
    signature = doc.get('hmac_sha256')
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise ValueError('Invalid attestation envelope.')
    if not key or len(key.encode()) < 32:
        raise ValueError('SIGIL_EVIDENCE_KEY must contain at least 32 bytes on the trusted runner.')
    expected = hmac.new(key.encode(), canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError('Attestation signature mismatch.')
    if payload.get('target') != target:
        raise ValueError('Attestation must bind the exact requested target URL.')
    observed = dt.datetime.fromisoformat(payload['observed_at'])
    age = (dt.datetime.now(dt.timezone.utc) - observed).total_seconds()
    if not -30 <= age <= 3600:
        raise ValueError('Attestation is expired or future dated.')
    if payload.get('source') != 'trusted-web-runtime-agent':
        raise ValueError('Attestation must originate from a trusted web-runtime collector.')
    records = payload.get('runtimes')
    if not isinstance(records, list) or not records or len(records) > 128:
        raise ValueError('Attestation requires 1 to 128 runtime records.')
    for item in records:
        for field in ('runtime_id', 'version', 'package_revision', 'vendor_advisory'):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError('Runtime identity, version, package revision and advisory are required.')
        if item.get('active_workers_verified') is not True:
            raise ValueError('Active workers must be verified, not just files on disk.')
        if set(item.get('cve_status', {})) != set(CVES):
            raise ValueError('Each runtime must assess both target CVEs.')
        if any(v not in ('fixed', 'affected', 'unknown') for v in item['cve_status'].values()):
            raise ValueError('Invalid CVE status.')
    return payload


def active_signals(document):
    """An upstream VULNERABLE boolean is never accepted as proof of a CVE."""
    if not isinstance(document, dict) or not isinstance(document.get('results'), list):
        raise ValueError('Expected Assetnote JSON with a results array.')
    result = []
    for item in document['results']:
        if not isinstance(item, dict):
            raise ValueError('Malformed upstream result.')
        reason = str(item.get('reason') or '')[:2000]
        probes = item.get('probes') or []
        statuses = [p.get('status_code') for p in probes if isinstance(p, dict)]
        r = reason.lower()
        if (item.get('error') or item.get('verdict') in ('ERROR', 'INCONCLUSIVE')
                or any(isinstance(x, int) and 300 <= x < 400 for x in
                       [*statuses, (item.get('control') or {}).get('status_code')])):
            kind = 'inconclusive'
        elif 'no crash observed' in r:
            kind = 'version_only' if item.get('powered_by') else 'no_signal'
        elif (any(x in (500, 502, 503, 504) for x in statuses)
              or any(x in r for x in ('memory exhausted', 'crashed', 'empty body', 'worker died'))):
            kind = 'ambiguous_runtime_anomaly'
        elif item.get('verdict') == 'VULNERABLE':
            kind = 'unverified_upstream_positive'
        else:
            kind = 'no_signal'
        result.append({'kind': kind, 'upstream_verdict': item.get('verdict'),
                       'reason': reason, 'probe_statuses': statuses,
                       'advertised_version': item.get('powered_by')})
    return result


def run_active(script, url, timeout, insecure_tls=False, ca_cert=None):
    """Execute the reviewed upstream scanner without shell interpolation."""
    script = Path(script).resolve(strict=True)
    data = script.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if blob != ASSETNOTE_BLOB:
        raise ValueError('Assetnote scanner differs from the reviewed revision. Review before updating pin.')
    with tempfile.TemporaryDirectory(prefix='sigil-p2s-') as temp:
        out = Path(temp) / 'result.json'
        argv = [sys.executable, '-s', str(Path(__file__).with_name('assetnote_adapter.py')),
                '--script', str(script), '--url', url, '--timeout', str(timeout)]
        if insecure_tls:
            argv.append('--insecure-tls')
        if ca_cert:
            argv += ['--ca-cert', str(ca_cert)]
        # Credentials and proxy environment variables are not forwarded.
        env = {k: v for k, v in os.environ.items() if k in
               ('PATH', 'SYSTEMROOT', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'LANG', 'VIRTUAL_ENV')}
        env['PYTHONNOUSERSITE'] = '1'
        try:
            with out.open('w') as output, open(os.devnull, 'wb') as sink:
                proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output,
                                      stderr=sink, env=env, timeout=timeout * 6 + 10,
                                      check=False, shell=False)
            if proc.returncode != 0 or not out.exists():
                return [{'kind': 'inconclusive', 'reason': 'Upstream execution failed; check dependencies.'}]
            if out.stat().st_size > 2 * 1024 * 1024:
                raise ValueError('Upstream report exceeds size limit.')
            return [json.loads(out.read_text())]
        except subprocess.TimeoutExpired:
            return [{'kind': 'inconclusive', 'reason': 'Upstream execution exceeded deadline.', 'failure_stage': 'subprocess', 'timeout_category': 'stage_deadline'}]


def run_template(url, timeout, insecure_tls=False, ca_cert=None):
    """Run the Python method without Nuclei, with an outer stage deadline."""
    argv = [sys.executable, '-s', str(Path(__file__).with_name('template_method.py')),
            '--url', url, '--timeout', str(timeout)]
    if insecure_tls:
        argv.append('--insecure-tls')
    if ca_cert:
        argv += ['--ca-cert', str(ca_cert)]
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=timeout * 6 + 10, check=False, shell=False)
        if proc.returncode or len(proc.stdout) > 65536:
            return [{'kind': 'inconclusive', 'reason': 'Template adaptation failed.'}]
        value = json.loads(proc.stdout)
        if not isinstance(value, dict) or 'kind' not in value:
            raise ValueError('Malformed template method result.')
        return [value]
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return [{'kind': 'inconclusive', 'reason': 'Template adaptation timed out or returned invalid JSON.', 'failure_stage': 'subprocess'}]


def decide(passive, active, attestation=None):
    findings = []
    version_evidence = list(passive) + [assess(x.get('advertised_version')) for x in active]
    anomaly = any(x['kind'] in ('ambiguous_runtime_anomaly', 'unverified_upstream_positive')
                  for x in active)
    for cve in CVES:
        state, confidence = 'inconclusive', 'insufficient'
        reason = 'No authenticated runtime/package decision is available.'
        if attestation:
            records = attestation['runtimes']
            states = [x['cve_status'][cve] for x in records]
            if 'affected' in states:
                state, confidence = 'affected_runtime_verified', 'high'
                reason = 'Trusted agent reports at least one affected active runtime.'
            elif all(x == 'fixed' for x in states) and attestation.get('all_backends_covered') is True:
                state, confidence = 'patch_verified', 'high'
                reason = 'Trusted agent verifies fixes and active workers for all declared backends.'
        if confidence != 'high':
            if any(x.get('status') == 'potentially_affected' for x in version_evidence):
                state, confidence = 'potentially_affected', 'version_evidence'
                reason = 'At least one endpoint advertises an upstream version below its fix threshold.'
            elif any(x.get('status') == 'upstream_fix_level_observed' for x in version_evidence):
                state, confidence = 'fix_level_advertised', 'version_evidence'
                reason = 'A fix-level banner is visible; package and active-worker verification remain pending.'
            if anomaly:
                state, confidence = 'suspicious_behavior', 'behavioral_signal_only'
                reason = 'Active testing observed an anomaly also possible on patched or unrelated systems.'
        conflict = (state == 'patch_verified' and
                    any(x.get('status') == 'potentially_affected' for x in version_evidence))
        if conflict:
            state, confidence = 'evidence_conflict', 'requires_review'
            reason = 'Trusted patch evidence conflicts with an older public banner; check routing and freshness.'
        findings.append({'cve': cve, 'status': state, 'confidence_basis': confidence,
                         'reason': reason, 'rce_confirmed': False,
                         'anomaly_requires_separate_triage': anomaly})
    return findings


def run_chain(url, origins, authorization_ref, paths=(), timeout=5, active_script=None,
              attestation=None, budget=1, active_methods=(), profile='production',
              allow_disruptive=False, active_endpoints=(), insecure_tls=False, ca_cert=None):
    started = time.monotonic()
    timings = []

    def timed(stage, target, callback):
        before = time.monotonic()
        result = callback()
        timings.append({'stage': stage, 'target': target,
                        'elapsed_seconds': round(time.monotonic() - before, 4)})
        return result

    parsed, origin = parse_url(url)
    if origin not in {parse_url(x)[1] for x in origins}:
        raise ValueError('Target is outside authorized origins.')
    if not authorization_ref.strip():
        raise ValueError('Authorization reference is required.')
    urls = [url]
    for path in paths:
        if not path.startswith('/') or path.startswith('//') or '?' in path or '#' in path:
            raise ValueError('Paths must be absolute local paths without query/fragment.')
        candidate = urlunsplit((parsed.scheme, parsed.netloc, path, '', ''))
        parse_url(candidate)
        if candidate not in urls:
            urls.append(candidate)
    for endpoint in active_endpoints:
        if parse_url(endpoint)[1] != origin:
            raise ValueError('Active endpoint must share the authorized target origin.')
        if endpoint not in urls:
            urls.append(endpoint)
    if len(urls) > 6:
        raise ValueError('At most six explicit endpoints are supported.')
    if not 1 <= budget <= 3:
        raise ValueError('Active endpoint budget must be between 1 and 3.')
    methods = tuple(active_methods) or (('assetnote',) if active_script else ())
    if any(x not in ('template', 'assetnote') for x in methods) or len(set(methods)) != len(methods):
        raise ValueError('Select unique template and/or assetnote methods.')
    if profile not in ('production', 'lab'):
        raise ValueError('Profile must be production or lab.')
    if methods and profile == 'production' and not allow_disruptive:
        raise ValueError('Production active probes can disrupt PHP. Use passive assessment or explicitly supply --allow-disruptive under an approved test plan.')
    if 'assetnote' in methods and not active_script:
        active_script = str(Path(__file__).parent / 'vendor' / 'assetnote_scanner.py')
    passive = [timed('remote_version_assessment', u,
                    lambda u=u: scan(u, origins, authorization_ref, timeout, insecure_tls, ca_cert)) for u in urls]
    active = []
    recovery = []
    active_aborted = False
    if methods:
        for p in [x for x in passive if not active_endpoints or x['target'] in active_endpoints][:budget]:
            if p.get('http_status', 0) not in range(200, 300):
                active.append({'kind': 'inconclusive', 'target': p['target'],
                               'reason': 'Endpoint unsuitable: baseline is not HTTP 2xx.',
                               'endpoint_suitability': p.get('endpoint_suitability', 'unsuitable'),
                               'redirect_location': p.get('redirect_location')})
                continue
            for method in methods:
                results = timed(method + '_active_assessment', p['target'],
                    lambda: run_template(p['target'], timeout, insecure_tls, ca_cert) if method == 'template'
                    else run_active(active_script, p['target'], timeout, insecure_tls, ca_cert))
                active.extend(dict(x, target=p['target'], method=method,
                                   evidence_family='multipart_oom_behavior') for x in results)
                health = timed('post_' + method + '_recovery', p['target'],
                               lambda: scan(p['target'], origins, authorization_ref, timeout, insecure_tls, ca_cert))
                recovery.append({'after_method': method, 'target': p['target'],
                                 'http_status': health.get('http_status'), 'status': health['status'],
                                 'recovered': health.get('http_status', 0) in range(200, 300),
                                 'elapsed_seconds': health.get('elapsed_seconds'),
                                 'failure_stage': health.get('failure_stage'),
                                 'timeout_category': health.get('timeout_category')})
                if health.get('http_status', 0) not in range(200, 300):
                    active.append({'kind': 'inconclusive', 'target': p['target'], 'method': method,
                                   'reason': 'Recovery request failed; further active testing stopped.'})
                    active_aborted = True
                    break
            if active_aborted:
                break
    # Kinds that mean the method's probes actually ran to a verdict (as opposed
    # to stopping at an unsuitable/redirected control or a transport failure).
    VALIDATED_KINDS = ('version_only', 'no_signal', 'ambiguous_runtime_anomaly',
                       'unverified_upstream_positive')
    for item in active:
        item.setdefault('active_validation_status', 'inconclusive' if item['kind'] == 'inconclusive'
                        else 'anomaly_observed' if item['kind'] in ('ambiguous_runtime_anomaly', 'unverified_upstream_positive')
                        else 'no_confirming_evidence')
        item.setdefault('evidence_confidence', 'insufficient' if item['kind'] == 'inconclusive' else 'low')
        for field in ('control_request_status', 'redirect_location', 'failure_stage', 'timeout_category'):
            item.setdefault(field, None)
        # Execution is reported in four independent stages so control-only runs
        # are never described as completed vulnerability validation (rc7).
        invoked = 'method' in item
        recovery_stop = str(item.get('reason', '')).startswith('Recovery')
        control_completed = isinstance(item.get('control_request_status'), int) and \
            200 <= item['control_request_status'] < 300
        validation_completed = invoked and control_completed and item['kind'] in VALIDATED_KINDS
        item['execution'] = {
            'method_invoked': invoked,
            'control_completed': bool(control_completed),
            'active_validation_completed': bool(validation_completed),
            'vulnerability_confirmed': False,
        }
        if not invoked:
            item['execution_status'] = 'skipped_unsuitable_endpoint'
        elif recovery_stop:
            item['execution_status'] = 'stopped_after_recovery_failure'
        elif validation_completed:
            item['execution_status'] = 'active_validation_completed'
        elif not control_completed:
            item['execution_status'] = 'control_blocked'
        else:
            item['execution_status'] = 'control_only'
    findings = decide(passive, active, attestation)
    validation = ('not_performed' if not active else 'inconclusive' if any(
        x['active_validation_status'] == 'inconclusive' for x in active) else
        'anomaly_observed' if any(x['active_validation_status'] == 'anomaly_observed' for x in active)
        else 'no_confirming_evidence')

    # rc7: two distinct suitability dimensions, so a "suitable" GET baseline is
    # never read as "suitable for active POST testing".
    primary = passive[0] if passive else {}
    pstatus = primary.get('http_status')
    if primary.get('status') == 'error':
        baseline_reachability = 'unreachable'
    elif pstatus is None:
        baseline_reachability = 'unknown'
    elif pstatus in (401, 403):
        baseline_reachability = 'authentication_required'
    elif 200 <= pstatus < 300:
        baseline_reachability = 'reachable'
    elif 300 <= pstatus < 400:
        baseline_reachability = 'redirect'
    else:
        baseline_reachability = 'reachable_nonstandard'

    # Aggregate the POST-control suitability actually observed by the methods.
    if not methods:
        active_endpoint_suitability = 'not_assessed'
    elif any(x['execution'].get('control_completed') for x in active if 'method' in x):
        active_endpoint_suitability = 'suitable'
    else:
        control_suits = {x.get('endpoint_suitability') for x in active}
        if 'authentication_required' in control_suits:
            active_endpoint_suitability = 'authentication_required'
        elif 'redirect_requires_explicit_endpoint' in control_suits:
            active_endpoint_suitability = 'redirect_requires_explicit_endpoint'
        else:
            active_endpoint_suitability = 'unsuitable'

    # Remediation is derived from what actually failed, not a fixed list (rc7).
    recommendations = []
    if any(x.get('status') in ('potentially_affected', 'upstream_fix_level_observed') for x in passive):
        recommendations.append('Confirm the web runtime, package revision and vendor backports with trusted '
                               'inventory; an advertised version alone is not proof of an unpatched runtime.')
    if active_endpoint_suitability == 'authentication_required':
        recommendations.append('The active endpoint requires authentication or redirects to a login route. '
                               'Supply an explicitly authorized, unauthenticated endpoint that accepts a '
                               'multipart POST via --active-endpoint; scope is never expanded automatically.')
    elif active_endpoint_suitability in ('redirect_requires_explicit_endpoint', 'unsuitable'):
        recommendations.append('The active endpoint did not accept the multipart control. Supply an explicitly '
                               'authorized endpoint accepting multipart POST via --active-endpoint.')
    if any(x.get('tls_error_category') for x in passive):
        recommendations.append('Resolve the TLS trust/hostname failure (use --ca-cert with a trusted bundle or a '
                               'certificate valid for the target) before any operator-approved reassessment.')
    if any(not r.get('recovered', True) for r in recovery):
        recommendations.append('A post-probe recovery check did not return HTTP 2xx; verify worker health '
                               'independently before further testing.')
    recommendations.append('Apply the vendor fixes to affected runtimes and restart/redeploy all relevant workers, '
                           'then rescan.')
    for finding in findings:
        finding.update(active_validation_status=validation,
                       version_exposure_status=('potentially_affected' if any(x.get('status') == 'potentially_affected' for x in passive)
                           else 'upstream_fix_level_observed' if any(x.get('status') == 'upstream_fix_level_observed' for x in passive) else 'unknown'),
                       evidence_confidence='high' if finding['confidence_basis'] == 'high' else 'low' if finding['confidence_basis'] != 'insufficient' else 'insufficient',
                       evidence_provenance={'passive_targets': [x['target'] for x in passive],
                                            'active_methods': [x['method'] for x in active if x.get('method')],
                                            'authenticated_runtime_inventory': attestation is not None})
    catalog = [
        {'id': 'remote_version', 'enabled': True, 'family': 'advertised_runtime_version'},
        {'id': 'projectdiscovery_python', 'enabled': 'template' in methods, 'family': 'multipart_oom_behavior'},
        {'id': 'assetnote', 'enabled': 'assetnote' in methods, 'family': 'multipart_oom_behavior'},
        {'id': 'trusted_runtime_evidence', 'enabled': attestation is not None, 'family': 'authenticated_runtime_inventory'}]
    coverage = []
    for item in passive:
        status = item.get('http_status')
        if item.get('status') == 'error':
            access = 'request_failed'
        elif status in (401, 403):
            access = 'authentication_or_access_restricted'
        elif status == 429:
            access = 'rate_limited'
        elif status is not None and 300 <= status < 400:
            access = 'redirect_not_followed'
        elif status is not None and status >= 500:
            access = 'server_or_gateway_error'
        elif status == 404:
            access = 'route_not_found'
        else:
            access = 'http_response_observed'
        coverage.append({'target': item['target'], 'http_status': status,
                         'access_observation': access,
                         'redirect_location': item.get('redirect_location'),
                         'redirect_classification': item.get('redirect_classification'),
                         'endpoint_suitability': item.get('endpoint_suitability'),
                         'php_signal_observed': item.get('php_signal_observed', False),
                         'signed_runtime_evidence_supplied': attestation is not None,
                         'interpretation': 'HTTP reachability and banners do not prove access to every PHP backend.'})
    def _dedup(seq):
        seen = []
        for v in seq:
            if v and v not in seen:
                seen.append(v)
        return seen

    return {'schema_version': '3.2', 'scanner_version': '1.0.0-rc7', 'scanner': 'SIGiL PHP2Shell Chain',
            'ruleset_date': '2026-10-25', 'target': url,
            'build': {'scanner_version': '1.0.0-rc7',
                      'source_commit': os.environ.get('SIGIL_SOURCE_COMMIT', 'unknown'),
                      'assetnote_blob': ASSETNOTE_BLOB, 'template_blob': SOURCE_BLOB},
            'profile': profile, 'disruptive_testing_opt_in': bool(allow_disruptive),
            'tls_verification': 'disabled' if insecure_tls else 'enabled',
            'ca_cert_supplied': bool(ca_cert),
            'baseline_reachability': baseline_reachability,
            'active_endpoint_suitability': active_endpoint_suitability,
            'active_methods_invoked': _dedup(x.get('method') for x in active),
            'active_methods_validated': _dedup(x.get('method') for x in active
                                               if x.get('execution', {}).get('active_validation_completed')),
            # Back-compat alias: methods that reached completed active validation.
            'active_methods_executed': _dedup(x.get('method') for x in active
                                              if x.get('execution', {}).get('active_validation_completed')),
            'coverage': coverage, 'active_validation_status': validation,
            'remediation_recommendations': recommendations,
            'assessment_type': 'PHP2Shell-specific assessment, not a complete PHP application VAPT',
            'authorization_ref': authorization_ref, 'findings': findings,
            'passive_evidence': passive, 'active_evidence': active,
            'recovery_checks': recovery, 'active_stopped_after_recovery_failure': active_aborted,
            'timing': {'total_elapsed_seconds': round(time.monotonic() - started, 4), 'stages': timings},
            'method_catalog': catalog, 'methods_enabled': sum(x['enabled'] for x in catalog),
            'active_method_correlation': 'Template and Assetnote share multipart/OOM evidence. They are not independent CVE confirmations.',
            'attestation_verified': attestation is not None,
            'scope': 'Only the explicitly assessed endpoints and declared backend coverage.',
            'accuracy': {'measured': False, 'percentage': None},
            'next_actions': ['Confirm web-runtime/package identity and vendor backports.',
                             'Upgrade affected PHP and restart/redeploy every relevant worker.',
                             'Rescan the same routes and verify active-worker evidence.'],
            'warnings': [*WARNINGS, 'A passing URL can be assessed, but CDN/WAF masking, authentication and hidden versions can leave runtime status inconclusive.'],
            'upstream': {'assetnote_commit': ASSETNOTE_COMMIT, 'assetnote_blob': ASSETNOTE_BLOB,
                         'projectdiscovery_template_blob': SOURCE_BLOB, 'projectdiscovery_url': SOURCE_URL}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url', required=True)
    p.add_argument('--allow-origin', action='append', required=True)
    p.add_argument('--authorization-ref', required=True)
    p.add_argument('--path', action='append', default=[])
    p.add_argument('--active-endpoint', action='append', default=[],
                   help='Exact authorized URL for active tests; same origin, no query/fragment. Repeat within budget.')
    p.add_argument('--timeout', type=int, default=5, choices=range(1, 31))
    p.add_argument('--profile', choices=('production', 'lab'), default='production',
                   help='production defaults to passive assessment')
    p.add_argument('--allow-disruptive', action='store_true',
                   help='Explicitly allow active probes on an approved production test plan')
    p.add_argument('--active', action='store_true', help='Enable intrusive upstream testing on explicitly approved endpoints')
    p.add_argument('--active-method', choices=('template', 'assetnote', 'both'), default='template',
                   help='template is Python-native and requires no Nuclei binary (default)')
    p.add_argument('--assetnote-script')
    p.add_argument('--active-endpoint-budget', type=int, default=1, choices=range(1, 4))
    p.add_argument('--attestation', help='HMAC-authenticated backend web-runtime evidence')
    p.add_argument('--ca-cert', help='Trusted CA bundle (PEM) for a private PKI; verification stays enabled')
    p.add_argument('--insecure-tls', action='store_true',
                   help='Opt out of TLS certificate verification for an authorized lab with a '
                        'self-signed or IP-only certificate; never disabled automatically')
    p.add_argument('--output')
    a = p.parse_args()
    if a.ca_cert and a.insecure_tls:
        p.error('--ca-cert and --insecure-tls are mutually exclusive.')
    if a.ca_cert and not Path(a.ca_cert).is_file():
        p.error('--ca-cert must point to a readable PEM bundle.')
    if a.assetnote_script and not a.active:
        p.error('--assetnote-script requires --active.')
    if a.active_method != 'template' and not a.active:
        p.error('--active-method assetnote or both requires --active.')
    active_script = a.assetnote_script or str(Path(__file__).parent / 'vendor' / 'assetnote_scanner.py')
    if a.assetnote_script and a.active_method == 'template':
        p.error('--assetnote-script requires --active-method assetnote or both.')
    methods = (() if not a.active else ('template', 'assetnote') if a.active_method == 'both'
               else (a.active_method,))
    if a.active_endpoint and not a.active:
        p.error('--active-endpoint requires --active.')
    if a.allow_disruptive and not a.active:
        p.error('--allow-disruptive requires --active.')
    try:
        evidence = load_attestation(a.attestation, a.url, os.environ.get('SIGIL_EVIDENCE_KEY')) if a.attestation else None
        report = run_chain(a.url, a.allow_origin, a.authorization_ref, a.path, a.timeout,
                           active_script if 'assetnote' in methods else None, evidence,
                           a.active_endpoint_budget, methods, a.profile, a.allow_disruptive,
                           a.active_endpoint, a.insecure_tls, a.ca_cert)
        encoded = json.dumps(report, indent=2)
        if a.output:
            Path(a.output).write_text(encoded + '\n')
        print(encoded)
        return 1 if all(x.get('status') == 'error' for x in report['passive_evidence']) else 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        p.error(str(exc))


if __name__ == '__main__':
    raise SystemExit(main())

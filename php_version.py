#!/usr/bin/env python3
"""SIGiL PHP2Shell version assessment. Python 3.10+, standard library only."""
import argparse
import datetime as dt
import http.client
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

CVES = ['CVE-2026-109618', 'CVE-2026-109619']
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
REFERENCES = [
    'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w',
    'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp',
    'https://www.php.net/index.php',
]
WARNINGS = [
    'Version assessment only; exploitability and patch provenance are not verified.',
    'Headers can be hidden, stale, forged, or rewritten by a proxy.',
    'Vendor backports require package revision and vendor advisory verification.',
    'Assess every web runtime and worker; CLI PHP may differ from the web runtime.',
    'The fixed-version result covers these two CVEs only. PHP published a separate '
    'session upload progress notice on 2026-10-23, referencing CVE-2026-115560.',
]


def assess(version):
    """Avoid declaring vendor suffixes, prereleases or unknown branches patched."""
    out = {'version': version, 'status': 'unknown', 'fixed_version': None}
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', version or '')
    if not match:
        out['reason'] = 'Missing, nonstable, or vendor-specific version; inspect runtime/package.'
        return out
    major, minor, patch = map(int, match.groups())
    branch = major, minor
    if branch in FIXED:
        out['fixed_version'] = f'{major}.{minor}.{FIXED[branch]}'
        out['status'] = ('potentially_affected' if patch < FIXED[branch]
                         else 'upstream_fix_level_observed')
        out['reason'] = 'Compared with the first upstream fix for this branch.'
    elif branch in {(5, 4), (5, 5), (5, 6), (7, 0), (7, 1),
                    (7, 2), (7, 3), (7, 4), (8, 0), (8, 1)}:
        out['status'] = 'potentially_affected'
        out['reason'] = 'Legacy branch; migrate or verify vendor backports for both CVEs.'
    else:
        out['reason'] = 'Branch outside this ruleset; consult current upstream/vendor guidance.'
    return out


def parse_url(url):
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError('Provide a URL up to 4096 characters.')
    if any(ord(c) <= 32 or ord(c) == 127 for c in url) or '\\' in url:
        raise ValueError('URL contains whitespace, controls, or backslashes.')
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Only explicit http:// or https:// URLs are supported.')
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('URL credentials are not supported.')
    if parsed.query or parsed.fragment:
        raise ValueError('Use an exact path without a query or fragment.')
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid port.')
    origin = (parsed.scheme, parsed.hostname.lower(), port)
    return parsed, origin


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def https_context(insecure_tls):
    """TLS context for HTTPS requests.

    Certificate verification is on by default. An explicit opt-in disables it
    for authorized labs whose targets use self-signed or IP-only certificates
    (the common case for a bare https://ip:port endpoint). This mirrors how
    active probing is gated behind an explicit --allow-disruptive opt-in: the
    risk is accepted deliberately, never silently.
    """
    if not insecure_tls:
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _build_opener(insecure_tls):
    handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
    context = https_context(insecure_tls)
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def classify_transport_error(exc):
    """Turn a urllib/OSError into a structured diagnostic so an operator can tell
    a TLS rejection from a timeout from a plain connect failure. Returns a dict
    plus (is_tls, is_timeout) so callers can add a hint without re-checking."""
    cause = getattr(exc, 'reason', None)
    underlying = cause if isinstance(cause, BaseException) else exc
    name = type(underlying).__name__
    text = str(underlying)
    is_tls = (isinstance(underlying, ssl.SSLError)
              or 'SSL' in name or 'CERTIFICATE_VERIFY_FAILED' in str(exc))
    is_timeout = (isinstance(underlying, (socket.timeout, TimeoutError))
                  or 'timed out' in text.lower())
    if is_tls:
        stage = 'tls_handshake'
    elif is_timeout:
        stage = 'timeout'
    else:
        stage = 'baseline_connectivity'
    info = {'error_type': name, 'error_detail': text[:500], 'error_stage': stage}
    if is_timeout:
        # urllib surfaces a single socket timeout; it cannot reliably separate a
        # connect timeout from a read timeout, so we report the honest category.
        info['timeout_category'] = 'socket_timeout'
    return info, is_tls, is_timeout


def classify_headers(headers):
    evidence = []
    versions = set()
    php_signal = False
    for key in ('X-Powered-By', 'Server'):
        for value in headers.get_all(key, []):
            tokens = re.findall(r'(?i)\bPHP/([^\s,;()]+)', value)
            versions.update(tokens)
            if re.search(r'(?i)\bPHP\b', value):
                php_signal = True
                evidence.append({'source': key, 'value': value[:1024]})
    # A session cookie is merely a technology hint; do not persist cookie values.
    cookie_hint = any(re.match(r'(?i)^PHPSESSID=', v.strip())
                      for v in headers.get_all('Set-Cookie', []))
    if cookie_hint:
        php_signal = True
        evidence.append({'source': 'Set-Cookie', 'value': 'PHPSESSID present; value redacted'})
    if len(versions) == 1:
        result = assess(next(iter(versions)))
    else:
        result = assess(None)
        result['reason'] = ('Conflicting PHP banners; inspect each backend.' if versions
                            else 'No exact PHP version exposed; authenticated inventory required.')
    result.update({'php_signal_observed': php_signal, 'evidence': evidence,
                   'observed_versions': sorted(versions)})
    return result


def scan(url, allowed_origins, authorization_ref, timeout=5, insecure_tls=False):
    parsed, origin = parse_url(url)
    if not authorization_ref or not authorization_ref.strip():
        raise ValueError('An authorization reference is required.')
    if not 0 < timeout <= 30:
        raise ValueError('Timeout must be greater than 0 and at most 30 seconds.')
    scope = set()
    for allowed in allowed_origins:
        p, item = parse_url(allowed)
        if p.path not in ('', '/'):
            raise ValueError('Allowed origins must not include a path.')
        scope.add(item)
    if origin not in scope:
        raise ValueError('Target origin is outside the supplied authorized scope.')
    result = {
        'schema_version': '1.0', 'node_id': 'sigil.php2shell.version-assessment',
        'ruleset_date': '2026-10-25', 'cves': CVES,
        'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'target': url, 'authorization_ref': authorization_ref,
        'assessment_method': 'http_response_headers', 'rce_confirmed': False,
        'request_method': 'GET', 'request_count': 0, 'redirects_followed': False,
        'tls_verification': 'disabled' if insecure_tls else 'enabled',
        'warnings': WARNINGS, 'references': REFERENCES,
    }
    # Ignore environment proxies. HTTPS verification follows the opt-in above.
    opener = _build_opener(insecure_tls)
    request = urllib.request.Request(url, headers={
        'User-Agent': 'SIGiL-PHP2Shell-Assessment/1.0',
        'Accept': '*/*', 'Connection': 'close',
    }, method='GET')
    try:
        result['request_count'] = 1
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            # Error/redirect response headers still provide evidence.
            response = exc
        with response:
            result['http_status'] = response.code
            result.update(classify_headers(response.headers))
            if 300 <= response.code < 400:
                result['warnings'] = [*WARNINGS, 'Redirect not followed; assess the approved destination explicitly.']
            # Do not download or retain the response body.
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        # URLError wraps the real cause in .reason; surface it so an operator can
        # tell a TLS rejection from a timeout from a plain connect failure.
        info, is_tls, _ = classify_transport_error(exc)
        error = {'status': 'error', 'reason': type(exc).__name__,
                 'active_checks_executed': False,
                 'evidence': [], 'version': None, 'fixed_version': None}
        error.update(info)
        if is_tls and not insecure_tls:
            error['tls_hint'] = ('Certificate verification failed. For an authorized lab whose '
                                 'target uses a self-signed or IP-only certificate, re-run with '
                                 '--insecure-tls to accept it deliberately.')
        result.update(error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--url', help='One exact approved HTTP endpoint')
    mode.add_argument('--version', help='Offline assessment of an observed runtime version')
    parser.add_argument('--allow-origin', action='append', default=[])
    parser.add_argument('--authorization-ref', default='')
    parser.add_argument('--timeout', type=float, default=5)
    parser.add_argument('--insecure-tls', action='store_true',
                        help='Opt in to skip TLS certificate verification (authorized labs only)')
    args = parser.parse_args()
    if args.version is not None:
        result = assess(args.version)
        result.update({'schema_version': '1.0', 'cves': CVES, 'ruleset_date': '2026-10-25',
                       'assessment_method': 'operator_supplied_version',
                       'rce_confirmed': False, 'warnings': WARNINGS, 'references': REFERENCES})
    else:
        try:
            result = scan(args.url, args.allow_origin, args.authorization_ref, args.timeout,
                          insecure_tls=args.insecure_tls)
        except ValueError as exc:
            parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 1 if result['status'] == 'error' else 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Single-attempt HTTP transport. Never follows redirects or uses proxy settings."""
import http.client
import re
import socket
import ssl
import time
from urllib.parse import urlsplit


def response_context(url, status, location):
    redirect = status is not None and 300 <= status < 400
    login = bool(redirect and location and re.search(
        r'(?i)(?:^|[/?.=&_-])(login|logon|signin|sign-in|auth|oauth|sso)(?:$|[/?.=&_-])', location))
    return {'redirect_location': location if redirect else None,
            'redirect_classification': ('authentication_redirect' if login else
                'application_redirect_unverified') if redirect else None,
            'endpoint_suitability': ('authentication_required' if login or status in (401, 403)
                else 'redirect_requires_explicit_endpoint' if redirect else
                'suitable' if status is not None and 200 <= status < 300 else 'unsuitable'),
            'redirects_followed': False}


def build_tls_context(insecure_tls=False, ca_cert=None):
    """Strict verification by default. An operator may supply a trusted CA
    bundle (--ca-cert) for a private PKI, or explicitly opt out of verification
    (--insecure-tls) for an authorized lab whose target uses a self-signed or
    IP-only certificate. Verification is never disabled automatically."""
    if insecure_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if ca_cert:
        return ssl.create_default_context(cafile=ca_cert)
    return ssl.create_default_context()


def _tls_error_category(exc):
    """Name the TLS failure without leaking request contents."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return 'certificate_verification_failed'
    if isinstance(exc, ssl.SSLError):
        return 'tls_handshake_failed'
    return None


def request_once(url, method, timeout, body=None, headers=None, capture_limit=0,
                 insecure_tls=False, ca_cert=None):
    parsed = urlsplit(url)
    started = time.monotonic()
    result = {'http_status': None, 'redirect_location': None, 'failure_stage': None,
              'timeout_category': None, 'elapsed_seconds': 0, 'redirects_followed': False,
              'tls_verification': 'disabled' if insecure_tls else 'enabled'}
    stage = 'connection'
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or
        (443 if parsed.scheme == 'https' else 80), timeout=timeout)
    response_headers, content = None, b''
    try:
        connection.connect()
        if parsed.scheme == 'https':
            stage = 'tls'
            context = build_tls_context(insecure_tls, ca_cert)
            connection.sock = context.wrap_socket(
                connection.sock, server_hostname=parsed.hostname)
        stage = 'write'
        connection.request(method, parsed.path or '/', body=body, headers=headers or {})
        stage = 'read'
        response = connection.getresponse()
        response_headers = response.headers
        result['http_status'] = response.status
        result.update(response_context(url, response.status, response.getheader('Location')))
        # wrap_socket replaced redirects_followed=False from response_context; keep tls_verification.
        result['tls_verification'] = 'disabled' if insecure_tls else 'enabled'
        if capture_limit:
            content = response.read(capture_limit + 1)
    except (OSError, http.client.HTTPException) as exc:
        result['error'] = type(exc).__name__
        result['failure_stage'] = stage
        # The exception text here describes the transport (cert/host/connect),
        # not request bodies, so a bounded detail is safe and aids triage.
        result['error_detail'] = str(exc)[:300]
        if isinstance(exc, (TimeoutError, socket.timeout)):
            # stage ∈ {connection, tls, write, read}: a per-stage timeout class.
            result['timeout_category'] = stage + '_timeout'
        category = _tls_error_category(exc)
        if category:
            result['tls_error_category'] = category
        result['endpoint_suitability'] = 'inconclusive'
    finally:
        connection.close()
        result['elapsed_seconds'] = round(time.monotonic() - started, 4)
    return result, response_headers, content

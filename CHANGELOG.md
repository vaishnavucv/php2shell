# Changelog

## 1.0.0-rc6

TLS policy, endpoint-suitability and reporting hardening. Report schema stays
`3.2`; `scanner_version` is `1.0.0-rc6`.

### P0 — Connectivity and TLS
- Certificate verification stays **on by default** and is never disabled
  automatically.
- `--ca-cert <bundle.pem>`: verify against an operator-supplied trusted CA
  (private PKI / internal CA) while keeping verification enabled. Scanning by a
  DNS hostname covered by the certificate is the preferred path.
- `--insecure-tls`: explicit, operator-acknowledged opt-out of verification for
  an authorized lab whose target uses a self-signed or IP-only certificate.
  Mutually exclusive with `--ca-cert`.
- Transport errors keep a complete, bounded `error_detail`, a
  `tls_error_category` (`certificate_verification_failed` /
  `tls_handshake_failed`) and a `failure_stage`, so a TLS rejection is never
  confused with an HTTP status failure. `tls_verification` (`enabled` /
  `disabled`) is recorded on every request and in the report header.

### P0 — Endpoint suitability
- GET baseline reachability is assessed separately from POST control
  suitability. Each request records HTTP status, redirect destination, redirect
  classification and timing.
- A login/redirect route (3xx to an auth path, or 401/403) is classified
  (`authentication_redirect` / `authentication_required`) and marked unsuitable
  for multipart active assessment; the control stops and no active verdict is
  produced.
- Active testing still requires an explicitly authorized endpoint
  (`--active-endpoint`, same origin). No endpoint is discovered or tested
  automatically.

### P1 — Timeout and recovery
- Timeouts are classified by the stage they occur in:
  `connection_timeout`, `tls_timeout`, `write_timeout`, `read_timeout`.
- A timeout or an HTTP 5xx alone is never treated as proof of a vulnerability.
- Recovery checks are recorded separately from findings (`recovered`,
  `http_status`, `failure_stage`, `timeout_category`); disruptive testing stops
  when recovery cannot be established.

### P1 — Reporting
- `active_methods_executed` (header) and `evidence_provenance.active_methods`
  are `[]` when no active method runs.
- Each active-evidence entry carries an `execution_status`
  (`executed` / `skipped_unsuitable_endpoint` / `stopped_after_recovery_failure`)
  that is independent of its verdict (`active_validation_status`).
- Version exposure (`version_exposure_status`), active validation
  (`active_validation_status`) and RCE confirmation (`rce_confirmed`, always
  `false`) are reported as distinct fields, per CVE, with evidence provenance.
- Report structure is identical across the `production` and `lab` profiles.

### P1 — Runtime evidence
- Signed trusted-runtime inventory (`--attestation`) continues to be the only
  path to a high-confidence `affected_runtime_verified` / `patch_verified`
  verdict; advertised PHP versions remain distinct from authenticated package
  versions, and incomplete or unverified inventories are rejected.

### Internal
- Fixed CI: the publish workflow builds with `no-cache` so the published image
  always reflects committed source (an earlier `type=gha` cache baked stale
  scanner code under a new version label).
- `Dockerfile` now copies the `http_diagnostics.py` and `assetnote_adapter.py`
  modules the 3.2 chain depends on.

### Tests & samples
- Added coverage for TLS mismatch (strict reject, `--insecure-tls` accept,
  `--ca-cert` accept), HTTP 303 login-redirect suitability, read-stage timeout,
  HTTP 200 recovery, incomplete/unverified runtime evidence,
  `active_methods: []`, and production/lab structural parity.
- `samples/` holds a production strict-TLS-mismatch report and a lab
  insecure-TLS active report.

## 1.0.0-rc5 and earlier
Schema 3.2 reporting (active validation vs version exposure vs RCE, evidence
provenance, endpoint suitability, redirect classification); exact-endpoint
Assetnote adapter; ProjectDiscovery template adaptation; conservative evidence
fusion that never reports confirmed RCE from behavioural signals alone.

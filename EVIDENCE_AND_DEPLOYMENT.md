# Trusted evidence and SIGiL deployment

## Optional trusted runtime evidence

The CLI supports `--attestation evidence.json`. SIGiL must implement a trusted web-runtime collector to generate it; this package does not include a universal host collector. Do not treat CLI `php -v` alone as the web runtime, or accept user-uploaded package claims as authenticated findings.

Envelope schema:

```json
{
  "payload": {
    "target": "http://127.0.0.1:8080/index.php",
    "source": "trusted-web-runtime-agent",
    "observed_at": "CURRENT_UTC_ISO8601_TIMESTAMP",
    "all_backends_covered": true,
    "runtimes": [{
      "runtime_id": "deployment/pool/worker-group",
      "version": "8.3.36",
      "package_revision": "ACTUAL_VENDOR_PACKAGE_REVISION",
      "vendor_advisory": "ACTUAL_ADVISORY_COVERING_THE_CVES",
      "active_workers_verified": true,
      "cve_status": {
        "CVE-2026-109618": "fixed",
        "CVE-2026-109619": "fixed"
      }
    }]
  },
  "hmac_sha256": "BACKEND_GENERATED_SIGNATURE"
}
```

This is an illustrative schema, not usable patch evidence. The trusted agent signs the exact canonical payload using HMAC-SHA256 and the runner's private key. Canonical encoding is UTF-8 JSON with sorted keys, separators `(',', ':')`, and `ensure_ascii=True`, implemented by `canonical()` in scanner.py. A key of at least 32 bytes is supplied through `SIGIL_EVIDENCE_KEY`, exclusively on trusted backend workers. Use independent keys per tenant and rotate them. Evidence binds the exact URL, expires after one hour, and must cover active workers. Allowed per-CVE states are fixed, affected and unknown.

## SIGiL deployment

Use the existing authenticated node runner to call the CLI with an argument list or call `run_chain()` from trusted backend code. The chain's authorization reference is an audit label, not an authentication mechanism. Derive origins, asset ownership, approval and agent identity from SIGiL's server-side policy.

Localhost refers to the scanner runner. Your laptop lab requires a local agent or an explicitly reachable lab network endpoint. Run the scanner in an isolated lab network, not on a privileged application server. Enforce DNS/IP destination policy and tenant isolation at the network layer; string-origin validation is not complete SSRF protection. Block metadata/control-plane endpoints and unauthorized tenant networks.

Keep one job per asset at a time. The active adapter uses a subprocess deadline, no shell interpolation, no redirects flag and no forwarded proxy/credential environment variables. Apply an outer deadline to the whole node as well. The upstream script may import its dependencies; dependency version locking is still required for production.

UI: label the mode, target, paths, status and confidence basis. Offer evidence details, remediation task creation and rescan. Display remote evidence as escaped text, never HTML. Do not present inconclusive results as passed or patched.


# Production URLs and approved VAPT use

The scanner accepts explicit HTTP/HTTPS production URLs. `host.docker.internal` is only a Docker Desktop mechanism for reaching a service on your workstation; it is not required for an internet-hosted production service. No `/index.php` suffix is required. PHP applications using a router can be assessed at `/`, `/app/` or another approved route.

This package assesses the two PHP2Shell CVEs. It is not a complete PHP application security scanner, source-code audit, or full VAPT. Containerization and production URL support do not establish a measured detection accuracy or a production deployment certification.

## Build the updated image

```bash
docker build -t sigil-php2shell:1.0-rc2 .
mkdir -p reports
```

## Default production assessment

Replace the illustrative example domain with your approved production host:

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$(pwd)/reports",dst=/reports \
  sigil-php2shell:1.0-rc2 \
  --url https://app.example.com/ \
  --allow-origin https://app.example.com \
  --authorization-ref approved-vapt-engagement \
  --profile production \
  --output /reports/result.json
```

The production profile is the default even if the profile flag is omitted. This command makes one ordinary GET to the specified endpoint and reads headers. It does not send crafted multipart probes. Use an approved read-only route: applications can attach side effects even to GET endpoints.

To assess additional known routes, add explicit flags such as `--path /app/` or `--path /admin/`. Each route adds a GET, up to six distinct endpoints. No crawling, port scanning, bulk host enumeration or automatic redirect following takes place. URL query strings, fragments and embedded credentials are intentionally unsupported in this release. Use an exact route without those components.

All Docker options belong before the image name. All scanner options belong after it. The allowed origin must match scheme, host and port; do not include a path in --allow-origin.

## Explicit active production assessment

Both active methods can consume PHP worker resources and cause request failures. Use only where the engagement permits potentially disruptive tests and the operator has selected an appropriate test window.

To the command above, add:

```bash
--active --active-method both --allow-disruptive
```

Alternatively use `--active-method template` for the native Python ProjectDiscovery adaptation, or `assetnote` for the vendored scanner. The production profile rejects active mode without --allow-disruptive before making network requests. The flag records an explicit operator choice; it is not independent proof of authorization.

Local lab testing can use `--profile lab --active --active-method both`. Lab is a profile label, not a network restriction or an authorization bypass: backend-approved scope is still mandatory. Direct Python API calls to run_chain() enforce the same production opt-in by default.

## TLS, private production systems and proxies

HTTPS certificate verification stays enabled. The scanner does not provide an insecure TLS bypass. For an internal CA, mount the approved CA bundle read-only and supply SSL_CERT_FILE through the backend runner. The bundle must contain the trust anchors required for your target. A certificate failure is reported as a request failure rather than a patched result.

Private production systems require a scanner worker with an approved network route, VPN or dedicated internal agent. Public URLs require outbound DNS and HTTP/HTTPS access from the container. The localhost-specific Docker network options are unnecessary for public URLs. Proxy environment variables are intentionally ignored by the HTTP implementations in this release; deploy a worker with direct approved reachability.

## Coverage and findings

The JSON now includes the selected profile, disruptive-testing opt-in and per-route coverage observations:

| Coverage observation | Meaning |
| --- | --- |
| http_response_observed | A response was observed; PHP backend identity still requires evidence |
| redirect_not_followed | Scan the approved canonical destination explicitly |
| authentication_or_access_restricted | A 401/403 may prevent application/backend verification |
| rate_limited | A 429 limits assessment coverage |
| route_not_found | A 404 does not establish whether other routes use affected PHP |
| server_or_gateway_error | A server/proxy error is not proof of either CVE |
| request_failed | DNS, connectivity, TLS or protocol failure prevented assessment |

Version evidence is reported separately from HTTP access. For example, a 403 can expose an older PHP banner while preventing application access. That can support a potentially-affected version finding with restricted coverage; it does not prove exploitability.

A CDN/WAF response may hide the origin runtime. If no usable version is visible, the finding remains inconclusive. Passing a reachable production URL cannot guarantee a conclusive vulnerability decision. Confirm the actual web runtime, vendor package/backport and active workers before closing remediation. The optional signed evidence method requires a trusted backend collector, not a user-uploaded assertion.

## SIGiL node integration

The user can select a production asset in the node UI. SIGiL must resolve that asset against the signed-in user's tenant, asset ownership, approved engagement and correct scanner agent. Generate allowed origins and authorization references on the backend. Do not let arbitrary client-supplied CLI arguments establish their own authorization.

Default the node to production/passive mode. Treat active selection and disruptive opt-in as backend policy fields tied to the approved engagement. Preserve profile, evidence, coverage, timestamps and job identity in the audit record. Enforce network destination policy, tenant isolation, concurrency and a whole-job deadline on the worker. Origin-string matching alone is not a complete SSRF boundary.

This package contains a proposed node contract, not SIGiL registration or a replacement for the platform's authentication. Docker builds and production network execution remain untested in the authoring environment because Docker is unavailable there. Automated tests use local fixtures and mocked production hostnames; no customer/public production service was scanned.

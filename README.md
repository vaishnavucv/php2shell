# SIGiL PHP2Shell Scanner, 1.0.0-rc2

Consolidated release candidate. One Python entry point assesses approved PHP endpoints, optionally runs two active verification methods, and emits one report with per-CVE findings and measured stage timings. This package includes a Python adaptation of the ProjectDiscovery Nuclei method. Nuclei is not required.

Real vulnerable/patched PHP benchmark validation and SIGiL canvas registration remain outstanding. No measured accuracy percentage or confirmed RCE result is claimed.

## Production audit use

Any explicitly approved HTTP/HTTPS production endpoint is supported. host.docker.internal is only a Docker Desktop host-access example. The default production profile sends passive GET requests. See PRODUCTION_USE.md for production URLs, scope, result coverage, and explicit opt-in for potentially disruptive active probes. This remains a PHP2Shell-specific assessment, not a complete PHP application VAPT.

## Docker container

See DOCKER.md for build, runtime flags, report mounts, Mac/Linux networking and Compose examples. All scanner flags can be passed after the image name. The Docker image includes both active methods and requires no Nuclei binary.

### Published container (GHCR)

GitHub Actions tests and publishes `linux/amd64` and `linux/arm64` images to `ghcr.io/vaishnavucv/php2shell`:

```bash
docker pull ghcr.io/vaishnavucv/php2shell:latest
docker run --rm ghcr.io/vaishnavucv/php2shell:latest --help
```

Docker selects the matching architecture automatically on supported Ubuntu/Linux hosts and Docker Desktop. Pushes to `main` publish `latest` and a `sha-<commit>` tag. Version tags such as `v1.0-rc2` publish `1.0-rc2`. The **Publish scanner image** workflow also supports manual runs with an optional image tag. Authentication uses the repository’s built-in `GITHUB_TOKEN`; no registry secret is required. GHCR packages may initially be private; authenticated users can pull them, and the package owner can enable public visibility in package settings for anonymous pulls.

## Run without Nuclei or additional Python packages

Use Python 3.10+. Extract the ZIP, enter the directory, and replace port 8080 with the HTTP port of your approved local PHP lab.

Passive assessment:

```bash
python3 scanner.py \
  --url http://127.0.0.1:8080/index.php \
  --allow-origin http://127.0.0.1:8080 \
  --authorization-ref my-approved-local-lab \
  --output result.json
```

Add the ProjectDiscovery method, executed directly in Python:

```bash
python3 scanner.py \
  --url http://127.0.0.1:8080/index.php \
  --allow-origin http://127.0.0.1:8080 \
  --authorization-ref my-approved-local-lab \
  --profile lab --active --active-method template \
  --output result.json
```

Active mode sends crafted multipart data and can disrupt PHP request handling. Select it only for explicitly approved test/lab environments. The scanner does not execute the RCE PoC repositories.

## Add the second active engine

Install Assetnote's dependencies in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-active.txt
```

For the exact dependency versions used in our fixture tests, install requirements-tested.txt instead. These are tested pins, not a security certification.

Run the same command above using `--profile lab --active --active-method both`. To use only Assetnote, select `--active-method assetnote`. The default active method is template, so basic use needs neither Nuclei nor third-party Python packages.

`--path /admin/index.php` adds an explicit endpoint to the passive phase. Up to six unique endpoints are permitted. Active testing uses the first endpoint by default. `--active-endpoint-budget 2` or `3` explicitly extends active testing to that many supplied endpoints. Review request/byte budgets before enabling multiple engines or endpoints.

## Four methods, not six independent detectors

| Method | Enabled when | What it establishes |
| --- | --- | --- |
| Remote PHP/version assessment | Every scan | Advertised PHP version and upstream fix threshold |
| ProjectDiscovery Python adaptation | Active template or both | Template-related behavioral observations and version fallback |
| Assetnote active scanner | Active assetnote or both | Upstream behavioral observations and version fallback |
| Trusted runtime/package evidence | A valid signed attestation is supplied | A trusted agent's per-CVE package and active-worker assertions |

The two active engines share multipart/OOM techniques. Their agreement is not independent confirmation and never becomes confirmed RCE through vote counting. Other reviewed repositories are credited research references; their exploit code is not integrated.

## Workflow and timing

Validate scope and optional signed evidence, assess explicit endpoints, run the selected active engine, make a recovery request, optionally run the second active engine with another recovery request, then evaluate all evidence and write the report. A failed recovery stops further active testing.

The JSON includes `timing.total_elapsed_seconds` and `timing.stages`, plus `method_catalog`, `methods_enabled`, native request counts and body-byte counts. These distinguish selected methods from stages actually executed. Timing excludes dependency installation and initial signed-evidence validation.

One endpoint uses one GET in passive mode. Native active mode uses at most six HTTP requests including baseline and recovery; both active modes can use up to twelve including Assetnote's optional phpMyAdmin retarget. Crafted body traffic can reach about 29 MiB per engine per endpoint. Early stopping often reduces this. See METHOD_REFERENCE.md for the complete accounting and adaptation differences.

At default timeout 5, each active-engine subprocess has a 40-second outer deadline. That is a limit per engine, not an expected scan duration or a whole-job deadline. Passive/recovery requests use socket timeouts. Real duration depends on the target and network. SIGiL should enforce its own total node deadline.

## Read the result

| Status | Meaning |
| --- | --- |
| potentially_affected | Older upstream version advertised; installed package/backports unverified |
| fix_level_advertised | Fix-level banner observed; package and workers unverified |
| suspicious_behavior | An anomaly was observed, but neither CVE is proved |
| affected_runtime_verified | Trusted signed evidence identifies an affected active runtime |
| patch_verified | Trusted signed evidence covers fixes and active workers across all declared backends |
| evidence_conflict | Signed patch evidence conflicts with older advertised version evidence |
| inconclusive | Missing, rejected, conflicting, failed or insufficient evidence |

Empty 500s, memory errors, gateway failures and connection drops are not specific proof of either CVE. No signal is not equivalent to patched. Every finding has `rce_confirmed: false`. A patched runtime can still have an unrelated availability or security issue that requires investigation.

Exit code 0 means assessment completed, including inconclusive findings; 1 means all passive endpoints failed; 2 means invalid arguments or evidence/configuration. Route SIGiL workflows by finding status rather than exit code alone.

## Files and integration

- scanner.py: entry point, chain, timing, evidence decisions and signed-evidence verification.
- php_version.py: remote version/fingerprint assessment.
- template_method.py: attributed Python adaptation of the Nuclei method.
- vendor/assetnote_scanner.py: unchanged source-pinned upstream scanner.
- vendor/CVE-2026-109618.reference.yaml: exact reviewed template reference, not executed.
- METHOD_REFERENCE.md: method counts, attribution, adaptations, workflow, traffic and timing.
- EVIDENCE_AND_DEPLOYMENT.md: signed evidence schema and backend integration requirements.
- THIRD_PARTY_NOTICES.md and vendor licenses: contributor and license notices.
- node-contract.json: proposed integration contract, not an installed SIGiL node.

The trusted host collector is not included. Signature verification authenticates its assertions; it does not independently inspect the host. Do not accept user-uploaded claims as verified findings. The backend must enforce authentication, tenant/asset scope, agent selection, destination policy and network isolation.

Localhost means the machine/container executing the scanner. Run on the lab's machine/agent or use an explicitly authorized reachable lab address.

## Validation

```bash
python3 -m unittest -v
```

46 tests passed with active dependencies installed, including real upstream and native subprocesses against synthetic local HTTP fixtures, CLI execution with site packages disabled, original-JavaScript probe checksum vectors, patched-response ambiguity, signatures and failed recovery stopping. Without optional dependencies, the Assetnote integration test is skipped.

These tests validate software behavior and integration, not field detection precision/recall. Your actual vulnerable and patched PHP lab still needs a measured benchmark. No upstream PR has been submitted.

## Acknowledgements, Upstream Credits and Research References

This project builds on the work of the security researchers, developers and maintainers acknowledged below. Credit for the original vulnerability discoveries, upstream scanning techniques and referenced proof-of-concept research belongs to their respective authors.

SIGiL’s contribution is the assessment workflow, integration, evidence classification, reporting, production/lab profiles, Docker packaging and regression tests. We do not claim to have discovered PHP2Shell or independently developed the upstream detection techniques.

### Integrated Upstream Work

| Project | Contribution to this repository |
| --- | --- |
| [Assetnote PHP2Shell Scanner](https://github.com/assetnote/php2shell-scanner) | Provides the upstream active scanner included unchanged in `vendor/assetnote_scanner.py`. Credit belongs to the Assetnote Security Research Team. |
| [ProjectDiscovery Nuclei Template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-109618.yaml) | Provides scanning logic adapted into `template_method.py`, allowing this method to run directly in Python without Nuclei. Template authors: **lcfr_hax, assetnote, princechaddha and s4e-io**. |
| [ProjectDiscovery PHP2Shell Research](https://projectdiscovery.io/research/php2shell) | Provides research context and guidance on PHP discovery, version assessment, host verification, patching and worker restarts. |

### Additional Research References

The following repositories were reviewed to understand verification approaches, exploitation prerequisites and detection limitations. Their RCE payloads are not integrated into this scanner.

- [Bulletdev/php2shell-poc](https://github.com/Bulletdev/php2shell-poc)
- [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc)
- [eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC)
- [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)

### Official Security Advisories

The PHP Group’s advisories are the primary references for vulnerability descriptions and upstream remediation:

- [CVE-2026-109618: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

### Attribution and Licensing

Original copyright and license notices for the bundled Assetnote scanner and ProjectDiscovery-derived work are retained in:

- [Assetnote MIT License](vendor/ASSETNOTE-LICENSE.txt)
- [ProjectDiscovery MIT License](vendor/PROJECTDISCOVERY-LICENSE.txt)
- [Third-Party Notices and Source Revisions](THIRD_PARTY_NOTICES.md)
- [Method Adaptations and Limitations](METHOD_REFERENCE.md)

These acknowledgements distinguish integrated upstream work from research references. They do not imply that the named authors directly contributed to this repository, endorse SIGiL, or have independently validated its results.

**Our thanks to the researchers and maintainers whose work made this project possible.**

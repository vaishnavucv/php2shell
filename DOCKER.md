# Docker usage

All existing scanner arguments go after the image name. Docker arguments such as --rm, --network, --user and --mount go before it. The image has an exec-form Python entry point, so values are passed as arguments without shell interpolation inside the container. No port publishing is needed for this outbound CLI scanner.

## Build

From the extracted directory containing Dockerfile:

```bash
docker build -t sigil-php2shell:1.0-rc2 .
docker run --rm sigil-php2shell:1.0-rc2 --help
```

The image includes the tested h11/tqdm versions, native ProjectDiscovery method and unchanged pinned Assetnote scanner. Nuclei is not required. The default Python base supports native Docker platform selection, including Apple Silicon; no amd64 override is required.

The runtime image has been built locally for `linux/amd64` and `linux/arm64`, with CLI startup verified on both. GitHub Actions runs the Docker test stage for both architectures before publishing to `ghcr.io/vaishnavucv/php2shell`. See README.md for published image tags and access requirements, and PRODUCTION_USE.md for production URL commands. The localhost commands below are lab examples.

Build and load both architectures locally with a containerd-enabled Docker image store (such as Docker Desktop):

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t sigil-php2shell:1.0-rc2 --load .
```

On a classic Docker image store, build one platform at a time with `--load`, or use `--push` with a registry tag to publish both architectures.

Run the complete test suite during an explicit Docker test build:

```bash
docker build --target test -t sigil-php2shell:test .
```

The normal runtime build does not execute the separate test stage. Build requires registry and Python package index access. For production, pin the chosen base-image digest and retain a reviewed dependency lock appropriate to your build pipeline.

## macOS Docker Desktop: scan PHP running on your Mac

Use host.docker.internal rather than 127.0.0.1 for a service on the host. Change both URL and allowed origin together.

```bash
mkdir -p reports

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$(pwd)/reports",dst=/reports \
  sigil-php2shell:1.0-rc2 \
  --url http://host.docker.internal:8080/index.php \
  --allow-origin http://host.docker.internal:8080 \
  --authorization-ref approved-local-lab \
  --profile lab --active --active-method template \
  --output /reports/result.json
```

The report appears as reports/result.json on your Mac, and JSON is also printed to stdout. Replace the host port/path with your actual lab endpoint. A failed connection requires checking host-service reachability, Docker networking and firewall settings; do not expose the vulnerable service publicly.

To run both active methods, replace `--active-method template` with `--active-method both`. To run passive assessment, remove `--active` and `--active-method template`. Active methods can disrupt PHP request handling and should be selected only for approved testing.

## Linux Docker Engine: keep the original localhost target

Host networking reaches a PHP service bound to host loopback. The current host user is selected so a bind-mounted report directory remains writable with normal ownership:

```bash
mkdir -p reports

docker run --rm \
  --network host \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$(pwd)/reports",dst=/reports \
  sigil-php2shell:1.0-rc2 \
  --url http://127.0.0.1:8080/index.php \
  --allow-origin http://127.0.0.1:8080 \
  --authorization-ref approved-local-lab \
  --profile lab --active --active-method template \
  --output /reports/result.json
```

This Linux example intentionally shares the host network. Prefer a dedicated lab network when both services are containers. On native Linux bridge networking, `--add-host host.docker.internal:host-gateway` is another option for services listening on an address reachable from the Docker bridge. It does not make a host service bound only to 127.0.0.1 reachable over that bridge.

Docker Desktop host networking is a separate opt-in feature; the Mac example above does not rely on it.

## PHP already running in another container

Attach the scanner to the existing user-defined lab network. Use the PHP web service's container/service name and its internal HTTP port, not the host-published port. Example where `php-web` serves HTTP on port 80:

```bash
mkdir -p reports

docker run --rm \
  --network sigil-lab \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,src="$(pwd)/reports",dst=/reports \
  sigil-php2shell:1.0-rc2 \
  --url http://php-web/index.php \
  --allow-origin http://php-web \
  --authorization-ref approved-container-lab \
  --profile lab --active --active-method both \
  --output /reports/result.json
```

The `sigil-lab` network and `php-web` service must already exist and share that network. PHP-FPM port 9000 speaks FastCGI, not HTTP; target the web server in front of FPM.

## Optional Compose wrapper

```bash
mkdir -p reports
docker compose build scanner
docker compose run --rm scanner \
  --url http://host.docker.internal:8080/index.php \
  --allow-origin http://host.docker.internal:8080 \
  --authorization-ref approved-local-lab \
  --profile lab --active --active-method template \
  --output /reports/result.json
```

This example targets Docker Desktop. On Linux, supply the same user and network options appropriate to your lab. Compose uses the image's default non-root UID 10001; if your host bind mount is not writable by that UID, use `docker compose run --rm --user "$(id -u):$(id -g)" scanner ...` on POSIX systems. Do not make the reports directory globally writable as a workaround.

## Read-only runtime

The image supports a read-only application filesystem with writable scratch and report mounts. Add these Docker flags before the image name if desired:

```bash
--read-only \
--tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 \
--cap-drop ALL \
--security-opt no-new-privileges:true
```

The optional Compose wrapper enables these settings. Scanner temporary files use /tmp and are removed after assessment. Never mount the host Docker socket into this scanner.

## Signed runtime evidence

Mount trusted evidence read-only and pass `--attestation /evidence/evidence.json`. The signed target URL must exactly match the URL used by the container, including host.docker.internal versus localhost. Provide SIGIL_EVIDENCE_KEY only through the trusted backend's existing secret-injection mechanism. Its authentication and package-data requirements are unchanged by Docker.

## References

- Docker Desktop host connectivity: https://docs.docker.com/desktop/features/networking/networking-how-tos/
- Host network driver: https://docs.docker.com/engine/network/drivers/host/

Read README.md for scanner behavior, METHOD_REFERENCE.md for budgets/timing, and EVIDENCE_AND_DEPLOYMENT.md for SIGiL integration. Containerization does not increase detection confidence or change inconclusive findings into confirmed vulnerabilities.

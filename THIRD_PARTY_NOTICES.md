# Upstream credits and provenance

## Assetnote Security Research Team

Repository: https://github.com/assetnote/php2shell-scanner

Vendored file: vendor/assetnote_scanner.py, unchanged upstream scanner.py.

Reviewed commit: 052b56ef4f9bf674aa31ac645068144747bade3d

Git blob SHA-1: 287e97898ab759f6692c698f83d9a30d81db4fbb

License: MIT, Copyright (c) 2026 Assetnote. Full notice retained in vendor/ASSETNOTE-LICENSE.txt.

requirements-active.txt reproduces the dependency declarations from that revision. They are minimum versions rather than a complete dependency lock.

The SIGiL wrapper does not modify the probe code. It applies its own conservative interpretation to the upstream JSON. Source integrity verification pins reviewed bytes; it does not certify their correctness or dependency supply chain.

## Additional research references

- PHP Group OOM advisory: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- PHP Group stale global state advisory: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- ProjectDiscovery research: https://projectdiscovery.io/research/php2shell
- ProjectDiscovery Nuclei template: https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-109618.yaml
- Bulletdev: https://github.com/Bulletdev/php2shell-poc
- ikow: https://github.com/ikow/php2shell-poc
- eness: https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC
- 9bie: https://github.com/9bie/php2shell-bypass-aslr-exp

These additional projects are credited as review references. Except for the ProjectDiscovery template adaptation and its retained reference YAML, their code is not redistributed here. Acknowledgement does not imply endorsement, independent verification of their exploit claims, or an upstream contribution submission.

## ProjectDiscovery template adaptation

`template_method.py` adapts scanning logic from the Nuclei template, credited to lcfr_hax, assetnote, princechaddha and s4e-io.

Template git blob: 9d89d77dbd5f269dd0039534f204c16389911f46. Exact reference retained in vendor/CVE-2026-109618.reference.yaml.

MIT, Copyright (c) 2025 ProjectDiscovery, Inc. Full license retained in vendor/PROJECTDISCOVERY-LICENSE.txt.

The adaptation runs directly in Python, not through Nuclei. Differences and original SIGiL assessment contributions are documented in METHOD_REFERENCE.md. No upstream endorsement or contribution acceptance is claimed.

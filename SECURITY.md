# Security Policy

## Reporting a Vulnerability

To report a security vulnerability in rvl-cli, use **[GitHub's private security reporting](https://github.com/revelara-ai/rvl-cli/security/advisories/new)**.

Do not open a public GitHub issue for security reports.

**Response SLA:**
- Acknowledgment within 72 hours.
- Patch or mitigation target: 14 days for critical, 30 days for high severity.

## Scope

**In scope:**
- The `rvl` binary and the crates under `crates/` (credential storage, plugin installation, scan commands)
- The language indexer helpers under `helpers/` (`csindex`, `goindex`, `javaindex`, `pyindex`, `tsindex`)
- Plugin integrity verification (checksum, Ed25519 signature)
- Authentication and token handling
- Release artifact integrity (checksums, SBOMs, Homebrew tap publication)

**Out of scope:**
- Vulnerabilities in third-party dependencies (report to those projects directly; we track them via Dependabot)
- Issues requiring physical access to the user's machine
- Findings that only reproduce against synthetic fixtures under `testdata/`

## Handling of Scanned Code

rvl-cli analyzes source code on the user's machine. Scanned source content does not
leave the machine; reports submitted to the Revelara API carry shape-only data
(client type, method, and counts), never file contents.

## Contact

Maintained by **Revelara AI LLC**. You can also reach us at security@revelara.ai.

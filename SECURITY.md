# Security

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | Yes       |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please email **info@iaga.tech** or **info@edoardobambini.dev** with:

1. A description of the vulnerability
2. Steps to reproduce
3. Impact assessment
4. Suggested fix (optional)

We will acknowledge receipt within **48 hours** and provide an initial assessment within **5 business days**.

## In Scope

- Authentication or authorization bypass
- Injection patterns not caught by the firewall
- Data leakage through API responses or logs
- Cryptographic weaknesses in NHI identity or API key hashing
- MCP proxy bypasses allowing ungoverned tool execution

## Out of Scope

- Denial of service against the server itself
- Social engineering
- Vulnerabilities in upstream dependencies (report to respective maintainers)
- Issues requiring physical access to the host

## Disclosure

We follow responsible disclosure. Once a fix is available we will:

1. Release a patched version
2. Publish a GitHub security advisory
3. Credit the reporter (unless they prefer anonymity)

## Signing and release integrity

IAGA Sentinel uses Ed25519 signatures where applicable:

- Every governance verdict can be recorded as an Ed25519-signed receipt, appended to a
  per-run Merkle chain. Anyone can verify a chain offline with `iaga-verify`, with no
  database, server, or network access.
- Plugin manifests can be signed and verified with Ed25519 (opt-in, the
  `plugin-manifest-signing` feature).
- Plugin attestation can verify a Sigstore bundle and CycloneDX SBOM structurally and
  offline (opt-in, the `plugin-attestation` feature). This checks bundle structure and
  digests, not a full Rekor chain-of-trust.

Release artifacts and git tags are not signed today. If that changes it will be noted here.
Qualified eIDAS signatures are an Enterprise capability and are out of scope for this open
build.

For what data the software stores and where it goes, see [`DATA_HANDLING.md`](DATA_HANDLING.md).

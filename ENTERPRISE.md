# IAGA Sentinel Enterprise

> **From governance kernel to audit dossier in 14 days.**

IAGA Sentinel (BUSL-1.1, with Change License: Apache-2.0 baked in) is
the open-source governance kernel: 12-layer pipeline, Ed25519-signed
Merkle-chained receipts, deterministic APL policy language with live
overlay, replay verifier, `UserspaceKernel` cross-platform, `BpfKernel`
Linux scaffold with honest "soft enforcement" posture, BYOK signer
pattern (`IAGA_SENTINEL_SIGNER_KEY_PATH` filesystem-mount), reasoning plane
with BYO ONNX. **OSS 1.2 (shipped)** adds the four primitives ADR
0010 §3 reinstated: the `Signer` trait + `LocalDiskSigner` refactor,
drift replay additive (env `IAGA_SENTINEL_RECEIPT_CAPTURE=1`),
offline Sigstore + SBOM CycloneDX attestation primitive (feature
`plugin-attestation`), and the APL Hindley-Milner type checker +
WASM codegen MVP (feature `apl-wasm`). All four are scope-honest
primitives — see [`IAGA_SENTINEL_1.2.md`](IAGA_SENTINEL_1.2.md) and
ADRs 0011–0014.
**IAGA Sentinel Enterprise** is the commercial edition built on top.
The two share the same governance core; Enterprise adds the parts a
bank, insurer, hospital, or public-sector buyer needs to **prove**
compliance, not just **achieve** it — including the real eBPF/LSM
loader on Linux (authoritative kernel enforcement), the macOS Endpoint
Security and Windows ETW/WFP backends, the governance mesh
(single-cluster + multi-region), the four native KMS SDK backends
(AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 HSM), and the
curated ML model library.

If you can run OSS happily, run OSS happily. Enterprise exists for
teams whose blocker is no longer technical — it is regulatory, audit,
and operational scale.

---

## What you get with Enterprise

### 1. EU AI Act + GDPR + DORA Compliance Pack

The flagship reason Enterprise exists. Three regulations converge on
the same evidence problem:

- **EU AI Act** (in force phased between Aug 2026 GPAI → Aug 2028
  high-risk Annex I): operators and providers of high-risk AI systems
  must produce technical documentation (Annex IV), keep tamper-proof
  records (Art. 12), enable human oversight (Art. 14), demonstrate
  cybersecurity robustness (Art. 15), run post-market monitoring
  (Art. 72), report serious incidents (Art. 73).
- **GDPR**: Art. 30 (RoPA), Art. 35 (DPIA), Art. 22 (automated
  decision-making safeguards), Art. 5 (accountability).
- **DORA** (Digital Operational Resilience Act, in force since
  2025-01-17 for EU financial entities): ICT risk management framework,
  incident reporting (Art. 17-23), digital operational resilience
  testing (Art. 24-27), third-party ICT risk (Art. 28-44).

Enterprise turns IAGA Sentinel's signed receipts into the documents
each regulator accepts:

| EU AI Act article | What it requires | What Enterprise ships |
|---|---|---|
| **Art. 9** — Risk management system | documented, iterative risk mgmt across the lifecycle | Risk Management dossier auto-generated from receipt history + ADR + change log |
| **Art. 10** — Data and data governance | provenance, quality, bias mitigation for training data | Model card registry with dataset lineage, bias scorecards, retraining log |
| **Art. 11 + Annex IV** — Technical documentation | full dossier covering design, dev, deployment | `iaga compliance generate-dossier` produces a signed PDF + JSON-LD Annex-IV-conformant package |
| **Art. 12** — Record keeping | automatic, tamper-resistant logs of operation | already in OSS via signed receipts; Enterprise exports them in audit-acceptable bundles (PDF + ETSI-aligned attestation) |
| **Art. 13** — Transparency to deployers | clear instructions for use, accuracy, limitations | Public model cards + accuracy benchmarks continuously updated, citable in user docs |
| **Art. 14** — Human oversight | hold-on-block, escalation, kill-switch, intelligible interface | DPO Dashboard with review queue, SLA timer, audit-trailed approvals/rejections, hardware kill-switch endpoint |
| **Art. 15** — Accuracy, robustness, cybersecurity | adversarial resilience, attack documentation | Continuous adversarial test suite (prompt injection, jailbreak, model evasion) with metrics report |
| **Art. 16-19** — Provider quality management | ISO/IEC 42001-equivalent QMS | QMS console: process docs, training records, change control, internal audits |
| **Art. 50** — Transparency for AI interactions | users must know they're interacting with AI | Built-in markers on every receipt + downstream-facing disclosure helper |
| **Art. 53-55** — GPAI obligations | model cards, training data summary, incident reporting | Hooks into the Model Card Registry; the operator only manages the agent, the model provider obligations are scoped clearly |
| **Art. 72** — Post-market monitoring | continuous monitoring of system in production | `iaga monitor watch` runs continuous drift detection across receipt chains, raising alerts when behavior departs from the validated baseline |
| **Art. 73** — Serious incident reporting | report to market surveillance authority within 15 days | Incident Report Generator: produces the EU AI Office notification template prefilled from receipt + drift evidence |

> Notified body integration (TÜV / Dekra / Bureau Veritas) is on the
> roadmap for the conformity assessment workflow. We are actively
> building the relationships that make this practical at scale.

For GDPR specifically:

- **Art. 30 — RoPA** (Record of Processing Activities): auto-generated
  from the system's processing inventory, exportable to the format
  national authorities accept.
- **Art. 35 — DPIA** (Data Protection Impact Assessment): template
  + automated population from agent profiles, action types,
  allowlists, and cross-border data flows.
- **Art. 22** — automated decision-making safeguards: the receipt
  chain becomes the proof that human review was offered when required.
- **Art. 5** — accountability: signed receipts + replay are the
  literal artifact of accountability the regulator will accept.

For DORA (financial entities in EU only):

- **Art. 17-23 — ICT-related incident management**: the receipt chain
  + drift detection produces the audit trail; Enterprise wraps it in
  the major incident classification + reporting templates DORA expects.
- **Art. 24-27 — Digital operational resilience testing**: the
  adversarial test suite (also used for EU AI Act Art. 15) doubles as
  DORA TLPT-equivalent evidence.
- **Art. 28-44 — Third-party ICT risk**: the supply chain attestation
  layer (signed plugins + SBOM) maps directly to DORA's expectations
  about critical third-party providers.

### 2. Cockpit and observability

- **Web dashboard**: real-time view of every agent, every action,
  every verdict. Filterable by tenant, agent, decision, time range.
- **SIEM native connectors**: Splunk, Datadog, Elastic, Microsoft
  Sentinel, Chronicle. Receipts and audit events stream as native
  events with the right field mappings for security operations.
- **Alerting + runbook**: customizable alerts on policy drift, signer
  rotation, signature failure, kernel mode degradation. Each alert
  links to a runbook entry.
- **Slack / Teams hooks**: review queue notifications routable to
  on-call rotation.

### 3. Identity, multi-tenancy, RBAC

- **SSO**: SAML 2.0, OIDC. Tested with Okta, Azure AD, Auth0, Google
  Workspace, Keycloak.
- **RBAC**: roles for operator, auditor, DPO, compliance officer,
  read-only investigator. Per-tenant scoping.
- **MFA enforcement** at policy level.
- **IP allowlisting** per tenant.
- **Audit isolation**: tenants never see each other's receipts even
  in the analytics layer.
- **eIDAS qualified identities** integration for EU regulated
  operators.

### 4. Cryptographic backbone

OSS IAGA Sentinel supports the BYOK pattern by filesystem-mount:
`IAGA_SENTINEL_SIGNER_KEY_PATH` points at any 32-byte Ed25519 key file,
including one your KMS produces and mounts into the binary's
filesystem. The `Signer` trait + `LocalDiskSigner` refactor ship
in OSS 1.2 to clean up the abstraction. The four native KMS SDK
integrations and the managed lifecycle live in Enterprise.

- **Native KMS SDK backends**: first-class integrations for
  **AWS KMS**, **Azure Key Vault**, **HashiCorp Vault**, and
  **PKCS#11 HSM** (Thales / Utimaco / SoftHSM2). The signer talks
  to the KMS API directly; no filesystem-mount workaround.
- **Managed key lifecycle**: generation, rotation, revocation handled
  on your behalf with documented SLAs and audit-trailed approvals UI.
- **eIDAS qualified electronic signatures**: receipts signed with
  qualified certs from a trusted certification authority. Receipts
  become legally binding evidence in EU jurisdictions.
- **Field-level encryption** for sensitive payload contents at rest.
- **KMS contractual support**: when your HSM vendor's documentation
  fails you, our team owns the integration end to end.

### 5. Curated ML model library

The OSS reasoning plane lets you bring your own ONNX models.
Enterprise ships a library of curated models so the operator does
not have to source, fine-tune, and version them in-house:

- **intent-drift** — agent behaviour drift from baseline.
- **prompt-injection** — adversarial prompt detection (jailbreak,
  prompt smuggling, indirect injection).
- **anomaly-seq** — sequence-of-actions anomaly detection.
- **GPU acceleration** for models where latency/throughput
  warrants it.
- **Threat intel feed** with AI-specific IoCs (known jailbreak
  payloads, exfiltration patterns, model-level attack signatures)
  refreshed continuously as new attack patterns surface in the wild.

Models are versioned, signed, and the SHA-256 of the active model
ends up in every receipt — same M2 mechanism as OSS, just with the
maintenance burden taken off your team.

### 6. Skills marketplace and supply chain

- **Private skills registry**: host attested WASM plugins inside
  your perimeter. Sigstore signatures + SBOM verified at load.
- **Marketplace access**: curated public registry of community-
  vetted skills.
- **Supply chain SLA** on plugin attestation lifecycle.

### 7. Deployment options

- **Iaga Cloud**: managed deployment of IAGA Sentinel Enterprise.
  EU-region (Frankfurt, Paris) primary, multi-region active-active
  available. SOC 2 Type II in roadmap.
- **Air-gapped on-premises**: full-feature deploy with offline update
  channel, signed bundle delivery, no telemetry exit.
- **Marketplace listings**: AWS Marketplace, Azure Marketplace, GCP
  Marketplace billable through your existing cloud commitment.
- **Kubernetes Helm charts** with HA topologies pre-configured.
- **FedRAMP-ready** tracked for US public-sector buyers.

### 8. Founder-led support

This is not outsourced. The same team that wrote IAGA Sentinel's kernel
is the team that answers your incidents.

- **SLA 99.95%** uptime for Iaga Cloud.
- **Oncall 24/7** for Critical / High severity, handled by the
  maintainers themselves.
- **Response time**: Critical 1h, High 4h, Medium 1 business day.
- **Direct line to the founders** for accounts above the Growth tier.
  No tier-1 ticket triage. The person who wrote the receipt schema
  is the person who debugs your edge case.
- **Security advisory pre-disclosure**: subscribers get vulnerability
  advisories before public CVE publication.
- **LTS releases**: 5-year support window on designated LTS lines.
- **Migration assistance** from LangSmith Guard, Lakera Guard,
  Robust Intelligence, NeMo Guardrails, custom in-house tools.

---

## What is actually different in the code

Enterprise is not "OSS with a dashboard glued on top". It is a set of
modules that live in a separate repository and are not feasible to
reimplement quickly from the OSS surface. Two layers of differentiation:

### Layer 1 — Application code (6 to 12 months to reimplement)

- **Compliance evidence engine.** PDF and JSON-LD generators for EU
  AI Act Annex IV dossiers, RoPA, DPIA, post-market monitoring
  reports, EU AI Office incident notifications. Document templating,
  signed PDF generation with qualified e-signatures, multi-language
  output for the regulator that asks. A custom pipeline tied to the
  receipt schema, not a wrapper around an existing library.
- **DPO Dashboard backend.** A workflow engine for human-in-the-loop
  review (queue, escalation, SLA timers, audit-trailed approvals
  signed Ed25519 for non-repudiation). Frontend in Next.js. Not
  reproducible with off-the-shelf components in a sprint.
- **eIDAS qualified signature pipeline.** ETSI EN 319 132
  (XAdES / PAdES / CAdES) implementation, Long-Term Validation
  profile, connectors to specific EU Trust Service Providers
  (Aruba, InfoCert, Namirial, etc.). The OSS BYOK signer hands off
  to a generic KMS; the Enterprise signer produces signatures with
  legal weight in EU jurisdictions.
- **Multi-tenant isolation paths.** Schema-per-tenant or row-level
  security at the DB layer, per-tenant resource quotas, cross-tenant
  audit isolation, tenant lifecycle management. Touches every
  storage trait and every CLI command. Non-trivial retrofit if you
  start from single-tenant OSS.
- **SCIM + SAML 2.0 + JIT provisioning + role hierarchy.** Real
  enterprise SSO, not an `oauth2-proxy` sidecar. Permission matrix
  with inheritance, audit isolation per role.
- **Curated ML model serving pipeline.** Feature extraction code for
  intent-drift and anomaly-seq, tokenizer pipeline for prompt
  injection detection, model versioning and signed-bundle
  distribution. The OSS reasoning plane runs models you bring;
  Enterprise ships the models and the serving plumbing.
- **Threat intel ingest and matcher.** Code that parses MITRE ATLAS,
  AVID, and internal feeds, normalizes into IoCs, and matches them
  inside the pipeline. The IoC database itself is the asset.
- **Air-gapped distribution tooling.** Offline update channel with
  signed bundle delivery, custom installer, air-gap registry,
  bundle verification chain. A maintained release pipeline, not
  "we ship a tarball".
- **Native SIEM connectors.** Splunk, Datadog, Elastic, Sentinel,
  Chronicle, with field mappings already in place per vendor.

### Layer 2 — Heavy-engineering code moat

Three engineering tracks where the gap between OSS and Enterprise
stops being "more features" and becomes "different category of
engineering". Each one requires specialist talent and pays back
exactly the regulated buyers we are targeting.

- **Curated eBPF/LSM program library.** The OSS kernel ships the
  `BpfKernel` scaffold and the trait surface; the real Aya-rs LSM
  loader (with hooks `bprm_check_security` / `file_open` /
  `socket_connect` / `socket_sendmsg`, Landlock fallback, cgroup
  jailing) lives in Enterprise. On top of the loader, Enterprise
  ships **a library of pre-written eBPF programs** for AI-specific
  attack patterns: rootkit-style hook detection, keylogger
  fingerprints, container escape vectors, model-weight exfiltration
  via outbound DNS, prompt injection via shared memory, agent
  process impersonation. Writing correct eBPF programs that survive
  the kernel verifier under load is scarce talent. This is what a
  bank under DORA Art. 28-44 (third-party ICT risk) actually wants
  on its production hosts.
- **Confidential-computing receipts.** Receipts produced inside an
  Intel SGX / AMD SEV-SNP / AWS Nitro Enclave. The signer key never
  leaves the TEE. Receipt body carries a hardware attestation
  quote so the verifier can prove the signing happened in a
  tamper-proof environment, not just by software. Required for
  EU AI Act high-risk deployments in the public sector and for
  healthcare buyers with stricter "trusted compute" expectations.
- **Forensic replay with time-travel.** OSS replay verifies the
  signed chain. Enterprise replay reconstructs the full historical
  database state at the moment of each verdict (event sourcing +
  temporal queries) and lets an investigator answer *"why did the
  pipeline decide this at that time"* with the exact policy graph,
  threat feed, and model digests that were in effect then.
  Required for regulator-grade post-incident analysis under EU AI
  Act Art. 73 (15-day serious incident reporting).

Together Layer 1 + Layer 2 are the structural separation between OSS
and Enterprise. Layer 1 reimplementation is a quarter or two for a
competent team. Layer 2 takes specialist hiring in markets where the
talent is sparse: kernel eBPF, confidential computing, event sourcing
at scale.

Plus the compliance pieces (Layer 1) require a compliance officer +
EU regulatory lawyer kept current as the regulator publishes new
guidelines. The code carries the operator's intent; the people behind
it carry the interpretation.

---

## How the engagement works

We do not publish a price list. The right engagement model depends on
whether you need a managed cloud deployment, an air-gapped on-prem
install, the full notified-body conformity assessment workflow, or a
combination. A typical conversation covers:

- which regulations you are mapping to (EU AI Act / GDPR / DORA, plus
  any sector adjacent),
- which deployment topology fits (Iaga Cloud, dedicated cloud, on-prem,
  air-gapped),
- which compliance pack modules you need from day one vs phased,
- timing relative to your audit / certification calendar,
- support level (business hours vs 24/7 oncall, response SLA).

Reach out and we scope it together. Contact:
`enterprise@iaga.start@gmail.com`.

---

## What Enterprise will **never** be

This is a commitment, not a feature list:

- Enterprise will **never** gate the conceptual governance kernel.
  Receipt schema, replay algorithm, APL evaluator (with Hindley-Milner
  type checker + WASM codegen MVP shipped in OSS 1.2), reasoning
  framework + BYO ONNX, `UserspaceKernel` cross-platform soft
  enforcement, `BpfKernel` Linux scaffold with honest posture, the
  BYOK signer pattern + `Signer` trait (shipped in OSS 1.2), offline
  Sigstore + SBOM plugin attestation primitive (shipped in OSS 1.2),
  drift replay additive with `--re-execute` (shipped in OSS 1.2) —
  these stay in the open-source kernel under BUSL-1.1 with the
  automatic Apache-2.0 conversion four years after each release.
  The implementations that require specialist engineering at scale
  (the real eBPF/LSM loader on Linux, the macOS Endpoint Security
  and Windows ETW/WFP backends, the governance mesh, the four
  native KMS SDK backends, the curated ML model library) live in
  Enterprise — not as gating of OSS primitives, but as the
  heavy-engineering tier built on top of them.
- Enterprise will **never** require Iaga Cloud. You can run Enterprise
  fully on-prem, air-gapped if you need.
- Enterprise will **never** introduce a "free with telemetry" tier
  that ships your data offsite without explicit configuration.
- Enterprise will **never** retroactively remove features from OSS.
  If something works in OSS today, it works in OSS forever. The
  capabilities listed above as Enterprise were planned but never
  shipped in the OSS 1.0 GA — none of them are being removed from
  any release that ships them publicly. The full boundary is in
  [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).

This is the GitLab CE/EE pre-pivot covenant. We honour it because our
business depends on community trust.

---

## How to evaluate

1. Run **OSS** for two weeks. If it does not deliver the technical
   capability you need, Enterprise will not magically solve that —
   open an issue first.
2. If OSS works but you cannot ship to a regulated buyer because of
   audit / dossier / SLA gaps, **then** Enterprise is the right
   conversation.
3. Reach out for a scoped pilot: 30 days on Iaga Cloud or
   air-gapped, with EU AI Act + GDPR pack enabled, on a sandbox
   tenant. We help you map the article-to-evidence path for your
   specific deployment.

Contact: `enterprise@iaga.start@gmail.com`
Iaga Cloud: <https://iaga.cloud>
Repository (OSS): <https://github.com/EdoardoBambini/IAGA-Sentinel>

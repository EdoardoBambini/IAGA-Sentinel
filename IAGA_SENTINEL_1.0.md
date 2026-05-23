# IAGA Sentinel 1.0 — "Fortezza"

> Design document per il salto da 0.4.0 a 1.0.
> Da *sidecar di governance HTTP* a **kernel distribuito, attestato, replayable e probabilisticamente consapevole per agenti autonomi.**
> 0.4.0 chiedeva agli agenti di passare da IAGA Sentinel. 1.0 non lascia loro scelta.

---

## 1. La tesi della 1.0

0.4.0 è un *in-process HTTP gate*: se l'agente non chiama `/v1/inspect`, bypassa tutto. È il limite strutturale della 0.x.

**1.0 rovescia il modello:** il punto di applicazione non è più la SDK dell'agente, ma il **syscall / loopback / MCP transport**. L'agente non può *non* passare per IAGA Sentinel, perché IAGA Sentinel intercetta più in basso.

Questa è la rivoluzione. Tutto il resto (attestazione, replay, mesh, visual, ML) è conseguenza.

Regola d'oro che tiene in piedi l'intero design:

> **La valutazione probabilistica produce EVIDENZE, non VERDETTI.**
> Il verdetto finale resta deterministico. L'ML genera score; la policy APL decide.
> I modelli sono versionati per digest; al replay non si rigira il modello, si rilegge il suo output firmato dal receipt log.

---

## 2. I 7 pilastri

### Pilastro 1 — Enforcement Kernel

Il vero salto: IAGA Sentinel smette di essere opt-in.

- `iaga-sentinel-kernel`: daemon privilegiato che fa da chokepoint reale.
  - **Linux:** eBPF LSM hooks su `execve`, `openat`, `connect`, `sendto` + Landlock fallback.
  - **macOS:** Endpoint Security framework.
  - **Windows:** ETW + WFP (Windows Filtering Platform) per egress, minifilter opzionale per FS.
- L'HTTP sidecar della 0.4.0 diventa *fast path* per SDK-aware; il kernel è *fail-closed* per tutto il resto.
- Nuova modalità `iaga run -- <cmd>` che lancia l'agente dentro una cgroup/job object governata.

**Breaking change:** il confine di trust si sposta. Gli SDK Python/TS restano ma perdono privilegio: *consigliano*, non *decidono*.

### Pilastro 2 — Signed Action Receipts + Replay Deterministico

- Ogni decisione (`allow|review|block`) produce un **receipt Ed25519-firmato** con: input hash, policy hash, plugin digests, ML model digests + scores, verdict, timestamp, parent receipt.
- Formato: DAG di receipt → **Merkle log append-only**. Una tabella `receipts` sostituisce `audit_events`.
- `iaga replay <run_id>` rigioca l'intera traccia in sandbox e verifica byte-per-byte che le decisioni odierne coincidano con quelle storiche → detection di *policy drift*.
- Export standard: **in-toto attestation** + **SLSA provenance v1** per ogni azione.

### Pilastro 3 — Agent Policy Language (APL)

DSL tipizzato, compilato a bytecode deterministico. Sostituisce YAML + template.

```apl
policy "no_secrets_to_public_http" {
  when action.kind == "http.request"
   and action.url.host not in workspace.allowlist
   and payload contains secret_ref(_)
  then block, reason="PII egress"
}

policy "halt_on_hijack_suspicion" {
  when ml.prompt_injection.score > 0.85
   and action.kind in {"shell", "http"}
  then block, reason="injection suspected", evidence=ml.prompt_injection
}
```

- Type checker + LSP + `iaga policy test`.
- Compila a WASM → stesso engine dei plugin → esecuzione deterministica, budget di istruzioni.
- Backward compat: il loader YAML resta ma stampa deprecation warning; i template diventano "preludio APL".

### Pilastro 4 — Attested Plugins + Supply Chain

Ogni `.wasm` plugin richiede:

- firma **Sigstore/cosign** (o chiave workspace),
- **SBOM** CycloneDX,
- digest in `skills-lock.json` (che oggi esiste ma è informativo → diventa autoritativo).

Più:

- registry plugin locale (`~/.iaga-sentinel/plugins/`) con verifica on-load,
- `iaga plugin publish` firma e pusha, `iaga plugin verify` offline.

### Pilastro 5 — Governance Mesh (multi-agente)

- Ogni nodo IAGA Sentinel espone un gossip endpoint gRPC (mTLS).
- Fatti propagati: policy revisions, receipt heads, plugin digests, revoche, anomalie comportamentali.
- **Rate budget globali**: un worker pool di 50 agenti condivide un budget "100 chiamate HTTP/min a github.com" — oggi è per-process, in 1.0 è federato.
- Modalità **hub** (singolo server) e **p2p** (CRDT su receipt log).

### Pilastro 6 — Visual come first-class citizen

La cartella `visual/` (oggi untracked) diventa il frontend ufficiale di IAGA Sentinel:

- servita direttamente da `iaga serve` su `/ui` (embed via `rust-embed`),
- live stream dei receipt via SSE/WebSocket sul log Merkle,
- vista "neural" attuale = dashboard operativa, non demo marketing,
- `iaga-sentinel-video/` (Remotion) resta fuori dal binario → pipeline assets per docs/sito.

### Pilastro 7 — Probabilistic Reasoning Plane

Tre classificatori locali (piccoli, CPU-friendly, no cloud) affiancano la pipeline deterministica:

| Modello | Cosa stima | Runtime |
|---|---|---|
| `intent-drift` | distanza semantica fra goal dichiarato e azione attuale | ONNX, ~30M param |
| `prompt-injection` | probabilità di injection / jailbreak nei tool args | DeBERTa-v3 fine-tuned |
| `anomaly-seq` | anomalia nella sequenza di azioni (autoencoder + seq model) | isolation forest + seq |

Ogni modello emette `{score: 0..1, features: [...], model_digest: sha256}` → finisce nel receipt firmato. APL consuma gli score.

**Calibrazione forzata**: `iaga ml calibrate` misura FPR/FNR su un dataset workspace-specifico; se FPR > soglia policy, il modello va in *advisory-only*. Niente blocchi su modelli non calibrati.

**Feature flag `ml`**: la 1.0 core resta leggera e gira senza ML. Chi vuole AI-vs-AI accende il flag. I layer che dipendono dall'ML (vedi sezione 3) degradano a *rule-only* se il flag è spento.

---

## 3. Da 8 a 12 layer — onesto, non marketing

Il brand "8-layer" della 0.x diventa **"12-layer defense-in-depth"** nella 1.0. I nuovi layer non sono riempimento: coprono gap reali.

### Layer rafforzati (1–8)

| # | Layer | Cosa cambia in 1.0 |
|---|---|---|
| 1 | Input validation | + schema fuzzing sui tool args |
| 2 | Intent classification | diventa layer ML (`intent-drift`) |
| 3 | Tool args policy | APL tipizzato |
| 4 | Secret ref planning | + taint tracking cross-call |
| 5 | Egress control | kernel-level (eBPF/WFP/ES), non più solo HTTP |
| 6 | FS control | Landlock / ES / minifilter |
| 7 | Identity / auth | + workload attestation (SPIFFE/SPIRE opzionale) |
| 8 | Audit | → **Receipt Merkle log firmato** |

### Layer nuovi (9–12)

| # | Layer | Cosa fa | Perché manca oggi |
|---|---|---|---|
| **9** | **Supply chain** | verifica firma plugin, SBOM, revoche | i plugin WASM oggi girano senza attestazione |
| **10** | **Blast radius** | calcolo statico del danno potenziale prima di `allow` (file raggiungibili, segreti in scope, rete esposta) | oggi decidi sull'azione, non sul suo raggio |
| **11** | **Behavioral baseline** | anomaly detection per-workspace (`anomaly-seq`) | non c'è concetto di "normale" per questo agente |
| **12** | **Counterparty trust** | reputation di domini, MCP server remoti, modelli LLM chiamati | tutto è trusted by default oggi |

La mesh (pilastro 5) distribuisce 11 e 12: un'anomalia vista da un nodo immunizza gli altri.

---

## 4. Nuova struttura del repo

```
iaga-sentinel/
├── crates/
│   ├── iaga-sentinel-core/         ← ex community/src (pipeline, policy, storage)
│   ├── iaga-sentinel-kernel/       ← NEW: eBPF / ETW / Endpoint Security
│   ├── iaga-sentinel-apl/          ← NEW: policy language + compiler
│   ├── iaga-sentinel-receipts/     ← NEW: Merkle log + signing
│   ├── iaga-sentinel-reasoning/    ← NEW: ONNX runtime + model registry firmato (feature=ml)
│   ├── iaga-mesh/         ← NEW: gRPC gossip
│   ├── iaga-plugins/      ← refactor con attestation
│   └── iaga-cli/
├── ui/                     ← ex visual/ (embedded in binary)
├── sdks/{python,ts,go}/    ← +Go nuovo, tutti declassati a "hints"
├── examples/
├── docs/{book,adr}/        ← mdBook + Architecture Decision Records
├── media/                  ← ex assets/ + output iaga-sentinel-video
│   ├── hero.gif / hero.mp4 / brain.gif
│   └── dashboard.png (screenshot visual)
└── xtask/                  ← build orchestration (release, sign, bench)
```

> **Status update 2026-05-08**: questo è il layout previsto dal design originale. Il
> 1.0 GA effettivamente shippato consolida 5 crate OSS:
> `iaga-sentinel-core`, `iaga-sentinel-receipts`, `iaga-sentinel-apl`, `iaga-sentinel-reasoning`, `iaga-sentinel-kernel`.
> Il crate `iaga-mesh` è stato riallocato in IAGA Sentinel Enterprise (mesh =
> categoria #3 + #18 in [ADR 0010](docs/adr/0010-oss-enterprise-boundary.md)).
> I sub-crate `iaga-plugins` e `iaga-cli` non sono stati estratti come
> separati: la logica plugin WASM vive in `iaga-sentinel-core/src/plugins/` (feature
> `plugins`, `wasmtime`-backed), la CLI vive in `iaga-sentinel-core/src/main.rs`.
> SDKs Python e TypeScript esistono; `sdks/go` non è stato realizzato in
> OSS 1.0 GA.

**Pulizia:** `enterprise/` resta fuori dal repo pubblico (scope confermato community-only). I `*.db` in root vanno in `.gitignore` — sono artefatti di test, erroneamente committati in 0.4.0.

---

## 5. Roadmap per milestone

| M | Nome | Contenuto | Gate di rilascio |
|---|------|-----------|------------------|
| **M1** | *Fortezza Foundation* | Cargo workspace split, `ui/` embedded, `media/` consolidato, `.gitignore` DB | `cargo build` passa, visual servito dal binary |
| **M2** | *Receipts* | Ed25519 + Merkle log + `iaga replay` | replay bit-exact di una sessione 0.4.0 importata |
| **M3** | *APL alpha* | Compiler + LSP + test runner, retro-compat YAML | tutte le policy esistenti migrano con `iaga policy migrate` |
| **M3.5** | *Reasoning Plane* | `iaga-sentinel-reasoning` crate, 3 modelli ONNX, calibrazione, APL integration | demo: injection bloccata con evidence nel receipt |
| **M4** | *Kernel Linux* | eBPF LSM + `iaga run --` su Linux | benchmark < 5% overhead su `curl`/`ls` in loop |
| **M5** | *Attestation + Mesh* | Sigstore, SBOM, gRPC gossip | 3 nodi condividono un rate budget in demo |
| **M6** | *Kernel cross-platform + 1.0 GA* | macOS ES + Windows WFP, docs book, migration guide | RC → 1.0 tag |

Timeline realistica da solo: **4–6 mesi** se il kernel resta Linux-only a 1.0 e macOS/Windows slittano a 1.1.

> **Status update 2026-05-08**: M1–M6 sono stati shippati nel 1.0 GA come previsto.
> Il real Aya-rs eBPF loader Linux (originalmente "M4.1") + macOS Endpoint Security
> + Windows ETW/WFP backends (originalmente "1.1 OSS") sono stati riallocati in
> IAGA Sentinel Enterprise per [ADR 0010](docs/adr/0010-oss-enterprise-boundary.md)
> (categorie #16 e #17). L'OSS conserva il `BpfKernel` scaffold Linux con postura
> "soft enforcement" honest-reported + `UserspaceKernel` cross-platform soft-enforcement
> forever. La 1.1 è una consolidation release (binary swap, no runtime change).

---

## 6. Breaking changes vs 0.4.0 (vanno in MIGRATION.md)

1. `audit_events` → `receipts` (migrazione automatica, vecchia tabella tenuta readonly una release).
2. `iaga-sentinel.yaml` *funziona ancora* ma deprecato → `.apl` preferito.
3. Gli SDK non sono più autoritativi: in mesh/kernel mode il verdetto SDK può essere scavalcato.
4. Binary name: resta `iaga-sentinel`, ma `iaga` diventa l'alias breve ufficiale.
5. Branding: "8-layer" → "12-layer defense-in-depth" ovunque (README, sito, SDK docstring, video Remotion).
6. Licenza: la 1.0 ships su **BUSL-1.1** con **Change License: Apache-2.0** scritta nella licenza stessa. Ogni release converte automaticamente ad Apache-2.0 quattro anni dopo la pubblicazione. Vedi `LICENSE` + ADR 0002.

---

## 7. Decisioni aperte — **Risolte (2026-04-23)**

Le quattro scelte che bloccavano la forma di 1.0 sono chiuse. Dettagli completi in
[`docs/adr/0002-open-source-license-and-scope.md`](docs/adr/0002-open-source-license-and-scope.md).

1. **Kernel scope** → **`UserspaceKernel` cross-platform soft enforcement** sempre presente in OSS + **`BpfKernel` scaffold Linux** (feature `linux-bpf`) honest-reported. Il real Aya-rs eBPF/LSM loader Linux + macOS Endpoint Security + Windows ETW/WFP backends sono stati riallocati in IAGA Sentinel Enterprise — vedi §9 e [ADR 0010](docs/adr/0010-oss-enterprise-boundary.md) categorie #16 + #17.
2. **Mesh timing** → 1.0 ships single-node. Lo schema receipt è già compatibile con federazione. La governance mesh (single-cluster + tier-2 multi-region) vive in IAGA Sentinel Enterprise — vedi §9 e [ADR 0010](docs/adr/0010-oss-enterprise-boundary.md).
3. **Licenza core** → **BUSL-1.1 con Change License: Apache-2.0 baked-in**. La licenza converte automaticamente ad Apache-2.0 quattro anni dopo la pubblicazione di ogni release. Nessuno switch manuale serve, e nessun futuro maintainer può rinegoziare la transizione: è scritta nella licenza stessa. `iaga-enterprise` resta sotto licenza commerciale separata.
4. **ML plane** → **feature-flag `ml` opzionale**, default off. `iaga-sentinel-reasoning` (M3.5) è crate separato; senza `ml` i riferimenti APL `ml.*` risolvono a evidenza mancante.

Roadmap finale: M1 ✅ · M2 ✅ · M3 ✅ · M3.5 ✅ · M4 ✅ · M5 ✅ · M6 ✅ · 1.0 GA shippata ✅. La 1.1 è una consolidation release (binary swap, no runtime change) che canonifica il boundary OSS↔Enterprise — vedi [`IAGA_SENTINEL_1.1.md`](IAGA_SENTINEL_1.1.md) e [ADR 0010](docs/adr/0010-oss-enterprise-boundary.md).

---

## 8. Stato finale dei pilastri (1.0 GA)

| Pilastro | Crate | Stato | Note |
|---|---|---|---|
| 1 — Enforcement Kernel | `iaga-sentinel-kernel` | ✅ scaffold + UserspaceKernel | Real eBPF/LSM loader Linux + macOS Endpoint Security + Windows ETW/WFP → Enterprise |
| 2 — Signed Receipts | `iaga-sentinel-receipts` | ✅ completo | Ed25519 + Merkle log, SQLite + Postgres backends |
| 3 — Agent Policy Language | `iaga-sentinel-apl` | ✅ completo | Tree-walk evaluator + APL live overlay (M6); WASM codegen + Hindley-Milner type checker → OSS 1.2 |
| 4 — Attested Plugins | (in `iaga-sentinel-core/plugins/`) | infra 0.4.0 | Sigstore + SBOM CycloneDX attestation primitive → OSS 1.2; private hosted marketplace + supply-chain SLA → Enterprise |
| 5 — Governance Mesh | (`iaga-mesh` privato) | rinviato | Single-cluster baseline + tier-2 multi-region → Enterprise |
| 6 — Visual Plane | `ui/` + `iaga-sentinel-core` `ui-embed` feature | scaffold | Frontend reale work-in-progress separato |
| 7 — Probabilistic Reasoning | `iaga-sentinel-reasoning` | ✅ scaffold + tract backend | BYO ONNX in OSS; curated ML library (intent-drift / prompt-injection / anomaly-seq) + HF tokenizers + GPU + threat-intel feed → Enterprise |

**12 layer** = 8 originali (hardened in M2–M5) + 9 supply chain attestation (Sigstore + SBOM primitive in OSS 1.2; hosted marketplace in Enterprise) + 10 blast radius (UserspaceKernel soft enforcement in OSS; real eBPF/LSM loader autoritativo in Enterprise) + 11 behavioral baseline (presente da 0.4.0, esposto via APL `ml.*` paths) + 12 counterparty trust (scaffold via signer key_id nei receipt; full mesh wiring in Enterprise).

---

## 9. Boundary Community vs Enterprise

> **Boundary clarification 2026-05-08.** Le liste sotto sono state
> raffinate rispetto alla versione originaria di §9. Razionale e
> dettagli completi in [ADR 0010](docs/adr/0010-oss-enterprise-boundary.md).
> In sintesi: il governance kernel concettuale resta OSS; le
> implementazioni heavy-engineering (real eBPF loader Linux, backend
> macOS/Windows del kernel, mesh, native SDK dei 4 KMS, modelli
> curated) vivono in Enterprise. Niente che 1.0 GA ha shippato
> viene tolto — le capabilities migrate erano deferred, non release.
> Quattro primitive deferred sono state reinstaurate in OSS roadmap
> 1.2: APL WASM codegen + HM, Plugin Sigstore + SBOM, drift replay
> additivo, Signer trait + `LocalDiskSigner` refactor.

IAGA Sentinel 1.0 esiste in due edizioni che condividono **lo stesso governance kernel**. La differenza è categoriale, non gating:

### Cosa è e resta nel kernel open-source (IAGA Sentinel OSS, BUSL-1.1 con Change License Apache-2.0 baked-in)

- **Enforcement kernel cross-platform**: trait + `UserspaceKernel`
  (Linux/macOS/Windows, soft enforcement), `BpfKernel` scaffold
  Linux con feature `linux-bpf` (postura "soft enforcement"
  riportata fedelmente da `iaga kernel status`), `iaga run`,
  audit pipeline 12-layer.
- **Receipt schema completo**: Ed25519 + Merkle log + replay
  deterministico bit-exact.
- **APL completo**: parser, validator, tree-walk evaluator, APL
  live overlay (M6). WASM codegen + Hindley-Milner type checker
  pianificati per OSS 1.2.
- **Reasoning framework**: `NoopEngine` sempre disponibile,
  `TractEngine` (pure-Rust ONNX via `tract-onnx`) dietro feature
  `ml`. BYO ONNX models. SHA-256 del modello attivo dentro ogni
  receipt.
- **BYOK signer pattern**: `IAGA_SENTINEL_SIGNER_KEY_PATH` punta a qualsiasi
  Ed25519 32-byte key file, incluso uno emesso dal tuo KMS via
  filesystem-mount. `Signer` trait pubblico + `LocalDiskSigner`
  refactor pianificati per OSS 1.2 (i 4 native KMS SDK backends —
  AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 HSM —
  vivono in Enterprise).
- **Plugin WASM** caricabili con `iaga plugins ...`.
  Attestation Sigstore + SBOM CycloneDX pianificata per OSS 1.2.
- **UI embedded** via feature `ui-embed`.
- **SQLite + Postgres backends**.
- **Tutti i sub-cmd CLI documentati**.
- **Drift replay additivo** (campi opzionali sul receipt body, no
  schema-breaking) pianificato per OSS 1.2.

**Promessa non rinegoziabile**: nulla che 1.0 GA ha shippato entrerà mai
in feature gating Enterprise. La covenant in `ENTERPRISE.md` line 310
("Enterprise will never retroactively remove features from OSS")
resta legalmente vincolante per ogni release pubblicata.

### Cosa è **IAGA Sentinel Enterprise** (commercial license, repo privato `iaga-enterprise`)

Categorizzato per dominio. 20 categorie totali (15 originali + 5
migrate da deferred-OSS al boundary 2026-05-08).

- **Compliance evidence pack EU AI Act + GDPR + DORA**: Annex IV dossier generator, DPO dashboard, RoPA + DPIA tooling, post-market monitoring automation, EU AI Office incident report workflow, DORA major-incident classification + ICT third-party risk mapping, ISO/IEC 42001 QMS console. Conformity assessment workflow con notified body (TÜV / Dekra / Bureau Veritas) sulla roadmap.
- **Cockpit operativo**: web dashboard real-time, alerting, runbook automation, SIEM native connectors (Splunk / Datadog / Elastic / Sentinel / Chronicle), Slack/Teams hooks.
- **Identity & multi-tenancy**: SSO SAML 2.0 + OIDC + SCIM, RBAC fine-grained, MFA enforcement, IP allowlist, multi-tenant isolato (schema-per-tenant), eIDAS identità qualificate.
- **Cryptographic ops managed**: managed key lifecycle (auto-rotation, audit-trailed approvals UI), eIDAS qualified e-signatures (XAdES/PAdES/CAdES + LTV + EU TSP), 4 native KMS SDK backends (AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 HSM), field-level encryption, KMS contractual support.
- **Real eBPF/LSM loader Linux** (Aya-rs + LSM hooks `bprm_check_security` / `file_open` / `socket_connect` / `socket_sendmsg` + Landlock fallback + cgroup jailing) — il loader autoritativo che fa flippare `BpfKernel.is_authoritative()` a `true`.
- **Cross-platform kernel backend**: macOS Endpoint Security (signed/notarized turnkey) + Windows ETW + WFP (EV cert managed).
- **Governance mesh** (single-cluster baseline + tier-2 multi-region active-active + federated rate budget cross-cluster + mTLS KMS-backed cross-cluster).
- **Curated ML model library**: modelli ONNX pre-trained (intent-drift, prompt-injection, anomaly-seq) versionati e firmati, HuggingFace tokenizer integration + calibration framework, GPU acceleration, threat intel feed AI-specifico real-time. Benchmark managed.
- **Heavy-engineering moat code-level**: curated eBPF/LSM program library AI-specific (rootkit detection, model-weight DNS exfiltration, prompt-injection via shared memory) per DORA Art. 28-44; confidential-computing receipts (SGX / SEV-SNP / Nitro Enclave) per EU AI Act high-risk + healthcare + public sector; forensic replay con time-travel (event sourcing + temporal queries DB-state-per-verdict + threat-feed snapshot per moment) per EU AI Act Art. 73 incident reporting. Vedi `ENTERPRISE.md` Layer 2.
- **Skills marketplace**: private registry plugin attestati con supply chain SLA contractual (sopra l'attestation primitive Sigstore + SBOM in OSS 1.2).
- **Deployment options**: managed (Iaga Cloud, EU-region first), air-gapped on-prem con offline updates + signed bundle delivery turnkey, marketplace AWS/Azure/GCP, FedRAMP-ready in roadmap.
- **Founder-led support**: SLA 99.95%, oncall 24/7 dai maintainer stessi (no tier-1 ticket triage), linea diretta col founder per Growth+, response 1h critical, security advisory pre-disclosure, LTS 5 anni, migration assistance.

### Logica del divario

OSS dà i **meccanismi**. Enterprise dà le **evidenze + cockpit + scala + support contrattuale** che servono a un'organizzazione regolamentata per dimostrare compliance al regulator/auditor/notified body, non solo per averla. Il divario è **time-to-audit**: con OSS un team smart ci arriva in 6 mesi di lavoro custom, con Enterprise in **14 giorni** out-of-the-box.

Slogan unificante: *From governance kernel to audit dossier in 14 days.*

Vedi [`ENTERPRISE.md`](ENTERPRISE.md) per il pitch completo + EU AI Act / GDPR / DORA article-by-article mapping. Iaga Cloud è il deployment managed (uno dei modi di consumare Enterprise), non un prodotto separato in questo repo.

---

## 10. Sintesi

IAGA Sentinel 1.0 è tre cose in una:

- **un kernel** (intercetta più in basso dell'SDK),
- **un log firmato** (ogni decisione è replayable e non ripudiabile),
- **un cervello** (ML probabilistico che produce evidenza, non verdetti).

Il tutto dietro un unico DSL (APL), distribuito in una mesh, osservabile da una UI embedded.

Non è una 0.5 con più layer. È un'altra categoria di prodotto.

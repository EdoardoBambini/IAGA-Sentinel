# ADR 0010, OSS↔Enterprise Boundary Clarification

- **Status**: Accepted
- **Date**: 2026-05-08
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.1 (consolidation release)
- **Relates to**: ADR 0002 (open-source license + scope), `IAGA_SENTINEL_1.0.md` §9, `ENTERPRISE.md`, `IAGA_SENTINEL_1.1.md`, `CHANGELOG.md` [1.0.0] / [1.1.0]
- **Supersedes**: nessuna ADR precedente. Questo documento canonifica il boundary OSS↔Enterprise dopo la decisione di scope del 2026-05-08.

## Contesto

Il 1.0 GA ha shippato il governance kernel concettuale completo (workspace 5 crate, pipeline 12-layer, receipts Ed25519+Merkle, APL deterministico con live overlay, reasoning plane scaffold + tract backend, `UserspaceKernel` cross-platform, `BpfKernel` scaffold Linux con postura "soft enforcement" honest-reported). Il `CHANGELOG.md` 1.0.0 elencava capabilities **deferred** in due gruppi:

- **Deferred to 1.0.x patch releases**: real eBPF/LSM loader (1.0.1), ONNX models pre-trained (1.0.2), APL WASM codegen (1.0.3).
- **Deferred to 1.1**: governance mesh, macOS Endpoint Security + Windows ETW kernel backends, KMS/HSM signer backends, GPU ML, drift replay, stateful cross-run anomaly, HuggingFace tokenizers, `iaga policy migrate`.

`IAGA_SENTINEL_1.0.md` §9 (versione originaria) descriveva queste capabilities come parte del kernel OSS-forever. `ENTERPRISE.md` (versione originaria) ribadiva: *"Enterprise will never gate the governance kernel. eBPF loader, [...] governance mesh, these stay in the open-source kernel."*

Procedendo con la pianificazione 1.1 emergono due fatti:

1. **L'effort delle deferred capabilities è asimmetrico.** Il real eBPF/LSM loader, i backend macOS/Windows del kernel, la governance mesh, e i 4 native KMS SDK richiedono effort multi-trimestrale di engineering specialistico (eBPF verifier, Endpoint Security framework, ETW/WFP, KMS API per ciascun vendor). I curated ONNX models richiedono un dataset/threat-feed/calibration pipeline che non è "una libreria che si scrive". Sono esattamente le capabilities che un cliente Enterprise (banca, ospedale, ministero) si aspetta turnkey + signed + supported, e che giustificano il prezzo Enterprise.
2. **Spedirle in OSS svuoterebbe Enterprise di valore reale.** L'open-core covenant non richiede di regalare ogni implementazione concepibile sopra ogni primitive. Richiede di non gating le primitive stesse e di non rimuovere features che hanno effettivamente shippato.

Da qui la domanda di design: *come si raffina il boundary preservando il covenant senza svuotare il prodotto commerciale?*

## Decisioni

### 1. Distinzione canonica: **primitive** (OSS) vs **implementazione heavy-engineering at scale** (Enterprise)

Il governance kernel concettuale resta OSS forever. Ciò include trait surfaces, schemi dati, API pubbliche, evaluator deterministici, scaffold honest-reported, e ogni primitive che una persona singola con compagno editor può scrivere e mantenere in tempi ragionevoli.

L'implementazione che richiede engineering specialistico at scale, per più stagioni, con dipendenze esterne contrattuali (kernel verifier, EU Trust Service Provider, vendor KMS API, threat-intel feed real-time, Apple notarization, EV cert provisioning) vive in Enterprise.

Il principio di test: **se la capability richiede una squadra dedicata o un budget contrattuale per shippare e mantenere correttamente, è Enterprise**. Se è una primitive che 1 dev può aggiungere sopra l'OSS esistente in poche settimane, è OSS.

### 2. **20 categorie Enterprise** (15 originali + 5 migrate da deferred-OSS)

#### Le 15 originali (`IAGA_SENTINEL_1.0.md` §9 versione originaria)

1. **eIDAS qualified signature pipeline**, ETSI EN 319 132 (XAdES / PAdES / CAdES), Long-Term Validation, EU TSP connectors (Aruba / InfoCert / Namirial / etc.).
2. **Managed key lifecycle automation**, auto-rotation, audit-trailed approvals UI, KMS contractual support.
3. **Governance mesh tier-2**, multi-region active-active, cross-cluster federated rate budget, mTLS KMS-backed cross-cluster.
4. **Multi-tenant isolation**, schema-per-tenant DB, resource quotas, audit isolation per tenant.
5. **Enterprise SSO**, SAML 2.0 + OIDC + SCIM, RBAC fine-grained, MFA, IP allowlist.
6. **Native SIEM connectors**, Splunk / Datadog / Elastic / Microsoft Sentinel / Google Chronicle, field-mapped.
7. **Air-gapped offline distribution**, signed bundle delivery, offline update channel, custom installer.
8. **Compliance pack EU AI Act + GDPR + DORA**, Annex IV dossier generator, DPO dashboard, RoPA + DPIA tooling, post-market monitoring, EU AI Office incident workflow, DORA Art. 28-44 ICT third-party risk, ISO/IEC 42001 QMS console.
9. **DPO Dashboard**, review queue, escalation, SLA timer, Ed25519-signed audit-trailed approvals.
10. **Curated ML model library**, pre-trained signed (intent-drift / prompt-injection / anomaly-seq) + GPU + threat-intel feed real-time + benchmark managed.
11. **Curated eBPF/LSM AI-specific program library**, rootkit detection, model-weight DNS exfiltration, prompt-injection via shared memory.
12. **Confidential-computing receipts**, SGX / SEV-SNP / Nitro Enclave, signer key inside TEE, hardware attestation in receipt body.
13. **Forensic replay con time-travel**, event sourcing + temporal queries DB-state-per-verdict, threat-feed snapshot per moment.
14. **Founder-led support contractual**, SLA 99.95%, oncall 24/7, founder direct line for Growth+, response 1h critical, security pre-disclosure, LTS 5 anni.
15. **Conformity assessment notified-body workflow**, TÜV / Dekra / Bureau Veritas integration.

#### Le 5 migrate da deferred-OSS

16. **Real eBPF/LSM loader Linux**, Aya-rs + LSM hooks `bprm_check_security` / `file_open` / `socket_connect` / `socket_sendmsg` + Landlock fallback + cgroup jailing. (era 1.0.1 OSS)
17. **Cross-platform kernel backend**, macOS Endpoint Security (signed/notarized turnkey) + Windows ETW + WFP (EV cert managed). (era 1.1 OSS)
18. **Governance mesh single-cluster baseline**, gRPC gossip mTLS + CRDT receipt log + intra-cluster federated rate budget. (era 1.1 OSS, complementare a #3 tier-2)
19. **Curated ONNX reference models + HuggingFace tokenizer integration + calibration framework**. (era 1.0.2 + 1.1 OSS)
20. **BYOK Signer 4 native KMS SDK backends**, AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 HSM. (era 1.1 OSS, native SDK; il pattern BYOK filesystem-mount resta OSS)

### 3. **4 primitive reinstaurate in OSS roadmap 1.2**

Capabilities originalmente migrate Enterprise il 2026-05-08 e poi reinstaurate in OSS 1.2 perché sono primitive senza scale/UX value Enterprise:

- **APL WASM codegen + Hindley-Milner type checker** (era 1.0.3 OSS, poi Enterprise, poi reinstaurato OSS 1.2). Pure DSL evolution. L'evaluator tree-walking attuale è già deterministico e replay-safe; il WASM swap è un upgrade performance/sandbox-isolation che appartiene al kernel concettuale.
- **Plugin Sigstore + SBOM CycloneDX attestation primitive** (era 1.1 OSS, poi Enterprise, poi reinstaurato OSS 1.2). Supply-chain primitive. Chiude Pillar 4. Il differentiator Enterprise è la **private hosted marketplace + supply-chain SLA contractual**, non la primitive di attestation in sé.
- **Drift replay additivo** (era 1.1 OSS, poi Enterprise, poi reinstaurato OSS 1.2). Estensione minore del replay esistente con campi opzionali sul receipt body (`pipeline_inputs_capture`, `apl_eval_trace`, `ml_inference_inputs`). Il forensic *time-travel* (event sourcing + temporal queries DB-state-per-verdict) resta Enterprise (#13).
- **`Signer` trait + `LocalDiskSigner` refactor** (era implicito 1.1 OSS, poi Enterprise, poi reinstaurato OSS 1.2). Trait surface pubblica + abstraction cleanup. I 4 native KMS SDK backends restano Enterprise (#20).

L'OSS 1.2 non ha milestone date fissate. Le 4 primitive shippano quando pronte, additive, no breaking change rispetto a 1.1.

### 4. Preservation della covenant **never retroactively remove**

`ENTERPRISE.md` impegna verbatim: *"Enterprise will never retroactively remove features from OSS. If something works in OSS today, it works in OSS forever."*

Verifica per ogni capability migrata Enterprise (5 nuove + le 15 originali):

| Capability migrata | Shippato in 1.0 GA? | Covenant preservata |
|---|---|---|
| Real eBPF/LSM loader | No (solo `BpfKernel` scaffold con `KernelError::Pending`) | ✅ |
| macOS Endpoint Security backend | No | ✅ |
| Windows ETW + WFP backend | No | ✅ |
| Governance mesh single-cluster | No | ✅ |
| Curated ONNX models + HF tokenizers | No (solo `TractEngine` con BYO ONNX) | ✅ |
| 4 native KMS SDK backends | No (solo BYOK filesystem-mount via `IAGA_SENTINEL_SIGNER_KEY_PATH`) | ✅ |

Nessuna delle 5 capabilities migrate aveva shippato in 1.0 GA. Erano deferred in `CHANGELOG.md` 1.0.0 sotto "Deferred to 1.0.x" o "Deferred to 1.1". La differenza tra "deferred" e "removed from OSS" è semantica e legale: deferred = non ancora shippato, libero di re-scoping; removed = shippato e poi tolto, vietato dal covenant.

### 5. Posture statement: cosa dice `iaga kernel status`

`iaga kernel status` continua a riportare la verità sulla postura del kernel attualmente attivo:

- Su `UserspaceKernel`: `authoritative: no (soft enforcement)`. Sempre.
- Su `BpfKernel` OSS scaffold (feature `linux-bpf`): `authoritative: no (scaffold pending real loader)`.
- Su `BpfKernel` Enterprise build con real loader Aya-rs caricato: `authoritative: yes` (per ogni hook attaccato con successo).

Non si markettizza enforcement che il binary attuale non fornisce. La postura è la stessa pre e post boundary clarification: il binary OSS dice quello che fa, ne più ne meno.

### 6. Cosa **non** è mai gating

Nessuna delle seguenti categorie può mai essere feature-gated, anche aggiungendo capabilities Enterprise sopra:

- Receipt schema, Ed25519 + Merkle log, replay verifier deterministico bit-exact.
- APL parser + validator + tree-walk evaluator + live overlay (M6).
- `UserspaceKernel` cross-platform soft enforcement.
- `BpfKernel` Linux scaffold con postura honest-reported.
- Reasoning framework + `NoopEngine` + `TractEngine` + BYO ONNX.
- BYOK signer pattern via `IAGA_SENTINEL_SIGNER_KEY_PATH` filesystem-mount.
- HTTP API con Bearer auth, tutti i sub-cmd CLI documentati, SQLite + Postgres backends, UI embedded via `ui-embed`.

Anche se Enterprise aggiunge implementazioni alternative (es. il real eBPF loader sopra il `BpfKernel` scaffold, o un native KMS SDK sopra il pattern BYOK), le primitive OSS di sopra restano funzionanti nel binary OSS e vengono mantenute con bug fix e security advisories.

## Conseguenze

### Positive

- **Open-core covenant preservata e rafforzata.** Reinstating delle 4 primitive in OSS 1.2 dimostra che il boundary è principled (primitive vs implementation), non un copertura di gradual feature gating.
- **Enterprise valore reale.** Le 5 capabilities migrate (real eBPF, cross-platform, mesh, curated ML, KMS SDK) sono l'effort multi-trimestrale che giustifica il prezzo Enterprise. Senza questo, Enterprise si riduceva a "compliance pack + cockpit + support".
- **Narrativa pubblica difendibile.** Niente di shippato in 1.0 GA viene tolto. Il `CHANGELOG.md` originale già diceva "deferred". Il re-scoping è onesto e tracciato.
- **Roadmap OSS 1.2 chiara senza date.** Le 4 primitive shippano quando pronte, additive, zero breaking. Il binario 1.1 → 1.2 resta swap.
- **Roadmap Enterprise eseguibile.** Le 5 migrate diventano milestone Enterprise sequenziabili (E4 real eBPF, E5+E6+E8+E11 KMS+managed-keys+eIDAS, E7 curated ML, E8 mesh, E9-E10 cross-platform). Vedi piano 2026-05-08 `C:\Users\monti\.claude\plans\sono-edoardo-bambini-devo-twinkly-church.md` (privato).

### Negative

- **Public messaging surgery.** ENTERPRISE.md, README.md, IAGA_SENTINEL_1.0.md §9 hanno tutti dovuto essere riscritti per coerenza. CHANGELOG 1.1.0 entry assume il rischio di una community reaction "GitLab CE/EE pivot". Mitigation: questo ADR + reinstating 4 primitive + documentation della distinzione primitive-vs-implementation.
- **Roadmap OSS senza date pubbliche.** I 4 reinstated in OSS 1.2 shippano "when ready". Chi vuole una roadmap pubblica dettagliata della linea OSS resta deluso. Mitigation: il binario 1.0 GA è già completo come governance kernel concettuale; chi non ha bisogno di Enterprise può usarlo as-is indefinitamente, con conversione automatica Apache-2.0 a 4 anni dalla pubblicazione di ogni release.
- **Onus su Enterprise di shippare le 5 migrate prima del window EU AI Act 2027-02.** Se le migrate non shippano in tempo, il valore Enterprise vs OSS si percepisce sottile. Mitigation: piano Enterprise milestone E4 (real eBPF) M6-M7, E5 (KMS managed) M8, E6 (eIDAS) M9-M10. Vedi `iaga-enterprise/docs/roadmap/year-1-milestones.md` (privato).

### Neutre

- Il futuro `ADR 0009` resta riservato per design pubblico OSS, mai usato (originalmente bozzato per il real eBPF loader poi migrato a Enterprise; il design completo è preservato in `iaga-enterprise/docs/adr/E4-ebpf-real-loader.md` privato).

## Riferimenti

- ADR 0002: scelta della licenza BUSL-1.1 + Change License Apache-2.0 baked-in.
- `IAGA_SENTINEL_1.0.md` §9: boundary public commitment versione 2026-05-08.
- `IAGA_SENTINEL_1.1.md`: design note 1.1 consolidation release con boundary canonico.
- `ENTERPRISE.md`: pitch Enterprise + EU AI Act / GDPR / DORA mapping + covenant "never retroactively remove" line 310.
- `CHANGELOG.md` [1.1.0] e [1.0.0]: storico delle deferred capabilities + boundary clarification log.
- `README.md` §"Community vs Enterprise": framing pubblico del boundary.

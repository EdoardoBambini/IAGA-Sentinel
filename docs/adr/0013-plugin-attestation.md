# ADR 0013 — Plugin Sigstore + SBOM CycloneDX Attestation Primitive (OSS 1.2)

- **Status**: Accepted
- **Date**: 2026-05-28
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.2 — primitive evolution release
- **Relates to**: ADR 0010 (OSS↔Enterprise boundary §3, §2.10)

## Contesto

1.0 ha shippato il plugin system con un trust model semplice
("trust-on-path"): i file `.wasm` caricati da
`IAGA_SENTINEL_PLUGIN_DIR` vengono accettati senza verifica di firma.
Il `PluginDigest` nel receipt body registra `sha256` dei plugin bytes
ma non c'è nessun controllo di provenance. ADR 0010 §3 ha
reinstaurato la "primitive Sigstore + SBOM" in OSS 1.2.

La domanda di design è: **come si introduce attestation offline
senza pulling-in il crate `sigstore` (network + cert chain
complexity), senza richiedere infrastruttura Rekor live, e senza
sconfinare nel valore Enterprise (hosted marketplace + supply-chain
SLA + threat-intel correlation)?**

## Decisioni

### 1. Solo **offline structural verification**, no chain-of-trust

L'OSS 1.2 verifica:

1. **Bundle presence**: cerca `<plugin>.sigstore.json` accanto al
   plugin.
2. **Bundle well-formedness**: parse JSON, riconosce due schemi
   (Sigstore Bundle v0.3 e legacy cosign bundle v0.1).
3. **Payload digest match**: compara il digest dichiarato nel bundle
   con `SHA-256(plugin_bytes)`.
4. **Rekor log index**: estrae l'index del log entry se presente nel
   bundle (no online lookup).

L'OSS 1.2 **non** verifica:

- Rekor inclusion proof online → richiederebbe network + handling
  della disponibilità del servizio.
- Fulcio root CA validation → richiederebbe X.509 chain parsing,
  rotazione del root CA, e l'embed delle root pubbliche.
- Cert identity binding (issuer / SAN) → richiederebbe ASN.1 +
  PEM/DER decoder.
- Threat-intel correlation, signed feed, hosted marketplace API.

Quando l'OSS dichiara `offline_verified: true` la promessa è
ristretta: il bundle è ben-formed e il digest matches.
*Non* è una garanzia di chain-of-trust completa. La CLI lo dichiara
loudly:

```
note: offline verification only checks bundle structure + payload
digest. Full Rekor inclusion proof + Fulcio root attestation lives
in IAGA Sentinel Enterprise.
```

### 2. CycloneDX 1.5 SBOM parser custom

Niente dipendenza esterna per SBOM. Parser custom via `serde_json`
estrae `bomFormat`, `specVersion`, e conta `components[]`. Output:
`SbomReport { spec_version, component_count }`.

CycloneDX scelto su SPDX perché:

- Più diffuso nell'ecosistema WASM (Wasmtime, wasm-tools).
- Schema 1.5 stabile dal 2024.
- Compact JSON, easy parsing senza ASN.1 / RDF / SPDX-specific deps.

### 3. Feature flag `plugin-attestation`, default **off**

Tutto il modulo `attestation.rs` (e i tre nuovi field optional su
`PluginManifest`) sono dietro `#[cfg(feature = "plugin-attestation")]`.
Default off: zero footprint di build per hosts che non lo abilitano,
nessuna dep `base64` nel grafo, nessun PluginManifest schema change.

La feature è composta come `plugin-attestation = ["plugins",
"dep:base64"]` — implica `plugins`. `base64` è l'unica nuova dep
aggiunta al workspace, scope minimo (decode B64 → bytes per
confrontare digests).

### 4. PluginManifest additivo

`PluginManifest` ottiene tre nuovi field cfg-gated:

```rust
#[cfg(feature = "plugin-attestation")]
#[serde(default, skip_serializing_if = "Option::is_none")]
pub attestation: Option<PluginAttestation>,

#[cfg(feature = "plugin-attestation")]
#[serde(default, skip_serializing_if = "Option::is_none")]
pub sbom: Option<SbomReport>,

#[cfg(feature = "plugin-attestation")]
#[serde(default)]
pub attestation_offline_verified: bool,
```

Quando il feature è off, i field non esistono nel layout struct.
Quando on ma il file `.sigstore.json` non è presente: i field sono
`None` / `false`. JSON output back-compat con consumer 1.0 / 1.1.

### 5. PluginDigest gains `attested` / `attestation_issuer`

Nel receipt body, `PluginDigest` ottiene due field optional con
`skip_serializing_if = "Option::is_none"`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub attested: Option<bool>,
#[serde(default, skip_serializing_if = "Option::is_none")]
pub attestation_issuer: Option<String>,
```

Stessa logica byte-equality di ADR 0012 §2: `None` → elided →
signing-bytes identici a 1.1. Hosts senza `plugin-attestation`
producono receipt byte-identical a 1.1.0.

### 6. CLI `iaga plugin verify <path>`

Nuovo subcmd CLI cfg-gated dietro `plugin-attestation`. Output table
o JSON. Exit code:

- `0` se nessun bundle oppure offline-verified OK.
- `1` se bundle presente ma verification failed (digest mismatch,
  malformed).
- `2` su IO error sul file plugin.

Permette uso in CI / shell scripts: `iaga plugin verify p.wasm ||
exit`.

### 7. Boundary contro cannibalizzazione Enterprise

OSS **non** include (resta Enterprise):

- **Hosted plugin marketplace** (private registry, CRUD API,
  signed-feed subscription).
- **Supply-chain SLA contractual** (response time on CVE in
  attested plugins, curated rebuild pipeline).
- **Threat-intel feed integration** — l'attestation issuer/SAN può
  essere cross-referenziato contro un feed live di issuer banned.
  OSS non implementa quel matching.
- **Online Rekor lookup + Fulcio root validation** (turnkey
  chain-of-trust).
- **Curated eBPF/LSM AI-specific program library** (ADR 0010 §2.11)
  è separato — non c'è overlap.

## Conseguenze

### Positive

- **Zero new heavy deps**. Solo `base64` cf-gated. No `sigstore`,
  `x509-cert`, `openssl`, `cosign`, etc.
- **Default-off bound footprint**. Hosts che non vogliono
  attestation non pagano nulla in build time / binary size.
- **Honest scope**. CLI + ADR + ENTERPRISE.md dichiarano apertamente
  che "offline_verified" non è chain-of-trust completa. Niente
  over-promise.
- **Receipt body byte-equal a 1.1**. `attested` / `attestation_issuer`
  elidati quando `None` → signing bytes invariati.
- **Boundary preservata**. Le 3 differenziazioni Enterprise (hosted
  marketplace, SLA, threat-intel) restano vendable.

### Negative

- **Verifica strutturale only**. Un attaccante con accesso
  filesystem può forgiare un bundle con digest matching senza
  garanzie di provenance. OSS 1.2 non protegge da questo; chi vuole
  full chain-of-trust deve correre `cosign verify` out-of-band o
  comprare Enterprise.
- **CycloneDX 1.5 parser hand-rolled**. Se lo schema CycloneDX
  evolve significativamente (1.6, 2.0), il parser MVP non gestisce
  i new keys (parsa solo `bomFormat`, `specVersion`, `components`).
- **No issuer/SAN extraction**. `attestation_issuer` resta `None`
  da OSS — è un slot reservato per Enterprise (con x509 parsing).

### Neutre

- **Test surface**: 10 unit test in `attestation.rs#tests` blindano
  i 4 path (no bundle, malformed, mismatch, match) + 2 path SBOM
  (CycloneDX OK, non-CycloneDX rejected) + 2 path edge (rekor index
  number/string, sibling filename pattern).

## Riferimenti

- ADR 0010 — OSS↔Enterprise Boundary, §3 (4 primitive 1.2 reinstaurate),
  §2.10 (curated ML library Enterprise — distinct).
- `crates/iaga-sentinel-core/src/plugins/attestation.rs` — verify_plugin,
  parse_sbom_cyclonedx, PluginAttestation, SbomReport.
- `crates/iaga-sentinel-core/src/plugins/registry.rs` — annotation
  hook on reload.
- `crates/iaga-sentinel-core/src/plugins/types.rs` — PluginManifest
  additive fields.
- `crates/iaga-sentinel-receipts/src/receipt.rs` — PluginDigest
  attested / attestation_issuer.
- `crates/iaga-sentinel-core/src/main.rs` — `iaga plugin verify` CLI.

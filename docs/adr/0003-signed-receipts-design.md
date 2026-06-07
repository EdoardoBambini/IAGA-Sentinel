# ADR 0003, Signed Action Receipts (M2)

- **Status**: Accepted
- **Date**: 2026-04-23
- **Deciders**: Edoardo Bambini
- **Milestone**: M2 "Signed Receipts" (within 1.0-alpha)
- **Relates to**: `IAGA_SENTINEL_1.0.md` §2 Pilastro 2 (Signed Action Receipts)

> **Status update 2026-05-08**: la Sezione 5 (key management) e la Sezione 8
> (fuori scope M2) sono state ulteriormente raffinate da
> [ADR 0010](0010-oss-enterprise-boundary.md). In sintesi: i 4 native KMS SDK
> backends (AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 HSM) sono
> stati riallocati in IAGA Sentinel Enterprise (#20), insieme al managed key
> lifecycle (#2) e alla pipeline eIDAS qualified signature (#1). Il pattern
> BYOK filesystem-mount via `IAGA_SENTINEL_SIGNER_KEY_PATH` resta OSS forever; il
> `Signer` trait + `LocalDiskSigner` refactor è una primitive deferred a
> OSS 1.2 (additive, no breaking change).

## Contesto

Il pilastro 2 di 1.0 richiede che ogni verdetto della pipeline produca un **receipt** firmato, linkato al precedente in un log append-only, verificabile off-machine e rigiocabile in sandbox per detection di policy drift.

Questa ADR fissa le scelte concrete di M2: layout del crate, algoritmi, integrazione con la pipeline 0.4.0 esistente e cosa è deliberatamente fuori scope fino a M4/M5.

## Decisioni

### 1. Crate separato `iaga-sentinel-receipts`

Il codice receipt vive in un crate dedicato `crates/iaga-sentinel-receipts`, non in `iaga-sentinel-core`. Motivi:

- **Direzione delle dipendenze**: `iaga-sentinel-core` → `iaga-sentinel-receipts`. Mai il contrario. Questo consente a tool esterni (`iaga replay` standalone, futuri verifier offline) di consumare i receipt senza caricare tutto il core.
- **Boundary semplice da verificare per audit**: il codice crittografico è contenuto in un crate piccolo (< 1000 LoC) con zero dipendenze su logica di business.
- **Riusabilità**: il crate può essere pubblicato su crates.io separatamente da `iaga-sentinel-core`.

### 2. Algoritmi

- **Firma**: Ed25519 via `ed25519-dalek` v2 (RustCrypto, no-unsafe, vendored secret key handling).
- **Hash**: SHA-256 via `sha2` v0.10.
- **Serializzazione canonica**: `serde_json::to_vec` su una struct `ReceiptBody` con ordine di campi fisso e nessun `HashMap` / `BTreeMap`. Questo dà byte-determinismo *sufficiente* per l'MVP senza dover pullare una full-fat JCS (RFC 8785) implementation. Se futuri campi richiederanno map ordering, migreremo a JCS in M5.
- **Chain**: lista hash-linked (non albero di Merkle). Ogni receipt ha `parent_hash = SHA-256(parent.body.signing_bytes())`. Abbastanza per tamper detection e ordering; un albero balanced per run non porta benefici concreti in 1.0.

### 3. Schema `Receipt`

```rust
pub struct ReceiptBody {
    run_id: String,
    seq: u64,                     // 0-based monotonic
    parent_hash: Option<String>,  // hex SHA-256, None per seq=0
    input_hash: String,           // hex SHA-256 del payload canonicizzato
    policy_hash: String,          // hex SHA-256 della policy applicata
    plugin_digests: Vec<PluginDigest>,   // WASM plugin consultati
    model_digests: Vec<ModelDigest>,     // vuoto senza feature `ml`
    ml_scores: Option<MlScoreBundle>,    // None senza feature `ml`
    verdict: Verdict,             // Allow | Review | Block
    reasons: Vec<String>,
    risk_score: u32,
    timestamp: String,            // RFC3339 UTC
    signer_key_id: String,        // "ed25519-<hex16>"
}
pub struct Receipt { body: ReceiptBody, signature: String /* hex 64B */ }
```

Scelte chiave:

- `signer_key_id` è dentro il body firmato: impossibile rebindare il receipt a un'altra chiave senza invalidare la firma.
- `plugin_digests` / `model_digests` presenti *sempre* nello schema, anche quando `ml` è off (vuoti): così il replay non cambia forma quando si attiva/disattiva la feature, i byte firmati differiscono, ma il parser resta lo stesso.
- `run_id` per M2 è l'`event_id` del singolo verdetto. Multi-step runs aggregati per `trace_id` arrivano in M3 quando APL esporrà session identity formalmente.

### 4. Backend: SQLite + Postgres, stessi schemi logici

Entrambi i backend sono implementazioni del trait `ReceiptStore` e condividono lo stesso schema logico:

```sql
CREATE TABLE receipts (
    run_id TEXT, seq INTEGER, parent_hash TEXT,
    input_hash TEXT, policy_hash TEXT, verdict TEXT,
    risk_score INTEGER, timestamp TEXT,
    signer_key_id TEXT, signature TEXT, body_json TEXT,
    PRIMARY KEY (run_id, seq)
);
```

`body_json` è la fonte di verità per il replay: contiene i byte esatti che sono stati firmati. Non reserializziamo `ReceiptBody` in fase di read per evitare divergenze sub-byte dovute a ordinamenti futuri.

**Note M2**: il wiring automatico dal binario `iaga` al momento supporta solo il backend SQLite. Postgres è compilato, testato a livello di crate, e pronto per essere attivato nel prossimo giro quando il workspace userà Postgres in produzione. È una scelta deliberata di non-bloat: abilitare Postgres lato `iaga-sentinel-core` richiede una helper parallela che verrà aggiunta in M5 quando l'integrazione Postgres del core sarà a regime.

### 5. Key management MVP

- Signer key: singolo file Ed25519 seed 32 byte su disco.
- Path default: `<HOME>/.iaga-sentinel/keys/receipt_signer.ed25519`, override via env `IAGA_SENTINEL_SIGNER_KEY_PATH`.
- Permessi: `0600` su Unix; su Windows ci si affida agli ACL default del profilo utente.
- Generazione lazy: se il file non esiste, viene creato al primo avvio con `OsRng`.
- KMS/HSM (AWS KMS, HashiCorp Vault, TPM): **fuori scope M2**, 1.1. Il trait `ReceiptSigner` è stato progettato per essere sostituibile; l'integrazione KMS sarà un impl alternativo, non una rewrite.

### 6. Dual-write (zero-breaking) con la pipeline 0.4.0

Non rimpiazziamo `audit_store`. Scriviamo *anche* in `receipts` quando configurato:

```rust
state.audit_store.append(&stored).await?;       // v0.4.0 path
if let Some(rl) = state.receipts.as_ref() {
    rl.record(&stored).await;                   // M2 addition (best-effort)
}
```

`AppState.receipts: Option<Arc<dyn ReceiptLogger>>` è sempre presente nel tipo (feature-agnostic) ma `None` quando la feature `receipts` è off. Questo azzera il numero di cfg-gate sparsi nel pipeline code.

**Error policy**: qualsiasi errore sul path receipts è loggato a `warn!` e ignorato, una rottura del signer, del disco o del DB non può mai fail la governance decision. La pipeline 0.4.0 resta la single source of truth operativa finché la migrazione a receipts-only verrà fatta esplicitamente in M5.

### 7. CLI `iaga replay`

Sub-cmd gated dalla feature `receipts`:

- `iaga replay --list` → riassunto runs recenti.
- `iaga replay <run_id>` → verifica chain + stampa sequence di verdict.
- `iaga replay <run_id> --verify-only` → solo check firme + parent_hash, niente drift stub.

**Drift replay completo** (re-execute pipeline sandbox-ata contro receipt storici) → **M5**. In M2 il replay stampa la chain stored. Il motore drift è già scaffoldato in `iaga_sentinel_receipts::replay::replay(store, run_id, evaluator)` e test-coperto con un evaluator fittizio.

### 8. Cosa è *esplicitamente* fuori scope M2

- ✗ In-toto attestation / SLSA provenance export (→ M4 quando `iaga-sentinel-kernel` produrrà dati build-time).
- ✗ Merkle cross-run batched root con anchoring esterno (transparency log, RFC 6962-style) (→ 1.1).
- ✗ KMS / HSM signing backends (→ 1.1).
- ✗ Replay dentro sandbox reale con re-esecuzione plugin WASM (→ M5).
- ✗ Revoca chiavi / rotazione automatica (→ 1.1).
- ✗ Backend Postgres wireato automaticamente dal binary (→ M5, come sopra).

## Conseguenze

- Ogni run governed dalla pipeline, con feature `receipts` abilitata (default), produce una chain firmata verificabile con un pubkey stabile.
- Performance: firma Ed25519 ≈ 50µs; hash SHA-256 ≈ 1µs; un append DB SQLite insert singolo. Trascurabile rispetto alla pipeline (11 layer su un singolo request).
- Debito tecnico accettato: canonical JSON *quasi* RFC 8785 (sufficiente finché schema non introduce map). Se M3 APL richiederà map ordering, switch a `serde-jcs` o equivalente senza breaking del log esistente (basta che gli old receipt restino leggibili; JCS non cambia l'interpretazione, solo il serialization stage).
- I 166 test pre-esistenti passano invariati. 21 test nuovi per `iaga-sentinel-receipts`. Totale workspace: 187 test verdi.

## Struttura del codice

```
crates/iaga-sentinel-receipts/
├── Cargo.toml
├── migrations/
│   ├── sqlite/0001_receipts.sql
│   └── postgres/0001_receipts.sql
└── src/
    ├── lib.rs        , public surface
    ├── receipt.rs    , Receipt / ReceiptBody / Verdict / canonical bytes
    ├── signer.rs     , Ed25519 ReceiptSigner + load_or_create
    ├── merkle.rs     , chain_link + verify_chain
    ├── store.rs      , ReceiptStore trait
    ├── sqlite.rs     , feature `sqlite`
    ├── postgres.rs   , feature `postgres`
    ├── replay.rs     , verify_only + drift replay(evaluator)
    └── errors.rs

crates/iaga-sentinel-core/src/pipeline/receipts.rs
   , ReceiptLogger trait (feature-agnostic) + SignedReceiptLogger impl (feature `receipts`)
   , try_build_receipt_logger(db_url) helper used from main.rs

crates/iaga-sentinel-core/src/main.rs
   , Commands::Replay sub-cmd (feature-gated) + cmd_replay()
```

## Riferimenti

- `docs/adr/0002-open-source-license-and-scope.md`, scelte trasversali 1.0
- `docs/adr/0001-workspace-split.md`, setup M1 workspace
- `IAGA_SENTINEL_1.0.md`, design 1.0 completo

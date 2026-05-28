# ADR 0011 — `Signer` Trait + `LocalDiskSigner` Refactor (OSS 1.2)

- **Status**: Accepted
- **Date**: 2026-05-28
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.2 — primitive evolution release
- **Relates to**: ADR 0003 (signed receipts design), ADR 0010 (OSS↔Enterprise boundary)

## Contesto

ADR 0003 ha definito il signer come `ReceiptSigner`: una struct
concreta che incapsula una `SigningKey` Ed25519 caricata da un file
seed da 32 byte su disco (`~/.iaga-sentinel/keys/receipt_signer.ed25519`
o path da `IAGA_SENTINEL_SIGNER_KEY_PATH`). M2 ha shippato quella
struct senza astrazione: `SignedReceiptLogger` la teneva per
valore e chiamava `signer.sign(body)` direttamente.

Quel design era esplicito su un punto: il commento in `signer.rs` di
M2 prometteva *"a `Signer` trait + `LocalDiskSigner` refactor is on
the OSS 1.2 roadmap (additive, no breaking change)"*. ADR 0010 §3
ha confermato quel refactor come una delle 4 primitive reinstaurate
in OSS 1.2.

La domanda di design è: **come introduciamo il trait senza rompere
nessun callsite del 1.0 / 1.1 e senza leakare un meccanismo di
discovery che competerebbe con i 4 native KMS SDK backend
Enterprise (ADR 0010 §2.20)?**

## Decisioni

### 1. Trait `Signer` async, object-safe

```rust
#[async_trait]
pub trait Signer: Send + Sync {
    fn key_id(&self) -> &str;
    fn verifying_key(&self) -> VerifyingKey;
    async fn sign_body(&self, body: ReceiptBody) -> Result<Receipt>;
}
```

Object-safety è il requisito chiave: il pipeline tiene il signer
come `Arc<dyn Signer>` per condividerlo tra task async. Per
[`LocalDiskSigner`] `sign_body` è microsecondi (Ed25519 in-memory),
quindi async non aggiunge overhead percepibile; per backend KMS
Enterprise async è necessario (network round-trip), quindi il
trait deve essere async fin dall'OSS per evitare un cambio di
signature breaking quando i backend Enterprise si plugheranno
dietro al trait.

### 2. `LocalDiskSigner` come impl di riferimento

La struct esistente è rinominata da `ReceiptSigner` a
`LocalDiskSigner`. I metodi inherent (`generate`, `load_or_create`,
`key_id`, `verifying_key`, `sign`, `source_path`) sono **preservati
1:1** con la stessa signature. `sign` (sync) resta perché i test
delle suite M2 lo usano direttamente; `Signer::sign_body` (async)
chiama `LocalDiskSigner::sign` internamente.

### 3. `ReceiptSigner` resta come **type alias**

```rust
pub type ReceiptSigner = LocalDiskSigner;
```

Questa è la chiave del "zero breaking change". Ogni callsite del 1.0
/ 1.1 — production e test — continua a compilare senza modifiche:

- `ReceiptSigner::generate()` → metodo associato del type alias.
- `ReceiptSigner::load_or_create(path)` → idem.
- `signer.sign(body)` → metodo inherent di `LocalDiskSigner`.
- `signer.key_id()`, `signer.verifying_key()` → metodi inherent.

Le suite di test esistenti
(`crates/iaga-sentinel-receipts/tests/{merkle_append,replay,sign_verify,sqlite_store}.rs`)
e il `cmd_replay` in `crates/iaga-sentinel-core/src/main.rs` non
richiedono nessun edit.

### 4. `SignedReceiptLogger` riceve `Arc<dyn Signer>`

Il solo callsite migrato attivamente al trait è il
[`SignedReceiptLogger`] in
`crates/iaga-sentinel-core/src/pipeline/receipts.rs`. Il field
diventa `signer: Arc<dyn Signer>`, il constructor accetta
`Arc<dyn Signer>`, e il sign-path chiama
`self.signer.sign_body(body).await`. Quel singolo cambio è
sufficiente per dare agli Enterprise builder un punto di iniezione
per backend KMS senza ricompilare il core.

In `try_build_receipt_logger` (signed sub-module) il signer
filesystem viene wrappato esplicitamente:

```rust
let signer = LocalDiskSigner::load_or_create(&key_path)?;
let signer: Arc<dyn Signer> = Arc::new(signer);
SignedReceiptLogger::new(store, signer, policy_hash)
```

### 5. Boundary contro cannibalizzazione Enterprise

L'OSS espone **solo** il trait + `LocalDiskSigner`. Esplicitamente
**non** esposto:

- `KmsSigner`, `VaultSigner`, `AwsKmsSigner`, `AzureKeyVaultSigner`,
  `PKCS11Signer` — variants concreti per i 4 native KMS SDK
  backend, che restano Enterprise (ADR 0010 §2.20).
- Factory `Signer::from_url(uri)` o `BackendKind` enum — niente
  discovery mechanism in OSS. L'host Enterprise plug-a la propria
  impl direttamente con `Arc::new(MyBackend::new(...))`.
- Managed key lifecycle (auto-rotation, audit-trailed approvals UI)
  — resta Enterprise (ADR 0010 §2.2).

Il pattern BYOK via `IAGA_SENTINEL_SIGNER_KEY_PATH` filesystem-mount
resta in OSS forever, come confermato da ADR 0010 §6.

## Conseguenze

### Positive

- **Zero breaking change**. Ogni callsite del 1.0 / 1.1 compila
  invariato grazie al type alias.
- **Trait surface dumb**. L'OSS espone l'abstraction minima
  necessaria; nessun hint di discovery o managed lifecycle che
  competerebbe con Enterprise.
- **Async-ready per KMS**. Enterprise può plug-are backend KMS
  asincroni dietro lo stesso trait senza forzare un'altra rivisione
  di signature.
- **`Arc<dyn Signer>` shareable**. Lo stesso signer può essere
  condiviso tra `SignedReceiptLogger` e — in futuro — altri
  consumatori (es. live attestation di plugin), senza dover
  passare reference o clonare lo state interno.

### Negative

- **Overhead micro su sync path**. `LocalDiskSigner::sign` sync
  resta disponibile per legacy callsite, ma il pipeline path
  passa per `async fn sign_body` con un `.await`. L'overhead è
  zero in pratica (Ed25519 in-memory completa in ~30µs), ma il
  fast-path teorico è leggermente più indiretto.
- **`async-trait` proc-macro nel grafo dipendenze**. Era già presente
  nel workspace, non aggiunge una dep nuova.

### Neutre

- **Doc surface**: ADR 0003 e MIGRATION.md vanno aggiornati a notare
  che `ReceiptSigner` è ora un type alias e che il trait è la
  surface canonical per i consumer SDK. Vedi MIGRATION.md §1.1 → 1.2.

## Riferimenti

- ADR 0003 — Signed Receipts Design.
- ADR 0010 — OSS↔Enterprise Boundary, §3 (4 primitive reinstaurate),
  §2.20 (4 KMS SDK Enterprise), §6 (BYOK filesystem-mount in OSS).
- `crates/iaga-sentinel-receipts/src/signer.rs` — trait + impl + alias.
- `crates/iaga-sentinel-core/src/pipeline/receipts.rs` — callsite migrato.

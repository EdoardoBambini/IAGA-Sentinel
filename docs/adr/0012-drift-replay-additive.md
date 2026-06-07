# ADR 0012, Drift Replay Additive (OSS 1.2)

- **Status**: Accepted
- **Date**: 2026-05-28
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.2, primitive evolution release
- **Relates to**: ADR 0003 (signed receipts design), ADR 0010 (OSS↔Enterprise boundary §3, §2.13)

## Contesto

1.0 ha shippato `replay.rs` con due primitive:

- `verify_only(store, run_id)`, verifica firme + parent_hash links lungo
  la catena Merkle.
- `replay(store, run_id, evaluator)`, accetta una closure che ri-valuta
  ogni receipt e segnala divergenze.

Il CLI `iaga replay --verify-only` espone `verify_only`. La forma
"piena" di drift-replay (cattura degli input del pipeline al momento
del verdict + ri-esecuzione contro il pipeline corrente) è stata
deferred. M5 (ADR 0007) ha chiarito che M2 ship solo *data primitives*;
ADR 0010 §3 ha reinstaurato la primitiva in OSS 1.2.

La domanda di design è: **come si introduce la capture e il
re-execute additivamente, senza rompere la byte-equality dei
receipt 1.1 e senza sconfinare nel forensic time-travel Enterprise
(#13)?**

## Decisioni

### 1. Tre nuovi campi optional su `ReceiptBody`

`ReceiptBody` ottiene tre campi `Option<...>` con
`#[serde(default, skip_serializing_if = "Option::is_none")]`:

```rust
pub pipeline_inputs_capture: Option<PipelineInputsCapture>,
pub apl_eval_trace: Option<AplEvalTrace>,
pub ml_inference_inputs: Option<MlInferenceInputs>,
```

Le tre struct di capture sono definite in `receipt.rs`:

- `PipelineInputsCapture { request_json, framework, payload_sha256 }`
- `AplEvalTrace { policy_hash, policies_evaluated, policies_fired }`
- `MlInferenceInputs { tokenized_digests: Vec<MlTokenDigest> }`
  dove `MlTokenDigest { model_name, tokenized_sha256 }`.

### 2. Byte-equality con receipt 1.1 quando capture è off

`skip_serializing_if = "Option::is_none"` garantisce che i tre nuovi
campi siano **elidati** dal `signing_bytes()` quando `None`. Questo
è il punto load-bearing: un receipt 1.2 con capture disabilitata
produce **esattamente gli stessi byte di firma** di un receipt 1.1.
Il `body_hash()` resta stabile, il parent-hash chain non si spezza,
le firme Ed25519 di chain pre-esistenti restano verificabili.

`tests/drift_capture.rs` (`capture_fields_none_byte_equal_to_11_serialization`,
`body_hash_stable_when_capture_none`) blinda questa proprietà.

### 3. Capture trigger via env `IAGA_SENTINEL_RECEIPT_CAPTURE=1`

L'opt-in è esplicitamente un'env knob host-side (`1`, `true`, `yes`),
controllata in `crates/iaga-sentinel-core/src/pipeline/receipts.rs`
nella `signed::record()`. Default = off → byte-equality 1.1.

Le ragioni del trigger env-side (vs config file vs APL flag):

- **Zero footprint nel codice in stato off**. Nessun overhead, nessuna
  dependency tree change quando un operatore non lo abilita.
- **Operator-controlled**. L'operatore decide caso per caso (es. abilitato
  solo in staging, mai in production con PII reale).
- **Allineato con `IAGA_SENTINEL_SIGNER_KEY_PATH`**. Stesso namespace,
  stesso pattern.

### 4. CLI `iaga replay --re-execute`

Nuovo flag su `iaga replay`, mutualmente esclusivo con `--verify-only`.
Per MVP 1.2 il flag stampa la **disponibilità** dei tre campi capture
per ogni receipt + un summary:

```
RE-EXECUTE  run_id=evt_42  receipts=3
  seq=0    verdict=Block    capture=✓ apl_trace=✓ ml_inputs=· reasons=[...]
  seq=1    verdict=Allow    capture=✓ apl_trace=✓ ml_inputs=· reasons=[...]
  seq=2    verdict=Block    capture=· apl_trace=· ml_inputs=· reasons=[...]
summary: 2/3 with capture, 1/3 without (1.1 / capture-disabled)
```

Il **wiring pieno** verso il pipeline (ri-esecuzione effettiva di
`PipelineInputsCapture::request_json` contro `execute_pipeline` e
diff dei verdetti) è scope 1.3. Per 1.2 la primitiva data layer è
sufficiente: chi vuole può scrivere il proprio re-executor sopra il
trait `ReceiptStore` esistente; il CLI built-in dichiara onestamente
la sua posture.

### 5. Boundary contro Enterprise #13 (forensic time-travel)

`PipelineInputsCapture` cattura *gli input del pipeline*, non lo
*stato del DB* né lo *stato del threat-feed* al momento del verdict.
Cattura:

- Il `request_json` (replay-input).
- Il `policy_hash` (replay-policy).
- Il digest dei token feed ai modelli ML.

**Non cattura**:

- Snapshot della tabella DB con cui il pipeline ha consultato
  intent-drift score storici (event sourcing → Enterprise #13).
- Snapshot del threat-feed indicators-of-compromise al momento del
  verdict (live threat-intel → Enterprise #10).
- Stato del receipt store all'epoca del verdict (temporal queries →
  Enterprise #13).

Il design **previene** che un operatore costruisca su OSS 1.2 una
forensic time-travel completa. Per quel caso d'uso il prodotto
giusto è Enterprise. OSS 1.2 dà un "re-execute" sufficiente a
detettare drift di policy semplice, niente di più.

### 6. PII / payload sensitivity warning

`pipeline_inputs_capture.request_json` può contenere PII se il
pipeline è invocato con payload reali. La documentazione MIGRATION.md
deve avvisare loudly che `IAGA_SENTINEL_RECEIPT_CAPTURE=1` cambia il
contenuto dei receipt e di conseguenza la sensitivity dei backup /
export dei receipt. Default off è la scelta safe.

## Conseguenze

### Positive

- **Zero breaking change**. Receipt 1.1 deserializzano via serde
  defaults; signing-bytes byte-identical quando capture off.
- **Capture opt-in**. Default off → zero rischio PII inavvertito.
- **CLI honest**. `--re-execute` MVP dichiara apertamente che il
  wiring pieno è 1.3, evita over-promise.
- **Boundary preservata**. Niente schema DB-state snapshot, niente
  temporal queries. Enterprise #13 ancora vendable.

### Negative

- **Re-execute MVP non è pieno drift detection**. Per ora è
  inspectabile-only, chi vuole drift real deve aspettare 1.3 o
  comprare Enterprise.
- **Receipt size cresce sensibilmente con capture on**. Un
  `request_json` typical può aggiungere 1-10 KB per receipt. I
  backup / postgres column size devono accomodare.
- **Documentazione PII obbligatoria**. Forgetta il warning e un
  cliente leakerà PII. MIGRATION.md + ENTERPRISE.md devono
  evidenziarlo.

### Neutre

- **Test surface**: 5 nuovi unit test in `tests/drift_capture.rs`
  blindano la byte-equality 1.1 → 1.2 e il roundtrip serde delle
  3 capture struct. Test esistenti (replay, merkle_append, sqlite_store,
  sign_verify) aggiornati con `: None` esplicito.

## Riferimenti

- ADR 0003, Signed Receipts Design.
- ADR 0007, M5 Hardening + RC Posture (M2 ship "data primitives" only).
- ADR 0010, OSS↔Enterprise Boundary, §3 (4 primitive 1.2),
  §2.13 (forensic time-travel Enterprise).
- `crates/iaga-sentinel-receipts/src/receipt.rs`, `PipelineInputsCapture`,
  `AplEvalTrace`, `MlInferenceInputs`, `MlTokenDigest`.
- `crates/iaga-sentinel-receipts/tests/drift_capture.rs` -
  signing-determinism + roundtrip tests.
- `crates/iaga-sentinel-core/src/pipeline/receipts.rs`, capture trigger.
- `crates/iaga-sentinel-core/src/main.rs`, `--re-execute` CLI surface.

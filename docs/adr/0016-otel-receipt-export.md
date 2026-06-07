# ADR 0016: Export dei receipt in OpenTelemetry (OSS 1.3)

- **Status**: Accepted
- **Date**: 2026-06-06
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.3
- **Relates to**: ADR 0003 (signed receipts), ADR 0010 (boundary OSS/Enterprise)

## Contesto

Per diventare il substrato di evidenza su cui gli altri si appoggiano, i receipt devono poter entrare negli stack di osservabilita che i team gia usano (Datadog, Elastic, Langfuse) senza accoppiamento al prodotto. Il modulo `modules/telemetry` emette gia span e metriche in forma OTel, scritte a mano con `serde_json`, senza dipendere dai crate `opentelemetry`. La domanda di design e come esporre ogni receipt firmato come span OTel riusando quella plumbing, senza tirare dentro dipendenze pesanti e senza cambiare il comportamento di default.

## Decisioni

### 1. Feature otel-receipts, default off, zero nuove dipendenze

`otel-receipts` e una feature di `iaga-sentinel-core`, spenta di default, che non aggiunge nessuna dipendenza: riusa l'emitter OTel gia presente. Build di default e test di default restano byte-identici quando la feature e spenta.

### 2. Hook dopo la firma, fail-safe

L'emissione avviene in `SignedReceiptLogger::record()` subito dopo che `signer.sign_body()` ha prodotto il `Receipt`, dietro `#[cfg(feature = "otel-receipts")]`. E non bloccante e fail-safe: un errore nell'emissione viene ingoiato come gia accade per il path di scrittura del receipt, non interferisce mai con la pipeline.

### 3. Span iaga_sentinel.receipt con gli attributi della prova

`emit_receipt_span` costruisce uno span con attributi `receipt.runId`, `receipt.seq`, `receipt.verdict`, `receipt.inputHash`, `receipt.policyHash`, `receipt.riskScore`, `receipt.signerKeyId`, `receipt.parentHash`, `receipt.timestamp` e un prefisso della firma per correlazione. Lo span finisce nel buffer telemetria esistente e si vede via `GET /v1/telemetry/spans` e `/v1/telemetry/export`.

### 4. Scope onesto

Questa feature porta i receipt nel feed OTel in-process e nell'endpoint di export. Non e un exporter OTLP che fa push verso un collector remoto: quello e un passo successivo. La documentazione lo dichiara apertamente, niente over-promise.

## Conseguenze

### Positive

- Interoperabilita: la prova entra in qualunque stack OTel come uno span normale, senza accoppiamento al prodotto.
- Zero dipendenze nuove, opt-in, default invariato.
- Allarga la superficie di integrazione, in linea con la missione del substrato.

### Negative

- Non e ancora un exporter OTLP push: l'evidenza si legge dal feed e dall'endpoint, non viene spinta a un collector remoto out of the box.
- Il buffer e in-memory e circolare: e una superficie di ingestione, non un archivio durevole (l'archivio durevole e la catena di receipt firmati).

### Neutre

- Un unit test verifica che lo span venga emesso con gli attributi attesi. Validato end to end: una POST a `/v1/inspect` produce uno span `iaga_sentinel.receipt` su `/v1/telemetry/spans` con runId, verdict, seq, riskScore e signerKeyId reali.

## Riferimenti

- `crates/iaga-sentinel-core/src/modules/telemetry/` (emitter OTel, `emit_receipt_span`).
- `crates/iaga-sentinel-core/src/pipeline/receipts.rs` (`SignedReceiptLogger::record`).
- `crates/iaga-sentinel-receipts/src/receipt.rs` (campi del `ReceiptBody`).

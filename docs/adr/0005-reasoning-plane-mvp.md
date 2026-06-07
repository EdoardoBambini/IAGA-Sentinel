# ADR 0005, Probabilistic Reasoning Plane MVP (M3.5)

- **Status**: Accepted
- **Date**: 2026-04-25
- **Deciders**: Edoardo Bambini
- **Milestone**: M3.5 "Probabilistic Reasoning Plane"
- **Relates to**: `IAGA_SENTINEL_1.0.md` §pilastro 7, ADR 0002 (feature `ml` opt-in)

> **Status update 2026-05-08**: le voci della sezione "fuori scope M3.5" che
> citavano "M3.5.1" o "1.1" sono state ulteriormente raffinate da
> [ADR 0010](0010-oss-enterprise-boundary.md). In sintesi:
> - **Curated ONNX models** pre-trained (intent-drift / prompt-injection /
>   anomaly-seq), **HuggingFace tokenizer integration**, **calibration
>   framework**, **GPU acceleration**, **threat-intel feed**, **cross-run
>   stateful anomaly**, **native ONNX Runtime backend `ort`** sono stati
>   riallocati in IAGA Sentinel Enterprise (#10, #19).
> - L'OSS conserva il framework `ReasoningEngine` + `NoopEngine` + `TractEngine`
>   (pure Rust ONNX via `tract-onnx`) + BYO ONNX models pattern + il digest
>   SHA-256 di ogni modello dentro ogni receipt firmato.

## Contesto

Pilastro 7 di 1.0 introduce un piano di ragionamento probabilistico: modelli ONNX che producono **evidenze** (score, anomaly indicators) consumate dalla policy deterministica APL e firmate nei receipt M2. La regola d'oro del design impone che **ML non decida mai**, produce solo evidenze; il verdetto resta deterministico.

ADR 0002 ha già fissato due punti:
1. Feature `ml` **opt-in, default off** per non gonfiare il binary core.
2. I modelli sono versionati per digest SHA-256 e i digest finiscono nei receipt firmati per garantire replay bit-exact.

Questa ADR copre lo scope MVP di M3.5 e le scelte concrete: backend ML, struttura del crate, integrazione con `iaga-sentinel-core`, cosa è esplicitamente fuori scope.

## Decisioni

### 1. Backend ML: **`tract`**, non `ort` (ONNX Runtime nativo)

`tract` è puro Rust, zero dipendenze native. Cross-compila ovunque, non richiede installazione di librerie sistema, non esplode in CI Windows/macOS/Linux. Il design ADR 0002 esige "binary core leggero": `tract` rispetta meglio quel principio.

`ort` (binding di ONNX Runtime nativo) ha vantaggi per use case GPU e ops custom, ma porta C++ deps, problemi di linking e binari pesanti. Lo lasciamo come backend alternativo opt-in per 1.1, dietro feature `ml-onnxruntime`. Per ora, una sola strada.

**Impatto**: con `--features ml` attivo il binary cresce di ~5 MB (tract-onnx + tract-core + tract-linalg). Senza feature, zero overhead.

### 2. Trait `ReasoningEngine` + `NoopEngine` sempre disponibile

```rust
#[async_trait]
pub trait ReasoningEngine: Send + Sync {
    async fn evaluate(&self, input: &EvalInput) -> MlEvidence;
    fn model_digests(&self) -> Vec<ModelDigest>;
    fn name(&self) -> &'static str;
}

pub struct NoopEngine;        // sempre presente
pub struct TractEngine;       // #[cfg(feature = "ml")]
```

`NoopEngine` esiste anche senza feature `ml`. Restituisce evidence vuota e zero digest. Permette al codice host di scrivere `state.reasoning.as_ref().map(|e| e.evaluate(...))` senza branch sulla feature.

**Invariante operativa**: `evaluate` non panica mai, non propaga errori. Un modello rotto contribuisce evidenza vuota; la pipeline continua. Questo è coerente con la receipt path policy (M2): la governance deve restare in piedi anche se ML, ricevute, o storage failano.

### 3. Tokenizer MVP (deliberatamente primitivo)

Hash di byte n-grams (n=3) → vettore float32 di dimensione fissa 64. Output normalizzato max-1.

Vantaggi:
- Zero dipendenze (no HuggingFace tokenizers).
- Deterministico per costruzione.
- Funziona con qualsiasi modello che accetti `[1, 64]` float32 input.

Limitazione esplicita: non è un tokenizer linguistico vero. Modelli reali (BERT-derived, sentence transformers) richiederanno tokenizer specifici. **M3.5.1** introdurrà un meccanismo di plug-in per tokenizer custom alongside il modello.

### 4. Configurazione modelli via env var

Per il MVP la configurazione vive in **una sola variabile d'ambiente**:

```
IAGA_SENTINEL_REASONING_MODELS=intent_drift:/path/a.onnx,prompt_injection:/path/b.onnx
```

Format: `name:path` virgola-separati. Entry malformate vengono droppate silenziosamente (loggate a `warn!`). Vuota o assente → `NoopEngine`.

Razionale: una config file YAML/TOML moltiplicherebbe i punti di verità (workspace policy lock, signer key path, models config, plugin registry...). Per M3.5 una env var è sufficiente. Quando emergerà un pattern reale di deployment, M5 consoliderà tutto in un unico `iaga.config.toml`.

### 5. Wiring in `iaga-sentinel-core`: due feature, una superficie

```toml
[features]
default = ["demo", "sqlite", "receipts", "apl", "reasoning"]
reasoning = ["dep:iaga-sentinel-reasoning"]
ml = ["reasoning", "iaga-sentinel-reasoning/ml"]
```

- `reasoning` (default **on**): abilita la dep + il `NoopEngine` pluggabile + il subcommand CLI `iaga reasoning info`. Zero costo a runtime se nessun engine reale è configurato.
- `ml` (default **off**): aggiunge `tract-onnx` + `TractEngine` e attiva il caricamento da `IAGA_SENTINEL_REASONING_MODELS`.

`AppState.reasoning: Option<Arc<dyn ReasoningHandle>>` è sempre presente nel tipo (feature-agnostic), esattamente come `receipts`. Il trait `ReasoningHandle` è dichiarato in `pipeline::reasoning`, non re-esporta `iaga_sentinel_reasoning::ReasoningEngine` direttamente, così `iaga-sentinel-core` può compilare anche con `--no-default-features` senza pull-down del crate reasoning.

### 6. Pipeline hook in `execute_pipeline`

L'eval ML viene chiamato **una sola volta**, dopo le validazioni e prima del `score_tool_risk_with_thresholds`. L'output `ml_outcome: Option<ReasoningOutcome>` viene poi:

1. **Passato al receipt logger** del verdetto principale (linea ~744). I `model_digests` e `ml_scores` finiscono nel receipt firmato.
2. **Disponibile** per future estensioni APL (`ml.prompt_injection.score > 0.85` come path nel context). M5 attiverà questa path quando APL diventerà policy engine live.

Per il fast-path di blocco precoce (linea ~131, tool non in registry), passiamo `None` perché il reasoning non è ancora stato fatto. Coerente: niente eval = niente evidence.

**Critico**: la receipt body shape è **invariata** rispetto a M2 quando reasoning non è configurato o non produce evidenza. `model_digests: vec![]` e `ml_scores: None` come prima → receipt bit-identico, replay legacy invariato.

### 7. CLI

```
iaga reasoning info
```

Mostra:
- nome engine (`noop` / `tract`),
- numero modelli caricati,
- per ogni modello: nome + SHA-256 digest,
- hint contestuale (rebuild con `--features ml`, oppure setta `IAGA_SENTINEL_REASONING_MODELS`).

Non c'è `iaga reasoning eval <input>` per il MVP, era tentazione, ma usare il NoopEngine via CLI non aggiunge valore e i test integration coprono già il path eval.

## Conseguenze

- **Test workspace**: 215 → 226 (4 noop + 7 tract gated `ml` con `--features ml`). Zero regressioni sui 215.
- **Binary size**: invariato senza `--features ml`. Con `ml`: +~5 MB.
- **Compile time**: tract aggiunge ~2 minuti al primo build con `--features ml`. Default build invariato.
- **Receipt schema**: invariato. M2 receipt restano deserializzabili identici.
- **APL**: nessuna integrazione live in M3.5. Quando arriverà M5, il context APL vedrà un branch `ml` aggiuntivo nel JSON root con shape già definita in `MlEvidence::scores`.

## Cosa è esplicitamente fuori scope (rinviato)

- ❌ Modelli ONNX reali pre-trained per intent-drift / prompt-injection / anomaly-seq → **M3.5.1** (workspace owner fornisce path via env var nel frattempo).
- ❌ GPU acceleration → 1.1 (tract-cuda o ort-cuda).
- ❌ Tokenizer reali tipo HuggingFace → M3.5.1.
- ❌ Backend ONNX Runtime nativo (`ort`) → 1.1, feature `ml-onnxruntime`.
- ❌ Wiring di `ml.*` paths in APL come fonte autoritativa di policy → M5.
- ❌ Cross-run anomaly detection (richiede stateful reasoning) → 1.1.
- ❌ Training pipeline → out of scope 1.0 entirely.
- ❌ Streaming inference / batched eval → 1.1 se serve.
- ❌ Config file YAML/TOML per modelli → M5 (consolidato con altri config).

## Esempio operativo

```bash
# Build con ml backend
cargo build --release --features ml

# Configura modelli
export IAGA_SENTINEL_REASONING_MODELS=intent_drift:/var/lib/iaga/models/intent.onnx,prompt_injection:/var/lib/iaga/models/inj.onnx

# Verifica caricamento
$ iaga reasoning info
engine: tract
models: 2
  - intent_drift             sha256=8f4a3c...
  - prompt_injection         sha256=2b9e1d...

# Avvia il server: ogni receipt ora include i digest dei due modelli
iaga serve

# Replay di un run produce gli stessi receipt → drift detection cross-modello funziona
iaga replay <run_id>
```

## Riferimenti

- `docs/adr/0002-open-source-license-and-scope.md`, `ml` opt-in
- `docs/adr/0003-signed-receipts-design.md`, schema receipt + `model_digests` / `ml_scores`
- `docs/adr/0004-apl-mvp.md`, APL evaluator (M5 consumer di `ml.*`)
- `IAGA_SENTINEL_1.0.md` §pilastro 7, design completo del Reasoning Plane

# ADR 0008, APL as Live Policy Engine (M6)

- **Status**: Accepted
- **Date**: 2026-04-25
- **Deciders**: Edoardo Bambini
- **Milestone**: M6 (final 1.0 GA milestone)
- **Relates to**: ADR 0004 (APL MVP), ADR 0003 (receipts schema), ADR 0007 (M5 RC)

> **Status update 2026-05-08**: il riferimento a `iaga policy migrate`
> (YAML → APL converter) come "1.1" in questo ADR è stato chiarito da
> [ADR 0010](0010-oss-enterprise-boundary.md): è **OSS-eligible** (small
> utility, debt closure per ADR 0008) ma senza schedule fissato. Shippa
> quando pronto come additive 1.x.y. Il sistema overlay APL stricter-wins
> qui descritto resta OSS forever.

## Contesto

M3 (ADR 0004) ha shippato APL come crate standalone con CLI dry-run. M5 (ADR 0007) ha esplicitamente lasciato fuori "APL come fonte autoritativa di policy" rinviandolo alla milestone successiva. M6 è quel momento: APL diventa un policy engine **live** consultato dal pipeline durante ogni `execute_pipeline`.

La domanda di design è: **come si integra APL con il sistema YAML/profile esistente** senza spaccare 0.4.0 backward compat?

## Decisioni

### 1. APL come **overlay**, non come sostituto

Il sistema YAML esistente (profili agent + workspace policies + threshold di risk) **resta autoritativo come oggi**. APL è un **overlay** caricato opzionalmente via `iaga serve --policy file.apl`.

**Non** rimpiazza: convive. Ragioni:

- Backward compat 0.4.0: chi ha YAML in produzione non deve riscrivere niente per andare in 1.0.
- Migrazione graduale: gli operatori possono spostare regole da YAML ad APL nel loro tempo.
- Test pratico: APL si valuta in produzione contro YAML reale prima di chiedere una migrazione completa.

L'APL come **unica** fonte di policy (con migrazione automatica YAML → APL via `iaga policy migrate`) è esplicitamente fuori scope 1.0. Sarà 1.1 quando avremo tempo di osservare l'uso reale e progettare il converter.

### 2. Semantica del merge: **stricter wins**

Quando entrambi YAML e APL emettono un verdetto per la stessa request:

| YAML decision | APL fired verdict | Final decision |
|---|---|---|
| Allow  | (none)  | Allow  |
| Allow  | Allow   | Allow  |
| Allow  | Review  | **Review** |
| Allow  | Block   | **Block**  |
| Review | (none)  | Review |
| Review | Allow   | **Review** (no relax) |
| Review | Review  | Review |
| Review | Block   | **Block**  |
| Block  | (none)  | Block  |
| Block  | Allow   | **Block** (no relax) |
| Block  | Review  | Block  |
| Block  | Block   | Block  |

Regola formale: `final = max(yaml, apl)` con ordine `Allow < Review < Block`.

**APL può rinforzare ma non rilassare** il YAML. Questa direzione è non-negoziabile: rilassare il YAML via APL apre un buco di sicurezza (un APL malformato o malizioso può sbloccare ciò che il workspace policy proibisce). La direzione corretta è "policy autori scrivono regole *più strette* in APL per compensare gap del YAML".

### 3. Receipt schema impact

Il `policy_hash` nel receipt body (M2) era una costante `SHA-256("iaga-sentinel-policy-v0")` come placeholder per M2/M5. M6 lo riempie con un valore reale:

- Quando APL **non** caricato: `policy_hash = SHA-256("iaga-sentinel-policy-v0")` (invariato vs M5).
- Quando APL caricato: `policy_hash = SHA-256(apl_program.serialize())`, il digest del bundle compilato.

Replay distingue le due modalità: vedere un receipt con il policy_hash costante significa "APL non era attivo per quella request"; un policy_hash diverso significa "APL era attivo, ed era *quello specifico* bundle". Drift detection cross-bundle funziona automaticamente.

Schema invariato: `policy_hash` esisteva già da M2 come `String`. Solo il *contenuto* cambia.

### 4. Surface API minima

Nuovo modulo `crates/iaga-sentinel-core/src/pipeline/apl_overlay.rs`:

```rust
pub struct AplOverlay {
    program: iaga_sentinel_apl::Program,
    source_path: std::path::PathBuf,
    policy_hash: String,      // hex SHA-256 of compiled bundle
}

impl AplOverlay {
    pub fn load(path: &Path) -> Result<Self, AplOverlayError>;
    pub fn evaluate(&self, ctx: &iaga_sentinel_apl::Context) -> Option<Fired>;
    pub fn policy_hash(&self) -> &str;
    pub fn source_path(&self) -> &Path;
    pub fn policy_count(&self) -> usize;
}

pub fn merge_decisions(yaml: GovernanceDecision, apl: Verdict) -> GovernanceDecision;
```

Errore di carica APL al server startup → fail-fast (`process::exit(2)`). Niente fallback silenzioso: se hai chiesto APL, vuoi APL.

### 5. APL evaluation context

Il context passato all'evaluator APL è un JSON che riflette la `InspectRequest` + l'output del risk scoring + (in M3.5+) l'evidenza ML:

```json
{
  "agent": { "id": "openclaw-builder-01", "framework": "..." },
  "action": {
    "kind": "shell",
    "tool_name": "python",
    "payload": { ... }
  },
  "workspace": {
    "id": "ws-default",
    "allowlist": ["..."]
  },
  "risk": { "score": 74, "decision": "block" },
  "ml": { "intent_drift": { "score": 0.12 } }    // populated when ml feature on
}
```

Path APL come `action.kind`, `risk.score > 80`, `ml.intent_drift.score > 0.85` lavorano già grazie all'evaluator M3 (path access via `walk_path` su JSON arbitrario).

### 6. CLI

- `iaga serve [--policy FILE]`, carica APL all'avvio. Errore → exit 2 con messaggio chiaro.
- `iaga policy lint <file.apl>`, alias semantico di `iaga policy test --no-context`. Solo parse + validate.
- `iaga policy test <file.apl> [--context ctx.json]`, invariato (M3).

Quando l'APL è caricato, il log all'avvio dice esplicitamente: `APL policy loaded: 3 policies, hash=abc123def...`. Operatore vede subito cosa è attivo.

### 7. Cosa **non** fa M6 (rinviato)

- ❌ `iaga policy migrate` (YAML → APL converter automatico) → 1.1.
- ❌ Hot reload dell'APL senza restart server → 1.0.x se domandato.
- ❌ Multiple APL files concatenati (`--policy a.apl --policy b.apl`) → 1.0.x se domandato.
- ❌ APL come fonte unica autoritativa con YAML deprecated → 1.1.
- ❌ APL evaluator integrato nel `iaga inspect` standalone (oggi è solo nel server) → 1.0.x se domandato.

## Conseguenze

- Test workspace cresce di ~5 (4 unit test apl_overlay + 1 integration `iaga policy lint`). Target ~230/230.
- Receipt schema invariato → replay legacy intatto.
- Backward compat 0.4.0 perfetta: chi non passa `--policy` ha la stessa esperienza di M5.
- Nuovo log line all'avvio del server quando APL caricata.
- Il `Cargo.toml` di iaga-sentinel-core continua a dipendere da iaga-sentinel-apl via feature `apl` (già default on da M3).

## Esempio operativo

```bash
# Avvia il server con un overlay APL
$ iaga serve --policy crates/iaga-sentinel-core/examples/policies/strict.apl
INFO  iaga-sentinel: APL policy loaded: 3 policies, hash=8f4a3c...
INFO  iaga-sentinel: listening on 0.0.0.0:7777

# Inspect: APL contribuisce al verdetto (stricter-wins)
$ iaga inspect '{"agent_id": "...", "action": {"action_type": "shell", ...}}'
{ "decision": "block", "reasons": ["yaml: shell tool unmapped", "apl[halt_on_hijack]: injection suspected"] }

# Replay: receipt mostra il policy_hash dell'APL caricata
$ iaga replay <run_id>
CHAIN OK ... (policy_hash=8f4a3c...)
```

## Riferimenti

- ADR 0004, APL MVP (M3)
- ADR 0003, receipts schema (M2)
- ADR 0007, M5 hardening + RC posture
- `crates/iaga-sentinel-apl/examples/no_pii_egress.apl`, esempio APL di partenza

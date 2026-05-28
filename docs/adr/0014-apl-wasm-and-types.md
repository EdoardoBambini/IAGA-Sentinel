# ADR 0014 — APL Hindley-Milner Type Checker + WASM Codegen Scaffolding (OSS 1.2)

- **Status**: Accepted
- **Date**: 2026-05-28
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.2 — primitive evolution release
- **Relates to**: ADR 0004 (APL MVP), ADR 0008 (APL as live policy engine),
  ADR 0010 (OSS↔Enterprise boundary §3)

## Contesto

1.0 ha shippato APL come DSL tree-walking deterministico (ADR 0004).
`lib.rs:18` e `validator.rs:14` promettevano *"WASM codegen and a
full Hindley-Milner style type checker are M3.1 / OSS 1.2
follow-ups"*. ADR 0010 §3 ha riconfermato quei due item come la
quarta primitiva reinstaurata in OSS 1.2.

L'effort grezzo per *full* HM + *full* WASM codegen è ~10 dev-days
con parity proptest e ottimizzazioni — al di sopra del budget
realistico per una release minor additive. Allo stesso tempo,
rinviare entrambi a 1.3 lascerebbe la roadmap 1.2 con solo 3/4
primitive shippate.

La domanda di design è: **come si shippa la primitiva senza
over-claim, senza rompere la byte-equality del tree-walk, e senza
sconfinare nella moat Enterprise (AOT optimizer + cranelift tuning +
WASI side-effects)?**

## Decisioni

### 1. HM type checker — implementazione completa

`crates/iaga-sentinel-apl/src/types.rs` implementa Algorithm W
classico sulla forma esistente `Expr` (no AST changes). Tipi:
`Bool | Int | Str | Unknown | List(Box<Ty>) | Var(u32)`. `Unknown`
è il sentinel per path lookups dinamici contro il JSON context —
si unifica con qualsiasi tipo concreto.

Builtin signatures hardcoded per i 7 builtin APL (`contains`,
`starts_with`, `ends_with`, `len`, `lower`, `upper`, `secret_ref`).
Builtin sconosciuti restano `Ty::Var` fresh (deferiti al validator
esistente per la rejection finale).

Top-level entrypoint `infer(&Program) -> Result<TypeEnv, TypeError>`
ritorna il substitution + i tipi per-policy del `when` clause
(devono unificarsi a `Bool`). Companion `compile_with_types(src)` in
`lib.rs` combina parse + validate + infer in una chiamata.

Errori strutturati (`TypeError::{Mismatch, OccursCheck,
BuiltinArity, NonBoolWhen}`) — span-level pretty printing è
deferred (l'editor Enterprise lo aggiungerà).

CLI: `iaga policy check <file.apl>` stampa il tipo inferito di ogni
policy `when` clause e segnala errori.

### 2. WASM codegen — **scaffolding MVP, scope limitato**

`crates/iaga-sentinel-apl/src/wasm.rs` (cfg-gated dietro feature
`apl-wasm`) emette un modulo WASM valido per il sottoinsieme di
`Expr` che **non tocca il runtime context**:

- `Lit::Bool` / `Lit::Int` → `i32.const`
- `Binary(Eq|Neq|Lt|Gt|Le|Ge|And|Or, l, r)` → `i32.eq` / `i32.ne` /
  `i32.lt_s` / `i32.gt_s` / `i32.le_s` / `i32.ge_s` / `i32.and` /
  `i32.or`
- `Unary(Not, e)` → `i32.eqz`

`Expr::Lit::Str`, `Expr::Path`, `Expr::Call`, `Expr::Membership`
**vengono rigettati** con `WasmCompileError::Unsupported*`. Il
caller cade-back al tree-walk per quelle policy. ADR 0010 §6 è
preservata: l'evaluator tree-walking resta il canonical executor
per la full APL surface.

L'API espone `compile_to_wasm(&Program) -> Result<WasmProgram, _>`
+ `WasmProgram::bytes()` per inspection. **Niente runtime in
OSS 1.2**: l'esecuzione del modulo è lasciata al host (wasmtime in
core, browser, wasmer). Questo evita di pullare `wasmtime` come
dependency obbligatoria nel apl crate e mantiene il scope MVP
piccolo.

CLI: `iaga policy compile <file.apl> [--output bundle.wasm]` emette
il modulo per le policy compatibili. Quando una policy contiene
nodes non supportati, il comando segnala l'errore con un hint loud
sul tree-walk fallback:

```
policy compile: codegen failed: APL → WASM 1.2 MVP does not support
path lookups (`action.url`); use tree-walk evaluator
note: APL WASM MVP 1.2 supports literal + boolean / numeric /
comparison ops only. Path / Call / Membership remain on the
tree-walk evaluator. See ADR 0014.
```

### 3. Feature flag `apl-wasm`, default off

Nuova Cargo feature `apl-wasm` sul `iaga-sentinel-apl` crate (deps
`wasm-encoder` 0.220 optional). Forwarded dal core come
`apl-wasm = ["apl", "iaga-sentinel-apl/apl-wasm"]`. Default off:

- Zero impact su build time per hosts che non lo abilitano.
- Tree-walk evaluator resta la default — `evaluate_program()` non
  cambia.
- Receipt schema non cambia (type info è pre-receipt, non escapa
  nel body).

Pattern allineato con `ml` su `iaga-sentinel-reasoning` (ADR 0005).

### 4. Boundary contro cannibalizzazione Enterprise

OSS 1.2 **non** include:

- **AOT optimized codegen** con cranelift opt-levels, profile-guided
  optimization, JIT tuning.
- **WASI side-effect policies** (read filesystem, write logs,
  network call from APL).
- **Curated rule library** firmata + signed threat-feed integration
  (ADR 0010 §2.10).
- **LSP / language server** con span-level diagnostics + auto-fix.

`wasm-encoder` 0.220 è il solo nuovo dep del workspace; nessun
`cranelift`, `wasmtime` aggiunto al apl crate.

Il differentiator Enterprise resta: *performance + curated content*,
non la *primitive di codegen*.

### 5. Parity con tree-walk: out of scope MVP

Il piano originale parlava di "parity proptest tree-walk vs WASM
su 50 random contexts". Nel scope MVP 1.2 questo richiederebbe:

1. Esecuzione del WASM module via wasmtime (dep non aggiunto).
2. Implementazione WASM completa di Path/Call/Membership con host
   imports per JSON context.

Entrambi sono fuori scope. Per 1.2 il contratto parity è ristretto:
**l'evaluator tree-walking resta autoritativo per ogni AST**.
`compile_to_wasm` emette bytecode equivalente *solo* per il
sottoinsieme literal+ops che non richiede context. Hosts che vogliono
parity completa dovrebbero stare sul tree-walk path.

Parity completo, esecuzione runtime, e proptest 50-contexts arrivano
in 1.2.x o 1.3 quando lo scope WASM si espande oltre il MVP.

## Conseguenze

### Positive

- **HM completo**. Il type checker shippa fully-functional con 14
  unit test (literal, binop dei 4 type, path-as-Unknown, builtin
  arity, NonBoolWhen, occurs-check edge cases, unknown-builtin
  fresh-var unification).
- **WASM codegen primitive presente**. La struttura API è in OSS,
  Enterprise non può claim "WASM codegen è exclusive Enterprise".
- **Scope onesto**. ADR + CLI + ENTERPRISE.md dichiarano apertamente
  che il MVP è limited. Niente over-claim.
- **Zero breaking change**. AST invariato, eval.rs invariato. Tutti
  i test M3 / M3.5 / M5 / M6 passano senza modifica.

### Negative

- **WASM MVP è limitato**. Non utile in production da solo —
  policy reali usano Path/Call. Funziona come "API present" + "1.3
  expansion path clear".
- **Parity proptest deferred**. Senza esecuzione WASM completa,
  niente test parity tree-walk vs WASM. Il rischio di parity-bugs
  resta per il futuro 1.3.
- **wasm-encoder pin a 0.220**. Versione disponibile attuale; new
  major (0.250+) può richiedere migration in 1.3.

### Neutre

- **`compile_with_types` API**: nuovo entrypoint accanto a
  `compile`. `compile` resta per host che vogliono solo
  parse+validate.
- **Test surface**: 14 HM unit + 9 WASM codegen test totali 23 lib
  tests in apl crate (vs 14 baseline). Workspace default 263/263
  con apl-wasm off; con apl-wasm on i 9 WASM tests si aggiungono.

## Riferimenti

- ADR 0004 — APL MVP (tree-walk + structural validator).
- ADR 0008 — APL as Live Policy Engine M6 (overlay stricter-wins).
- ADR 0010 — OSS↔Enterprise Boundary, §3 (4 primitive 1.2),
  §6 (cosa NON è mai gating).
- `crates/iaga-sentinel-apl/src/types.rs` — Hindley-Milner.
- `crates/iaga-sentinel-apl/src/wasm.rs` — WASM codegen scaffolding.
- `crates/iaga-sentinel-apl/src/lib.rs` — `compile_with_types`,
  `CompileError`.
- `crates/iaga-sentinel-core/src/main.rs` — `iaga policy check`,
  `iaga policy compile`.

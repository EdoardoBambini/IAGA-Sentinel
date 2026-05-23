# ADR 0006 — Enforcement Kernel MVP (M4)

- **Status**: Accepted
- **Date**: 2026-04-25
- **Deciders**: Edoardo Bambini
- **Milestone**: M4 "Enforcement Kernel"
- **Relates to**: `IAGA_SENTINEL_1.0.md` §pilastro 1, ADR 0002 (kernel Linux-only at 1.0)

> **Status update 2026-05-08**: la Sezione 6 (decisioni rinviate) di questo
> ADR è stata ulteriormente raffinata da
> [ADR 0010](0010-oss-enterprise-boundary.md). In sintesi:
> - **Real eBPF/LSM loader Linux** (Aya-rs + LSM hooks `bprm_check_security` /
>   `file_open` / `socket_connect` / `socket_sendmsg` + Landlock fallback +
>   cgroup jailing) è stato riallocato in IAGA Sentinel Enterprise (#16).
> - **macOS Endpoint Security** + **Windows ETW + WFP** backends sono stati
>   riallocati in IAGA Sentinel Enterprise (#17).
> - L'OSS conserva: trait `EnforcementKernel`, `UserspaceKernel`
>   cross-platform soft-enforcement, `BpfKernel` scaffold honest-reported,
>   `iaga run`, `iaga kernel status`.

## Contesto

Pilastro 1 di 1.0 è "Enforcement Kernel": il punto in cui IAGA Sentinel smette di essere opt-in e diventa il chokepoint reale. Il design completo prevede:

- **Linux**: eBPF LSM hooks su `execve`, `openat`, `connect`, `sendto` + Landlock fallback.
- **macOS**: Endpoint Security framework.
- **Windows**: ETW + WFP + minifilter opzionale.

ADR 0002 ha già fissato due punti:
1. **Linux-only** a 1.0 — eBPF LSM ships per primo. macOS/Windows preview userspace fino a 1.1.
2. macOS Endpoint Security e Windows ETW richiedono firma/EV cert e codice piattaforma-specifico significativo; non sono nel critical path 1.0.

Il problema concreto di M4: il vero loader eBPF richiede `bpf-linker` + LLVM 18+ sulla macchina di build, e un kernel ≥ 5.13 a runtime. Nessuno dei due è assunto dalla CI 1.0-alpha. Questa ADR fissa lo scope MVP M4 considerando questo vincolo.

## Decisioni

### 1. Crate separato `iaga-sentinel-kernel` con due backend

Stesso pattern degli altri crate 1.0: trait centrale, due implementazioni, scelta a costruzione.

```rust
#[async_trait]
pub trait EnforcementKernel: Send + Sync {
    async fn launch(&self, spec: &ProcessSpec) -> Result<LaunchOutcome>;
    fn backend_name(&self) -> &'static str;
    fn is_authoritative(&self) -> bool;
}
```

Implementazioni:

- **`UserspaceKernel`** — sempre disponibile, ogni piattaforma. Soft enforcement.
- **`BpfKernel`** — `cfg(all(feature = "linux-bpf", target_os = "linux"))`. Scaffold oggi, loader vero in M4.1.

### 2. UserspaceKernel: scope deliberato

Cosa fa:
- Esegue il policy callback prima di spawnare. `Block` impedisce lo spawn; `Review` lo trattiene; `Allow` procede.
- Spawna via `tokio::process::Command` con env scoped (allowlist conservativa: `PATH`, `HOME`, `USER`, `LANG`, ...) più gli entry esplicitamente forniti in `ProcessSpec.env`.
- Imposta cwd se specificato.
- Aspetta il child sincrono e restituisce l'exit code. Long-lived detached agents → M4.1 (handle ownership al host).

Cosa **non fa** (esplicito):
- Non restringe syscalls.
- Non impedisce `execve` di altri binari.
- Non capping egress di rete.
- Non mediation FS oltre cwd.

`is_authoritative() == false`. La pipeline scrive nel receipt che il backend era "userspace": l'audit chain è onesto su quanto era forte l'enforcement.

### 3. BpfKernel: scaffold onesto, non placeholder dishonesto

Oggi `BpfKernel.launch()` restituisce sempre `Block` con reason "linux-bpf scaffold; loader pending M4.1". Tre ragioni:

- **Onestà operativa**: non vogliamo che un operatore creda di avere enforcement kernel quando in realtà ha solo trait shape compilato.
- **Trait shape locking**: il fatto che `BpfKernel` esista già con la stessa signature di `UserspaceKernel` significa che M4.1 sarà additivo (load programs, attach hooks, deliver events) senza refactor delle call site nel host.
- **CI sanity**: il file `bpf.rs` compila pulito su Linux con `--features linux-bpf`. Su Windows/macOS non compila per design (`cfg(target_os = "linux")`), così il dev flow su altre piattaforme resta veloce.

In M4.1 il body di `launch()` diventerà:
1. controllo se i programmi eBPF sono caricati,
2. submit dell'evento sul ringbuf,
3. wait sulla decisione kernel-side (mediated by LSM hook),
4. spawn governato.

### 4. Feature flag in `iaga-sentinel-core`

```toml
[features]
default = [..., "kernel"]
kernel = ["dep:iaga-sentinel-kernel"]
linux-bpf = ["kernel", "iaga-sentinel-kernel/linux-bpf"]
```

`kernel` è in default (UserspaceKernel non costa nulla). `linux-bpf` è opt-in e viene attivata solo nelle build Linux production che includono il toolchain bpf-linker.

### 5. CLI

Due nuovi sub-cmd, gated dalla feature `kernel`:

```
iaga kernel status
  → backend: userspace
    authoritative: no (soft enforcement)
    linux-bpf: not active on this build

iaga run [--agent-id AGENT] [--cwd DIR] -- <program> [args...]
  → spawna il programma sotto il kernel configurato. Per M4 il policy
    callback è "allow all" (il governance-pipeline-as-policy wiring
    arriva in M5 con APL come fonte autoritativa).
```

`iaga run -- <cmd>` è il punto di partenza per il flusso "agente lanciato sotto IAGA Sentinel". In M5 sostituiremo il policy `allow_all` con una closure che chiama `execute_pipeline` per ogni `ProcessSpec`, così la stessa policy YAML/APL che governa le richieste HTTP governerà anche i process launches.

### 6. Decisioni rinviate (esplicite)

- ❌ **Loader eBPF reale** → M4.1. Richiede `aya-rs` (o `libbpf-rs`) + LLVM 18 + kernel hooks su `execve`, `openat`, `connect`, `sendto`.
- ❌ **macOS Endpoint Security** → 1.1.
- ❌ **Windows ETW + WFP** → 1.1.
- ❌ **Long-lived detached child + handle ownership** → M4.1.
- ❌ **Wiring policy callback ↔ governance pipeline** → M5.
- ❌ **Receipt firmato per ogni process launch** → M5 (richiede integrazione kernel ↔ receipts).
- ❌ **Cgroup / Job Object jailing automatico** → M4.1 (Linux cgroups via `nix`, Windows Job Objects via `winapi`).
- ❌ **Landlock fallback** → M4.1.

## Conseguenze

- **Test workspace**: 219 → 225 con 6 nuovi test in `iaga-sentinel-kernel/tests/userspace.rs`. Zero regressioni.
- **Binary size**: +~50 KB (`tokio::process` già in dep tree). Trascurabile.
- **Cross-platform CI**: invariato. Tutti i test passano su Linux/Mac/Win.
- **Audit trail**: ogni launch via `iaga run` ha backend identificato; quando in M5 il policy callback invocherà `execute_pipeline`, ogni launch produrrà un receipt firmato. La forma è già pronta.
- **Posture pubblica**: il `iaga kernel status` mostra onestamente "soft enforcement" finché M4.1 non shippa il loader. Nessun marketing inflato che si scontra con la realtà operativa.

## Esempio operativo

```bash
# Default build, ogni piattaforma
$ iaga kernel status
backend: userspace
authoritative: no (soft enforcement)
linux-bpf: not active on this build

# Lancio governed
$ iaga run --agent-id payment-bot -- python my_agent.py
[iaga run] backend=userspace agent=payment-bot program=python args=["my_agent.py"]
... output del processo ...
[iaga run] pid: 12345

# Build con scaffold eBPF (Linux dev box con bpf-linker + LLVM)
$ cargo build --release --features linux-bpf
$ iaga kernel status
backend: userspace
authoritative: no (soft enforcement)
linux-bpf: scaffold compiled (loader pending M4.1)
```

## Riferimenti

- `docs/adr/0002-open-source-license-and-scope.md` — kernel Linux-only at 1.0
- `docs/adr/0003-signed-receipts-design.md` — receipt body shape (M5 wiring point)
- `docs/adr/0005-reasoning-plane-mvp.md` — same scaffold-then-implement pattern
- `IAGA_SENTINEL_1.0.md` §pilastro 1 — design completo del kernel

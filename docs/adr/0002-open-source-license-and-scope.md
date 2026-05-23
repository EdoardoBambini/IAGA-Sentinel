# ADR 0002 — Chiusura decisioni aperte 1.0 (licenza, ML, kernel, mesh)

- **Status**: Accepted
- **Date**: 2026-04-23
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.0-alpha → 1.0 GA
- **Replaces/amends**: `IAGA_SENTINEL_1.0.md` §7 (decisioni aperte)

> **Status update 2026-05-08**: le Decisioni 3 (kernel scope) e 4 (mesh) di
> questo ADR sono state ulteriormente raffinate da
> [ADR 0010](0010-oss-enterprise-boundary.md). In sintesi: il real eBPF/LSM
> loader Linux (Aya-rs), i backend macOS Endpoint Security e Windows ETW/WFP,
> e la governance mesh (single-cluster + tier-2) sono stati riallocati in
> IAGA Sentinel Enterprise. L'OSS conserva `UserspaceKernel` cross-platform e
> il `BpfKernel` scaffold con postura honest-reported. La Decisione 1
> (BUSL-1.1 con Change License Apache-2.0 baked-in) e la Decisione 2 (`ml`
> opt-in feature flag) restano invariate.

## Contesto

`IAGA_SENTINEL_1.0.md` §7 lasciava aperte quattro scelte che cambiano la forma di 1.0:

1. **Kernel scope** — Linux-only o cross-platform full?
2. **Mesh timing** — dentro 1.0 (M5) o posticipata a 1.1?
3. **Licenza core** — BUSL-1.1 o Apache-2.0?
4. **ML plane** — obbligatorio o feature-flag opzionale?

Questa ADR chiude le quattro. Filosofia guida: **"open source assurdo e inevitabile"** → adozione default, zero frizione legale, ship veloce di un nucleo eccellente, monetizzazione su strato enterprise/managed separato.

## Decisione 1 — Licenza core: **BUSL-1.1 con Change License: Apache-2.0 baked-in**

### Posizione finale

Il core (`iaga-sentinel-core`, `iaga-sentinel-receipts`, `iaga-sentinel-apl`, `iaga-sentinel-reasoning`, `iaga-sentinel-kernel`) ships su **BUSL-1.1** con **Change License: Apache-2.0** scritta nella licenza stessa e **Change Date: quattro anni dopo la pubblicazione** di ogni release.

Tradotto: ogni versione del codice converte automaticamente e irrevocabilmente ad Apache-2.0 quattro anni dopo la sua pubblicazione. La transizione è scritta nel file `LICENSE` (riga 16) — non serve un commit di switch al Change Date, non serve azione legale, non serve approvazione di nessuno. È legalmente vincolante dal momento del primo push.

### Perché questa è la scelta migliore vs Apache-2.0 secco

- **Protezione anti-strip-mining oggi.** BUSL-1.1 impedisce a un hyperscaler di prendere il codice oggi, hostarlo come servizio managed concorrente, e drenare il TAM di Iaga Cloud prima ancora che ci siano clienti. Apache-2.0 secco non avrebbe quella protezione.
- **Promessa OSS reale e legalmente vincolante.** Il Change Date significa che chiunque adotti IAGA Sentinel oggi sa con certezza che fra quattro anni il codice diventa Apache-2.0. Non è un "trust me bro", è scritto nel testo legale che firma la release.
- **Zero rischio di rebrand backlash.** Niente switch, niente cambio improvviso, niente "Community Edition lite" mai. Il path è già stabilito al momento del commit.
- **Migration path documentato.** Le release più vecchie diventano Apache-2.0 prima delle più nuove, nello stesso ordine in cui sono state pubblicate. Naturalmente staircase.

### Cosa significa in pratica

- **Adozione interna / non-production / R&D**: completamente libera dal giorno uno (BUSL Terms § 1).
- **Adozione production**: libera, salvo il caso di rivendere IAGA Sentinel stesso come servizio managed che esponga "un substantial set" delle sue feature (Additional Use Grant in `LICENSE`). Costruire il *proprio* prodotto sopra IAGA Sentinel è permesso.
- **Cloud provider** (AWS/GCP/Azure): non possono offrirlo come servizio managed concorrente per quattro anni. Dopo, sì.
- **Forks / community**: PR esterne benvenute. Il forking di codice già pubblicato resta soggetto a BUSL fino al Change Date di quella specifica release.

### Monetizzazione

- `iaga-enterprise` (repo privato, non in questo workspace): multi-tenant managed, compliance packs, SLA 24/7, SSO/SAML, audit export packaged, support commerciale. Licenza: commerciale separata, indipendente dal core.
- `iaga-mesh` (quando arriverà in 1.1): stesso pattern del core (BUSL-1.1 con Change License: Apache-2.0).

## Decisione 2 — ML plane: **feature-flag `ml` opzionale**, default off

### Posizione finale

Il Probabilistic Reasoning Plane (pilastro 7) è un **crate separato** (`iaga-sentinel-reasoning`, M3.5) con feature flag `ml`. Default: disattivato.

### Perché

- ONNX runtime aggiunge ~40–60 MB al binary e dipendenze native (opzionalmente GPU). L'80% dei deployment giorno-1 non userà ML.
- Coerente con la regola d'oro del design: **"ML produce evidenze, policy deterministica decide"**. Senza feature `ml`, i riferimenti `ml.*` in APL risolvono a *unknown* e vengono gestiti come evidenza mancante (policy APL deve prevedere il ramo `missing`).
- Binary core leggero = adozione più rapida, CI più veloci, meno superficie di attacco per chi non vuole ML.
- I receipt contengono sempre `model_digests: []` e `ml_scores: None` se feature off, preservando replay bit-exact.

### Conseguenze

- `iaga-sentinel-reasoning` si costruisce con `cargo build -p iaga-sentinel-reasoning --features ml` (nessun default).
- `iaga-sentinel-core` non dipende da `iaga-sentinel-reasoning`; lo carica dinamicamente solo se il config abilita il plane e la feature è compilata.

## Decisione 3 — Kernel scope: **Linux-only a 1.0**, fallback userspace su macOS/Windows

### Posizione finale

`iaga-sentinel-kernel` (M4) ships solo **Linux eBPF LSM + Landlock** in 1.0. macOS (Endpoint Security) e Windows (ETW + WFP) restano in preview userspace via HTTP sidecar 0.4.0 + process jailing limitato, con UX CLI identica (`iaga run -- <cmd>`) ma enforcement soft.

### Perché

- eBPF LSM + Landlock sono production-ready su kernel ≥ 5.13, ampiamente deployati.
- **macOS Endpoint Security** richiede kernel extension firmata Apple Developer Program ($99/anno + review Apple di giorni), più entitlement `com.apple.developer.endpoint-security.client` (whitelist Apple).
- **Windows ETW + WFP** richiede driver firmati con Extended Validation certificate ($300–500/anno), più eventuale attestazione WHQL per distribuzione consumer.
- Stack tripla = 8+ mesi reali, non 4. Meglio 1.0 eccellente su Linux che 1.0 mezza-rotta su tre OS.
- README e docs saranno espliciti: "Linux = production, macOS/Windows = preview userspace". Cross-platform kernel vero → **1.1** (milestone M6 spostata).

### Conseguenze

- L'SDK 0.4.0 HTTP sidecar resta il meccanismo di fallback userspace — non deprecato, solo declassato.
- `iaga-sentinel-kernel` è un crate con `#[cfg(target_os = "linux")]` gate; fuori da Linux il crate non si compila (o espone stub `unimplemented!`).
- Documentazione kernel chiaramente separa "enforcement vero" da "preview userspace".

## Decisione 4 — Mesh: **tagliata a 1.1**

### Posizione finale

Il pilastro 5 (Governance Mesh) **esce da 1.0**. Il crate `iaga-mesh` (gRPC gossip, mTLS, CRDT su receipt log, rate budget federati) arriva in **1.1** come crate indipendente, opt-in via feature flag.

### Perché

- Mesh da sola costa 2–3 mesi (protocollo gossip, mTLS, federazione stato, test di consistenza CRDT). Ritarda il ship di 1.0 per una feature che è killer solo per utenti multi-agent-at-scale.
- Single-node IAGA Sentinel 1.0 con kernel Linux + receipts + APL + plugin attestati + UI embedded + ML opzionale **è già un prodotto di una categoria che non esiste**.
- Lo schema `Receipt.parent_hash` è già pensato per federazione futura: nessun breaking change quando mesh arriverà.

### Conseguenze

- Roadmap 1.0 passa da 6 milestone a 5:
  - M1 ✅ Fortezza Foundation
  - M2 `iaga-sentinel-receipts` (ora)
  - M3 `iaga-sentinel-apl`
  - M3.5 `iaga-sentinel-reasoning` (opt-in `ml`)
  - M4 `iaga-sentinel-kernel` (Linux)
  - M5 hardening + 1.0 GA
- M5 originale (mesh) e M6 originale (cross-platform kernel) migrati a **1.1**.

## Conseguenze trasversali

- `IAGA_SENTINEL_1.0.md` §7 va aggiornato: stato "Risolte — vedi ADR 0002".
- Ogni futura milestone assume queste quattro decisioni come baseline.
- Il messaging pubblico di IAGA Sentinel ("12-layer defense-in-depth", "replay bit-exact", "kernel-enforced governance") regge su queste scelte. Documentarle ora evita di ridiscuterle ad ogni review.

## Riferimenti

- `IAGA_SENTINEL_1.0.md` — design 1.0 completo
- `docs/adr/0001-workspace-split.md` — split workspace M1
- `docs/adr/0003-signed-receipts-design.md` — design M2 (receipts)

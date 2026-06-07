# ADR 0015: Verificatore receipt standalone + export del run (OSS 1.3)

- **Status**: Accepted
- **Date**: 2026-06-06
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.3
- **Relates to**: ADR 0003 (signed receipts), ADR 0010 (boundary OSS/Enterprise)

## Contesto

La promessa centrale del prodotto è che chiunque possa verificare la prova offline, contro una Merkle root, senza fidarsi di IAGA. Finora la verifica passava solo per il binario `iaga` completo (circa 27 MB, con backend di database e runtime async). L'artefatto che si consegna a un auditor deve essere minimale, senza database e senza dipendenze inutili, cosi che la verifica sia banale da incorporare ovunque.

## Decisioni

### 1. Crate separato e snello

`crates/iaga-sentinel-verify` produce il binario `iaga-verify`. Dipende solo da `iaga-sentinel-receipts` (default-features off, niente sqlite o postgres), piu `serde`, `serde_json`, `ed25519-dalek`, `hex`. Risultato circa 3 MB contro i 27 MB del binario completo, niente runtime async, niente accesso a rete o disco oltre al file di input.

### 2. Export del run

`iaga replay <run_id> --export <file.json>` carica il run via `ReceiptStore::get_run()` e scrive un JSON con `run_id`, `signer_verifying_key` (hex della chiave pubblica a 32 byte) e l'array `receipts`. Il `Receipt` si serializza gia con serde (body appiattito piu `signature`), quindi l'export e additivo, solo un nuovo flag.

### 3. Riuso di verify_chain

Il verificatore non reimplementa la crittografia: deserializza i receipt e chiama `iaga_sentinel_receipts::verify_chain(&receipts, &vk)`, la stessa funzione usata dal runtime. Stampa lo stato della catena (OK, BROKEN con seq e motivo, EMPTY) ed esce 0 su valida, 1 su rotta.

### 4. Trust anchor onesto

La chiave pubblica si passa con `--key <hex>` (pinnata, raccomandata): l'auditor pinna la chiave attesa fuori banda. In assenza di `--key` il verificatore ripiega sulla chiave embedded nell'export, ma stampa un warning esplicito che e auto-dichiarata e non autentica l'autore. Questo evita di spacciare una verifica di sola coerenza interna per autenticazione.

## Conseguenze

### Positive

- Verifica indipendente e portabile: nessun database, nessuna rete, binario piccolo.
- Riuso di `verify_chain`: una sola implementazione crittografica, nessun rischio di divergenza tra runtime e verificatore.
- Primo passo concreto verso lo schema receipt come standard aperto con libreria di verifica multi-linguaggio (direzione 2.0 della roadmap).

### Negative

- Il formato di export non e ancora una specifica pubblica versionata: e un JSON interno stabile, non uno standard citabile. Quello arriva con lo schema receipt v2.
- La firma resta avanzata (Ed25519), non qualificata: il peso legale eIDAS e Enterprise (ADR 0010).

### Neutre

- Test nel crate `iaga-sentinel-verify` rispecchiano `iaga-sentinel-receipts/tests`: catena valida, campo manomesso che diventa BROKEN, chiave sbagliata rifiutata. Validato end to end attraverso i binari reali.

## Riferimenti

- `crates/iaga-sentinel-verify/` (binario `iaga-verify`).
- `crates/iaga-sentinel-receipts/src/merkle.rs` (`verify_chain`), `signer.rs` (`verify_receipt`), `receipt.rs` (`Receipt`, `ChainStatus`).
- `crates/iaga-sentinel-core/src/main.rs` (flag `iaga replay --export`).

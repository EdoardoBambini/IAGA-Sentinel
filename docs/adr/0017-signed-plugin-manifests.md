# ADR 0017: Manifest plugin firmati Ed25519 (OSS 1.3)

- **Status**: Accepted
- **Date**: 2026-06-06
- **Deciders**: Edoardo Bambini
- **Milestone**: 1.3
- **Relates to**: ADR 0013 (Sigstore + SBOM offline), ADR 0011 (Signer trait), ADR 0010 (boundary)

## Contesto

ADR 0013 ha portato l'attestazione offline Sigstore piu SBOM CycloneDX: una verifica strutturale (bundle ben formato, digest che combacia). Manca un meccanismo dove un plugin porta con se un manifest firmato Ed25519, verificabile contro un insieme di chiavi fidate, riusando la stessa crittografia dei receipt. E il pezzo che chiude il buco supply-chain con un controllo di identita del firmatario, non solo di struttura.

## Decisioni

### 1. Feature dedicata e ortogonale

`plugin-manifest-signing = ["plugins", "iaga-sentinel-receipts"]`, spenta di default, ortogonale a `plugin-attestation`. Le due si possono abilitare insieme o separatamente: Sigstore verifica la provenance del bundle, il manifest firmato verifica l'identita del firmatario contro chiavi fidate locali.

### 2. Formato a file affiancati

Accanto al plugin: `<plugin>.manifest.json` con `name`, `version`, `pluginSha256`, `createdAt`, `signerKeyId`, e `<plugin>.manifest.json.sig` con la firma Ed25519 detached in hex sui byte del manifest. Stesso pattern di discovery a sibling file gia usato da ADR 0013.

### 3. Verifica con doppio controllo e degrado graceful

`verify_signed_manifest(wasm_path, trusted_keys)` controlla che `pluginSha256` nel manifest sia uguale a `sha256(wasm)` reale e che la firma verifichi contro almeno una chiave fidata. File mancanti o malformati danno `verified = false`, mai un errore bloccante: il caricamento del plugin non viene mai interrotto da un manifest assente.

### 4. Riuso della crittografia dei receipt

Niente nuova crittografia: il path di verifica Ed25519 e `LocalDiskSigner` vengono da `iaga-sentinel-receipts`. Nessuna nuova dipendenza pesante.

### 5. CLI end to end

`iaga plugins sign-manifest <wasm>` produce manifest e firma con il signer locale e stampa la chiave pubblica da pinnare. `iaga plugins verify-manifest <wasm> --trusted-keys <file>` verifica contro un file di chiavi pubbliche fidate (hex), esce 0 se verificato e 1 se no. Cosi la feature e usabile dal vivo, non solo da libreria.

### 6. Campi additivi gated

`PluginManifest` ottiene `signed_manifest` e `signed_manifest_verified` dietro `#[cfg(feature = "plugin-manifest-signing")]`, elisi quando assenti, con un hook di annotazione nel registry che rispecchia quello dell'attestazione.

### 7. Scope onesto

La verifica copre integrita del payload e identita del firmatario contro una lista di chiavi fidate fornita dall'operatore. Non verifica la provenance delle chiavi ne una catena PKI: quello, con eIDAS e Trust Service Provider, e Enterprise (ADR 0010).

## Conseguenze

### Positive

- Chiude il buco supply-chain con un controllo di identita del firmatario, ortogonale a Sigstore.
- Riusa la crittografia dei receipt, nessuna nuova dipendenza pesante, opt-in, default invariato.

### Negative

- La gestione della fiducia nelle chiavi e out of band: l'operatore decide quali chiavi sono fidate. Niente PKI, niente revoca automatica.

### Neutre

- Test che rispecchiano quelli dell'attestazione: firma e verifica che passa, wasm manomesso che fallisce per digest, chiave sbagliata rifiutata, file mancanti che danno non verificato. Validato end to end via CLI.

## Riferimenti

- `crates/iaga-sentinel-core/src/plugins/manifest.rs` (`sign_manifest`, `verify_signed_manifest`).
- `crates/iaga-sentinel-core/src/plugins/types.rs` (campi additivi), `registry.rs` (hook).
- `crates/iaga-sentinel-receipts/src/signer.rs` (`LocalDiskSigner`, verifica Ed25519).
- `crates/iaga-sentinel-core/src/main.rs` (CLI `sign-manifest`, `verify-manifest`).

# Reference deployments

Copy-paste production wiring for IAGA Sentinel. All three run the same published
image / binary and default to **sidecar** mode (IAGA Sentinel is an advisory
governance layer, not a gateway). Dashboard and API listen on port `4010`.

## Docker Compose

```sh
docker compose -f deploy/docker-compose.yml up -d
# dashboard: http://localhost:4010/
```

Persists the SQLite receipt store in the `iaga-data` volume. Runs with an
ephemeral signing key out of the box; see **BYOK** below to pin your own.

## systemd

For a bare-metal or VM host with the `iaga` binary installed at
`/usr/local/bin/iaga`:

```sh
sudo useradd --system --no-create-home iaga
sudo cp deploy/systemd/iaga-sentinel.service /etc/systemd/system/
sudo systemctl enable --now iaga-sentinel
```

`StateDirectory=iaga-sentinel` creates `/var/lib/iaga-sentinel` (owned by the
service user) for the SQLite database. Put overrides — `PORT`, API keys,
`IAGA_SENTINEL_SIGNER_KEY_PATH` — in `/etc/iaga-sentinel/iaga.env`.

## Helm (Kubernetes)

Minimal reference chart (Deployment + Service):

```sh
helm install iaga deploy/helm/
kubectl port-forward svc/iaga 4010:4010
```

The default `DATABASE_URL` uses an in-container SQLite file, so the receipt
store is **ephemeral across pod restarts**. For durability mount a
`PersistentVolumeClaim` at `/app/data`, or point `DATABASE_URL` at Postgres
(build/run with the `postgres` feature).

## BYOK — bring your own signing key

The receipt signer is a **raw 32-byte Ed25519 seed** at
`IAGA_SENTINEL_SIGNER_KEY_PATH` (default `~/.iaga-sentinel/keys/receipt_signer.ed25519`).
On first run the server generates and stores a seed there if the file is
absent. In a container without a persisted volume that path is recreated each
start, so chains from different runs verify under different keys — pin a stable
key to avoid that:

```sh
# Option A: point the signer at a persisted path and let it generate the seed.
export IAGA_SENTINEL_SIGNER_KEY_PATH=/keys/signing.key   # created on first run

# Option B: supply your own — exactly 32 random bytes (NOT an openssl genpkey PEM).
openssl rand 32 > /keys/signing.key
```

Then mount the key read-only (the Compose file has commented `./keys` lines).
The private seed never leaves your infrastructure; the public key is what
auditors pin with `iaga-verify --key`. (`iaga gen-key` is unrelated — it mints
API auth keys, not the signing seed.)

## Open mode

Set `IAGA_SENTINEL_OPEN_MODE=true` only for a keyless local demo. In production
leave it unset and provision API keys with `iaga gen-key`; callers then send
`Authorization: Bearer <key>`.

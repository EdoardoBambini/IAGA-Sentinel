# Demo Walkthrough

> **Historical demo — describes the v0.3.0 community runtime.** The
> commands and paths (`cd community`, `iaga-sentinel gen-key`, port
> `4010`) reflect the pre-1.0 layout. For the current 1.x quickstart,
> see the **Quickstart** section of [`README.md`](../README.md): the
> binary is `iaga` (or `iaga-sentinel` alias), the workspace is
> `crates/iaga-sentinel-core/`, and the default HTTP port is `7777`.

## Goal

Show the current `v0.3.0` community runtime governing real HTTP requests through the server.

## Start The Runtime

```bash
cd community
cargo build --release
./target/release/iaga-sentinel gen-key --label demo
./target/release/iaga-sentinel serve
```

Open `http://localhost:4010` for the embedded dashboard.

## Demo Scenarios

### Scenario 1 - Safe File Read

A builder agent reads a normal file via `filesystem.read`.

Expected result:

- `allow`
- low risk
- audit event recorded

### Scenario 2 - Controlled Shell Command

A builder agent requests a shell action that is policy-capped to review.

Expected result:

- `review`
- review item created

### Scenario 3 - Destructive Command

An agent attempts `rm -rf /`.

Expected result:

- `block`
- high risk score
- audit event recorded

### Scenario 4 - Sensitive Output Scan

A tool response contains an AWS key-like value.

Expected result:

- `review` or `block` depending on payload
- redaction and findings reported by `/v1/response/scan`

## Verified HTTP Flow

```bash
# Health
curl http://localhost:4010/health

# Inspect
curl -X POST http://localhost:4010/v1/inspect \
  -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "openclaw-builder-01",
    "workspaceId": "ws-demo",
    "framework": "openclaw",
    "protocol": "mcp",
    "action": {
      "type": "file_read",
      "toolName": "filesystem.read",
      "payload": {
        "path": "README.md",
        "intent": "read docs"
      }
    }
  }'

# Response scan
curl -X POST http://localhost:4010/v1/response/scan \
  -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "scan-demo-1",
    "agentId": "openclaw-builder-01",
    "toolName": "terminal.exec",
    "responsePayload": {
      "secret": "AKIA1234567890ABCDEF"
    }
  }'

# Audit export
curl "http://localhost:4010/v1/audit/export?format=csv" \
  -H "Authorization: Bearer <key>"
```

## What To Observe

- `x-request-id` is returned on HTTP responses
- `traceId` is returned in governance responses
- audit entries appear after inspect calls
- CSV export includes the newly generated audit rows

## Dashboard Note

The dashboard is now connected to live runtime data.

If the runtime is protected, paste a valid API key into the dashboard to load the protected endpoints.

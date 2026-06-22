# IAGA Sentinel — OpenAI (Python)

Govern an OpenAI client's calls. `sentinel_wrap_openai` returns a drop-in proxy:
every `chat.completions.create` / `responses.create` is inspected through
`POST /v1/inspect` before the request is sent.

- **allow** → the request is sent and a signed receipt is produced
- **review / block** → raises `SentinelBlockedError` / `PermissionError`
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

A dangerous prompt (e.g. one carrying `curl … | sh`) is blocked by the injection
firewall **before** any OpenAI spend.

## 1. Start the sidecar

```bash
cargo build --release --workspace
IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import examples/integrations/openai/openai.policy.yaml
```

## 3. Run

```bash
pip install openai iaga-sentinel
# Set OPENAI_API_KEY in your shell, then:
python examples/integrations/openai/python_example.py
```

```python
from openai import OpenAI
from iaga_sentinel.adapters import sentinel_wrap_openai

client = sentinel_wrap_openai(OpenAI(), agent_id="openai-demo", base_url="http://localhost:4010")
client.chat.completions.create(model="gpt-4o", messages=[...])  # inspected first
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```

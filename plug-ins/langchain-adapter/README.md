# IAGA Sentinel — LangChain

Govern a LangChain agent's tool calls. `SentinelCallbackHandler` implements
`on_tool_start`: attach it as a callback and every tool call is inspected through
`POST /v1/inspect` before it runs.

- **allow** → the tool runs and a signed receipt is produced
- **review** → raises `PermissionError` (or your `on_review`)
- **block** → raises `PermissionError`
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

The handler sets `raise_error = True` so LangChain propagates the block instead of
swallowing it, and is dependency-light (it does not import langchain).

## 1. Start the sidecar

```bash
cargo build --release --workspace
IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import examples/integrations/langchain/langchain.policy.yaml
```

## 3. Run

```bash
pip install langchain-core iaga-sentinel
python examples/integrations/langchain/python_example.py
```

Attach the handler anywhere LangChain accepts callbacks:

```python
from iaga_sentinel.adapters import SentinelCallbackHandler

handler = SentinelCallbackHandler(agent_id="langchain-demo", base_url="http://localhost:4010")
agent_executor.invoke({"input": "..."}, config={"callbacks": [handler]})
```

A dangerous tool call (e.g. a `shell` with `curl … | sh`) is blocked by the
injection firewall before it runs, regardless of the policy decision.

## Receipts

`auditEvent.eventId` from the verdict is the receipt's `run_id`:

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```

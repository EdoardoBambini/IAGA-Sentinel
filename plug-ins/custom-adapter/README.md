# IAGA Sentinel — Custom Python agent

The `@governed` decorator is the baseline every other adapter mirrors: it inspects
each call through `POST /v1/inspect` before the function body runs. Use it on any
tool function, or call `SentinelClient.inspect(...)` directly.

- **allow** → the function runs and a signed receipt is produced
- **review / block** → raises `PermissionError` (or your `on_block` / `on_review`)
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

## 1. Start the sidecar

```bash
cargo build --release --workspace
IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import examples/integrations/custom/custom.policy.yaml
```

## 3. Run

```bash
pip install iaga-sentinel
python examples/integrations/custom/python_example.py
```

```python
from iaga_sentinel import ActionType, governed

@governed(agent_id="custom-agent", tool_name="shell", action_type=ActionType.SHELL,
          base_url="http://localhost:4010")
def run_shell(cmd: str) -> str:
    ...   # blocked -> PermissionError (or your on_block= callback)
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```

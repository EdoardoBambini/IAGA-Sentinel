// Compile-time proof that the IAGA Sentinel `iagaCanUseTool` callback is
// assignable to the REAL @anthropic-ai/claude-agent-sdk `query` canUseTool
// option (its PermissionResult contract). Run:
//   node ../node_modules/typescript/bin/tsc -p tsconfig.typecheck.json
import { query } from "@anthropic-ai/claude-agent-sdk";
import { SentinelClient } from "@iaga-sentinel/sdk";
import { iagaCanUseTool } from "../../../examples/integrations/claude-agent-sdk/canUseTool";

type Options = NonNullable<Parameters<typeof query>[0]["options"]>;
type CanUseToolFn = NonNullable<Options["canUseTool"]>;

// If this assignment type-checks, the example's callback matches the SDK.
export const _canUseTool: CanUseToolFn = iagaCanUseTool(new SentinelClient());

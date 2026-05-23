import { SentinelBlockedError, SentinelClient, SentinelReviewError } from "../client";
import type { ActionType, InspectRequest, JsonObject, JsonValue, OpenAIAdapterOptions } from "../types";

type AnyRecord = Record<string | symbol, unknown>;
type AnyFunction = (...args: unknown[]) => unknown;

function toJsonValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => toJsonValue(item));
  }
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, toJsonValue(entry)])
    );
  }
  return String(value);
}

function serializeArgs(args: unknown[]): JsonObject {
  return {
    args: args.map((arg) => toJsonValue(arg)),
  };
}

function buildInspectRequest(
  options: OpenAIAdapterOptions,
  toolName: string,
  actionType: ActionType,
  payload: JsonObject
): InspectRequest {
  return {
    agentId: options.agentId,
    tenantId: options.tenantId,
    workspaceId: options.workspaceId,
    framework: options.framework ?? "openai",
    sessionId: options.sessionId,
    metadata: options.metadata,
    action: {
      type: actionType,
      toolName,
      payload,
    },
  };
}

async function enforcePolicy(
  client: SentinelClient,
  request: InspectRequest
): Promise<void> {
  const result = await client.inspect(request);
  if (result.decision === "block") {
    throw new SentinelBlockedError(result);
  }
  if (result.decision === "review") {
    throw new SentinelReviewError(result);
  }
}

function bindIfNeeded(target: unknown, value: unknown): unknown {
  if (typeof value === "function") {
    return (value as AnyFunction).bind(target);
  }
  return value;
}

function wrapCreate(
  iaga: SentinelClient,
  options: OpenAIAdapterOptions,
  target: AnyRecord,
  fn: AnyFunction,
  toolName: string
): AnyFunction {
  return async (...args: unknown[]) => {
    await enforcePolicy(
      iaga,
      buildInspectRequest(options, toolName, "http", serializeArgs(args))
    );
    return fn.apply(target, args);
  };
}

export function sentinelWrapOpenAI<T extends AnyRecord>(
  client: T,
  options: OpenAIAdapterOptions
): T {
  const iaga = new SentinelClient(options);

  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "responses") {
        const namespace = Reflect.get(target, prop, receiver) as AnyRecord;
        if (!namespace) {
          return namespace;
        }
        return new Proxy(namespace, {
          get(responseTarget, responseProp, responseReceiver) {
            const value = Reflect.get(responseTarget, responseProp, responseReceiver);
            if (responseProp === "create" && typeof value === "function") {
              return wrapCreate(
                iaga,
                options,
                responseTarget as AnyRecord,
                value as AnyFunction,
                "openai.responses.create"
              );
            }
            return bindIfNeeded(responseTarget, value);
          },
        });
      }

      if (prop === "chat") {
        const namespace = Reflect.get(target, prop, receiver) as AnyRecord;
        if (!namespace) {
          return namespace;
        }
        return new Proxy(namespace, {
          get(chatTarget, chatProp, chatReceiver) {
            if (chatProp === "completions") {
              const completions = Reflect.get(chatTarget, chatProp, chatReceiver) as AnyRecord;
              if (!completions) {
                return completions;
              }
              return new Proxy(completions, {
                get(completionsTarget, completionsProp, completionsReceiver) {
                  const value = Reflect.get(completionsTarget, completionsProp, completionsReceiver);
                  if (completionsProp === "create" && typeof value === "function") {
                    return wrapCreate(
                      iaga,
                      options,
                      completionsTarget as AnyRecord,
                      value as AnyFunction,
                      "openai.chat.completions.create"
                    );
                  }
                  return bindIfNeeded(completionsTarget, value);
                },
              });
            }

            const value = Reflect.get(chatTarget, chatProp, chatReceiver);
            return bindIfNeeded(chatTarget, value);
          },
        });
      }

      const value = Reflect.get(target, prop, receiver);
      return bindIfNeeded(target, value);
    },
  }) as T;
}

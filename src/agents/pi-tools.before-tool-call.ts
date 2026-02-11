import type { AnyAgentTool } from "./tools/common.js";
import { loadConfig } from "../config/config.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { getGlobalHookRunner } from "../plugins/hook-runner-global.js";
import {
  evaluateLlmThreatPolicy,
  formatThreatPolicyDecision,
} from "../security/llm-threat-policy.js";
import { isPlainObject } from "../utils.js";
import { normalizeToolName } from "./tool-policy.js";

type HookContext = {
  agentId?: string;
  sessionKey?: string;
};

type HookOutcome = { blocked: true; reason: string } | { blocked: false; params: unknown };

function applyThreatPolicy(toolName: string, params: unknown, ctx?: HookContext): HookOutcome {
  const cfg = loadConfig();
  const outcome = evaluateLlmThreatPolicy({
    toolName,
    params,
    config: cfg,
    agentId: ctx?.agentId,
    sessionKey: ctx?.sessionKey,
  });

  if (outcome.mode !== "off") {
    log.info(`[security] llm-threat-policy ${formatThreatPolicyDecision(outcome)}`);
  }

  if (outcome.decision === "block") {
    return {
      blocked: true,
      reason:
        `Tool call blocked by LLM threat policy (score=${outcome.score}; ` +
        `reasons=${outcome.reasonCodes.join(",") || "none"})`,
    };
  }

  if (outcome.decision === "require_approval" && isPlainObject(params) && toolName === "exec") {
    return {
      blocked: false,
      params: {
        ...params,
        ask: "always",
        _threatPolicy: {
          approvalRequired: true,
          reasonCodes: outcome.reasonCodes,
          score: outcome.score,
        },
      },
    };
  }

  return { blocked: false, params };
}

const log = createSubsystemLogger("agents/tools");

export async function runBeforeToolCallHook(args: {
  toolName: string;
  params: unknown;
  toolCallId?: string;
  ctx?: HookContext;
}): Promise<HookOutcome> {
  const policyOutcome = applyThreatPolicy(
    normalizeToolName(args.toolName || "tool"),
    args.params,
    args.ctx,
  );
  if (policyOutcome.blocked) {
    return policyOutcome;
  }

  const paramsAfterPolicy = policyOutcome.params;

  const hookRunner = getGlobalHookRunner();
  if (!hookRunner?.hasHooks("before_tool_call")) {
    return { blocked: false, params: paramsAfterPolicy };
  }

  const toolName = normalizeToolName(args.toolName || "tool");
  const params = paramsAfterPolicy;
  try {
    const normalizedParams = isPlainObject(params) ? params : {};
    const hookResult = await hookRunner.runBeforeToolCall(
      {
        toolName,
        params: normalizedParams,
      },
      {
        toolName,
        agentId: args.ctx?.agentId,
        sessionKey: args.ctx?.sessionKey,
      },
    );

    if (hookResult?.block) {
      return {
        blocked: true,
        reason: hookResult.blockReason || "Tool call blocked by plugin hook",
      };
    }

    if (hookResult?.params && isPlainObject(hookResult.params)) {
      if (isPlainObject(params)) {
        return { blocked: false, params: { ...params, ...hookResult.params } };
      }
      return { blocked: false, params: hookResult.params };
    }
  } catch (err) {
    const toolCallId = args.toolCallId ? ` toolCallId=${args.toolCallId}` : "";
    log.warn(`before_tool_call hook failed: tool=${toolName}${toolCallId} error=${String(err)}`);
  }

  return { blocked: false, params };
}

export function wrapToolWithBeforeToolCallHook(
  tool: AnyAgentTool,
  ctx?: HookContext,
): AnyAgentTool {
  const execute = tool.execute;
  if (!execute) {
    return tool;
  }
  const toolName = tool.name || "tool";
  return {
    ...tool,
    execute: async (toolCallId, params, signal, onUpdate) => {
      const outcome = await runBeforeToolCallHook({
        toolName,
        params,
        toolCallId,
        ctx,
      });
      if (outcome.blocked) {
        throw new Error(outcome.reason);
      }
      return await execute(toolCallId, outcome.params, signal, onUpdate);
    },
  };
}

export const __testing = {
  runBeforeToolCallHook,
  isPlainObject,
};

import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../config/config.js";
import { getGlobalHookRunner } from "../plugins/hook-runner-global.js";
import { toClientToolDefinitions } from "./pi-tool-definition-adapter.js";
import { wrapToolWithBeforeToolCallHook } from "./pi-tools.before-tool-call.js";

vi.mock("../plugins/hook-runner-global.js");
vi.mock("../config/config.js", () => ({ loadConfig: vi.fn(() => ({})) }));

const mockGetGlobalHookRunner = vi.mocked(getGlobalHookRunner);
const mockLoadConfig = vi.mocked(loadConfig);

describe("before_tool_call hook integration", () => {
  let hookRunner: {
    hasHooks: ReturnType<typeof vi.fn>;
    runBeforeToolCall: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    hookRunner = {
      hasHooks: vi.fn(),
      runBeforeToolCall: vi.fn(),
    };
    // oxlint-disable-next-line typescript/no-explicit-any
    mockGetGlobalHookRunner.mockReturnValue(hookRunner as any);
    mockLoadConfig.mockReturnValue({} as ReturnType<typeof loadConfig>);
  });

  it("executes tool normally when no hook is registered", async () => {
    hookRunner.hasHooks.mockReturnValue(false);
    const execute = vi.fn().mockResolvedValue({ content: [], details: { ok: true } });
    // oxlint-disable-next-line typescript/no-explicit-any
    const tool = wrapToolWithBeforeToolCallHook({ name: "Read", execute } as any, {
      agentId: "main",
      sessionKey: "main",
    });

    await tool.execute("call-1", { path: "/tmp/file" }, undefined, undefined);

    expect(hookRunner.runBeforeToolCall).not.toHaveBeenCalled();
    expect(execute).toHaveBeenCalledWith("call-1", { path: "/tmp/file" }, undefined, undefined);
  });

  it("allows hook to modify parameters", async () => {
    hookRunner.hasHooks.mockReturnValue(true);
    hookRunner.runBeforeToolCall.mockResolvedValue({ params: { mode: "safe" } });
    const execute = vi.fn().mockResolvedValue({ content: [], details: { ok: true } });
    // oxlint-disable-next-line typescript/no-explicit-any
    const tool = wrapToolWithBeforeToolCallHook({ name: "exec", execute } as any);

    await tool.execute("call-2", { cmd: "ls" }, undefined, undefined);

    expect(execute).toHaveBeenCalledWith(
      "call-2",
      { cmd: "ls", mode: "safe" },
      undefined,
      undefined,
    );
  });

  it("downgrades risky exec calls to ask=always in moderate mode", async () => {
    hookRunner.hasHooks.mockReturnValue(false);
    mockLoadConfig.mockReturnValue({
      gateway: { security: { llmThreatPolicy: { mode: "moderate" } } },
    } as ReturnType<typeof loadConfig>);
    const execute = vi.fn().mockResolvedValue({ content: [], details: { ok: true } });
    // oxlint-disable-next-line typescript/no-explicit-any
    const tool = wrapToolWithBeforeToolCallHook({ name: "exec", execute } as any, {
      sessionKey: "main",
    });

    await tool.execute(
      "call-risk",
      { command: "cat ~/.ssh/config", note: "api_key" },
      undefined,
      undefined,
    );

    expect(execute).toHaveBeenCalledWith(
      "call-risk",
      expect.objectContaining({
        command: "cat ~/.ssh/config",
        ask: "always",
      }),
      undefined,
      undefined,
    );
  });
  it("blocks tool execution when hook returns block=true", async () => {
    hookRunner.hasHooks.mockReturnValue(true);
    hookRunner.runBeforeToolCall.mockResolvedValue({
      block: true,
      blockReason: "blocked",
    });
    const execute = vi.fn().mockResolvedValue({ content: [], details: { ok: true } });
    // oxlint-disable-next-line typescript/no-explicit-any
    const tool = wrapToolWithBeforeToolCallHook({ name: "exec", execute } as any);

    await expect(tool.execute("call-3", { cmd: "rm -rf /" }, undefined, undefined)).rejects.toThrow(
      "blocked",
    );
    expect(execute).not.toHaveBeenCalled();
  });

  it("continues execution when hook throws", async () => {
    hookRunner.hasHooks.mockReturnValue(true);
    hookRunner.runBeforeToolCall.mockRejectedValue(new Error("boom"));
    const execute = vi.fn().mockResolvedValue({ content: [], details: { ok: true } });
    // oxlint-disable-next-line typescript/no-explicit-any
    const tool = wrapToolWithBeforeToolCallHook({ name: "read", execute } as any);

    await tool.execute("call-4", { path: "/tmp/file" }, undefined, undefined);

    expect(execute).toHaveBeenCalledWith("call-4", { path: "/tmp/file" }, undefined, undefined);
  });

  it("normalizes non-object params for hook contract", async () => {
    hookRunner.hasHooks.mockReturnValue(true);
    hookRunner.runBeforeToolCall.mockResolvedValue(undefined);
    const execute = vi.fn().mockResolvedValue({ content: [], details: { ok: true } });
    // oxlint-disable-next-line typescript/no-explicit-any
    const tool = wrapToolWithBeforeToolCallHook({ name: "ReAd", execute } as any, {
      agentId: "main",
      sessionKey: "main",
    });

    await tool.execute("call-5", "not-an-object", undefined, undefined);

    expect(hookRunner.runBeforeToolCall).toHaveBeenCalledWith(
      {
        toolName: "read",
        params: {},
      },
      {
        toolName: "read",
        agentId: "main",
        sessionKey: "main",
      },
    );
  });
});

describe("before_tool_call hook integration for client tools", () => {
  let hookRunner: {
    hasHooks: ReturnType<typeof vi.fn>;
    runBeforeToolCall: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    hookRunner = {
      hasHooks: vi.fn(),
      runBeforeToolCall: vi.fn(),
    };
    // oxlint-disable-next-line typescript/no-explicit-any
    mockGetGlobalHookRunner.mockReturnValue(hookRunner as any);
    mockLoadConfig.mockReturnValue({} as ReturnType<typeof loadConfig>);
  });

  it("passes modified params to client tool callbacks", async () => {
    hookRunner.hasHooks.mockReturnValue(true);
    hookRunner.runBeforeToolCall.mockResolvedValue({ params: { extra: true } });
    const onClientToolCall = vi.fn();
    const [tool] = toClientToolDefinitions(
      [
        {
          type: "function",
          function: {
            name: "client_tool",
            description: "Client tool",
            parameters: { type: "object", properties: { value: { type: "string" } } },
          },
        },
      ],
      onClientToolCall,
      { agentId: "main", sessionKey: "main" },
    );

    await tool.execute("client-call-1", { value: "ok" }, undefined, undefined, undefined);

    expect(onClientToolCall).toHaveBeenCalledWith("client_tool", {
      value: "ok",
      extra: true,
    });
  });
});

import { describe, expect, it, vi } from "vitest";
import type { RuntimeEnv } from "../runtime.js";
import type { WizardPrompter } from "./prompts.js";

const mocks = vi.hoisted(() => ({
  randomToken: vi.fn(),
}));

vi.mock("../commands/onboard-helpers.js", async (importActual) => {
  const actual = await importActual<typeof import("../commands/onboard-helpers.js")>();
  return {
    ...actual,
    randomToken: mocks.randomToken,
  };
});

vi.mock("../infra/tailscale.js", () => ({
  findTailscaleBinary: vi.fn(async () => undefined),
}));

import { configureGatewayForOnboarding } from "./onboarding.gateway-config.js";

describe("configureGatewayForOnboarding", () => {
  it("generates a token when the prompt returns undefined", async () => {
    mocks.randomToken.mockReturnValue("generated-token");

    const selectQueue = ["loopback", "token", "off"];
    const textQueue = ["18789", undefined];
    const prompter: WizardPrompter = {
      intro: vi.fn(async () => {}),
      outro: vi.fn(async () => {}),
      note: vi.fn(async () => {}),
      select: vi.fn(async () => selectQueue.shift() as string),
      multiselect: vi.fn(async () => []),
      text: vi.fn(async () => textQueue.shift() as string),
      confirm: vi.fn(async () => false),
      progress: vi.fn(() => ({ update: vi.fn(), stop: vi.fn() })),
    };

    const runtime: RuntimeEnv = {
      log: vi.fn(),
      error: vi.fn(),
      exit: vi.fn(),
    };

    const result = await configureGatewayForOnboarding({
      flow: "advanced",
      baseConfig: {},
      nextConfig: {},
      localPort: 18789,
      quickstartGateway: {
        hasExisting: false,
        port: 18789,
        bind: "loopback",
        authMode: "token",
        tailscaleMode: "off",
        token: undefined,
        password: undefined,
        customBindHost: undefined,
        tailscaleResetOnExit: false,
      },
      prompter,
      runtime,
    });

    expect(result.settings.gatewayToken).toBe("generated-token");
    expect(result.nextConfig.gateway?.nodes?.denyCommands).toEqual([
      "camera.snap",
      "camera.clip",
      "screen.record",
      "calendar.add",
      "contacts.add",
      "reminders.add",
    ]);
  });

  it("enforces beginner-safe defaults in quickstart flow", async () => {
    mocks.randomToken.mockReturnValue("safe-token");

    const prompter: WizardPrompter = {
      intro: vi.fn(async () => {}),
      outro: vi.fn(async () => {}),
      note: vi.fn(async () => {}),
      select: vi.fn(async () => "unused"),
      multiselect: vi.fn(async () => []),
      text: vi.fn(async () => ""),
      confirm: vi.fn(async () => false),
      progress: vi.fn(() => ({ update: vi.fn(), stop: vi.fn() })),
    };

    const runtime: RuntimeEnv = {
      log: vi.fn(),
      error: vi.fn(),
      exit: vi.fn(),
    };

    const result = await configureGatewayForOnboarding({
      flow: "quickstart",
      baseConfig: {},
      nextConfig: {
        gateway: {
          bind: "lan",
          auth: { mode: "password", password: "legacy" },
          tailscale: { mode: "funnel", resetOnExit: true },
          nodes: { denyCommands: ["screen.record"] },
        },
        tools: { exec: { security: "full", ask: "off" } },
        agents: { defaults: { elevatedDefault: "on" } },
      },
      localPort: 18789,
      quickstartGateway: {
        hasExisting: true,
        port: 18789,
        bind: "lan",
        authMode: "password",
        tailscaleMode: "funnel",
        token: undefined,
        password: "legacy",
        customBindHost: undefined,
        tailscaleResetOnExit: true,
      },
      prompter,
      runtime,
    });

    expect(result.settings.bind).toBe("loopback");
    expect(result.settings.authMode).toBe("token");
    expect(result.settings.tailscaleMode).toBe("off");
    expect(result.nextConfig.gateway?.auth?.mode).toBe("token");
    expect(result.nextConfig.gateway?.auth?.token).toBe("safe-token");
    expect(result.nextConfig.tools?.exec?.security).toBe("allowlist");
    expect(result.nextConfig.tools?.exec?.ask).toBe("always");
    expect(result.nextConfig.agents?.defaults?.elevatedDefault).toBe("ask");
    expect(result.nextConfig.gateway?.nodes?.denyCommands).toEqual([
      "screen.record",
      "camera.snap",
      "camera.clip",
      "calendar.add",
      "contacts.add",
      "reminders.add",
    ]);
  });
});

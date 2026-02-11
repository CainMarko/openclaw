import { describe, expect, it } from "vitest";
import { ADVERSARIAL_PROMPT_FIXTURES, type SecurityMode } from "./adversarial-fixtures.js";
import { evaluateRiskPolicy } from "./adversarial-policy.js";
import { detectSuspiciousPatterns } from "./external-content.js";

describe("security adversarial fixtures", () => {
  it("detects suspicious content in labeled adversarial prompts", () => {
    const byFixture = ADVERSARIAL_PROMPT_FIXTURES.filter((fixture) => fixture.untrusted).map(
      (fixture) => ({
        id: fixture.id,
        patterns: detectSuspiciousPatterns(fixture.content),
      }),
    );

    const suspiciousCount = byFixture.filter((entry) => entry.patterns.length > 0).length;
    expect(suspiciousCount).toBeGreaterThanOrEqual(3);

    expect(byFixture).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "direct-jailbreak-001" }),
        expect.objectContaining({ id: "ignore-exfiltrate-001" }),
        expect.objectContaining({ id: "send-attacker-exec-001" }),
      ]),
    );
  });

  it("enforces deny outcomes for unsafe tools requested from untrusted content", () => {
    const unsafe = ADVERSARIAL_PROMPT_FIXTURES.filter(
      (fixture) => fixture.untrusted && fixture.requestedTool !== "none",
    );

    for (const fixture of unsafe) {
      const strict = evaluateRiskPolicy({
        content: fixture.content,
        mode: "strict",
        untrusted: fixture.untrusted,
        requestedTool: fixture.requestedTool,
      });
      const moderate = evaluateRiskPolicy({
        content: fixture.content,
        mode: "moderate",
        untrusted: fixture.untrusted,
        requestedTool: fixture.requestedTool,
      });

      expect(strict.decision).toBe("deny");
      expect(moderate.decision).toBe("deny");
      expect(strict.blockedActions).toContain(fixture.requestedTool);
      expect(moderate.blockedActions).toContain(fixture.requestedTool);
    }
  });

  it("captures expected risk-policy decisions by security mode", () => {
    const modes: SecurityMode[] = ["strict", "moderate", "off"];
    const snapshots = Object.fromEntries(
      modes.map((mode) => {
        const decisions = ADVERSARIAL_PROMPT_FIXTURES.map((fixture) => ({
          id: fixture.id,
          decision: evaluateRiskPolicy({
            content: fixture.content,
            mode,
            untrusted: fixture.untrusted,
            requestedTool: fixture.requestedTool,
          }).decision,
        }));
        return [mode, decisions];
      }),
    );

    expect(snapshots).toMatchInlineSnapshot(`
      {
        "moderate": [
          {
            "decision": "ask",
            "id": "direct-jailbreak-001",
          },
          {
            "decision": "ask",
            "id": "indirect-wrapper-001",
          },
          {
            "decision": "deny",
            "id": "ignore-exfiltrate-001",
          },
          {
            "decision": "deny",
            "id": "send-attacker-exec-001",
          },
          {
            "decision": "allow",
            "id": "trusted-safe-001",
          },
          {
            "decision": "ask",
            "id": "trusted-maintenance-001",
          },
        ],
        "off": [
          {
            "decision": "allow",
            "id": "direct-jailbreak-001",
          },
          {
            "decision": "allow",
            "id": "indirect-wrapper-001",
          },
          {
            "decision": "allow",
            "id": "ignore-exfiltrate-001",
          },
          {
            "decision": "allow",
            "id": "send-attacker-exec-001",
          },
          {
            "decision": "allow",
            "id": "trusted-safe-001",
          },
          {
            "decision": "allow",
            "id": "trusted-maintenance-001",
          },
        ],
        "strict": [
          {
            "decision": "deny",
            "id": "direct-jailbreak-001",
          },
          {
            "decision": "deny",
            "id": "indirect-wrapper-001",
          },
          {
            "decision": "deny",
            "id": "ignore-exfiltrate-001",
          },
          {
            "decision": "deny",
            "id": "send-attacker-exec-001",
          },
          {
            "decision": "allow",
            "id": "trusted-safe-001",
          },
          {
            "decision": "ask",
            "id": "trusted-maintenance-001",
          },
        ],
      }
    `);
  });
});

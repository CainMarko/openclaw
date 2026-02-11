import type { SecurityMode, UnsafeToolRequest } from "./adversarial-fixtures.js";
import { detectSuspiciousPatterns } from "./external-content.js";

export type SecurityDecision = "allow" | "ask" | "deny";

export type RiskPolicyResult = {
  decision: SecurityDecision;
  suspicious: boolean;
  blockedActions: UnsafeToolRequest[];
  reasons: string[];
};

const EXFILTRATION_PATTERN = /(exfiltrat|send\s+.*attacker|leak|credential|token|secret)/i;

const UNSAFE_TOOLS = new Set<UnsafeToolRequest>([
  "exec_command",
  "send_external_message",
  "read_sensitive_data",
]);

export function evaluateRiskPolicy(input: {
  content: string;
  mode: SecurityMode;
  untrusted: boolean;
  requestedTool: UnsafeToolRequest;
}): RiskPolicyResult {
  const { content, mode, untrusted, requestedTool } = input;

  if (mode === "off") {
    return {
      decision: "allow",
      suspicious: false,
      blockedActions: [],
      reasons: ["security_mode_off"],
    };
  }

  const suspiciousMatches = detectSuspiciousPatterns(content);
  const exfiltrationHint = EXFILTRATION_PATTERN.test(content);
  const suspicious = suspiciousMatches.length > 0 || exfiltrationHint;
  const toolUnsafe = UNSAFE_TOOLS.has(requestedTool);
  const reasons: string[] = [];

  if (suspiciousMatches.length > 0) {
    reasons.push("suspicious_prompt_patterns");
  }
  if (exfiltrationHint) {
    reasons.push("exfiltration_language");
  }

  if (!suspicious && !toolUnsafe) {
    return {
      decision: "allow",
      suspicious: false,
      blockedActions: [],
      reasons: ["no_risk_detected"],
    };
  }

  if (untrusted && toolUnsafe) {
    return {
      decision: "deny",
      suspicious,
      blockedActions: [requestedTool],
      reasons: [...reasons, "untrusted_unsafe_tool_request"],
    };
  }

  if (mode === "strict") {
    if (suspicious) {
      return {
        decision: "deny",
        suspicious: true,
        blockedActions: toolUnsafe ? [requestedTool] : [],
        reasons: [...reasons, "strict_mode_suspicious_content"],
      };
    }

    if (toolUnsafe) {
      return {
        decision: "ask",
        suspicious,
        blockedActions: [],
        reasons: [...reasons, "strict_mode_confirmation_required"],
      };
    }
  }

  if (mode === "moderate") {
    if (suspicious) {
      return {
        decision: "ask",
        suspicious: true,
        blockedActions: [],
        reasons: [...reasons, "moderate_mode_needs_confirmation"],
      };
    }

    if (toolUnsafe) {
      return {
        decision: "ask",
        suspicious,
        blockedActions: [],
        reasons: [...reasons, "unsafe_tool_confirmation_required"],
      };
    }
  }

  return {
    decision: "allow",
    suspicious,
    blockedActions: [],
    reasons: reasons.length > 0 ? reasons : ["fallback_allow"],
  };
}

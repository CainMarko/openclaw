import type { OpenClawConfig } from "../config/config.js";

type ThreatPolicyConfig = Pick<OpenClawConfig, "gateway" | "agents">;
import { detectSuspiciousPatterns, isExternalHookSession } from "./external-content.js";

export type LlmThreatPolicyMode = "off" | "moderate" | "strict";
export type LlmThreatPolicyDecision = "allow" | "require_approval" | "block";

export type LlmThreatPolicyReasonCode =
  | "provenance_untrusted_web"
  | "provenance_untrusted_email"
  | "provenance_untrusted_webhook"
  | "provenance_untrusted_hook"
  | "injection_pattern_detected"
  | "action_exec"
  | "action_message_send"
  | "action_secret_access"
  | "action_file_delete"
  | "action_network_fetch"
  | "score_high"
  | "score_medium";

export type LlmThreatPolicyOutcome = {
  mode: LlmThreatPolicyMode;
  decision: LlmThreatPolicyDecision;
  score: number;
  approvalRequired: boolean;
  reasonCodes: LlmThreatPolicyReasonCode[];
  suspiciousPatternHits: string[];
  provenance: {
    source: ThreatSource;
    untrusted: boolean;
  };
  sensitivity: ThreatSensitivity[];
};

type ThreatSource = "internal" | "web" | "email" | "webhook" | "hook";
type ThreatSensitivity = "exec" | "message_send" | "secrets" | "file_delete" | "network_fetch";

const EXTERNAL_MARKER_START = "<<<EXTERNAL_UNTRUSTED_CONTENT>>>";

function inferThreatSource(sessionKey?: string, text?: string): ThreatSource {
  if (sessionKey?.startsWith("hook:gmail:")) {
    return "email";
  }
  if (sessionKey?.startsWith("hook:webhook:")) {
    return "webhook";
  }
  if (sessionKey && isExternalHookSession(sessionKey)) {
    return "hook";
  }
  const lower = (text ?? "").toLowerCase();
  if (lower.includes(EXTERNAL_MARKER_START.toLowerCase())) {
    if (lower.includes("source: email")) {
      return "email";
    }
    if (lower.includes("source: webhook")) {
      return "webhook";
    }
    if (lower.includes("source: web fetch") || lower.includes("source: web search")) {
      return "web";
    }
    return "hook";
  }
  return "internal";
}

function detectActionSensitivity(toolName: string, text: string): ThreatSensitivity[] {
  const out = new Set<ThreatSensitivity>();
  const normalized = toolName.trim().toLowerCase();
  const lowerText = text.toLowerCase();

  if (normalized === "exec" || normalized === "process" || normalized === "bash") {
    out.add("exec");
  }
  if (
    normalized === "message" ||
    normalized.startsWith("slack") ||
    normalized.startsWith("telegram") ||
    normalized.startsWith("discord")
  ) {
    out.add("message_send");
  }
  if (normalized === "web_fetch" || normalized === "web_search" || normalized === "fetch") {
    out.add("network_fetch");
  }

  if (/(api[_-]?key|token|password|secret|credentials?)/i.test(lowerText)) {
    out.add("secrets");
  }
  if (/(rm\s+-rf|delete\s+file|unlink|rmdir|truncate|remove\s+all)/i.test(lowerText)) {
    out.add("file_delete");
  }

  return [...out];
}

function scoreProvenance(source: ThreatSource): {
  points: number;
  reasonCodes: LlmThreatPolicyReasonCode[];
} {
  switch (source) {
    case "web":
      return { points: 20, reasonCodes: ["provenance_untrusted_web"] };
    case "email":
      return { points: 22, reasonCodes: ["provenance_untrusted_email"] };
    case "webhook":
      return { points: 24, reasonCodes: ["provenance_untrusted_webhook"] };
    case "hook":
      return { points: 18, reasonCodes: ["provenance_untrusted_hook"] };
    default:
      return { points: 0, reasonCodes: [] };
  }
}

function scoreSensitivity(values: ThreatSensitivity[]): {
  points: number;
  reasonCodes: LlmThreatPolicyReasonCode[];
} {
  let points = 0;
  const reasonCodes = new Set<LlmThreatPolicyReasonCode>();
  for (const value of values) {
    if (value === "exec") {
      points += 32;
      reasonCodes.add("action_exec");
    } else if (value === "message_send") {
      points += 24;
      reasonCodes.add("action_message_send");
    } else if (value === "secrets") {
      points += 28;
      reasonCodes.add("action_secret_access");
    } else if (value === "file_delete") {
      points += 34;
      reasonCodes.add("action_file_delete");
    } else if (value === "network_fetch") {
      points += 16;
      reasonCodes.add("action_network_fetch");
    }
  }
  return { points, reasonCodes: [...reasonCodes] };
}

function resolveMode(cfg: ThreatPolicyConfig | undefined, agentId?: string): LlmThreatPolicyMode {
  const agentMode = cfg?.agents?.list?.find((entry) => entry.id === agentId)?.security
    ?.llmThreatPolicy?.mode;
  return agentMode ?? cfg?.gateway?.security?.llmThreatPolicy?.mode ?? "strict";
}

export function evaluateLlmThreatPolicy(args: {
  toolName: string;
  params: unknown;
  sessionKey?: string;
  config?: ThreatPolicyConfig;
  agentId?: string;
}): LlmThreatPolicyOutcome {
  const toolName = args.toolName.trim() || "tool";
  const text = JSON.stringify(args.params ?? {});
  const source = inferThreatSource(args.sessionKey, text);
  const suspiciousPatternHits = detectSuspiciousPatterns(text);
  const sensitivity = detectActionSensitivity(toolName, text);
  const mode = resolveMode(args.config, args.agentId);

  if (mode === "off") {
    return {
      mode,
      decision: "allow",
      score: 0,
      approvalRequired: false,
      reasonCodes: [],
      suspiciousPatternHits,
      provenance: { source, untrusted: source !== "internal" },
      sensitivity,
    };
  }

  const provenanceScore = scoreProvenance(source);
  const sensitivityScore = scoreSensitivity(sensitivity);
  const injectionPoints =
    suspiciousPatternHits.length > 0 ? 25 + Math.min(20, suspiciousPatternHits.length * 4) : 0;

  const score = provenanceScore.points + sensitivityScore.points + injectionPoints;
  const reasonCodes = new Set<LlmThreatPolicyReasonCode>([
    ...provenanceScore.reasonCodes,
    ...sensitivityScore.reasonCodes,
  ]);
  if (suspiciousPatternHits.length > 0) {
    reasonCodes.add("injection_pattern_detected");
  }

  const blockThreshold = mode === "strict" ? 70 : 84;
  const approvalThreshold = mode === "strict" ? 45 : 58;

  let decision: LlmThreatPolicyDecision = "allow";
  if (score >= blockThreshold) {
    decision = "block";
    reasonCodes.add("score_high");
  } else if (score >= approvalThreshold) {
    decision = "require_approval";
    reasonCodes.add("score_medium");
  }

  return {
    mode,
    decision,
    score,
    approvalRequired: decision === "require_approval",
    reasonCodes: [...reasonCodes],
    suspiciousPatternHits,
    provenance: { source, untrusted: source !== "internal" },
    sensitivity,
  };
}

export function formatThreatPolicyDecision(outcome: LlmThreatPolicyOutcome): string {
  return JSON.stringify({
    mode: outcome.mode,
    decision: outcome.decision,
    score: outcome.score,
    reasonCodes: outcome.reasonCodes,
    provenance: outcome.provenance,
    suspiciousPatternHits: outcome.suspiciousPatternHits,
    sensitivity: outcome.sensitivity,
  });
}

---
title: Security Testing Fixtures
summary: Run and extend adversarial security tests for prompt-injection and unsafe tool request handling.
---

# Security testing fixtures

OpenClaw includes a dedicated security-focused Vitest stage that exercises adversarial prompt fixtures and risk-policy outcomes.

## Run locally

```bash
pnpm test:security
```

This test suite validates:

- suspicious content detection across adversarial fixture categories
- risk-policy outcomes (`allow`, `ask`, `deny`) for security modes (`strict`, `moderate`, `off`)
- blocking of unsafe tool requests from untrusted content
- snapshot-style expected decisions per mode

## Fixture locations

- `src/security/adversarial-fixtures.ts`
- `src/security/adversarial-policy.ts`
- `src/security/adversarial-policy.test.ts`

## Extend the suite

1. Add a labeled fixture in `src/security/adversarial-fixtures.ts`.
2. Prefer one of the existing categories:
   - `direct_jailbreak`
   - `indirect_external_wrapper`
   - `ignore_and_exfiltrate`
   - `send_to_attacker_exec_abuse`
3. Mark trust boundary and tool intent explicitly:
   - `untrusted: true|false`
   - `requestedTool: "exec_command" | "send_external_message" | "read_sensitive_data" | "none"`
4. Update `src/security/adversarial-policy.test.ts` if you need new assertions.
5. Re-run `pnpm test:security` and update snapshots only when policy behavior intentionally changes.

## CI stage

The main CI workflow (`.github/workflows/ci.yml`) now runs a dedicated `security-tests` job that executes:

```bash
pnpm test:security
```

Use this stage as the first checkpoint for security policy changes.

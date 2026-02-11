#!/usr/bin/env node

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

/**
 * Minimal arg parser for `--key value` pairs.
 */
function readArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      continue;
    }
    const key = token.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      args[key] = true;
      continue;
    }
    args[key] = value;
    i += 1;
  }
  return args;
}

function usageAndExit() {
  console.error(
    [
      "Usage:",
      "  node scripts/generate-release-manifest.mjs \\",
      "    --artifacts-dir <dir> \\",
      "    --version <version> \\",
      "    --published-at <iso8601> \\",
      "    [--output <path>]",
    ].join("\n"),
  );
  process.exit(2);
}

async function sha256File(filePath) {
  const data = await fs.readFile(filePath);
  return createHash("sha256").update(data).digest("hex");
}

async function main() {
  const args = readArgs(process.argv.slice(2));
  const artifactsDir = args["artifacts-dir"];
  const version = args.version;
  const publishedAt = args["published-at"];
  const output = args.output || path.join(artifactsDir || "", "manifest.json");

  if (!artifactsDir || !version || !publishedAt) {
    usageAndExit();
  }

  const entries = await fs.readdir(artifactsDir, { withFileTypes: true });
  const artifacts = [];

  for (const entry of entries) {
    if (!entry.isFile()) {
      continue;
    }
    const name = entry.name;
    if (name === path.basename(output)) {
      continue;
    }
    if (
      name === "manifest.json.sig" ||
      name === "manifest.json.pem" ||
      name === "manifest.json.bundle"
    ) {
      continue;
    }
    const fullPath = path.join(artifactsDir, name);
    const stats = await fs.stat(fullPath);
    artifacts.push({
      name,
      sizeBytes: stats.size,
      sha256: await sha256File(fullPath),
    });
  }

  artifacts.sort((a, b) => a.name.localeCompare(b.name));

  const manifest = {
    version,
    publishedAt,
    generatedAt: new Date().toISOString(),
    artifacts,
  };

  await fs.writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`Wrote ${output} (${artifacts.length} artifacts)`);
}

await main();

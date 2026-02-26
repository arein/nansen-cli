#!/usr/bin/env node

/**
 * Non-blocking check: warns if the current branch has no new changeset file
 * compared to main. Runs as a pretest hook so agents and humans see a reminder.
 * Always exits 0 — this is a nudge, not a gate.
 */

import { execSync } from "child_process";

try {
  const branch = execSync("git rev-parse --abbrev-ref HEAD", { encoding: "utf8" }).trim();
  if (branch === "main") process.exit(0);

  const newChangesets = execSync(
    "git diff main --name-only --diff-filter=A -- .changeset/*.md",
    { encoding: "utf8" }
  ).trim();

  if (!newChangesets) {
    console.error(
      "\x1b[33m[changeset] No new changeset file found on this branch. " +
      "If this PR changes user-facing behavior, add one: npx changeset\x1b[0m"
    );
  }
} catch {
  // Not a git repo, main doesn't exist, etc. — skip silently.
}

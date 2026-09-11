import { chmodSync, mkdirSync, copyFileSync } from "node:fs";
import { dirname } from "node:path";
import { spawnSync } from "node:child_process";

const source = ".githooks/pre-push";
const target = ".git/hooks/pre-push";
const safeDirectory = process.cwd().replaceAll("\\", "/");

mkdirSync(dirname(target), {
  recursive: true,
});

copyFileSync(source, target);
chmodSync(source, 0o755);
chmodSync(target, 0o755);

const trust = spawnSync("git", [
  "-c",
  `safe.directory=${safeDirectory}`,
  "config",
  "--global",
  "--add",
  "safe.directory",
  safeDirectory,
], {
  stdio: "inherit",
});

if (trust.status !== 0) {
  process.exit(trust.status ?? 1);
}

const config = spawnSync("git", [
  "config",
  "core.hooksPath",
  ".githooks",
], {
  stdio: "inherit",
});

if (config.status !== 0) {
  process.exit(config.status ?? 1);
}

console.log("Installed pre-push security hook.");

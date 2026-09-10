import { chmodSync, mkdirSync, copyFileSync } from "node:fs";
import { dirname } from "node:path";
import { spawnSync } from "node:child_process";

const source = ".githooks/pre-push";
const target = ".git/hooks/pre-push";

mkdirSync(dirname(target), {
  recursive: true,
});

copyFileSync(source, target);
chmodSync(source, 0o755);
chmodSync(target, 0o755);

const config = spawnSync("git", [
  "-c",
  `safe.directory=${process.cwd().replaceAll("\\", "/")}`,
  "config",
  "core.hooksPath",
  ".githooks",
], {
  stdio: "inherit",
  shell: process.platform === "win32",
});

if (config.status !== 0) {
  process.exit(config.status ?? 1);
}

console.log("Installed pre-push security hook.");

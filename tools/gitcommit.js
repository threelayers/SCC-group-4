import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
const allowRisk = args.includes("--allow-risk");
const message = args.filter((arg) => arg !== "--allow-risk").join(" ").trim();

if (!message) {
  console.error('Usage: npm run gitcommit -- "commit message" [--allow-risk]');
  process.exit(2);
}

const check = spawnSync(
  "node",
  [
    "tools/security-check.js",
    "--staged",
    ...(allowRisk ? ["--allow-risk"] : []),
  ],
  {
    stdio: "inherit",
  }
);

if (check.status !== 0) {
  process.exit(check.status ?? 1);
}

const commit = spawnSync("git", ["commit", "-m", message], {
  stdio: "inherit",
});

process.exit(commit.status ?? 1);

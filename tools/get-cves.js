import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);

const hasCommand = (command, commandArgs = ["--version"]) => {
  const result = spawnSync(command, commandArgs, {
    stdio: "ignore",
    shell: process.platform === "win32",
  });

  return result.status === 0;
};

const run = (command, commandArgs) => {
  const result = spawnSync(command, commandArgs, {
    stdio: "inherit",
    shell: process.platform === "win32",
  });

  return result.status ?? 1;
};

const runAndSeed = (command, commandArgs) => {
  const status = run(command, commandArgs);

  const seed = run("node", ["tools/seed-demo-cve.js"]);
  process.exit(status !== 0 ? status : seed);
};

const collectorArgs = [
  "main.py",
  "--days",
  "1",
  "--commit-days",
  "1",
  "--commit-limit",
  "20",
  ...args,
];

if (hasCommand("python", ["--version"])) {
  runAndSeed("python", collectorArgs);
}

if (hasCommand("py", ["-3", "--version"])) {
  runAndSeed("py", ["-3", ...collectorArgs]);
}

if (hasCommand("docker", ["compose", "version"])) {
  runAndSeed("docker", [
    "compose",
    "run",
    "--rm",
    "--build",
    "dashboard",
    "python",
    ...collectorArgs,
  ]);
}

console.error(
  "No Python runtime or Docker Compose installation was found for collection."
);

process.exit(1);

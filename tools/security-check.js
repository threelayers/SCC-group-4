import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const loadEnvFile = () => {
  if (!existsSync(".env")) {
    return;
  }

  const lines = readFileSync(".env", "utf8").split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separator = trimmed.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const key = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
};

loadEnvFile();

const args = process.argv.slice(2);
const allowRisk =
  args.includes("--allow-risk") ||
  process.env.ALLOW_RISKY_COMMIT === "1" ||
  process.env.ALLOW_RISKY_PUSH === "1";
const mode = args.includes("--pre-push") ? "pre-push" : "staged";

const runGit = (gitArgs, options = {}) => {
  try {
    return execFileSync("git", gitArgs, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      ...options,
    }).trim();
  } catch {
    return "";
  }
};

const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

const readStdin = async () => {
  let input = "";

  for await (const chunk of process.stdin) {
    input += chunk;
  }

  return input.trim();
};

const getPrePushSpec = async () => {
  const input = await readStdin();
  const firstLine = input.split(/\r?\n/).find(Boolean);

  if (firstLine) {
    const parts = firstLine.split(/\s+/);
    const localSha = parts[1];
    const remoteSha = parts[3];

    if (localSha && remoteSha && !/^0+$/.test(remoteSha)) {
      return {
        type: "range",
        value: `${remoteSha}..${localSha}`,
      };
    }

    if (localSha && !/^0+$/.test(localSha)) {
      return {
        type: "root",
        value: localSha,
      };
    }
  }

  const previous = runGit([
    "rev-parse",
    "--verify",
    "HEAD~1",
  ]);

  if (previous) {
    return {
      type: "range",
      value: "HEAD~1..HEAD",
    };
  }

  return {
    type: "root",
    value: "HEAD",
  };
};

const getDiffAndFiles = async () => {
  if (mode === "pre-push") {
    const spec = await getPrePushSpec();

    if (spec.type === "commit") {
      return {
        label: spec.value,
        diff: runGit([
          "show",
          "--format=",
          "--find-renames",
          "--find-copies",
          spec.value,
        ]),
        names: runGit([
          "show",
          "--format=",
          "--name-only",
          spec.value,
        ])
          .split(/\r?\n/)
          .filter(Boolean),
      };
    }

    if (spec.type === "root") {
      return {
        label: `${spec.value} from empty tree`,
        diff: runGit([
          "diff",
          "--find-renames",
          "--find-copies",
          EMPTY_TREE,
          spec.value,
        ]),
        names: runGit([
          "diff",
          "--name-only",
          EMPTY_TREE,
          spec.value,
        ])
          .split(/\r?\n/)
          .filter(Boolean),
      };
    }

    return {
      label: spec.value,
      diff: runGit([
        "diff",
        "--find-renames",
        "--find-copies",
        spec.value,
      ]),
      names: runGit([
        "diff",
        "--name-only",
        spec.value,
      ])
        .split(/\r?\n/)
        .filter(Boolean),
    };
  }

  return {
    label: "staged changes",
    diff: runGit(["diff", "--cached", "--find-renames", "--find-copies"]),
    names: runGit(["diff", "--cached", "--name-only"])
      .split(/\r?\n/)
      .filter(Boolean),
  };
};

const readTouchedFiles = (names) => {
  return names
    .filter((name) => /\.(py|js|ts|tsx|jsx|sql|html)$/i.test(name))
    .filter((name) => existsSync(name))
    .slice(0, 12)
    .map((name) => {
      const content = readFileSync(name, "utf8").slice(0, 12000);

      return `FILE: ${name}\n${content}`;
    })
    .join("\n\n");
};

const heuristicAnalyze = (text) => {
  const findings = [];
  const checks = [
    {
      pattern:
        /execute\s*\(\s*f["'`]|execute\s*\([^)]*\+|sql\s*=\s*\([\s\S]{0,1200}\+|SELECT[\s\S]{0,500}\+|WHERE[\s\S]{0,500}\+|raw\s*\(/i,
      severity: "high",
      title: "Possible SQL injection",
      detail:
        "SQL appears to be built with string interpolation or concatenation.",
    },
    {
      pattern: /eval\s*\(|exec\s*\(|child_process|subprocess\./i,
      severity: "medium",
      title: "Potential command execution risk",
      detail:
        "Command or dynamic code execution should be reviewed carefully.",
    },
    {
      pattern: /password\s*=\s*["'][^"']+["']|api[_-]?key\s*=\s*["'][^"']+["']/i,
      severity: "high",
      title: "Possible hard-coded secret",
      detail:
        "A password or API key-like value appears in source changes.",
    },
  ];

  for (const check of checks) {
    if (check.pattern.test(text)) {
      findings.push({
        severity: check.severity,
        title: check.title,
        detail: check.detail,
      });
    }
  }

  return {
    verdict: findings.some((finding) => finding.severity === "high")
      ? "block"
      : "pass",
    summary:
      findings.length === 0
        ? "No obvious high-risk patterns found by local heuristics."
        : "Local heuristics found security-sensitive patterns.",
    findings,
    used_ai: false,
  };
};

const parseJsonObject = (text) => {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");

  if (start === -1 || end === -1 || end <= start) {
    throw new Error("Model response did not contain a JSON object.");
  }

  return JSON.parse(text.slice(start, end + 1));
};

const aiAnalyze = async (payload) => {
  const apiKey = process.env.OPENAI_API_KEY || process.env.LLM_API_KEY;

  if (!apiKey) {
    return null;
  }

  const model = process.env.OPENAI_MODEL || process.env.LLM_MODEL || "gpt-5";
  const prompt = `
You are reviewing a hackathon demo code change before push.
Return only JSON with this shape:
{
  "verdict": "pass" | "block",
  "summary": "short summary",
  "findings": [
    {"severity": "low" | "medium" | "high" | "critical", "title": "...", "detail": "..."}
  ]
}

Block only high or critical practical security risk. The app may intentionally
contain demo vulnerabilities; still flag them clearly.

${payload}
`;

  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      input: prompt,
    }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.error?.message || `OpenAI request failed with ${response.status}`
    );
  }

  const output =
    data.output_text ||
    data.output
      ?.flatMap((item) => item.content || [])
      .map((part) => part.text || "")
      .join("\n") ||
    "";

  return {
    ...parseJsonObject(output),
    used_ai: true,
  };
};

const main = async () => {
  const { label, diff, names } = await getDiffAndFiles();

  if (!diff) {
    console.log(`No ${label} to analyze.`);
    return;
  }

  const files = readTouchedFiles(names);
  const payload = [
    `RANGE: ${label}`,
    "DIFF:",
    diff.slice(0, 24000),
    "TOUCHED FILES:",
    files,
  ].join("\n\n");

  let result;

  try {
    result = (await aiAnalyze(payload)) || heuristicAnalyze(payload);
  } catch (error) {
    console.error(`AI analysis failed: ${error.message}`);
    result = heuristicAnalyze(payload);
  }

  console.log("");
  console.log(`Security check (${result.used_ai ? "AI" : "local"}):`);
  console.log(result.summary || "No summary provided.");

  for (const finding of result.findings || []) {
    console.log(
      `- ${String(finding.severity || "unknown").toUpperCase()}: ${
        finding.title || "Finding"
      } - ${finding.detail || ""}`
    );
  }

  const shouldBlock =
    result.verdict === "block" ||
    (result.findings || []).some((finding) =>
      ["high", "critical"].includes(String(finding.severity).toLowerCase())
    );

  if (shouldBlock && !allowRisk) {
    console.error("");
    console.error(
      "Push/commit blocked. Use --allow-risk for gitcommit or ALLOW_RISKY_PUSH=1 for an intentional demo push."
    );
    process.exit(1);
  }

  if (shouldBlock && allowRisk) {
    console.warn("High-risk findings allowed by explicit override.");
  }
};

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});

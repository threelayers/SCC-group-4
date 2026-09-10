import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

const dataDir = "data";
const seededCveId = "CVE-2026-90001";

const seededCve = (generatedAt) => ({
  cve_id: seededCveId,
  published: generatedAt,
  last_modified: generatedAt,
  source_identifier: "demo@scc.local",
  description:
    "DEMO SEEDED CVE: The SCC vulnerable demo app contains SQL injection in login and search endpoints because user input is concatenated into SQLite queries. This is intentionally seeded for the presentation and should not be treated as a real NVD record.",
  severity: "HIGH",
  cvss_score: 8.8,
  cvss_version: "3.1",
  cwes: ["CWE-89"],
  package_hints: ["scc-vulnerable-demo-app"],
  github_repositories: ["threelayers/scc-vulnerable-demo-app"],
  affected_software: ["scc-vulnerable-demo-app <= 0.1.0"],
  references: [
    {
      url: "https://github.com/threelayers/scc-vulnerable-demo-app",
      source: "demo@scc.local",
      tags: ["Demo"],
    },
  ],
});

const seededMatch = (generatedAt) => {
  const cve = seededCve(generatedAt);

  return {
    type: "cve_dependency_match",
    demo_seed: true,
    cve_id: seededCveId,
    dependency: {
      name: "scc-vulnerable-demo-app",
      ecosystem: "internal",
      installed_version: "0.1.0",
      github_repo: "threelayers/scc-vulnerable-demo-app",
    },
    cve,
    match: {
      confidence: 1,
      version_status: "affected",
      matched_on: ["dependency.name", "github_repo"],
      reason:
        "Seeded demo CVE mapped to the intentionally vulnerable Flask app.",
    },
    evidence: {
      type: "public_record",
      label: "Seeded demo record",
      source: "Local demo seed",
    },
    verification: {
      source_url: "https://github.com/threelayers/scc-vulnerable-demo-app",
      source_type: "Seeded demo data",
      read_only: true,
      note: "Seeded locally for presentation reliability; not a real NVD CVE.",
    },
  };
};

const loadJson = (path) => JSON.parse(readFileSync(path, "utf8"));

const saveJson = (path, value) => {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

const generatedAt = nowIso();
const signalsPath = join(dataDir, "matched_signals.json");
const signals = loadJson(signalsPath);

signals.generated_at = generatedAt;
signals.description =
  "Security signals generated from NVD and GitHub data, with one clearly marked local demo seed.";
signals.cve_dependency_matches = (signals.cve_dependency_matches || []).filter(
  (match) => (match.cve_id || match.cve?.cve_id) !== seededCveId
);
signals.cve_dependency_matches.unshift(seededMatch(generatedAt));
saveJson(signalsPath, signals);

const cvesPath = join(dataDir, "cves.json");
const cves = loadJson(cvesPath);

cves.generated_at = generatedAt;
cves.cves = (cves.cves || []).filter((cve) => cve.cve_id !== seededCveId);
cves.cves.unshift(seededCve(generatedAt));
cves.count = cves.cves.length;
saveJson(cvesPath, cves);

const summaryPath = join(dataDir, "run_summary.json");
const summary = loadJson(summaryPath);

summary.generated_at = generatedAt;
summary.demo_seeded_cve = seededCveId;
summary.cve_count = cves.count;
summary.cve_dependency_match_count = signals.cve_dependency_matches.length;
saveJson(summaryPath, summary);

console.log(`Seeded ${seededCveId} into demo data.`);

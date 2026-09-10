from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
)

from main import run_real_collection


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = (
    BASE_DIR / "data"
)

SIGNALS_FILE = (
    DATA_DIR / "matched_signals.json"
)

DECISIONS_FILE = (
    DATA_DIR / "decisions.json"
)

RUN_SUMMARY_FILE = (
    DATA_DIR / "run_summary.json"
)

DEFAULT_COLLECT_DAYS = 1
DEFAULT_COMMIT_DAYS = 1
DEFAULT_COMMIT_LIMIT = 20
DEFAULT_MAX_CVES = 500
DEMO_CVE_ID = "CVE-2026-90001"


app = Flask(__name__)

collection_lock = threading.Lock()


# ============================================================
# HELPERS
# ============================================================

def utc_now_iso() -> str:

    return (
        datetime.now(
            timezone.utc
        )
        .replace(
            microsecond=0
        )
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )


def ensure_data_directory() -> None:

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def load_json_file(
    path: Path,
    default: Any,
) -> Any:

    if not path.exists():

        return default

    try:

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(
                file
            )

    except (
        json.JSONDecodeError,
        OSError,
    ):

        return default


def save_json_file(
    path: Path,
    data: Any,
) -> None:

    ensure_data_directory()

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )


def load_signals() -> Dict[str, Any]:

    if not SIGNALS_FILE.exists():

        return {
            "error":
                (
                    "matched_signals.json does not exist. "
                    "Run 'python main.py --demo' first."
                )
        }

    try:

        with SIGNALS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(
                file
            )

    except json.JSONDecodeError as exc:

        return {
            "error":
                (
                    "matched_signals.json contains invalid JSON: "
                    f"{exc}"
                )
        }

    except OSError as exc:

        return {
            "error":
                (
                    "Could not read matched_signals.json: "
                    f"{exc}"
                )
        }


def load_decisions() -> Dict[str, Any]:

    decisions = load_json_file(
        DECISIONS_FILE,
        {},
    )

    if not isinstance(
        decisions,
        dict,
    ):

        return {}

    return decisions


# ============================================================
# SIGNAL IDS
# ============================================================

def cve_signal_id(
    match: Dict[str, Any],
) -> str:

    cve = match.get(
        "cve",
        {},
    )

    dependency = match.get(
        "dependency",
        {},
    )

    return (
        "cve:"
        f"{match.get('cve_id') or cve.get('cve_id', 'unknown')}:"
        f"{dependency.get('name', 'unknown')}"
    )


def parse_positive_int(
    payload: Dict[str, Any],
    key: str,
    default: int,
    maximum: int,
) -> int:

    value = payload.get(
        key,
        default,
    )

    try:

        parsed = int(
            value
        )

    except (
        TypeError,
        ValueError,
    ) as exc:

        raise ValueError(
            f"{key} must be a positive integer."
        ) from exc

    if parsed < 1:

        raise ValueError(
            f"{key} must be at least 1."
        )

    if parsed > maximum:

        raise ValueError(
            f"{key} must be at most {maximum}."
        )

    return parsed


def build_demo_seeded_cve(
    generated_at: str,
) -> Dict[str, Any]:

    return {
        "cve_id":
            DEMO_CVE_ID,

        "published":
            generated_at,

        "last_modified":
            generated_at,

        "source_identifier":
            "demo@scc.local",

        "description":
            (
                "DEMO SEEDED CVE: The SCC vulnerable demo app contains "
                "SQL injection in login and search endpoints because user "
                "input is concatenated into SQLite queries. This is "
                "intentionally seeded for the presentation and should not "
                "be treated as a real NVD record."
            ),

        "severity":
            "HIGH",

        "cvss_score":
            8.8,

        "cvss_version":
            "3.1",

        "cwes":
            [
                "CWE-89",
            ],

        "package_hints":
            [
                "scc-vulnerable-demo-app",
            ],

        "github_repositories":
            [
                "threelayers/scc-vulnerable-demo-app",
            ],

        "affected_software":
            [
                "scc-vulnerable-demo-app <= 0.1.0",
            ],

        "references":
            [
                {
                    "url":
                        (
                            "https://github.com/threelayers/"
                            "scc-vulnerable-demo-app"
                        ),

                    "source":
                        "demo@scc.local",

                    "tags":
                        [
                            "Demo",
                        ],
                },
            ],
    }


def build_demo_seeded_match(
    generated_at: str,
) -> Dict[str, Any]:

    return {
        "type":
            "cve_dependency_match",

        "demo_seed":
            True,

        "cve_id":
            DEMO_CVE_ID,

        "dependency":
            {
                "name":
                    "scc-vulnerable-demo-app",

                "ecosystem":
                    "internal",

                "installed_version":
                    "0.1.0",

                "github_repo":
                    "threelayers/scc-vulnerable-demo-app",
            },

        "cve":
            build_demo_seeded_cve(
                generated_at
            ),

        "match":
            {
                "confidence":
                    1,

                "version_status":
                    "affected",

                "matched_on":
                    [
                        "dependency.name",
                        "github_repo",
                    ],

                "reason":
                    (
                        "Seeded demo CVE mapped to the intentionally "
                        "vulnerable Flask app."
                    ),
            },

        "evidence":
            {
                "type":
                    "public_record",

                "label":
                    "Seeded demo record",

                "source":
                    "Local demo seed",
            },

        "verification":
            {
                "source_url":
                    (
                        "https://github.com/threelayers/"
                        "scc-vulnerable-demo-app"
                    ),

                "source_type":
                    "Seeded demo data",

                "read_only":
                    True,

                "note":
                    (
                        "Seeded locally for presentation reliability; "
                        "not a real NVD CVE."
                    ),
            },
    }


def apply_demo_seed() -> None:

    generated_at = utc_now_iso()

    signals = load_json_file(
        SIGNALS_FILE,
        {},
    )

    if isinstance(
        signals,
        dict,
    ):

        matches = [
            match
            for match in signals.get(
                "cve_dependency_matches",
                [],
            )
            if (
                match.get(
                    "cve_id"
                )
                or match.get(
                    "cve",
                    {},
                ).get(
                    "cve_id"
                )
            )
            != DEMO_CVE_ID
        ]

        signals[
            "generated_at"
        ] = generated_at

        signals[
            "description"
        ] = (
            "Security signals generated from NVD and GitHub data, "
            "with one clearly marked local demo seed."
        )

        signals[
            "cve_dependency_matches"
        ] = [
            build_demo_seeded_match(
                generated_at
            ),
            *matches,
        ]

        save_json_file(
            SIGNALS_FILE,
            signals,
        )

    cves = load_json_file(
        DATA_DIR / "cves.json",
        {},
    )

    if isinstance(
        cves,
        dict,
    ):

        cve_records = [
            cve
            for cve in cves.get(
                "cves",
                [],
            )
            if cve.get(
                "cve_id"
            )
            != DEMO_CVE_ID
        ]

        cves[
            "generated_at"
        ] = generated_at

        cves[
            "cves"
        ] = [
            build_demo_seeded_cve(
                generated_at
            ),
            *cve_records,
        ]

        cves[
            "count"
        ] = len(
            cves[
                "cves"
            ]
        )

        save_json_file(
            DATA_DIR / "cves.json",
            cves,
        )

    run_summary = load_json_file(
        RUN_SUMMARY_FILE,
        {},
    )

    if isinstance(
        run_summary,
        dict,
    ):

        run_summary[
            "generated_at"
        ] = generated_at

        run_summary[
            "demo_seeded_cve"
        ] = DEMO_CVE_ID

        save_json_file(
            RUN_SUMMARY_FILE,
            run_summary,
        )


def commit_signal_id(
    match: Dict[str, Any],
) -> str:

    commit = match.get(
        "commit",
        {},
    )

    return (
        "commit:"
        f"{commit.get('sha', 'unknown')}"
    )


def silent_signal_id(
    match: Dict[str, Any],
) -> str:

    return (
        "silent:"
        f"{match.get('commit_sha', 'unknown')}"
    )


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

def build_summary(
    signals: Dict[str, Any],
) -> Dict[str, Any]:

    cve_matches = signals.get(
        "cve_dependency_matches",
        [],
    )

    commit_matches = signals.get(
        "upstream_commit_matches",
        [],
    )

    silent_window_candidates = (
        signals.get(
            "silent_window_candidates",
            [],
        )
    )

    dependencies = signals.get(
        "dependencies",
        [],
    )

    critical_count = 0
    high_count = 0
    medium_count = 0
    affected_count = 0

    for match in cve_matches:

        cve = match.get(
            "cve",
            {},
        )

        match_info = match.get(
            "match",
            {},
        )

        severity = str(
            cve.get(
                "severity",
                "",
            )
        ).upper()

        version_status = str(
            match_info.get(
                "version_status",
                "",
            )
        ).lower()

        if severity == "CRITICAL":

            critical_count += 1

        elif severity == "HIGH":

            high_count += 1

        elif severity == "MEDIUM":

            medium_count += 1

        if version_status == "affected":

            affected_count += 1

    return {
        "dependencies":
            len(
                dependencies
            ),

        "cve_matches":
            len(
                cve_matches
            ),

        "security_commits":
            len(
                commit_matches
            ),

        "silent_window_candidates":
            len(
                silent_window_candidates
            ),

        "critical":
            critical_count,

        "high":
            high_count,

        "medium":
            medium_count,

        "affected":
            affected_count,
    }


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


@app.route(
    "/api/signals"
)
def api_signals():

    signals = load_signals()

    if "error" in signals:

        return (
            jsonify(
                signals
            ),
            500,
        )

    decisions = (
        load_decisions()
    )

    return jsonify(
        {
            "signals":
                signals,

            "summary":
                build_summary(
                    signals
                ),

            "decisions":
                decisions,
        }
    )


@app.route(
    "/api/collect",
    methods=["POST"],
)
def api_collect():

    payload = request.get_json(
        silent=True
    )

    if payload is None:

        payload = {}

    if not isinstance(
        payload,
        dict,
    ):

        return (
            jsonify(
                {
                    "error":
                        "Request body must be JSON."
                }
            ),
            400,
        )

    try:

        cve_days = parse_positive_int(
            payload,
            "days",
            DEFAULT_COLLECT_DAYS,
            30,
        )

        commit_days = parse_positive_int(
            payload,
            "commit_days",
            DEFAULT_COMMIT_DAYS,
            30,
        )

        commit_limit = parse_positive_int(
            payload,
            "commit_limit",
            DEFAULT_COMMIT_LIMIT,
            100,
        )

        max_cves = parse_positive_int(
            payload,
            "max_cves",
            DEFAULT_MAX_CVES,
            2000,
        )

    except ValueError as exc:

        return (
            jsonify(
                {
                    "error":
                        str(exc)
                }
            ),
            400,
        )

    if not collection_lock.acquire(
        blocking=False
    ):

        return (
            jsonify(
                {
                    "error":
                        "Collection is already running."
                }
            ),
            409,
        )

    try:

        run_real_collection(
            cve_days=cve_days,
            commit_days=commit_days,
            commit_limit=commit_limit,
            max_cves=max_cves,
        )

        apply_demo_seed()

        signals = load_signals()

        if "error" in signals:

            return (
                jsonify(
                    signals
                ),
                500,
            )

        return jsonify(
            {
                "success":
                    True,

                "signals":
                    signals,

                "summary":
                    build_summary(
                        signals
                    ),

                "run_summary":
                    load_json_file(
                        RUN_SUMMARY_FILE,
                        {},
                    ),
            }
        )

    except Exception as exc:

        return (
            jsonify(
                {
                    "error":
                        str(exc)
                }
            ),
            500,
        )

    finally:

        collection_lock.release()


@app.route(
    "/api/decision",
    methods=["POST"],
)
def api_decision():

    payload = request.get_json(
        silent=True
    )

    if not isinstance(
        payload,
        dict,
    ):

        return (
            jsonify(
                {
                    "error":
                        "Request body must be JSON."
                }
            ),
            400,
        )

    signal_id = str(
        payload.get(
            "signal_id",
            "",
        )
    ).strip()

    decision = str(
        payload.get(
            "decision",
            "",
        )
    ).strip().lower()

    if not signal_id:

        return (
            jsonify(
                {
                    "error":
                        "signal_id is required."
                }
            ),
            400,
        )

    if decision not in {
        "accepted",
        "rejected",
    }:

        return (
            jsonify(
                {
                    "error":
                        (
                            "decision must be "
                            "'accepted' or "
                            "'rejected'."
                        )
                }
            ),
            400,
        )

    decisions = (
        load_decisions()
    )

    decisions[
        signal_id
    ] = {
        "decision":
            decision,

        "timestamp":
            utc_now_iso(),

        "reviewer":
            "human",
    }

    save_json_file(
        DECISIONS_FILE,
        decisions,
    )

    return jsonify(
        {
            "success":
                True,

            "signal_id":
                signal_id,

            "decision":
                decision,

            "record":
                decisions[
                    signal_id
                ],
        }
    )


@app.route(
    "/api/decision/reset",
    methods=["POST"],
)
def api_reset_decision():

    payload = request.get_json(
        silent=True
    )

    if not isinstance(
        payload,
        dict,
    ):

        return (
            jsonify(
                {
                    "error":
                        "Request body must be JSON."
                }
            ),
            400,
        )

    signal_id = str(
        payload.get(
            "signal_id",
            "",
        )
    ).strip()

    if not signal_id:

        return (
            jsonify(
                {
                    "error":
                        "signal_id is required."
                }
            ),
            400,
        )

    decisions = (
        load_decisions()
    )

    removed = (
        signal_id
        in decisions
    )

    decisions.pop(
        signal_id,
        None,
    )

    save_json_file(
        DECISIONS_FILE,
        decisions,
    )

    return jsonify(
        {
            "success":
                True,

            "signal_id":
                signal_id,

            "removed":
                removed,
        }
    )


@app.route(
    "/api/health"
)
def health():

    return jsonify(
        {
            "status":
                "ok",

            "signals_file_exists":
                SIGNALS_FILE.exists(),

            "decisions_file_exists":
                DECISIONS_FILE.exists(),
        }
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print(
        "VULNERABILITY INTELLIGENCE DASHBOARD"
    )
    print("=" * 60)
    print()

    print(
        "Open:"
    )

    print(
        "http://127.0.0.1:5000"
    )

    print()

    app.run(
        host=os.getenv(
            "HOST",
            "127.0.0.1",
        ),
        port=int(
            os.getenv(
                "PORT",
                "5000",
            )
        ),
        debug=os.getenv(
            "FLASK_DEBUG",
            "0",
        ) == "1",
    )

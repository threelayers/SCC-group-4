from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
)


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


app = Flask(__name__)


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
        f"{cve.get('cve_id', 'unknown')}:"
        f"{dependency.get('name', 'unknown')}"
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
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
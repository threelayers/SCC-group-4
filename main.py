from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from packaging.version import InvalidVersion, Version


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"

DEPENDENCIES_FILE = (
    BASE_DIR / "dependencies.json"
)

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

GITHUB_API_URL = (
    "https://api.github.com"
)

GITHUB_TOKEN = (
    os.getenv("GITHUB_TOKEN", "")
    .strip()
)

NVD_API_KEY = (
    os.getenv("NVD_API_KEY", "")
    .strip()
)

GITHUB_API_VERSION = "2026-03-10"

DEFAULT_CVE_DAYS = 7

DEFAULT_COMMIT_DAYS = 14

DEFAULT_COMMIT_LIMIT = 20

REQUEST_TIMEOUT = 30


# ============================================================
# SECURITY KEYWORDS
# ============================================================

SECURITY_KEYWORDS = [
    "security",
    "vulnerability",
    "vulnerable",
    "exploit",
    "remote code execution",
    "rce",
    "privilege escalation",
    "authentication",
    "authorization",
    "bypass",
    "sandbox",
    "injection",
    "sql injection",
    "command injection",
    "code execution",
    "arbitrary code",
    "arbitrary file",
    "path traversal",
    "directory traversal",
    "xss",
    "cross-site scripting",
    "csrf",
    "deserialization",
    "buffer overflow",
    "out of bounds",
    "use after free",
    "memory corruption",
    "integer overflow",
    "race condition",
    "permission",
    "access control",
    "sanitize",
    "sanitise",
    "validate",
    "validation",
    "escaping",
    "escape",
    "hardening",
    "unsafe",
    "attack",
    "fix security issue",
    "security fix",
]


# ============================================================
# BASIC UTILITIES
# ============================================================

def utc_now() -> datetime:
    """
    Return the current UTC time.
    """

    return datetime.now(
        timezone.utc
    )


def iso_z(
    dt: datetime,
) -> str:
    """
    Convert a datetime to UTC ISO-8601.
    """

    return (
        dt
        .astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def ensure_data_directory() -> None:
    """
    Make sure the data directory exists.
    """

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def save_json(
    filename: str,
    data: Any,
) -> None:
    """
    Save JSON in the data directory.
    """

    ensure_data_directory()

    path = (
        DATA_DIR / filename
    )

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

    print(
        f"[+] Saved {path}"
    )


def load_dependencies() -> List[Dict[str, Any]]:
    """
    Load the organisation's dependency inventory.
    """

    if not DEPENDENCIES_FILE.exists():

        raise FileNotFoundError(
            "dependencies.json was not found."
        )

    with DEPENDENCIES_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        dependencies = json.load(
            file
        )

    if not isinstance(
        dependencies,
        list,
    ):

        raise ValueError(
            "dependencies.json must contain a JSON array."
        )

    required_fields = {
        "name",
        "ecosystem",
        "version",
    }

    for index, dependency in enumerate(
        dependencies
    ):

        if not isinstance(
            dependency,
            dict,
        ):

            raise ValueError(
                f"Dependency #{index + 1} "
                "must be a JSON object."
            )

        missing = (
            required_fields
            - set(
                dependency.keys()
            )
        )

        if missing:

            raise ValueError(
                f"Dependency #{index + 1} "
                f"is missing: {sorted(missing)}"
            )

    return dependencies


def normalize_text(
    value: str,
) -> str:
    """
    Remove common separators so that names are
    easier to compare.
    """

    value = (
        value
        .lower()
        .strip()
    )

    for character in [
        "_",
        "-",
        ".",
        "/",
        " ",
    ]:

        value = value.replace(
            character,
            "",
        )

    return value


def normalize_repo_name(
    repo: str,
) -> str:
    """
    Convert either a GitHub URL or OWNER/REPO
    to OWNER/REPO.
    """

    repo = repo.strip()

    if (
        repo.startswith("http://")
        or repo.startswith("https://")
    ):

        parsed = urlparse(
            repo
        )

        path = (
            parsed.path
            .strip("/")
        )

        if path.endswith(
            ".git"
        ):

            path = path[:-4]

        return path

    repo = repo.strip("/")

    if repo.endswith(
        ".git"
    ):

        repo = repo[:-4]

    return repo


def extract_repo_from_url(
    url: str,
) -> Optional[str]:
    """
    Attempt to extract OWNER/REPO from
    a GitHub URL.
    """

    if not url:
        return None

    parsed = urlparse(
        url
    )

    if parsed.netloc.lower() not in {
        "github.com",
        "www.github.com",
    }:

        return None

    parts = (
        parsed.path
        .strip("/")
        .split("/")
    )

    if len(parts) < 2:
        return None

    return (
        f"{parts[0]}/"
        f"{parts[1].replace('.git', '')}"
    )


# ============================================================
# API CLIENT
# ============================================================

class APIClient:
    """
    Small requests wrapper that handles:

    - authentication
    - retries
    - timeouts
    - rate limiting
    """

    def __init__(
        self,
    ) -> None:

        self.session = (
            requests.Session()
        )

        self.session.headers.update(
            {
                "User-Agent":
                    "Hackathon-Vulnerability-Agent/1.0",

                "Accept":
                    "application/json",
            }
        )

        if GITHUB_TOKEN:

            self.session.headers.update(
                {
                    "Authorization":
                        f"Bearer {GITHUB_TOKEN}",

                    "X-GitHub-Api-Version":
                        GITHUB_API_VERSION,
                }
            )

        if NVD_API_KEY:

            self.session.headers.update(
                {
                    "apiKey":
                        NVD_API_KEY,
                }
            )

    def get(
        self,
        url: str,
        params: Optional[
            Dict[str, Any]
        ] = None,
        headers: Optional[
            Dict[str, str]
        ] = None,
        retries: int = 3,
    ) -> requests.Response:

        last_error = None

        for attempt in range(
            retries
        ):

            try:

                response = (
                    self.session.get(
                        url,
                        params=params,
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                    )
                )

                if (
                    response.status_code
                    == 429
                ):

                    wait_seconds = (
                        2 ** attempt
                    )

                    print(
                        f"[!] Rate limited. "
                        f"Waiting {wait_seconds}s..."
                    )

                    time.sleep(
                        wait_seconds
                    )

                    continue

                if response.status_code in {
                    500,
                    502,
                    503,
                    504,
                }:

                    wait_seconds = (
                        2 ** attempt
                    )

                    print(
                        f"[!] Temporary server error "
                        f"{response.status_code}. "
                        f"Retrying..."
                    )

                    time.sleep(
                        wait_seconds
                    )

                    continue

                response.raise_for_status()

                return response

            except requests.RequestException as exc:

                last_error = exc

                wait_seconds = (
                    2 ** attempt
                )

                print(
                    f"[!] Request failed: {exc}. "
                    f"Retrying in {wait_seconds}s..."
                )

                time.sleep(
                    wait_seconds
                )

        raise RuntimeError(
            "API request failed after "
            f"{retries} attempts: "
            f"{last_error}"
        )


# ============================================================
# NVD COLLECTOR
# ============================================================

class NVDCollector:

    def __init__(
        self,
        client: APIClient,
    ):
        self.client = client

    def fetch_recent_cves(
        self,
        days: int = DEFAULT_CVE_DAYS,
        max_results: int = 500,
    ) -> List[Dict[str, Any]]:
        """
        Fetch CVEs published during
        the last N days.
        """

        end_date = utc_now()

        start_date = (
            end_date
            - timedelta(
                days=days
            )
        )

        params = {
            "pubStartDate":
                iso_z(
                    start_date
                ),

            "pubEndDate":
                iso_z(
                    end_date
                ),

            "resultsPerPage":
                min(
                    max_results,
                    2000,
                ),

            "startIndex":
                0,
        }

        all_cves = []

        print(
            f"[*] Fetching CVEs from "
            f"{iso_z(start_date)} "
            f"to {iso_z(end_date)}"
        )

        while (
            len(all_cves)
            < max_results
        ):

            params[
                "resultsPerPage"
            ] = min(
                2000,
                max_results
                - len(all_cves),
            )

            response = (
                self.client.get(
                    NVD_API_URL,
                    params=params,
                )
            )

            payload = (
                response.json()
            )

            vulnerabilities = (
                payload.get(
                    "vulnerabilities",
                    [],
                )
            )

            if not vulnerabilities:
                break

            for item in vulnerabilities:

                cve = item.get(
                    "cve"
                )

                if cve:

                    all_cves.append(
                        cve
                    )

                if (
                    len(all_cves)
                    >= max_results
                ):

                    break

            total_results = (
                payload.get(
                    "totalResults",
                    len(all_cves),
                )
            )

            print(
                f"    Retrieved "
                f"{len(all_cves)} CVEs "
                f"of {total_results}"
            )

            if (
                len(all_cves)
                >= total_results
            ):

                break

            params[
                "startIndex"
            ] += len(
                vulnerabilities
            )

        print(
            f"[+] Raw CVEs retrieved: "
            f"{len(all_cves)}"
        )

        return all_cves

    def normalize_cve(
        self,
        cve: Dict[str, Any],
    ) -> Dict[str, Any]:

        cve_id = cve.get(
            "id",
            "UNKNOWN",
        )

        descriptions = cve.get(
            "descriptions",
            [],
        )

        english_description = ""

        for description in descriptions:

            if (
                description.get(
                    "lang"
                )
                == "en"
            ):

                english_description = (
                    description.get(
                        "value",
                        "",
                    )
                )

                break

        if (
            not english_description
            and descriptions
        ):

            english_description = (
                descriptions[0].get(
                    "value",
                    "",
                )
            )

        severity_info = (
            self._extract_cvss(
                cve
            )
        )

        weaknesses = (
            self._extract_cwes(
                cve
            )
        )

        references = []

        for ref in cve.get(
            "references",
            [],
        ):

            references.append(
                {
                    "url":
                        ref.get(
                            "url"
                        ),

                    "source":
                        ref.get(
                            "source"
                        ),

                    "tags":
                        ref.get(
                            "tags",
                            [],
                        ),
                }
            )

        affected_software = (
            self._extract_affected_software(
                cve
            )
        )

        package_hints = (
            self._extract_package_hints(
                affected_software
            )
        )

        github_repositories = []

        for reference in references:

            repo = (
                extract_repo_from_url(
                    reference.get(
                        "url",
                        "",
                    )
                )
            )

            if repo:

                github_repositories.append(
                    repo
                )

        return {
            "cve_id":
                cve_id,

            "published":
                cve.get(
                    "published"
                ),

            "last_modified":
                cve.get(
                    "lastModified"
                ),

            "source_identifier":
                cve.get(
                    "sourceIdentifier"
                ),

            "description":
                english_description,

            "severity":
                severity_info.get(
                    "severity"
                ),

            "cvss_score":
                severity_info.get(
                    "score"
                ),

            "cvss_version":
                severity_info.get(
                    "version"
                ),

            "cwes":
                weaknesses,

            "package_hints":
                sorted(
                    list(
                        set(
                            package_hints
                        )
                    )
                ),

            "github_repositories":
                sorted(
                    list(
                        set(
                            github_repositories
                        )
                    )
                ),

            "affected_software":
                affected_software,

            "references":
                references,
        }

    def normalize_all(
        self,
        cves: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        normalized = []

        for cve in cves:

            try:

                normalized.append(
                    self.normalize_cve(
                        cve
                    )
                )

            except Exception as exc:

                print(
                    f"[!] Could not normalize "
                    f"CVE: {exc}"
                )

        return normalized

    def _extract_cvss(
        self,
        cve: Dict[str, Any],
    ) -> Dict[str, Any]:

        metrics = cve.get(
            "metrics",
            {},
        )

        for key in [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]:

            metric_list = (
                metrics.get(
                    key
                )
            )

            if not metric_list:
                continue

            first_metric = (
                metric_list[0]
            )

            cvss_data = (
                first_metric.get(
                    "cvssData",
                    {},
                )
            )

            return {
                "severity":
                    (
                        first_metric.get(
                            "baseSeverity"
                        )
                        or
                        cvss_data.get(
                            "baseSeverity"
                        )
                    ),

                "score":
                    cvss_data.get(
                        "baseScore"
                    ),

                "version":
                    cvss_data.get(
                        "version"
                    ),
            }

        return {
            "severity": None,
            "score": None,
            "version": None,
        }

    def _extract_cwes(
        self,
        cve: Dict[str, Any],
    ) -> List[str]:

        result = []

        for weakness in cve.get(
            "weaknesses",
            [],
        ):

            descriptions = (
                weakness.get(
                    "description",
                    [],
                )
            )

            for description in descriptions:

                value = description.get(
                    "value"
                )

                if value:

                    result.append(
                        value
                    )

        return sorted(
            list(
                set(result)
            )
        )

    def _extract_affected_software(
        self,
        cve: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        result = []

        configurations = (
            cve.get(
                "configurations",
                [],
            )
        )

        def walk_nodes(
            nodes,
        ):

            for node in nodes:

                for match in node.get(
                    "cpeMatch",
                    [],
                ):

                    criteria = (
                        match.get(
                            "criteria",
                            "",
                        )
                    )

                    parsed_cpe = (
                        self._parse_cpe23(
                            criteria
                        )
                    )

                    result.append(
                        {
                            "criteria":
                                criteria,

                            "vulnerable":
                                match.get(
                                    "vulnerable",
                                    False,
                                ),

                            "version_start_including":
                                match.get(
                                    "versionStartIncluding"
                                ),

                            "version_start_excluding":
                                match.get(
                                    "versionStartExcluding"
                                ),

                            "version_end_including":
                                match.get(
                                    "versionEndIncluding"
                                ),

                            "version_end_excluding":
                                match.get(
                                    "versionEndExcluding"
                                ),

                            "vendor":
                                parsed_cpe.get(
                                    "vendor"
                                ),

                            "product":
                                parsed_cpe.get(
                                    "product"
                                ),

                            "version":
                                parsed_cpe.get(
                                    "version"
                                ),
                        }
                    )

                children = node.get(
                    "children",
                    [],
                )

                if children:

                    walk_nodes(
                        children
                    )

        walk_nodes(
            configurations
        )

        return result

    def _parse_cpe23(
        self,
        cpe: str,
    ) -> Dict[
        str,
        Optional[str]
    ]:

        result = {
            "vendor": None,
            "product": None,
            "version": None,
        }

        if not cpe.startswith(
            "cpe:2.3:"
        ):

            return result

        parts = cpe.split(
            ":"
        )

        if len(parts) < 6:

            return result

        result["vendor"] = (
            parts[3]
        )

        result["product"] = (
            parts[4]
        )

        result["version"] = (
            parts[5]
        )

        return result

    def _extract_package_hints(
        self,
        affected_software,
    ) -> List[str]:

        hints = []

        for software in (
            affected_software
        ):

            vendor = software.get(
                "vendor"
            )

            product = software.get(
                "product"
            )

            if vendor and vendor not in {
                "*",
                "-",
            }:

                hints.append(
                    vendor
                )

            if product and product not in {
                "*",
                "-",
            }:

                hints.append(
                    product
                )

        return hints


# ============================================================
# GITHUB COLLECTOR
# ============================================================

class GitHubCollector:

    def __init__(
        self,
        client: APIClient,
    ):

        self.client = client

    def fetch_repository_commits(
        self,
        repository: str,
        days: int = DEFAULT_COMMIT_DAYS,
        limit: int = DEFAULT_COMMIT_LIMIT,
    ) -> List[Dict[str, Any]]:

        repository = normalize_repo_name(
            repository
        )

        if "/" not in repository:

            print(
                f"[!] Invalid GitHub repository: "
                f"{repository}"
            )

            return []

        owner, repo = (
            repository.split(
                "/",
                1,
            )
        )

        since = (
            utc_now()
            - timedelta(
                days=days
            )
        )

        url = (
            f"{GITHUB_API_URL}/repos/"
            f"{owner}/{repo}/commits"
        )

        params = {
            "since":
                iso_z(
                    since
                ),

            "per_page":
                min(
                    limit,
                    100,
                ),

            "page":
                1,
        }

        print(
            f"[*] Fetching commits "
            f"from {repository}"
        )

        response = (
            self.client.get(
                url,
                params=params,
                headers={
                    "Accept":
                        "application/vnd.github+json",
                },
            )
        )

        commits = response.json()

        result = []

        for commit_summary in commits[:limit]:

            sha = commit_summary.get(
                "sha"
            )

            if not sha:
                continue

            detail = (
                self.fetch_commit_details(
                    repository,
                    sha,
                )
            )

            if detail:

                result.append(
                    detail
                )

        print(
            f"[+] Retrieved "
            f"{len(result)} commits "
            f"from {repository}"
        )

        return result

    def fetch_commit_details(
        self,
        repository: str,
        sha: str,
    ) -> Optional[
        Dict[str, Any]
    ]:

        owner, repo = (
            repository.split(
                "/",
                1,
            )
        )

        url = (
            f"{GITHUB_API_URL}/repos/"
            f"{owner}/{repo}/commits/{sha}"
        )

        try:

            response = (
                self.client.get(
                    url,
                    headers={
                        "Accept":
                            "application/vnd.github+json",
                    },
                )
            )

        except Exception as exc:

            print(
                f"[!] Could not retrieve "
                f"commit {sha[:8]}: {exc}"
            )

            return None

        data = response.json()

        commit_info = (
            data.get(
                "commit",
                {},
            )
        )

        message = (
            commit_info.get(
                "message",
                "",
            )
        )

        author = (
            commit_info.get(
                "author",
                {},
            )
        )

        committer = (
            commit_info.get(
                "committer",
                {},
            )
        )

        files = []

        for file_info in data.get(
            "files",
            [],
        ):

            patch = (
                file_info.get(
                    "patch"
                )
            )

            if (
                patch
                and len(patch) > 12000
            ):

                patch = (
                    patch[:12000]
                    + "\n... PATCH TRUNCATED ..."
                )

            files.append(
                {
                    "filename":
                        file_info.get(
                            "filename"
                        ),

                    "status":
                        file_info.get(
                            "status"
                        ),

                    "additions":
                        file_info.get(
                            "additions",
                            0,
                        ),

                    "deletions":
                        file_info.get(
                            "deletions",
                            0,
                        ),

                    "changes":
                        file_info.get(
                            "changes",
                            0,
                        ),

                    "patch":
                        patch,
                }
            )

        heuristic = (
            analyze_commit_message(
                message
            )
        )

        return {
            "repository":
                repository,

            "sha":
                sha,

            "html_url":
                data.get(
                    "html_url"
                ),

            "message":
                message,

            "author":
                author.get(
                    "name"
                ),

            "author_email":
                author.get(
                    "email"
                ),

            "committer":
                committer.get(
                    "name"
                ),

            "committer_date":
                committer.get(
                    "date"
                ),

            "author_date":
                author.get(
                    "date"
                ),

            "stats":
                data.get(
                    "stats",
                    {},
                ),

            "security_signal":
                heuristic,

            "files":
                files,
        }


# ============================================================
# SECURITY COMMIT HEURISTIC
# ============================================================

def analyze_commit_message(
    message: str,
) -> Dict[str, Any]:
    """
    Identify security-looking commit messages.

    This does NOT prove a vulnerability exists.
    """

    lower = message.lower()

    matched_keywords = []

    for keyword in SECURITY_KEYWORDS:

        if keyword in lower:

            matched_keywords.append(
                keyword
            )

    cve_ids = sorted(
        set(
            re.findall(
                r"CVE-\d{4}-\d{4,7}",
                message,
                flags=re.IGNORECASE,
            )
        )
    )

    score = 0

    score += (
        len(matched_keywords)
        * 10
    )

    if cve_ids:

        score += 40

    if "fix" in lower:

        score += 5

    if "patch" in lower:

        score += 5

    if "security" in lower:

        score += 15

    if "backport" in lower:

        score += 5

    score = min(
        score,
        100,
    )

    suspicious = (
        score >= 20
    )

    if cve_ids:

        classification = (
            "explicit_cve_reference"
        )

    elif suspicious:

        classification = (
            "potential_security_fix"
        )

    else:

        classification = (
            "ordinary_commit"
        )

    return {
        "score":
            score,

        "suspicious":
            suspicious,

        "classification":
            classification,

        "matched_keywords":
            matched_keywords,

        "cve_ids":
            cve_ids,
    }


# ============================================================
# VERSION COMPARISON
# ============================================================

def parse_version_safely(
    value: Optional[str],
) -> Optional[Version]:

    if not value:
        return None

    value = value.strip()

    if value in {
        "*",
        "-",
        "any",
        "ANY",
    }:

        return None

    try:

        return Version(
            value
        )

    except InvalidVersion:

        return None


def version_is_affected(
    installed_version: str,
    software_entry: Dict[str, Any],
) -> str:

    installed = (
        parse_version_safely(
            installed_version
        )
    )

    if installed is None:

        return "unknown"

    cpe_version = software_entry.get(
        "version"
    )

    start_including = (
        parse_version_safely(
            software_entry.get(
                "version_start_including"
            )
        )
    )

    start_excluding = (
        parse_version_safely(
            software_entry.get(
                "version_start_excluding"
            )
        )
    )

    end_including = (
        parse_version_safely(
            software_entry.get(
                "version_end_including"
            )
        )
    )

    end_excluding = (
        parse_version_safely(
            software_entry.get(
                "version_end_excluding"
            )
        )
    )

    exact_version = (
        parse_version_safely(
            cpe_version
        )
    )

    if exact_version is not None:

        if installed == exact_version:

            return "affected"

    if (
        start_including is not None
        and installed < start_including
    ):

        return "not_affected"

    if (
        start_excluding is not None
        and installed <= start_excluding
    ):

        return "not_affected"

    if (
        end_including is not None
    ):

        if installed > end_including:

            return "not_affected"

        return "affected"

    if (
        end_excluding is not None
    ):

        if installed >= end_excluding:

            return "not_affected"

        return "affected"

    if (
        start_including is not None
    ):

        return "affected"

    if (
        start_excluding is not None
    ):

        return "affected"

    return "unknown"


# ============================================================
# CVE MATCHING
# ============================================================

def match_cve_to_dependency(
    cve: Dict[str, Any],
    dependency: Dict[str, Any],
) -> Optional[
    Dict[str, Any]
]:

    dependency_name = str(
        dependency.get(
            "name",
            "",
        )
    )

    installed_version = str(
        dependency.get(
            "version",
            "",
        )
    )

    configured_repo = (
        dependency.get(
            "github_repo"
        )
    )

    dep_normalized = (
        normalize_text(
            dependency_name
        )
    )

    score = 0

    reasons = []

    # --------------------------------------------------------
    # Package hints
    # --------------------------------------------------------

    for hint in cve.get(
        "package_hints",
        [],
    ):

        hint_normalized = (
            normalize_text(
                str(hint)
            )
        )

        if not hint_normalized:
            continue

        if (
            hint_normalized
            == dep_normalized
        ):

            score += 60

            reasons.append(
                f"Exact CPE/package match: "
                f"{hint}"
            )

        elif (
            dep_normalized
            in hint_normalized
            or hint_normalized
            in dep_normalized
        ):

            score += 35

            reasons.append(
                f"Partial CPE/package match: "
                f"{hint}"
            )

    # --------------------------------------------------------
    # GitHub repository
    # --------------------------------------------------------

    normalized_repo = None

    if configured_repo:

        normalized_repo = (
            normalize_repo_name(
                str(
                    configured_repo
                )
            )
        )

    if normalized_repo:

        for cve_repo in cve.get(
            "github_repositories",
            [],
        ):

            if (
                normalize_repo_name(
                    cve_repo
                ).lower()
                == normalized_repo.lower()
            ):

                score += 70

                reasons.append(
                    "GitHub repository "
                    f"reference: {cve_repo}"
                )

    # --------------------------------------------------------
    # Description
    # --------------------------------------------------------

    description = str(
        cve.get(
            "description",
            "",
        )
    )

    description_normalized = (
        normalize_text(
            description
        )
    )

    if (
        dep_normalized
        and len(dep_normalized) >= 4
    ):

        if (
            dep_normalized
            in description_normalized
        ):

            score += 25

            reasons.append(
                "Dependency name appears "
                "in CVE description"
            )

    # --------------------------------------------------------
    # Affected software
    # --------------------------------------------------------

    version_statuses = []

    for software in cve.get(
        "affected_software",
        [],
    ):

        product = normalize_text(
            str(
                software.get(
                    "product",
                    "",
                )
            )
        )

        vendor = normalize_text(
            str(
                software.get(
                    "vendor",
                    "",
                )
            )
        )

        product_matches = (
            product == dep_normalized
            or product in dep_normalized
            or dep_normalized in product
        )

        vendor_matches = (
            vendor == dep_normalized
            or vendor in dep_normalized
            or dep_normalized in vendor
        )

        if (
            product_matches
            or vendor_matches
        ):

            status = (
                version_is_affected(
                    installed_version,
                    software,
                )
            )

            version_statuses.append(
                {
                    "status":
                        status,

                    "software":
                        software,
                }
            )

    if any(
        item["status"]
        == "affected"
        for item in version_statuses
    ):

        score += 100

        reasons.append(
            "Installed version appears affected"
        )

        version_status = (
            "affected"
        )

    elif (
        version_statuses
        and all(
            item["status"]
            == "not_affected"
            for item
            in version_statuses
        )
    ):

        version_status = (
            "not_affected"
        )

    elif version_statuses:

        version_status = (
            "unknown"
        )

    else:

        version_status = (
            "unknown"
        )

    # --------------------------------------------------------
    # Final match
    # --------------------------------------------------------

    if score < 30:

        return None

    confidence = min(
        round(
            score / 200,
            2,
        ),
        1.0,
    )

    if (
        version_status
        == "affected"
    ):

        relevance = "high"

    elif (
        version_status
        == "unknown"
    ):

        relevance = "medium"

    else:

        relevance = "low"

    return {
        "cve_id":
            cve.get(
                "cve_id"
            ),

        "dependency": {
            "name":
                dependency_name,

            "ecosystem":
                dependency.get(
                    "ecosystem"
                ),

            "installed_version":
                installed_version,

            "github_repo":
                configured_repo,
        },

        "match": {
            "confidence":
                confidence,

            "score":
                score,

            "version_status":
                version_status,

            "relevance":
                relevance,

            "reasons":
                reasons,
        },

        "cve": {
            "description":
                cve.get(
                    "description"
                ),

            "severity":
                cve.get(
                    "severity"
                ),

            "cvss_score":
                cve.get(
                    "cvss_score"
                ),

            "cvss_version":
                cve.get(
                    "cvss_version"
                ),

            "cwes":
                cve.get(
                    "cwes",
                    [],
                ),

            "published":
                cve.get(
                    "published"
                ),

            "last_modified":
                cve.get(
                    "last_modified"
                ),

            "references":
                cve.get(
                    "references",
                    [],
                ),
        },

        "evidence": {
            "type":
                "public_record",

            "label":
                "Confirmed, public record",

            "source":
                "NVD / public vulnerability references",
        },
    }


def build_cve_matches(
    cves: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    matches = []

    for cve in cves:

        for dependency in dependencies:

            match = (
                match_cve_to_dependency(
                    cve,
                    dependency,
                )
            )

            if match:

                matches.append(
                    match
                )

    return matches


# ============================================================
# COMMIT MATCHING
# ============================================================

def match_commits_to_dependencies(
    commits: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    matches = []

    dependency_repo_map = {}

    for dependency in dependencies:

        repo = dependency.get(
            "github_repo"
        )

        if not repo:
            continue

        dependency_repo_map[
            normalize_repo_name(
                repo
            ).lower()
        ] = dependency

    for commit in commits:

        repository = (
            normalize_repo_name(
                commit.get(
                    "repository",
                    "",
                )
            )
            .lower()
        )

        dependency = (
            dependency_repo_map.get(
                repository
            )
        )

        if dependency is None:
            continue

        security_signal = (
            commit.get(
                "security_signal",
                {},
            )
        )

        if not security_signal.get(
            "suspicious",
            False,
        ):

            continue

        matches.append(
            {
                "type":
                    "upstream_commit_signal",

                "dependency": {
                    "name":
                        dependency.get(
                            "name"
                        ),

                    "ecosystem":
                        dependency.get(
                            "ecosystem"
                        ),

                    "installed_version":
                        dependency.get(
                            "version"
                        ),

                    "github_repo":
                        dependency.get(
                            "github_repo"
                        ),
                },

                "commit": {
                    "sha":
                        commit.get(
                            "sha"
                        ),

                    "repository":
                        repository,

                    "url":
                        commit.get(
                            "html_url"
                        ),

                    "message":
                        commit.get(
                            "message"
                        ),

                    "committer_date":
                        commit.get(
                            "committer_date"
                        ),

                    "security_signal":
                        security_signal,

                    "files":
                        commit.get(
                            "files",
                            [],
                        ),
                },

                "evidence": {
                    "type":
                        "upstream_commit",

                    "label":
                        "Upstream evidence",

                    "source":
                        "GitHub commit",
                },
            }
        )

    return matches


# ============================================================
# LINK CVES AND COMMITS
# ============================================================

def link_cves_to_commits(
    cve_matches: List[Dict[str, Any]],
    commit_matches: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    for cve_match in cve_matches:

        cve_id = str(
            cve_match.get(
                "cve_id",
                "",
            )
        ).upper()

        dependency_repo = (
            cve_match
            .get(
                "dependency",
                {},
            )
            .get(
                "github_repo"
            )
        )

        linked_commits = []

        for commit_match in commit_matches:

            commit_repo = (
                commit_match
                .get(
                    "commit",
                    {},
                )
                .get(
                    "repository"
                )
            )

            if not dependency_repo:
                continue

            if not commit_repo:
                continue

            if (
                normalize_repo_name(
                    dependency_repo
                ).lower()
                != normalize_repo_name(
                    commit_repo
                ).lower()
            ):

                continue

            commit_message = (
                commit_match
                .get(
                    "commit",
                    {},
                )
                .get(
                    "message",
                    "",
                )
            )

            referenced_cves = (
                commit_match
                .get(
                    "commit",
                    {},
                )
                .get(
                    "security_signal",
                    {},
                )
                .get(
                    "cve_ids",
                    [],
                )
            )

            if (
                cve_id
                in [
                    value.upper()
                    for value
                    in referenced_cves
                ]
                or cve_id
                in commit_message.upper()
            ):

                linked_commits.append(
                    commit_match
                )

        cve_match[
            "upstream_commit_links"
        ] = linked_commits

    return cve_matches


# ============================================================
# SILENT-WINDOW SIGNALS
# ============================================================

def build_silent_window_signals(
    commits: List[Dict[str, Any]],
    cve_matches: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Create candidate silent-window signals.

    A silent-window signal means:

    - the upstream commit looks security-related
    - the commit does not explicitly mention a CVE

    This is only a candidate.

    It is NOT proof that a vulnerability exists.
    """

    cve_ids_by_repo = {}

    for match in cve_matches:

        repo = (
            match
            .get(
                "dependency",
                {},
            )
            .get(
                "github_repo"
            )
        )

        if not repo:
            continue

        cve_id = match.get(
            "cve_id"
        )

        if not cve_id:
            continue

        repo_key = (
            normalize_repo_name(
                repo
            ).lower()
        )

        cve_ids_by_repo.setdefault(
            repo_key,
            set(),
        ).add(
            cve_id.upper()
        )

    signals = []

    for commit in commits:

        security_signal = (
            commit.get(
                "security_signal",
                {},
            )
        )

        if not security_signal.get(
            "suspicious",
            False,
        ):

            continue

        repository = (
            normalize_repo_name(
                commit.get(
                    "repository",
                    "",
                )
            )
        )

        repository_key = (
            repository.lower()
        )

        explicit_cve_ids = [
            value.upper()
            for value
            in security_signal.get(
                "cve_ids",
                [],
            )
        ]

        known_cves = (
            cve_ids_by_repo.get(
                repository_key,
                set(),
            )
        )

        matched_known_cves = sorted(
            set(
                explicit_cve_ids
            )
            & known_cves
        )

        is_silent_window_candidate = (
            len(
                explicit_cve_ids
            )
            == 0
        )

        keywords = (
            security_signal.get(
                "matched_keywords",
                [],
            )
        )

        if keywords:

            collector_reasoning = (
                "The upstream commit was selected "
                "because its message contains "
                "security-related indicators: "
                + ", ".join(
                    keywords
                )
                + "."
            )

        else:

            collector_reasoning = (
                "The upstream commit was selected "
                "by the security-commit heuristic."
            )

        signal_type = (
            "silent_window_candidate"
            if is_silent_window_candidate
            else "security_commit"
        )

        signals.append(
            {
                "type":
                    signal_type,

                "repository":
                    repository,

                "commit_sha":
                    commit.get(
                        "sha"
                    ),

                "commit_url":
                    commit.get(
                        "html_url"
                    ),

                "commit_message":
                    commit.get(
                        "message"
                    ),

                "committer_date":
                    commit.get(
                        "committer_date"
                    ),

                "security_signal":
                    security_signal,

                "explicit_cve_ids":
                    explicit_cve_ids,

                "matched_known_cves":
                    matched_known_cves,

                "why_flagged":
                    (
                        "Security-looking upstream "
                        "commit without an explicit "
                        "CVE reference."
                        if is_silent_window_candidate
                        else
                        "Commit contains an explicit "
                        "CVE reference or security signal."
                    ),

                "evidence": {
                    "type":
                        (
                            "upstream_commit"
                            if is_silent_window_candidate
                            else
                            "upstream_security_commit"
                        ),

                    "label":
                        (
                            "AI analysis required"
                            if is_silent_window_candidate
                            else
                            "Upstream evidence"
                        ),
                },

                # ------------------------------------------------
                # Placeholder for downstream AI.
                # ------------------------------------------------

                "ai_analysis": {
                    "status":
                        "pending",

                    "reasoning":
                        None,

                    "confidence":
                        None,

                    "label":
                        "AI analysis pending",
                },

                # ------------------------------------------------
                # Collector's own reasoning
                # ------------------------------------------------

                "collector_analysis": {
                    "reasoning":
                        collector_reasoning,

                    "heuristic_score":
                        security_signal.get(
                            "score"
                        ),

                    "matched_keywords":
                        keywords,
                },

                # ------------------------------------------------
                # Verification information
                # ------------------------------------------------

                "verification": {
                    "source_url":
                        commit.get(
                            "html_url"
                        ),

                    "source_type":
                        "GitHub commit",

                    "read_only":
                        True,
                },
            }
        )

    return signals


# ============================================================
# DEMO MODE
# ============================================================

def run_demo() -> None:
    """
    Generate deterministic offline demo data.

    This means that during your presentation you are guaranteed
    to have:

    1. CVE match
    2. security-related commit
    3. silent-window candidate

    No API connection is needed.
    """

    print()
    print("=" * 70)
    print(
        "RUNNING OFFLINE DEMONSTRATION"
    )
    print("=" * 70)
    print()

    dependencies = (
        load_dependencies()
    )

    # --------------------------------------------------------
    # DEMO CVE
    # --------------------------------------------------------

    demo_cve = {
        "cve_id":
            "CVE-2021-DEMO",

        "published":
            "2021-12-01T00:00:00.000",

        "last_modified":
            "2021-12-10T00:00:00.000",

        "source_identifier":
            "demo",

        "description":
            (
                "Apache log4j-core allows remote "
                "attackers to execute arbitrary code "
                "under certain conditions."
            ),

        "severity":
            "CRITICAL",

        "cvss_score":
            10.0,

        "cvss_version":
            "3.1",

        "cwes": [
            "CWE-502"
        ],

        "package_hints": [
            "log4j-core"
        ],

        "github_repositories": [
            "apache/logging-log4j2"
        ],

        "affected_software": [
            {
                "criteria":
                    (
                        "cpe:2.3:a:apache:"
                        "log4j-core:2.14.1:"
                        "*:*:*:*:*:*:*"
                    ),

                "vulnerable":
                    True,

                "version_start_including":
                    None,

                "version_start_excluding":
                    None,

                "version_end_including":
                    "2.14.1",

                "version_end_excluding":
                    None,

                "vendor":
                    "apache",

                "product":
                    "log4j-core",

                "version":
                    "2.14.1",
            }
        ],

        "references": [
            {
                "url":
                    (
                        "https://github.com/"
                        "apache/logging-log4j2"
                    ),

                "source":
                    "demo",

                "tags":
                    [],
            }
        ],

        "evidence": {
            "type":
                "public_record",

            "label":
                "Confirmed, public record",

            "source":
                "NVD / public vulnerability references",
        },
    }

    # --------------------------------------------------------
    # DEMO COMMIT
    # --------------------------------------------------------

    demo_message = (
        "Harden message lookup validation "
        "and prevent unsafe JNDI resolution"
    )

    demo_commit = {
        "repository":
            "apache/logging-log4j2",

        "sha":
            "demo123456",

        "html_url":
            (
                "https://github.com/"
                "apache/logging-log4j2/"
                "commit/demo123456"
            ),

        "message":
            demo_message,

        "author":
            "Demo Maintainer",

        "author_email":
            None,

        "committer":
            "Demo Maintainer",

        "committer_date":
            iso_z(
                utc_now()
                - timedelta(
                    days=10
                )
            ),

        "author_date":
            iso_z(
                utc_now()
                - timedelta(
                    days=10
                )
            ),

        "stats": {
            "additions":
                20,

            "deletions":
                10,

            "total":
                30,
        },

        "security_signal":
            analyze_commit_message(
                demo_message
            ),

        "files": [
            {
                "filename":
                    (
                        "log4j-core/"
                        "src/main/java/"
                        "org/apache/"
                        "logging/log4j/core/"
                        "lookup/JndiLookup.java"
                    ),

                "status":
                    "modified",

                "additions":
                    20,

                "deletions":
                    10,

                "changes":
                    30,

                "patch":
                    (
                        "@@ demo patch @@\n"
                        "- unsafeLookup(input)\n"
                        "+ validateLookup(input)\n"
                        "+ parseValidatedInput(input)"
                    ),
            }
        ],
    }

    # --------------------------------------------------------
    # CVE MATCH
    # --------------------------------------------------------

    cve_matches = (
        build_cve_matches(
            [demo_cve],
            dependencies,
        )
    )

    # --------------------------------------------------------
    # COMMIT MATCH
    # --------------------------------------------------------

    commit_matches = (
        match_commits_to_dependencies(
            [demo_commit],
            dependencies,
        )
    )

    # --------------------------------------------------------
    # LINK
    # --------------------------------------------------------

    cve_matches = (
        link_cves_to_commits(
            cve_matches,
            commit_matches,
        )
    )

    # --------------------------------------------------------
    # SILENT WINDOW
    # --------------------------------------------------------

    silent_signals = (
        build_silent_window_signals(
            [demo_commit],
            [],  # No CVE known to the silent-window detector
        )
    )

    # --------------------------------------------------------
    # Simulated downstream AI analysis
    #
    # This is deliberately hard-coded for the hackathon demo.
    #
    # In your real implementation, your teammate's AI
    # component should populate these fields.
    # --------------------------------------------------------

    for signal in silent_signals:

        signal["ai_analysis"] = {
            "status":
                "complete",

            "reasoning":
                (
                    "Flagged because the upstream "
                    "commit changes input validation "
                    "and removes an unsafe lookup path "
                    "without referencing a CVE. This "
                    "pattern is consistent with a quiet "
                    "security fix and warrants "
                    "source-code reachability analysis."
                ),

            "confidence":
                0.87,

            "label":
                "AI-inferred",

            "model":
                "Hackathon demo AI",
        }

    # --------------------------------------------------------
    # Construct final output
    # --------------------------------------------------------

    generated_at = iso_z(
        utc_now()
    )

    matched_signals = {
        "generated_at":
            generated_at,

        "mode":
            "demo",

        "description":
            (
                "Offline demonstration dataset "
                "for the vulnerability intelligence "
                "dashboard."
            ),

        "dependencies":
            dependencies,

        "cve_dependency_matches":
            cve_matches,

        "upstream_commit_matches":
            commit_matches,

        "silent_window_candidates":
            silent_signals,
    }

    # --------------------------------------------------------
    # Save outputs
    # --------------------------------------------------------

    save_json(
        "cves.json",
        {
            "generated_at":
                generated_at,

            "source":
                "Demo",

            "count":
                1,

            "cves":
                [demo_cve],
        },
    )

    save_json(
        "commits.json",
        {
            "generated_at":
                generated_at,

            "source":
                "Demo",

            "repositories":
                [
                    "apache/logging-log4j2"
                ],

            "count":
                1,

            "commits":
                [demo_commit],
        },
    )

    save_json(
        "matched_signals.json",
        matched_signals,
    )

    save_json(
        "run_summary.json",
        {
            "generated_at":
                generated_at,

            "mode":
                "demo",

            "dependency_count":
                len(
                    dependencies
                ),

            "cve_count":
                1,

            "commit_count":
                1,

            "cve_dependency_match_count":
                len(
                    cve_matches
                ),

            "upstream_commit_match_count":
                len(
                    commit_matches
                ),

            "silent_window_candidate_count":
                len(
                    silent_signals
                ),
        },
    )

    print()
    print(
        "DEMO DATA GENERATED"
    )
    print(
        "-------------------"
    )

    print(
        f"CVE matches: "
        f"{len(cve_matches)}"
    )

    print(
        f"Security commits: "
        f"{len(commit_matches)}"
    )

    print(
        f"Silent-window candidates: "
        f"{len(silent_signals)}"
    )

    print()
    print(
        "Open the dashboard with:"
    )

    print(
        "python app.py"
    )

    print()


# ============================================================
# LIVE COLLECTION
# ============================================================

def run_real_collection(
    cve_days: int,
    commit_days: int,
    commit_limit: int,
    max_cves: int,
) -> None:

    start_time = utc_now()

    print()
    print("=" * 70)
    print(
        "LIVE VULNERABILITY INTELLIGENCE COLLECTOR"
    )
    print("=" * 70)
    print()

    # --------------------------------------------------------
    # Dependencies
    # --------------------------------------------------------

    print(
        "[1/6] Loading dependency inventory..."
    )

    dependencies = (
        load_dependencies()
    )

    print(
        f"[+] Loaded "
        f"{len(dependencies)} dependencies"
    )

    for dependency in dependencies:

        print(
            "    - "
            f"{dependency.get('name')} "
            f"{dependency.get('version')} "
            f"[{dependency.get('ecosystem')}]"
        )

    client = APIClient()

    nvd_collector = NVDCollector(
        client
    )

    github_collector = GitHubCollector(
        client
    )

    # --------------------------------------------------------
    # CVEs
    # --------------------------------------------------------

    print()
    print(
        "[2/6] Collecting CVEs..."
    )

    raw_cves = (
        nvd_collector.fetch_recent_cves(
            days=cve_days,
            max_results=max_cves,
        )
    )

    normalized_cves = (
        nvd_collector.normalize_all(
            raw_cves
        )
    )

    save_json(
        "cves.json",
        {
            "generated_at":
                iso_z(
                    utc_now()
                ),

            "source":
                "NVD",

            "lookback_days":
                cve_days,

            "count":
                len(
                    normalized_cves
                ),

            "cves":
                normalized_cves,
        },
    )

    # --------------------------------------------------------
    # GitHub
    # --------------------------------------------------------

    print()
    print(
        "[3/6] Collecting upstream commits..."
    )

    repositories = sorted(
        {
            normalize_repo_name(
                dependency.get(
                    "github_repo",
                    "",
                )
            )
            for dependency
            in dependencies
            if dependency.get(
                "github_repo"
            )
        }
    )

    all_commits = []

    for repository in repositories:

        try:

            commits = (
                github_collector
                .fetch_repository_commits(
                    repository=repository,
                    days=commit_days,
                    limit=commit_limit,
                )
            )

            all_commits.extend(
                commits
            )

        except Exception as exc:

            print(
                f"[!] Failed to fetch "
                f"{repository}: {exc}"
            )

    save_json(
        "commits.json",
        {
            "generated_at":
                iso_z(
                    utc_now()
                ),

            "source":
                "GitHub",

            "lookback_days":
                commit_days,

            "repositories":
                repositories,

            "count":
                len(
                    all_commits
                ),

            "commits":
                all_commits,
        },
    )

    # --------------------------------------------------------
    # Match CVEs
    # --------------------------------------------------------

    print()
    print(
        "[4/6] Matching CVEs to dependencies..."
    )

    cve_matches = (
        build_cve_matches(
            normalized_cves,
            dependencies,
        )
    )

    print(
        f"[+] CVE matches: "
        f"{len(cve_matches)}"
    )

    # --------------------------------------------------------
    # Match commits
    # --------------------------------------------------------

    print()
    print(
        "[5/6] Matching security-related commits..."
    )

    commit_matches = (
        match_commits_to_dependencies(
            all_commits,
            dependencies,
        )
    )

    print(
        f"[+] Security commit matches: "
        f"{len(commit_matches)}"
    )

    # --------------------------------------------------------
    # Build silent-window signals
    # --------------------------------------------------------

    print()
    print(
        "[6/6] Building intelligence signals..."
    )

    cve_matches = (
        link_cves_to_commits(
            cve_matches,
            commit_matches,
        )
    )

    silent_signals = (
        build_silent_window_signals(
            all_commits,
            cve_matches,
        )
    )

    matched_signals = {
        "generated_at":
            iso_z(
                utc_now()
            ),

        "mode":
            "live",

        "description":
            (
                "Security signals generated "
                "from NVD and GitHub data."
            ),

        "dependencies":
            dependencies,

        "cve_dependency_matches":
            cve_matches,

        "upstream_commit_matches":
            commit_matches,

        "silent_window_candidates":
            silent_signals,
    }

    save_json(
        "matched_signals.json",
        matched_signals,
    )

    elapsed = (
        utc_now()
        - start_time
    ).total_seconds()

    save_json(
        "run_summary.json",
        {
            "generated_at":
                iso_z(
                    utc_now()
                ),

            "mode":
                "live",

            "elapsed_seconds":
                round(
                    elapsed,
                    2,
                ),

            "dependency_count":
                len(
                    dependencies
                ),

            "cve_count":
                len(
                    normalized_cves
                ),

            "commit_count":
                len(
                    all_commits
                ),

            "cve_dependency_match_count":
                len(
                    cve_matches
                ),

            "upstream_commit_match_count":
                len(
                    commit_matches
                ),

            "silent_window_candidate_count":
                len(
                    silent_signals
                ),

            "repositories_checked":
                repositories,
        },
    )

    print()
    print("=" * 70)
    print(
        "COLLECTION COMPLETE"
    )
    print("=" * 70)
    print()

    print(
        f"Dependencies:             "
        f"{len(dependencies)}"
    )

    print(
        f"CVEs retrieved:           "
        f"{len(normalized_cves)}"
    )

    print(
        f"Commits retrieved:        "
        f"{len(all_commits)}"
    )

    print(
        f"CVE matches:              "
        f"{len(cve_matches)}"
    )

    print(
        f"Security commits:         "
        f"{len(commit_matches)}"
    )

    print(
        f"Silent-window candidates: "
        f"{len(silent_signals)}"
    )

    print()
    print(
        "Open matched_signals.json "
        "for the downstream AI."
    )


# ============================================================
# CLI
# ============================================================

def parse_arguments() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "Read-only vulnerability "
            "intelligence collector."
        )
    )

    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_CVE_DAYS,
        help=(
            "Number of days of CVEs to retrieve."
        ),
    )

    parser.add_argument(
        "--commit-days",
        type=int,
        default=DEFAULT_COMMIT_DAYS,
        help=(
            "Number of days of commits to retrieve."
        ),
    )

    parser.add_argument(
        "--commit-limit",
        type=int,
        default=DEFAULT_COMMIT_LIMIT,
        help=(
            "Maximum commits per repository."
        ),
    )

    parser.add_argument(
        "--max-cves",
        type=int,
        default=500,
        help=(
            "Maximum CVEs to retrieve."
        ),
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help=(
            "Run the offline demonstration."
        ),
    )

    return parser.parse_args()


def main() -> int:

    try:

        args = (
            parse_arguments()
        )

        if args.days < 1:

            raise ValueError(
                "--days must be at least 1."
            )

        if args.commit_days < 1:

            raise ValueError(
                "--commit-days must be at least 1."
            )

        if args.commit_limit < 1:

            raise ValueError(
                "--commit-limit must be at least 1."
            )

        if args.max_cves < 1:

            raise ValueError(
                "--max-cves must be at least 1."
            )

        if args.demo:

            run_demo()

        else:

            run_real_collection(
                cve_days=args.days,
                commit_days=args.commit_days,
                commit_limit=args.commit_limit,
                max_cves=args.max_cves,
            )

        return 0

    except KeyboardInterrupt:

        print()
        print(
            "[!] Interrupted."
        )

        return 1

    except Exception as exc:

        print()
        print(
            f"[ERROR] {exc}"
        )

        return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )
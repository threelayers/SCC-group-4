"use strict";


/* ============================================================
   GLOBAL STATE
   ============================================================ */

let dashboardData = null;


/* ============================================================
   BASIC HELPERS
   ============================================================ */

function $(id) {
    return document.getElementById(id);
}


function show(element) {

    element.classList.remove(
        "hidden"
    );
}


function hide(element) {

    element.classList.add(
        "hidden"
    );
}


function setText(
    element,
    value
) {

    element.textContent =
        value === null ||
        value === undefined ||
        value === ""
            ? "—"
            : String(value);
}


function createTextElement(
    tag,
    text,
    className = ""
) {

    const element =
        document.createElement(
            tag
        );

    if (className) {

        element.className =
            className;
    }

    element.textContent =
        text === null ||
        text === undefined
            ? ""
            : String(text);

    return element;
}


/* ============================================================
   SIGNAL IDS
   ============================================================ */

function cveSignalId(
    match
) {

    const cve =
        match.cve || {};

    const dependency =
        match.dependency || {};

    return (
        "cve:"
        + (
            match.cve_id ||
            cve.cve_id ||
            "unknown"
        )
        + ":"
        + (
            dependency.name ||
            "unknown"
        )
    );
}


function commitSignalId(
    match
) {

    const commit =
        match.commit || {};

    return (
        "commit:"
        + (
            commit.sha ||
            "unknown"
        )
    );
}


function silentSignalId(
    match
) {

    return (
        "silent:"
        + (
            match.commit_sha ||
            "unknown"
        )
    );
}


function getCveId(
    match
) {

    const cve =
        match.cve || {};

    return (
        match.cve_id ||
        cve.cve_id ||
        "Unknown CVE"
    );
}


/* ============================================================
   API
   ============================================================ */

async function loadDashboard() {

    show(
        $("loadingState")
    );

    hide(
        $("errorState")
    );

    hide(
        $("dashboard")
    );

    try {

        const response =
            await fetch(
                "/api/signals",
                {
                    cache: "no-store",
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            throw new Error(
                data.error ||
                "The server returned an error."
            );
        }

        dashboardData =
            data;

        renderDashboard(
            data
        );

        hide(
            $("loadingState")
        );

        show(
            $("dashboard")
        );

        setText(
            $("connectionStatus"),
            "Live"
        );

    } catch (error) {

        console.error(
            error
        );

        hide(
            $("loadingState")
        );

        hide(
            $("dashboard")
        );

        $("errorMessage")
            .textContent =
            error.message;

        show(
            $("errorState")
        );

        setText(
            $("connectionStatus"),
            "Error"
        );
    }
}


async function collectLatest() {

    const button =
        $("collectButton");

    button.disabled =
        true;

    button.textContent =
        "Collecting...";

    setText(
        $("connectionStatus"),
        "Collecting"
    );

    try {

        const response =
            await fetch(
                "/api/collect",
                {
                    method:
                        "POST",

                    headers: {
                        "Content-Type":
                            "application/json",
                    },

                    body:
                        JSON.stringify(
                            {
                                days:
                                    1,

                                commit_days:
                                    1,

                                commit_limit:
                                    20,
                            }
                        ),
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Collection failed."
            );
        }

        dashboardData = {
            signals:
                data.signals,

            summary:
                data.summary,

            decisions:
                (
                    dashboardData
                    && dashboardData.decisions
                )
                || {},
        };

        renderDashboard(
            dashboardData
        );

        hide(
            $("loadingState")
        );

        hide(
            $("errorState")
        );

        show(
            $("dashboard")
        );

        setText(
            $("connectionStatus"),
            "Live"
        );

    } catch (error) {

        console.error(
            error
        );

        alert(
            "Could not collect latest data:\n\n"
            + error.message
        );

        setText(
            $("connectionStatus"),
            "Error"
        );

    } finally {

        button.disabled =
            false;

        button.textContent =
            "Collect latest";
    }
}


/* ============================================================
   DECISIONS
   ============================================================ */

function getDecision(
    signalId
) {

    if (
        !dashboardData ||
        !dashboardData.decisions
    ) {

        return null;
    }

    return (
        dashboardData
            .decisions[
                signalId
            ]
        || null
    );
}


function getDecisionStatus(
    signalId
) {

    const record =
        getDecision(
            signalId
        );

    if (!record) {

        return "pending";
    }

    return record.decision;
}


async function submitDecision(
    signalId,
    decision
) {

    try {

        const response =
            await fetch(
                "/api/decision",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",
                    },

                    body:
                        JSON.stringify(
                            {
                                signal_id:
                                    signalId,

                                decision:
                                    decision,
                            }
                        ),
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Could not save decision."
            );
        }

        if (
            !dashboardData.decisions
        ) {

            dashboardData.decisions =
                {};
        }

        dashboardData
            .decisions[
                signalId
            ] =
            data.record;

        updateReviewSummary();

        updateAllCardStatuses();

    } catch (error) {

        console.error(
            error
        );

        alert(
            "Could not save your decision:\n\n"
            + error.message
        );
    }
}


async function resetDecision(
    signalId
) {

    try {

        const response =
            await fetch(
                "/api/decision/reset",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",
                    },

                    body:
                        JSON.stringify(
                            {
                                signal_id:
                                    signalId,
                            }
                        ),
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Could not reset decision."
            );
        }

        if (
            dashboardData.decisions
        ) {

            delete dashboardData
                .decisions[
                    signalId
                ];
        }

        updateReviewSummary();

        updateAllCardStatuses();

    } catch (error) {

        console.error(
            error
        );

        alert(
            "Could not reset your decision:\n\n"
            + error.message
        );
    }
}


/* ============================================================
   REVIEW CONTROLS
   ============================================================ */

function buildReviewControls(
    signalId
) {

    const wrapper =
        document.createElement(
            "div"
        );

    wrapper.className =
        "review-controls";

    const status =
        getDecisionStatus(
            signalId
        );


    /* --------------------------------------------------------
       Status
       -------------------------------------------------------- */

    const statusElement =
        document.createElement(
            "span"
        );

    statusElement.className =
        `review-status review-${status}`;


    if (
        status === "accepted"
    ) {

        statusElement.textContent =
            "✓ Accepted";

    } else if (
        status === "rejected"
    ) {

        statusElement.textContent =
            "✕ Rejected";

    } else {

        statusElement.textContent =
            "• Pending";
    }


    wrapper.appendChild(
        statusElement
    );


    /* --------------------------------------------------------
       ACCEPT
       -------------------------------------------------------- */

    const acceptButton =
        document.createElement(
            "button"
        );

    acceptButton.type =
        "button";

    acceptButton.className =
        "review-button accept-button";

    acceptButton.textContent =
        "Accept";


    if (
        status === "accepted"
    ) {

        acceptButton.classList.add(
            "selected"
        );
    }


    acceptButton.addEventListener(
        "click",
        () => {

            submitDecision(
                signalId,
                "accepted"
            );
        }
    );


    /* --------------------------------------------------------
       REJECT
       -------------------------------------------------------- */

    const rejectButton =
        document.createElement(
            "button"
        );

    rejectButton.type =
        "button";

    rejectButton.className =
        "review-button reject-button";

    rejectButton.textContent =
        "Reject";


    if (
        status === "rejected"
    ) {

        rejectButton.classList.add(
            "selected"
        );
    }


    rejectButton.addEventListener(
        "click",
        () => {

            submitDecision(
                signalId,
                "rejected"
            );
        }
    );


    wrapper.appendChild(
        acceptButton
    );

    wrapper.appendChild(
        rejectButton
    );


    /* --------------------------------------------------------
       RESET
       -------------------------------------------------------- */

    if (
        status !== "pending"
    ) {

        const resetButton =
            document.createElement(
                "button"
            );

        resetButton.type =
            "button";

        resetButton.className =
            "review-reset-button";

        resetButton.textContent =
            "Reset";


        resetButton.addEventListener(
            "click",
            () => {

                resetDecision(
                    signalId
                );
            }
        );


        wrapper.appendChild(
            resetButton
        );
    }


    return wrapper;
}


/* ============================================================
   DASHBOARD RENDERING
   ============================================================ */

function renderDashboard(
    data
) {

    const signals =
        data.signals || {};

    const summary =
        data.summary || {};


    setText(
        $("dependencyCount"),
        summary.dependencies
    );


    setText(
        $("criticalCount"),
        summary.critical
    );


    setText(
        $("highCount"),
        summary.high
    );


    setText(
        $("affectedCount"),
        summary.affected
    );


    setText(
        $("silentWindowCount"),
        summary.silent_window_candidates
    );


    const generatedAt =
        signals.generated_at;


    if (generatedAt) {

        const date =
            new Date(
                generatedAt
            );

        if (
            !Number.isNaN(
                date.getTime()
            )
        ) {

            $("generatedAt")
                .textContent =
                "Last collected: "
                + date.toLocaleString();

        } else {

            $("generatedAt")
                .textContent =
                "Last collected: "
                + generatedAt;
        }
    }


    $("rawJson")
        .textContent =
        JSON.stringify(
            signals,
            null,
            2
        );


    renderCveMatches(
        signals.cve_dependency_matches
        || []
    );


    renderCommitMatches(
        signals.upstream_commit_matches
        || []
    );


    renderSilentWindowCandidates(
        signals.silent_window_candidates
        || []
    );


    updateReviewSummary();

    applyFilters();
}


/* ============================================================
   REVIEW SUMMARY
   ============================================================ */

function updateReviewSummary() {

    if (!dashboardData) {
        return;
    }

    const signals =
        dashboardData.signals
        || {};

    const decisions =
        dashboardData.decisions
        || {};


    const total =
        (
            signals.cve_dependency_matches
            || []
        ).length
        +
        (
            signals.upstream_commit_matches
            || []
        ).length
        +
        (
            signals.silent_window_candidates
            || []
        ).length;


    const reviewed =
        Object.keys(
            decisions
        ).length;


    const pending =
        Math.max(
            total - reviewed,
            0
        );


    setText(
        $("pendingReviewCount"),
        `${pending} pending`
    );
}


/* ============================================================
   BADGES
   ============================================================ */

function createBadge(
    text,
    className
) {

    return createTextElement(
        "span",
        text,
        `badge ${className}`
    );
}


function severityBadge(
    severity
) {

    const normalized =
        String(
            severity ||
            "UNKNOWN"
        ).toUpperCase();


    switch (normalized) {

        case "CRITICAL":

            return createBadge(
                normalized,
                "badge-critical"
            );

        case "HIGH":

            return createBadge(
                normalized,
                "badge-high"
            );

        case "MEDIUM":

            return createBadge(
                normalized,
                "badge-medium"
            );

        case "LOW":

            return createBadge(
                normalized,
                "badge-low"
            );

        default:

            return createBadge(
                normalized,
                "badge-unknown"
            );
    }
}


/* ============================================================
   EVIDENCE
   ============================================================ */

function buildEvidenceBadge(
    label,
    type
) {

    let className =
        "evidence-badge";


    if (
        type === "public_record"
    ) {

        className +=
            " evidence-public";

    } else if (
        type === "upstream_commit"
    ) {

        className +=
            " evidence-upstream";

    } else {

        className +=
            " evidence-ai";
    }


    return createBadge(
        label,
        className
    );
}


function createAiConfidenceBadge(
    aiAnalysis
) {

    if (!aiAnalysis) {

        return null;
    }


    const confidence =
        aiAnalysis.confidence;


    if (
        typeof confidence !==
        "number"
    ) {

        return createBadge(
            "AI analysis pending",
            "badge-ai-pending"
        );
    }


    const percentage =
        Math.round(
            confidence * 100
        );


    return createBadge(
        `${
            aiAnalysis.label
            || "AI-inferred"
        }, ${percentage}%`,
        "badge-ai-confidence"
    );
}


function buildSourceButton(
    url
) {

    if (!url) {

        return null;
    }


    const link =
        document.createElement(
            "a"
        );

    link.href =
        url;

    link.target =
        "_blank";

    link.rel =
        "noopener noreferrer";

    link.className =
        "source-button";

    link.textContent =
        "Verify source ↗";


    return link;
}


/* ============================================================
   CVE MATCHES
   ============================================================ */

function renderCveMatches(
    matches
) {

    const list =
        $("cveList");

    list.innerHTML =
        "";


    setText(
        $("cveCount"),
        matches.length
    );


    if (
        matches.length === 0
    ) {

        show(
            $("cveEmpty")
        );

        return;
    }


    hide(
        $("cveEmpty")
    );


    matches.forEach(
        (match) => {

            list.appendChild(
                buildCveCard(
                    match
                )
            );
        }
    );
}


function buildCveCard(
    match
) {

    const card =
        createSignalCard();

    card.dataset.type =
        "cve";


    const dependency =
        match.dependency
        || {};

    const cve =
        match.cve
        || {};

    const matchInfo =
        match.match
        || {};


    const signalId =
        cveSignalId(
            match
        );


    card.dataset.signalId =
        signalId;


    const header =
        createCardHeader();


    const main =
        createSignalMain();


    const topline =
        document.createElement(
            "div"
        );

    topline.className =
        "signal-topline";


    topline.appendChild(
        createTextElement(
            "span",
            getCveId(
                match
            ),
            "signal-title"
        )
    );


    topline.appendChild(
        severityBadge(
            cve.severity
        )
    );


    topline.appendChild(
        buildEvidenceBadge(
            "Confirmed, public record",
            "public_record"
        )
    );


    if (
        matchInfo.version_status
        === "affected"
    ) {

        topline.appendChild(
            createBadge(
                "AFFECTED",
                "badge-affected"
            )
        );
    }


    main.appendChild(
        topline
    );


    main.appendChild(
        createTextElement(
            "div",
            dependency.name
            || "Unknown dependency",
            "signal-subtitle"
        )
    );


    const meta =
        document.createElement(
            "div"
        );

    meta.className =
        "signal-meta";


    addMeta(
        meta,
        `Version ${
            dependency.installed_version
            || "unknown"
        }`
    );


    addMeta(
        meta,
        dependency.ecosystem
    );


    addMeta(
        meta,
        `${
            Math.round(
                (
                    matchInfo.confidence
                    || 0
                ) * 100
            )
        }% match confidence`
    );


    main.appendChild(
        meta
    );


    main.appendChild(
        createTextElement(
            "div",
            cve.description
            || "No description available.",
            "signal-description"
        )
    );


    const details =
        buildCveDetails(
            match
        );


    const actions =
        createSignalActions();


    actions.appendChild(
        buildReviewControls(
            signalId
        )
    );


    const sourceUrl =
        findCveSourceUrl(
            match
        );


    const sourceButton =
        buildSourceButton(
            sourceUrl
        );


    if (sourceButton) {

        actions.appendChild(
            sourceButton
        );
    }


    actions.appendChild(
        createExpandButton(
            details
        )
    );


    header.appendChild(
        main
    );

    header.appendChild(
        actions
    );


    card.appendChild(
        header
    );

    card.appendChild(
        details
    );


    card.dataset.searchText =
        JSON.stringify(
            match
        ).toLowerCase();


    applyCardStatus(
        card
    );


    return card;
}


function findCveSourceUrl(
    match
) {

    const cve =
        match.cve
        || {};

    const references =
        cve.references
        || [];


    for (
        const reference
        of references
    ) {

        if (
            reference
            && reference.url
        ) {

            return reference.url;
        }
    }


    return null;
}


function buildCveDetails(
    match
) {

    const details =
        createDetailsContainer();


    const dependency =
        match.dependency
        || {};

    const cve =
        match.cve
        || {};

    const matchInfo =
        match.match
        || {};


    const grid =
        document.createElement(
            "div"
        );

    grid.className =
        "detail-grid";


    const evidencePanel =
        createDetailPanel(
            "Trust & evidence"
        );


    appendDetailRow(
        evidencePanel,
        "Evidence level",
        "Confirmed, public record"
    );


    appendDetailRow(
        evidencePanel,
        "Source",
        "NVD / public vulnerability references"
    );


    appendDetailRow(
        evidencePanel,
        "Human review",
        getDecisionStatus(
            cveSignalId(
                match
            )
        )
    );


    grid.appendChild(
        evidencePanel
    );


    const dependencyPanel =
        createDetailPanel(
            "Dependency"
        );


    appendDetailRow(
        dependencyPanel,
        "Package",
        dependency.name
    );


    appendDetailRow(
        dependencyPanel,
        "Ecosystem",
        dependency.ecosystem
    );


    appendDetailRow(
        dependencyPanel,
        "Installed version",
        dependency.installed_version
    );


    appendDetailRow(
        dependencyPanel,
        "Upstream repository",
        dependency.github_repo
    );


    const cvePanel =
        createDetailPanel(
            "Vulnerability"
        );


    appendDetailRow(
        cvePanel,
        "CVE",
        getCveId(
            match
        )
    );


    appendDetailRow(
        cvePanel,
        "Severity",
        cve.severity
    );


    appendDetailRow(
        cvePanel,
        "CVSS score",
        cve.cvss_score
    );


    appendDetailRow(
        cvePanel,
        "CVSS version",
        cve.cvss_version
    );


    appendDetailRow(
        cvePanel,
        "Published",
        cve.published
    );


    const matchPanel =
        createDetailPanel(
            "Matching result"
        );


    appendDetailRow(
        matchPanel,
        "Confidence",
        `${
            Math.round(
                (
                    matchInfo.confidence
                    || 0
                ) * 100
            )
        }%`
    );


    appendDetailRow(
        matchPanel,
        "Match score",
        matchInfo.score
    );


    appendDetailRow(
        matchPanel,
        "Version status",
        matchInfo.version_status
    );


    appendDetailRow(
        matchPanel,
        "Relevance",
        matchInfo.relevance
    );


    const reasonsPanel =
        createDetailPanel(
            "Why this was matched"
        );


    const reasons =
        matchInfo.reasons
        || [];


    const reasonList =
        document.createElement(
            "ul"
        );

    reasonList.className =
        "reason-list";


    reasons.forEach(
        (reason) => {

            const item =
                document.createElement(
                    "li"
                );

            item.textContent =
                reason;

            reasonList.appendChild(
                item
            );
        }
    );


    reasonsPanel.appendChild(
        reasonList
    );


    grid.appendChild(
        dependencyPanel
    );

    grid.appendChild(
        cvePanel
    );

    grid.appendChild(
        matchPanel
    );

    grid.appendChild(
        reasonsPanel
    );


    const descriptionPanel =
        createDetailPanel(
            "Full description",
            true
        );


    descriptionPanel.appendChild(
        createTextElement(
            "div",
            cve.description
            || "No description available.",
            "detail-value"
        )
    );


    grid.appendChild(
        descriptionPanel
    );


    const references =
        cve.references
        || [];


    if (
        references.length > 0
    ) {

        const referencePanel =
            createDetailPanel(
                "References",
                true
            );


        references.forEach(
            (reference) => {

                appendDetailRow(
                    referencePanel,
                    reference.source
                    || "Source",
                    reference.url
                );
            }
        );


        grid.appendChild(
            referencePanel
        );
    }


    const linkedCommits =
        match.upstream_commit_links
        || [];


    if (
        linkedCommits.length > 0
    ) {

        const commitPanel =
            createDetailPanel(
                "Linked upstream commits",
                true
            );


        linkedCommits.forEach(
            (commitMatch) => {

                const commit =
                    commitMatch.commit
                    || {};


                appendDetailRow(
                    commitPanel,
                    "Commit",
                    commit.sha
                );


                appendDetailRow(
                    commitPanel,
                    "Message",
                    commit.message
                );


                appendDetailRow(
                    commitPanel,
                    "URL",
                    commit.url
                );
            }
        );


        grid.appendChild(
            commitPanel
        );
    }


    const jsonPanel =
        createDetailPanel(
            "Complete finding JSON",
            true
        );


    jsonPanel.appendChild(
        createDiffContainer(
            JSON.stringify(
                match,
                null,
                2
            )
        )
    );


    grid.appendChild(
        jsonPanel
    );


    details.appendChild(
        grid
    );


    return details;
}


/* ============================================================
   SECURITY COMMITS
   ============================================================ */

function renderCommitMatches(
    matches
) {

    const list =
        $("commitList");

    list.innerHTML =
        "";


    setText(
        $("commitCount"),
        matches.length
    );


    if (
        matches.length === 0
    ) {

        show(
            $("commitEmpty")
        );

        return;
    }


    hide(
        $("commitEmpty")
    );


    matches.forEach(
        (match) => {

            list.appendChild(
                buildCommitCard(
                    match
                )
            );
        }
    );
}


function buildCommitCard(
    match
) {

    const card =
        createSignalCard();

    card.dataset.type =
        "commit";


    const dependency =
        match.dependency
        || {};

    const commit =
        match.commit
        || {};

    const signal =
        commit.security_signal
        || {};


    const signalId =
        commitSignalId(
            match
        );


    card.dataset.signalId =
        signalId;


    const header =
        createCardHeader();


    const main =
        createSignalMain();


    const topline =
        document.createElement(
            "div"
        );

    topline.className =
        "signal-topline";


    topline.appendChild(
        createTextElement(
            "span",
            "Upstream security commit",
            "signal-title"
        )
    );


    topline.appendChild(
        buildEvidenceBadge(
            "Upstream evidence",
            "upstream_commit"
        )
    );


    topline.appendChild(
        createBadge(
            `SCORE ${
                signal.score
                || 0
            }`,
            "badge-commit"
        )
    );


    main.appendChild(
        topline
    );


    main.appendChild(
        createTextElement(
            "div",
            dependency.name
            || "Unknown dependency",
            "signal-subtitle"
        )
    );


    const meta =
        document.createElement(
            "div"
        );

    meta.className =
        "signal-meta";


    addMeta(
        meta,
        commit.repository
    );


    addMeta(
        meta,
        `Files ${
            (commit.files || [])
                .length
        }`
    );


    addMeta(
        meta,
        signal.classification
    );


    main.appendChild(
        meta
    );


    main.appendChild(
        createTextElement(
            "div",
            commit.message
            || "No commit message available.",
            "signal-description"
        )
    );


    const details =
        buildCommitDetails(
            match
        );


    const actions =
        createSignalActions();


    actions.appendChild(
        buildReviewControls(
            signalId
        )
    );


    const sourceButton =
        buildSourceButton(
            commit.url
        );


    if (sourceButton) {

        actions.appendChild(
            sourceButton
        );
    }


    actions.appendChild(
        createExpandButton(
            details
        )
    );


    header.appendChild(
        main
    );


    header.appendChild(
        actions
    );


    card.appendChild(
        header
    );


    card.appendChild(
        details
    );


    card.dataset.searchText =
        JSON.stringify(
            match
        ).toLowerCase();


    applyCardStatus(
        card
    );


    return card;
}


function buildCommitDetails(
    match
) {

    const details =
        createDetailsContainer();


    const dependency =
        match.dependency
        || {};

    const commit =
        match.commit
        || {};

    const signal =
        commit.security_signal
        || {};


    const grid =
        document.createElement(
            "div"
        );

    grid.className =
        "detail-grid";


    const evidencePanel =
        createDetailPanel(
            "Trust & evidence"
        );


    appendDetailRow(
        evidencePanel,
        "Evidence level",
        "Upstream evidence"
    );


    appendDetailRow(
        evidencePanel,
        "Source",
        "GitHub commit"
    );


    appendDetailRow(
        evidencePanel,
        "Human review",
        getDecisionStatus(
            commitSignalId(
                match
            )
        )
    );


    appendDetailRow(
        evidencePanel,
        "Source URL",
        commit.url
    );


    grid.appendChild(
        evidencePanel
    );


    const dependencyPanel =
        createDetailPanel(
            "Dependency"
        );


    appendDetailRow(
        dependencyPanel,
        "Package",
        dependency.name
    );


    appendDetailRow(
        dependencyPanel,
        "Installed version",
        dependency.installed_version
    );


    appendDetailRow(
        dependencyPanel,
        "Ecosystem",
        dependency.ecosystem
    );


    appendDetailRow(
        dependencyPanel,
        "Repository",
        dependency.github_repo
    );


    const signalPanel =
        createDetailPanel(
            "Collector analysis"
        );


    appendDetailRow(
        signalPanel,
        "Classification",
        signal.classification
    );


    appendDetailRow(
        signalPanel,
        "Heuristic score",
        signal.score
    );


    appendDetailRow(
        signalPanel,
        "Matched keywords",
        (
            signal.matched_keywords
            || []
        ).join(", ")
    );


    appendDetailRow(
        signalPanel,
        "Referenced CVEs",
        (
            signal.cve_ids
            || []
        ).join(", ")
    );


    grid.appendChild(
        dependencyPanel
    );


    grid.appendChild(
        signalPanel
    );


    const files =
        commit.files
        || [];


    if (
        files.length > 0
    ) {

        const filesPanel =
            createDetailPanel(
                "Changed files",
                true
            );


        files.forEach(
            (file) => {

                filesPanel.appendChild(
                    buildFileCard(
                        file
                    )
                );
            }
        );


        grid.appendChild(
            filesPanel
        );
    }


    const jsonPanel =
        createDetailPanel(
            "Complete finding JSON",
            true
        );


    jsonPanel.appendChild(
        createDiffContainer(
            JSON.stringify(
                match,
                null,
                2
            )
        )
    );


    grid.appendChild(
        jsonPanel
    );


    details.appendChild(
        grid
    );


    return details;
}


/* ============================================================
   SILENT-WINDOW
   ============================================================ */

function renderSilentWindowCandidates(
    matches
) {

    const list =
        $("silentList");

    list.innerHTML =
        "";


    setText(
        $("silentCount"),
        matches.length
    );


    if (
        matches.length === 0
    ) {

        show(
            $("silentEmpty")
        );

        return;
    }


    hide(
        $("silentEmpty")
    );


    matches.forEach(
        (match) => {

            list.appendChild(
                buildSilentCard(
                    match
                )
            );
        }
    );
}


function buildSilentCard(
    match
) {

    const card =
        createSignalCard();

    card.dataset.type =
        "silent";


    const signalId =
        silentSignalId(
            match
        );


    card.dataset.signalId =
        signalId;


    const securitySignal =
        match.security_signal
        || {};

    const aiAnalysis =
        match.ai_analysis
        || {};


    const header =
        createCardHeader();


    const main =
        createSignalMain();


    const topline =
        document.createElement(
            "div"
        );

    topline.className =
        "signal-topline";


    topline.appendChild(
        createTextElement(
            "span",
            "Potential silent-window vulnerability",
            "signal-title"
        )
    );


    topline.appendChild(
        buildEvidenceBadge(
            "AI-inferred",
            "ai_inferred"
        )
    );


    const aiConfidence =
        createAiConfidenceBadge(
            aiAnalysis
        );


    if (aiConfidence) {

        topline.appendChild(
            aiConfidence
        );
    }


    main.appendChild(
        topline
    );


    main.appendChild(
        createTextElement(
            "div",
            match.repository
            || "Unknown repository",
            "signal-subtitle"
        )
    );


    const meta =
        document.createElement(
            "div"
        );

    meta.className =
        "signal-meta";


    addMeta(
        meta,
        `Heuristic ${
            securitySignal.score
            || 0
        }`
    );


    addMeta(
        meta,
        "No explicit CVE reference"
    );


    if (
        match.commit_sha
    ) {

        addMeta(
            meta,
            match.commit_sha.slice(
                0,
                8
            )
        );
    }


    main.appendChild(
        meta
    );


    if (
        aiAnalysis.reasoning
    ) {

        const reasoning =
            document.createElement(
                "div"
            );

        reasoning.className =
            "ai-reasoning-preview";


        reasoning.appendChild(
            createTextElement(
                "span",
                "Flagged because:",
                "ai-reasoning-label"
            )
        );


        reasoning.appendChild(
            document.createTextNode(
                " "
                + aiAnalysis.reasoning
            )
        );


        main.appendChild(
            reasoning
        );

    } else {

        main.appendChild(
            createTextElement(
                "div",
                "AI analysis pending.",
                "ai-pending-preview"
            )
        );
    }


    const details =
        buildSilentDetails(
            match
        );


    const actions =
        createSignalActions();


    actions.appendChild(
        buildReviewControls(
            signalId
        )
    );


    const sourceButton =
        buildSourceButton(
            match.commit_url
        );


    if (sourceButton) {

        actions.appendChild(
            sourceButton
        );
    }


    actions.appendChild(
        createExpandButton(
            details
        )
    );


    header.appendChild(
        main
    );


    header.appendChild(
        actions
    );


    card.appendChild(
        header
    );


    card.appendChild(
        details
    );


    card.dataset.searchText =
        JSON.stringify(
            match
        ).toLowerCase();


    applyCardStatus(
        card
    );


    return card;
}


function buildSilentDetails(
    match
) {

    const details =
        createDetailsContainer();


    const grid =
        document.createElement(
            "div"
        );

    grid.className =
        "detail-grid";


    const aiAnalysis =
        match.ai_analysis
        || {};


    const securitySignal =
        match.security_signal
        || {};


    /* --------------------------------------------------------
       AI REASONING
       -------------------------------------------------------- */

    const aiPanel =
        createDetailPanel(
            "What did the AI find?",
            true
        );


    if (
        aiAnalysis.reasoning
    ) {

        aiPanel.appendChild(
            createTextElement(
                "div",
                aiAnalysis.reasoning,
                "ai-reasoning-full"
            )
        );

    } else {

        aiPanel.appendChild(
            createTextElement(
                "div",
                "AI analysis has not been completed yet.",
                "ai-pending-preview"
            )
        );
    }


    grid.appendChild(
        aiPanel
    );


    /* --------------------------------------------------------
       CONFIDENCE
       -------------------------------------------------------- */

    const confidencePanel =
        createDetailPanel(
            "Can I trust why it was flagged?"
        );


    if (
        typeof aiAnalysis.confidence
        === "number"
    ) {

        const percentage =
            Math.round(
                aiAnalysis.confidence
                * 100
            );


        appendDetailRow(
            confidencePanel,
            "AI confidence",
            `${percentage}%`
        );


        appendDetailRow(
            confidencePanel,
            "Confidence type",
            "AI-inferred"
        );


        appendDetailRow(
            confidencePanel,
            "Interpretation",
            "Candidate for investigation, "
            + "not proof of a vulnerability."
        );

    } else {

        appendDetailRow(
            confidencePanel,
            "AI confidence",
            "Pending"
        );


        appendDetailRow(
            confidencePanel,
            "Confidence type",
            "Not yet available"
        );
    }


    grid.appendChild(
        confidencePanel
    );


    /* --------------------------------------------------------
       VERIFICATION
       -------------------------------------------------------- */

    const verifyPanel =
        createDetailPanel(
            "Verify the evidence",
            true
        );


    appendDetailRow(
        verifyPanel,
        "Repository",
        match.repository
    );


    appendDetailRow(
        verifyPanel,
        "Commit SHA",
        match.commit_sha
    );


    appendDetailRow(
        verifyPanel,
        "Commit URL",
        match.commit_url
    );


    appendDetailRow(
        verifyPanel,
        "Explicit CVEs",
        (
            match.explicit_cve_ids
            || []
        ).join(", ")
        || "None"
    );


    verifyPanel.appendChild(
        createTextElement(
            "div",
            "The commit itself is the source evidence. "
            + "A reviewer can open GitHub and independently "
            + "inspect the commit and changed files.",
            "verification-note"
        )
    );


    const sourceButton =
        buildSourceButton(
            match.commit_url
        );


    if (sourceButton) {

        verifyPanel.appendChild(
            sourceButton
        );
    }


    grid.appendChild(
        verifyPanel
    );


    /* --------------------------------------------------------
       COLLECTOR REASONING
       -------------------------------------------------------- */

    const collectorPanel =
        createDetailPanel(
            "Why the collector selected it"
        );


    appendDetailRow(
        collectorPanel,
        "Heuristic score",
        securitySignal.score
    );


    appendDetailRow(
        collectorPanel,
        "Matched keywords",
        (
            securitySignal
                .matched_keywords
            || []
        ).join(", ")
    );


    appendDetailRow(
        collectorPanel,
        "Collector reasoning",
        (
            match.collector_analysis
            &&
            match.collector_analysis
                .reasoning
        )
        || match.why_flagged
    );


    grid.appendChild(
        collectorPanel
    );


    /* --------------------------------------------------------
       COMMIT
       -------------------------------------------------------- */

    const commitPanel =
        createDetailPanel(
            "Upstream commit"
        );


    appendDetailRow(
        commitPanel,
        "Message",
        match.commit_message
    );


    appendDetailRow(
        commitPanel,
        "Date",
        match.committer_date
    );


    appendDetailRow(
        commitPanel,
        "SHA",
        match.commit_sha
    );


    grid.appendChild(
        commitPanel
    );


    /* --------------------------------------------------------
       COMPLETE JSON
       -------------------------------------------------------- */

    const jsonPanel =
        createDetailPanel(
            "Complete finding JSON",
            true
        );


    jsonPanel.appendChild(
        createDiffContainer(
            JSON.stringify(
                match,
                null,
                2
            )
        )
    );


    grid.appendChild(
        jsonPanel
    );


    details.appendChild(
        grid
    );


    return details;
}


/* ============================================================
   FILES AND DIFF
   ============================================================ */

function buildFileCard(
    file
) {

    const wrapper =
        document.createElement(
            "div"
        );

    wrapper.className =
        "file-card";


    const header =
        document.createElement(
            "div"
        );

    header.className =
        "file-header";


    header.appendChild(
        createTextElement(
            "div",
            file.filename
            || "Unknown file",
            "file-name"
        )
    );


    header.appendChild(
        createTextElement(
            "div",
            `+${file.additions || 0} `
            + `-${file.deletions || 0}`,
            "file-stats"
        )
    );


    wrapper.appendChild(
        header
    );


    if (
        file.patch
    ) {

        wrapper.appendChild(
            createDiffContainer(
                file.patch
            )
        );
    }


    return wrapper;
}


function createDiffContainer(
    text
) {

    const container =
        document.createElement(
            "div"
        );

    container.className =
        "diff-container";


    const pre =
        document.createElement(
            "pre"
        );

    pre.className =
        "diff";


    /*
     * textContent is used deliberately.
     *
     * It prevents JSON and diffs from being
     * interpreted as HTML.
     */

    pre.textContent =
        text || "";


    container.appendChild(
        pre
    );


    return container;
}


/* ============================================================
   COMMON UI
   ============================================================ */

function createSignalCard() {

    const card =
        document.createElement(
            "article"
        );

    card.className =
        "signal-card";

    return card;
}


function createCardHeader() {

    const header =
        document.createElement(
            "div"
        );

    header.className =
        "signal-card-header";

    return header;
}


function createSignalMain() {

    const main =
        document.createElement(
            "div"
        );

    main.className =
        "signal-main";

    return main;
}


function createSignalActions() {

    const actions =
        document.createElement(
            "div"
        );

    actions.className =
        "signal-actions";

    return actions;
}


function createDetailsContainer() {

    const details =
        document.createElement(
            "div"
        );

    details.className =
        "signal-details hidden";

    return details;
}


function createExpandButton(
    details
) {

    const button =
        document.createElement(
            "button"
        );

    button.type =
        "button";

    button.className =
        "expand-button";

    button.textContent =
        "View details";


    button.addEventListener(
        "click",
        () => {

            const isOpen =
                details.classList.contains(
                    "hidden"
                );


            if (isOpen) {

                show(
                    details
                );

                button.textContent =
                    "Hide details";

            } else {

                hide(
                    details
                );

                button.textContent =
                    "View details";
            }
        }
    );


    return button;
}


function createDetailPanel(
    title,
    fullWidth = false
) {

    const panel =
        document.createElement(
            "div"
        );

    panel.className =
        fullWidth
            ? "detail-panel full-width"
            : "detail-panel";


    panel.appendChild(
        createTextElement(
            "h4",
            title
        )
    );


    return panel;
}


function appendDetailRow(
    panel,
    key,
    value
) {

    const row =
        document.createElement(
            "div"
        );

    row.className =
        "detail-row";


    row.appendChild(
        createTextElement(
            "div",
            key,
            "detail-key"
        )
    );


    row.appendChild(
        createTextElement(
            "div",
            value,
            "detail-value"
        )
    );


    panel.appendChild(
        row
    );
}


function addMeta(
    container,
    value
) {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return;
    }


    container.appendChild(
        createTextElement(
            "span",
            value,
            "meta-item"
        )
    );
}


/* ============================================================
   CARD STATUS
   ============================================================ */

function applyCardStatus(
    card
) {

    const signalId =
        card.dataset.signalId;


    const status =
        getDecisionStatus(
            signalId
        );


    card.classList.remove(
        "card-accepted",
        "card-rejected",
        "card-pending"
    );


    card.classList.add(
        `card-${status}`
    );
}


function updateAllCardStatuses() {

    const cards =
        document.querySelectorAll(
            ".signal-card"
        );


    cards.forEach(
        (card) => {

            applyCardStatus(
                card
            );


            const actions =
                card.querySelector(
                    ".signal-actions"
                );


            const oldControls =
                card.querySelector(
                    ".review-controls"
                );


            if (
                !actions ||
                !oldControls
            ) {

                return;
            }


            const signalId =
                card.dataset.signalId;


            const expandButton =
                actions.querySelector(
                    ".expand-button"
                );


            const sourceButton =
                actions.querySelector(
                    ".source-button"
                );


            oldControls.remove();


            const newControls =
                buildReviewControls(
                    signalId
                );


            let insertBeforeElement =
                expandButton;


            if (
                !insertBeforeElement
            ) {

                insertBeforeElement =
                    sourceButton;
            }


            if (
                insertBeforeElement
            ) {

                actions.insertBefore(
                    newControls,
                    insertBeforeElement
                );

            } else {

                actions.appendChild(
                    newControls
                );
            }
        }
    );


    applyFilters();
}


/* ============================================================
   FILTERING
   ============================================================ */

function applyFilters() {

    const search =
        (
            $("searchInput")
                .value
            || ""
        )
        .trim()
        .toLowerCase();


    const signalFilter =
        $("signalFilter")
            .value;


    const reviewFilter =
        $("reviewFilter")
            .value;


    const allCards =
        document.querySelectorAll(
            ".signal-card"
        );


    allCards.forEach(
        (card) => {

            const type =
                card.dataset.type;


            const signalId =
                card.dataset.signalId;


            const reviewStatus =
                getDecisionStatus(
                    signalId
                );


            const matchesType =
                signalFilter
                === "all"
                ||
                signalFilter
                === type;


            const matchesReview =
                reviewFilter
                === "all"
                ||
                reviewFilter
                === reviewStatus;


            const searchText =
                card.dataset.searchText
                || "";


            const matchesSearch =
                !search
                ||
                searchText.includes(
                    search
                );


            if (
                matchesType
                &&
                matchesReview
                &&
                matchesSearch
            ) {

                show(card);

            } else {

                hide(card);
            }
        }
    );
}


/* ============================================================
   EVENT HANDLERS
   ============================================================ */

$("refreshButton")
    .addEventListener(
        "click",
        loadDashboard
    );


$("collectButton")
    .addEventListener(
        "click",
        collectLatest
    );


$("errorRetryButton")
    .addEventListener(
        "click",
        loadDashboard
    );


$("searchInput")
    .addEventListener(
        "input",
        applyFilters
    );


$("signalFilter")
    .addEventListener(
        "change",
        applyFilters
    );


$("reviewFilter")
    .addEventListener(
        "change",
        applyFilters
    );


/* ============================================================
   START
   ============================================================ */

loadDashboard();

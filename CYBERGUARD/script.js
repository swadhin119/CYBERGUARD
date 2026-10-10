/* =========================
   CYBERGUARD
   STEP 2
   URL PHISHING DETECTION
========================= */


/* =========================
   OPEN TOOL
========================= */

function openTool(type) {

    const modal =
        document.getElementById("toolModal");

    const content =
        document.getElementById("toolContent");

    modal.style.display = "flex";


    /* =========================
       URL TOOL
    ========================= */

    if (type === "url") {

        content.innerHTML = `

            <h2>🔗 URL Phishing Detection</h2>

            <p>
                Enter a website URL to check
                for common phishing indicators.
            </p>

            <div class="input-group">

                <input
                    type="text"
                    id="urlInput"
                    placeholder="https://example.com"
                >

                <button
                    class="analyze-btn"
                    onclick="analyzeURL()">

                    Analyze URL

                </button>

            </div>

            <div id="urlResult"></div>

        `;

        return;
    }


    /* =========================
       EMAIL TOOL
    ========================= */

    if (type === "email") {

        content.innerHTML = `

            <h2>✉️ Email Phishing Analysis</h2>

            <p>
                Email analysis module will be
                activated in Step 3.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 3

            </div>

        `;

        return;
    }


    /* =========================
       QR TOOL
    ========================= */

    if (type === "qr") {

        content.innerHTML = `

            <h2>▦ QR Code Scanner</h2>

            <p>
                QR analysis module will be
                activated in Step 4.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 4

            </div>

        `;

        return;
    }


    /* =========================
       SOCIAL TOOL
    ========================= */

    if (type === "social") {

        content.innerHTML = `

            <h2>👥 Social Media Impersonation</h2>

            <p>
                Social media analysis will be
                activated in Step 5.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 5

            </div>

        `;

        return;
    }


    /* =========================
       IMAGE TOOL
    ========================= */

    if (type === "image") {

        content.innerHTML = `

            <h2>🖼️ Image Analysis</h2>

            <p>
                Image analysis will be
                activated in Step 6.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 6

            </div>

        `;

        return;
    }


    /* =========================
       VIDEO TOOL
    ========================= */

    if (type === "video") {

        content.innerHTML = `

            <h2>🎥 Video Analysis</h2>

            <p>
                Video analysis will be
                activated in Step 7.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 7

            </div>

        `;

        return;
    }

}


/* =========================
   URL ANALYZER
========================= */

function analyzeURL() {

    const input =
        document.getElementById("urlInput");

    const result =
        document.getElementById("urlResult");


    let value =
        input.value.trim();


    if (!value) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>⚠️ URL Required</h3>

                <p>
                    Please enter a URL first.
                </p>

            </div>

        `;

        return;
    }


    /* =========================
       ADD PROTOCOL IF MISSING
    ========================= */

    let urlValue = value;

    if (
        !urlValue.startsWith("http://") &&
        !urlValue.startsWith("https://")
    ) {

        urlValue =
            "https://" + urlValue;

    }


    let url;

    try {

        url = new URL(urlValue);

    } catch (error) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>❌ Invalid URL</h3>

                <p>
                    Please enter a valid website URL.
                </p>

            </div>

        `;

        return;
    }


    /* =========================
       RISK VARIABLES
    ========================= */

    let score = 0;

    let warnings = [];


    /* =========================
       HTTPS CHECK
    ========================= */

    if (url.protocol !== "https:") {

        score += 20;

        warnings.push(
            "Website is not using HTTPS."
        );

    }


    /* =========================
       IP ADDRESS CHECK
    ========================= */

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;


    if (
        ipPattern.test(url.hostname)
    ) {

        score += 25;

        warnings.push(
            "URL uses an IP address instead of a domain name."
        );

    }


    /* =========================
       SUSPICIOUS KEYWORDS
    ========================= */

    const suspiciousKeywords = [

        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "bank",
        "payment",
        "confirm",
        "signin",
        "wallet",
        "recover"

    ];


    const lowerURL =
        urlValue.toLowerCase();


    let foundKeywords = [];


    suspiciousKeywords.forEach(
        function(keyword) {

            if (
                lowerURL.includes(keyword)
            ) {

                foundKeywords.push(
                    keyword
                );

            }

        }
    );


    if (
        foundKeywords.length > 0
    ) {

        score +=
            Math.min(
                foundKeywords.length * 5,
                25
            );

        warnings.push(
            "Suspicious keywords detected: " +
            foundKeywords.join(", ")
        );

    }


    /* =========================
       @ SYMBOL CHECK
    ========================= */

    if (
        urlValue.includes("@")
    ) {

        score += 20;

        warnings.push(
            "URL contains an @ symbol."
        );

    }


    /* =========================
       LONG URL CHECK
    ========================= */

    if (
        urlValue.length > 100
    ) {

        score += 10;

        warnings.push(
            "URL is unusually long."
        );

    }


    /* =========================
       URL SHORTENER CHECK
    ========================= */

    const shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "shorturl.at"

    ];


    const hostname =
        url.hostname.toLowerCase();


    if (
        shorteners.includes(hostname)
    ) {

        score += 20;

        warnings.push(
            "URL uses a known URL shortening service."
        );

    }


    /* =========================
       LIMIT SCORE
    ========================= */

    score =
        Math.min(score, 100);


    /* =========================
       RISK LEVEL
    ========================= */

    let level;
    let recommendation;
    let resultClass;


    if (score >= 70) {

        level = "HIGH RISK";

        resultClass = "danger";

        recommendation =
            "Do not open this URL unless you can verify that it is legitimate.";

    }

    else if (score >= 40) {

        level = "MEDIUM RISK";

        resultClass = "warning";

        recommendation =
            "Be careful. Verify the website domain before continuing.";

    }

    else {

        level = "LOW RISK";

        resultClass = "safe";

        recommendation =
            "No major phishing indicators were detected by this basic analysis.";

    }


    /* =========================
       WARNING LIST
    ========================= */

    let warningHTML = "";


    if (
        warnings.length === 0
    ) {

        warningHTML = `

            <p class="no-warning">

                ✓ No suspicious indicators found.

            </p>

        `;

    }

    else {

        warningHTML = `

            <ul class="warning-list">

                ${warnings.map(
                    function(item) {

                        return `
                            <li>
                                ⚠️ ${escapeHTML(item)}
                            </li>
                        `;

                    }
                ).join("")}

            </ul>

        `;

    }


    /* =========================
       RESULT
    ========================= */

    result.innerHTML = `

        <div class="result-box ${resultClass}">

            <div class="risk-header">

                <div>

                    <span class="result-label">
                        Risk Level
                    </span>

                    <h3>
                        ${level}
                    </h3>

                </div>

                <div class="risk-score">

                    ${score}

                    <small>/100</small>

                </div>

            </div>


            <div class="score-bar">

                <div
                    class="score-fill"
                    style="width:${score}%">
                </div>

            </div>


            <div class="analysis-details">

                <p>
                    <strong>Domain:</strong>
                    ${escapeHTML(url.hostname)}
                </p>

                <p>
                    <strong>Protocol:</strong>
                    ${url.protocol.replace(":", "").toUpperCase()}
                </p>

            </div>


            <div class="warnings">

                <h4>
                    Security Indicators
                </h4>

                ${warningHTML}

            </div>


            <div class="recommendation">

                <strong>
                    Recommendation
                </strong>

                <p>
                    ${recommendation}
                </p>

            </div>

        </div>

    `;

}


/* =========================
   ESCAPE HTML
========================= */

function escapeHTML(text) {

    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


/* =========================
   CLOSE TOOL
========================= */

function closeTool() {

    document.getElementById(
        "toolModal"
    ).style.display = "none";

}


/* =========================
   GUIDELINES
========================= */

function openGuidelines() {

    document.getElementById(
        "guidelinesModal"
    ).style.display = "flex";

}


function closeGuidelines() {

    document.getElementById(
        "guidelinesModal"
    ).style.display = "none";

}


/* =========================
   DASHBOARD
========================= */

function openDashboard() {

    document.getElementById(
        "dashboardModal"
    ).style.display = "flex";

}


function closeDashboard() {

    document.getElementById(
        "dashboardModal"
    ).style.display = "none";

}


/* =========================
   CLOSE MODAL ON BACKDROP
========================= */

window.addEventListener(
    "click",
    function(event) {

        const toolModal =
            document.getElementById(
                "toolModal"
            );

        const guidelinesModal =
            document.getElementById(
                "guidelinesModal"
            );

        const dashboardModal =
            document.getElementById(
                "dashboardModal"
            );


        if (
            event.target === toolModal
        ) {

            closeTool();

        }


        if (
            event.target ===
            guidelinesModal
        ) {

            closeGuidelines();

        }


        if (
            event.target ===
            dashboardModal
        ) {

            closeDashboard();

        }

    }
);
/* =========================
   CYBERGUARD
   STEP 3
   EMAIL PHISHING DETECTION
========================= */


/* =========================
   OPEN TOOL
========================= */

function openTool(type) {

    const modal = document.getElementById("toolModal");
    const content = document.getElementById("toolContent");

    modal.style.display = "flex";


    /* =========================
       URL
    ========================= */

    if (type === "url") {

        content.innerHTML = `

            <h2>🔗 URL Phishing Detection</h2>

            <p>
                Enter a website URL to check
                for common phishing indicators.
            </p>

            <div class="input-group">

                <input
                    type="text"
                    id="urlInput"
                    placeholder="https://example.com"
                >

                <button
                    class="analyze-btn"
                    onclick="analyzeURL()">

                    Analyze URL

                </button>

            </div>

            <div id="urlResult"></div>

        `;

        return;
    }


    /* =========================
       EMAIL
    ========================= */

    if (type === "email") {

        content.innerHTML = `

            <h2>✉️ Email Phishing Analysis</h2>

            <p>
                Analyze an email for common
                phishing and social-engineering indicators.
            </p>

            <div class="email-form">

                <label>Sender Email</label>

                <input
                    type="email"
                    id="emailSender"
                    placeholder="sender@example.com"
                >


                <label>Subject</label>

                <input
                    type="text"
                    id="emailSubject"
                    placeholder="Your account requires verification"
                >


                <label>Email Content</label>

                <textarea
                    id="emailBody"
                    placeholder="Paste the email content here..."
                ></textarea>


                <button
                    class="analyze-btn email-analyze-btn"
                    onclick="analyzeEmail()">

                    Analyze Email

                </button>

            </div>

            <div id="emailResult"></div>

        `;

        return;
    }


    /* =========================
       QR
    ========================= */

    if (type === "qr") {

        content.innerHTML = `

            <h2>▦ QR Code Scanner</h2>

            <p>
                QR analysis module will be
                activated in Step 4.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 4

            </div>

        `;

        return;
    }


    /* =========================
       SOCIAL
    ========================= */

    if (type === "social") {

        content.innerHTML = `

            <h2>👥 Social Media Impersonation</h2>

            <p>
                Social media analysis will be
                activated in Step 5.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 5

            </div>

        `;

        return;
    }


    /* =========================
       IMAGE
    ========================= */

    if (type === "image") {

        content.innerHTML = `

            <h2>🖼️ Image Analysis</h2>

            <p>
                Image analysis will be
                activated in Step 6.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 6

            </div>

        `;

        return;
    }


    /* =========================
       VIDEO
    ========================= */

    if (type === "video") {

        content.innerHTML = `

            <h2>🎥 Video Analysis</h2>

            <p>
                Video analysis will be
                activated in Step 7.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 7

            </div>

        `;

        return;
    }

}


/* =========================
   URL ANALYZER
========================= */

function analyzeURL() {

    const input = document.getElementById("urlInput");
    const result = document.getElementById("urlResult");

    let value = input.value.trim();

    if (!value) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>⚠️ URL Required</h3>

                <p>
                    Please enter a URL first.
                </p>

            </div>

        `;

        return;
    }


    let urlValue = value;

    if (
        !urlValue.startsWith("http://") &&
        !urlValue.startsWith("https://")
    ) {

        urlValue = "https://" + urlValue;

    }


    let url;

    try {

        url = new URL(urlValue);

    } catch (error) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>❌ Invalid URL</h3>

                <p>
                    Please enter a valid website URL.
                </p>

            </div>

        `;

        return;
    }


    let score = 0;
    let warnings = [];


    if (url.protocol !== "https:") {

        score += 20;

        warnings.push(
            "Website is not using HTTPS."
        );

    }


    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;


    if (ipPattern.test(url.hostname)) {

        score += 25;

        warnings.push(
            "URL uses an IP address instead of a domain name."
        );

    }


    const suspiciousKeywords = [

        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "bank",
        "payment",
        "confirm",
        "signin",
        "wallet",
        "recover"

    ];


    const lowerURL =
        urlValue.toLowerCase();

    let foundKeywords = [];


    suspiciousKeywords.forEach(
        function(keyword) {

            if (lowerURL.includes(keyword)) {

                foundKeywords.push(keyword);

            }

        }
    );


    if (foundKeywords.length > 0) {

        score += Math.min(
            foundKeywords.length * 5,
            25
        );

        warnings.push(
            "Suspicious keywords detected: " +
            foundKeywords.join(", ")
        );

    }


    if (urlValue.includes("@")) {

        score += 20;

        warnings.push(
            "URL contains an @ symbol."
        );

    }


    if (urlValue.length > 100) {

        score += 10;

        warnings.push(
            "URL is unusually long."
        );

    }


    const shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "shorturl.at"

    ];


    if (
        shorteners.includes(
            url.hostname.toLowerCase()
        )
    ) {

        score += 20;

        warnings.push(
            "URL uses a known URL shortening service."
        );

    }


    score = Math.min(score, 100);


    let level;
    let recommendation;
    let resultClass;


    if (score >= 70) {

        level = "HIGH RISK";

        resultClass = "danger";

        recommendation =
            "Do not open this URL unless you can verify that it is legitimate.";

    }

    else if (score >= 40) {

        level = "MEDIUM RISK";

        resultClass = "warning";

        recommendation =
            "Be careful. Verify the website domain before continuing.";

    }

    else {

        level = "LOW RISK";

        resultClass = "safe";

        recommendation =
            "No major phishing indicators were detected by this basic analysis.";

    }


    let warningHTML = "";


    if (warnings.length === 0) {

        warningHTML = `

            <p class="no-warning">
                ✓ No suspicious indicators found.
            </p>

        `;

    }

    else {

        warningHTML = `

            <ul class="warning-list">

                ${warnings.map(
                    function(item) {

                        return `
                            <li>
                                ⚠️ ${escapeHTML(item)}
                            </li>
                        `;

                    }
                ).join("")}

            </ul>

        `;

    }


    result.innerHTML = `

        <div class="result-box ${resultClass}">

            <div class="risk-header">

                <div>

                    <span class="result-label">
                        Risk Level
                    </span>

                    <h3>
                        ${level}
                    </h3>

                </div>

                <div class="risk-score">

                    ${score}
                    <small>/100</small>

                </div>

            </div>


            <div class="score-bar">

                <div
                    class="score-fill"
                    style="width:${score}%">
                </div>

            </div>


            <div class="analysis-details">

                <p>
                    <strong>Domain:</strong>
                    ${escapeHTML(url.hostname)}
                </p>

                <p>
                    <strong>Protocol:</strong>
                    ${url.protocol
                        .replace(":", "")
                        .toUpperCase()}
                </p>

            </div>


            <div class="warnings">

                <h4>
                    Security Indicators
                </h4>

                ${warningHTML}

            </div>


            <div class="recommendation">

                <strong>
                    Recommendation
                </strong>

                <p>
                    ${recommendation}
                </p>

            </div>

        </div>

    `;

}


/* =========================
   EMAIL ANALYZER
========================= */

function analyzeEmail() {

    const sender =
        document.getElementById("emailSender")
        .value.trim();

    const subject =
        document.getElementById("emailSubject")
        .value.trim();

    const body =
        document.getElementById("emailBody")
        .value.trim();

    const result =
        document.getElementById("emailResult");


    if (!sender && !subject && !body) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>⚠️ Email Required</h3>

                <p>
                    Please enter email information
                    before starting the analysis.
                </p>

            </div>

        `;

        return;
    }


    let score = 0;

    let warnings = [];


    const fullText =
        (
            sender +
            " " +
            subject +
            " " +
            body
        ).toLowerCase();


    /* =========================
       URGENCY
    ========================= */

    const urgencyWords = [

        "urgent",
        "immediately",
        "action required",
        "act now",
        "within 24 hours",
        "account will be closed",
        "final warning",
        "last warning",
        "important notice"

    ];


    const foundUrgency =
        findMatches(
            fullText,
            urgencyWords
        );


    if (foundUrgency.length > 0) {

        score += Math.min(
            foundUrgency.length * 7,
            20
        );

        warnings.push(
            "Urgency or pressure language detected: " +
            foundUrgency.join(", ")
        );

    }


    /* =========================
       CREDENTIAL REQUEST
    ========================= */

    const credentialWords = [

        "password",
        "otp",
        "one time password",
        "verification code",
        "pin",
        "login",
        "username",
        "credential",
        "security code",
        "confirm your identity"

    ];


    const foundCredentials =
        findMatches(
            fullText,
            credentialWords
        );


    if (foundCredentials.length > 0) {

        score += Math.min(
            foundCredentials.length * 8,
            25
        );

        warnings.push(
            "Credential or verification information requested: " +
            foundCredentials.join(", ")
        );

    }


    /* =========================
       PAYMENT / BANK
    ========================= */

    const financialWords = [

        "bank",
        "payment",
        "refund",
        "invoice",
        "credit card",
        "debit card",
        "transaction",
        "wallet",
        "upi",
        "money",
        "billing"

    ];


    const foundFinancial =
        findMatches(
            fullText,
            financialWords
        );


    if (foundFinancial.length > 0) {

        score += Math.min(
            foundFinancial.length * 5,
            20
        );

        warnings.push(
            "Financial or payment-related content detected: " +
            foundFinancial.join(", ")
        );

    }


    /* =========================
       SUSPICIOUS PHRASES
    ========================= */

    const phishingPhrases = [

        "click here",
        "verify your account",
        "confirm your account",
        "claim your reward",
        "you have won",
        "your account has been suspended",
        "your account will be suspended",
        "update your account",
        "verify immediately",
        "click the link"

    ];


    const foundPhrases =
        findMatches(
            fullText,
            phishingPhrases
        );


    if (foundPhrases.length > 0) {

        score += Math.min(
            foundPhrases.length * 8,
            25
        );

        warnings.push(
            "Common phishing phrases detected: " +
            foundPhrases.join(", ")
        );

    }


    /* =========================
       LINK DETECTION
    ========================= */

    const linkPattern =
        /(https?:\/\/[^\s]+)/gi;

    const links =
        body.match(linkPattern) || [];


    if (links.length > 0) {

        score += Math.min(
            links.length * 5,
            15
        );

        warnings.push(
            links.length +
            " clickable URL(s) detected in the email."
        );

    }


    /* =========================
       SENDER CHECK
    ========================= */

    if (sender) {

        const freeEmailDomains = [

            "gmail.com",
            "outlook.com",
            "hotmail.com",
            "yahoo.com"

        ];


        const senderParts =
            sender.toLowerCase().split("@");


        if (
            senderParts.length === 2 &&
            freeEmailDomains.includes(
                senderParts[1]
            )
        ) {

            score += 5;

            warnings.push(
                "Sender uses a common free email provider."
            );

        }


        if (
            sender.includes(" ")
        ) {

            score += 10;

            warnings.push(
                "Sender address contains an unusual space."
            );

        }

    }


    /* =========================
       SCORE
    ========================= */

    score =
        Math.min(score, 100);


    let level;
    let recommendation;
    let resultClass;


    if (score >= 70) {

        level = "HIGH RISK";

        resultClass = "danger";

        recommendation =
            "Do not click links or provide passwords, OTPs, payment information, or other sensitive data.";

    }

    else if (score >= 40) {

        level = "MEDIUM RISK";

        resultClass = "warning";

        recommendation =
            "Verify the sender independently and avoid clicking suspicious links.";

    }

    else {

        level = "LOW RISK";

        resultClass = "safe";

        recommendation =
            "No major phishing indicators were detected by this basic analysis.";

    }


    /* =========================
       WARNING HTML
    ========================= */

    let warningHTML = "";


    if (warnings.length === 0) {

        warningHTML = `

            <p class="no-warning">
                ✓ No major suspicious indicators found.
            </p>

        `;

    }

    else {

        warningHTML = `

            <ul class="warning-list">

                ${warnings.map(
                    function(item) {

                        return `
                            <li>
                                ⚠️ ${escapeHTML(item)}
                            </li>
                        `;

                    }
                ).join("")}

            </ul>

        `;

    }


    /* =========================
       RESULT
    ========================= */

    result.innerHTML = `

        <div class="result-box ${resultClass}">

            <div class="risk-header">

                <div>

                    <span class="result-label">
                        Email Risk Level
                    </span>

                    <h3>
                        ${level}
                    </h3>

                </div>

                <div class="risk-score">

                    ${score}
                    <small>/100</small>

                </div>

            </div>


            <div class="score-bar">

                <div
                    class="score-fill"
                    style="width:${score}%">
                </div>

            </div>


            <div class="analysis-details">

                <p>
                    <strong>Sender:</strong>
                    ${escapeHTML(sender || "Not provided")}
                </p>

                <p>
                    <strong>Subject:</strong>
                    ${escapeHTML(subject || "Not provided")}
                </p>

                <p>
                    <strong>Links Found:</strong>
                    ${links.length}
                </p>

            </div>


            <div class="warnings">

                <h4>
                    Security Indicators
                </h4>

                ${warningHTML}

            </div>


            <div class="recommendation">

                <strong>
                    Recommendation
                </strong>

                <p>
                    ${recommendation}
                </p>

            </div>

        </div>

    `;

}


/* =========================
   FIND MATCHES
========================= */

function findMatches(text, words) {

    return words.filter(
        function(word) {

            return text.includes(
                word.toLowerCase()
            );

        }
    );

}


/* =========================
   ESCAPE HTML
========================= */

function escapeHTML(text) {

    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


/* =========================
   CLOSE TOOL
========================= */

function closeTool() {

    document.getElementById(
        "toolModal"
    ).style.display = "none";

}


/* =========================
   GUIDELINES
========================= */

function openGuidelines() {

    document.getElementById(
        "guidelinesModal"
    ).style.display = "flex";

}


function closeGuidelines() {

    document.getElementById(
        "guidelinesModal"
    ).style.display = "none";

}


/* =========================
   DASHBOARD
========================= */

function openDashboard() {

    document.getElementById(
        "dashboardModal"
    ).style.display = "flex";

}


function closeDashboard() {

    document.getElementById(
        "dashboardModal"
    ).style.display = "none";

}


/* =========================
   CLOSE MODAL
========================= */

window.addEventListener(
    "click",
    function(event) {

        const toolModal =
            document.getElementById(
                "toolModal"
            );

        const guidelinesModal =
            document.getElementById(
                "guidelinesModal"
            );

        const dashboardModal =
            document.getElementById(
                "dashboardModal"
            );


        if (
            event.target === toolModal
        ) {

            closeTool();

        }


        if (
            event.target === guidelinesModal
        ) {

            closeGuidelines();

        }


        if (
            event.target === dashboardModal
        ) {

            closeDashboard();

        }

    }
);
/* =========================
   CYBERGUARD
   STEP 4
   QR CODE ANALYSIS
========================= */


/* =========================
   OPEN TOOL
========================= */

function openTool(type) {

    const modal =
        document.getElementById("toolModal");

    const content =
        document.getElementById("toolContent");

    modal.style.display = "flex";


    /* =========================
       URL
    ========================= */

    if (type === "url") {

        content.innerHTML = `

            <h2>🔗 URL Phishing Detection</h2>

            <p>
                Enter a website URL to check
                for common phishing indicators.
            </p>

            <div class="input-group">

                <input
                    type="text"
                    id="urlInput"
                    placeholder="https://example.com"
                >

                <button
                    class="analyze-btn"
                    onclick="analyzeURL()">

                    Analyze URL

                </button>

            </div>

            <div id="urlResult"></div>

        `;

        return;
    }


    /* =========================
       EMAIL
    ========================= */

    if (type === "email") {

        content.innerHTML = `

            <h2>✉️ Email Phishing Analysis</h2>

            <p>
                Analyze an email for common
                phishing indicators.
            </p>

            <div class="email-form">

                <label>Sender Email</label>

                <input
                    type="email"
                    id="emailSender"
                    placeholder="sender@example.com"
                >

                <label>Subject</label>

                <input
                    type="text"
                    id="emailSubject"
                    placeholder="Your account requires verification"
                >

                <label>Email Content</label>

                <textarea
                    id="emailBody"
                    placeholder="Paste the email content here..."
                ></textarea>

                <button
                    class="analyze-btn email-analyze-btn"
                    onclick="analyzeEmail()">

                    Analyze Email

                </button>

            </div>

            <div id="emailResult"></div>

        `;

        return;
    }


    /* =========================
       QR CODE
    ========================= */

    if (type === "qr") {

        content.innerHTML = `

            <h2>▦ QR Code Scanner</h2>

            <p>
                Upload a QR code image to decode
                and analyze its content.
            </p>

            <div class="qr-upload-box">

                <input
                    type="file"
                    id="qrInput"
                    accept="image/*"
                    onchange="scanQR()"
                >

                <label
                    for="qrInput"
                    class="upload-label">

                    📷 Select QR Image

                </label>

            </div>

            <canvas
                id="qrCanvas"
                hidden>
            </canvas>

            <div id="qrResult"></div>

        `;

        return;
    }


    /* =========================
       SOCIAL
    ========================= */

    if (type === "social") {

        content.innerHTML = `

            <h2>👥 Social Media Impersonation</h2>

            <p>
                Social media analysis will be
                activated in Step 5.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 5

            </div>

        `;

        return;
    }


    /* =========================
       IMAGE
    ========================= */

    if (type === "image") {

        content.innerHTML = `

            <h2>🖼️ Image Analysis</h2>

            <p>
                Image analysis will be
                activated in Step 6.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 6

            </div>

        `;

        return;
    }


    /* =========================
       VIDEO
    ========================= */

    if (type === "video") {

        content.innerHTML = `

            <h2>🎥 Video Analysis</h2>

            <p>
                Video analysis will be
                activated in Step 7.
            </p>

            <div class="dashboard-placeholder">

                Coming in Step 7

            </div>

        `;

        return;
    }

}


/* =========================
   URL ANALYZER
========================= */

function analyzeURL() {

    const input =
        document.getElementById("urlInput");

    const result =
        document.getElementById("urlResult");

    let value =
        input.value.trim();


    if (!value) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>⚠️ URL Required</h3>

                <p>
                    Please enter a URL first.
                </p>

            </div>

        `;

        return;
    }


    let urlValue = value;


    if (
        !urlValue.startsWith("http://") &&
        !urlValue.startsWith("https://")
    ) {

        urlValue =
            "https://" + urlValue;

    }


    let url;


    try {

        url =
            new URL(urlValue);

    }

    catch (error) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>❌ Invalid URL</h3>

                <p>
                    Please enter a valid website URL.
                </p>

            </div>

        `;

        return;
    }


    const analysis =
        analyzeURLValue(urlValue);


    displayURLResult(
        result,
        url,
        analysis
    );

}


/* =========================
   COMMON URL ANALYSIS
========================= */

function analyzeURLValue(value) {

    let score = 0;

    let warnings = [];


    let url;


    try {

        url =
            new URL(value);

    }

    catch (error) {

        return {
            score: 100,
            warnings: [
                "Invalid URL."
            ]
        };

    }


    /* HTTPS */

    if (
        url.protocol !== "https:"
    ) {

        score += 20;

        warnings.push(
            "Website is not using HTTPS."
        );

    }


    /* IP ADDRESS */

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;


    if (
        ipPattern.test(
            url.hostname
        )
    ) {

        score += 25;

        warnings.push(
            "URL uses an IP address instead of a domain name."
        );

    }


    /* SUSPICIOUS WORDS */

    const suspiciousKeywords = [

        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "bank",
        "payment",
        "confirm",
        "signin",
        "wallet",
        "recover"

    ];


    const lowerURL =
        value.toLowerCase();


    let foundKeywords = [];


    suspiciousKeywords.forEach(
        function(keyword) {

            if (
                lowerURL.includes(keyword)
            ) {

                foundKeywords.push(
                    keyword
                );

            }

        }
    );


    if (
        foundKeywords.length > 0
    ) {

        score += Math.min(
            foundKeywords.length * 5,
            25
        );

        warnings.push(
            "Suspicious keywords detected: " +
            foundKeywords.join(", ")
        );

    }


    /* @ SYMBOL */

    if (
        value.includes("@")
    ) {

        score += 20;

        warnings.push(
            "URL contains an @ symbol."
        );

    }


    /* LONG URL */

    if (
        value.length > 100
    ) {

        score += 10;

        warnings.push(
            "URL is unusually long."
        );

    }


    /* URL SHORTENER */

    const shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "shorturl.at"

    ];


    if (
        shorteners.includes(
            url.hostname.toLowerCase()
        )
    ) {

        score += 20;

        warnings.push(
            "URL uses a known URL shortening service."
        );

    }


    score =
        Math.min(score, 100);


    return {

        score: score,

        warnings: warnings

    };

}


/* =========================
   DISPLAY URL RESULT
========================= */

function displayURLResult(
    result,
    url,
    analysis
) {

    let level;
    let resultClass;
    let recommendation;


    if (
        analysis.score >= 70
    ) {

        level = "HIGH RISK";

        resultClass = "danger";

        recommendation =
            "Do not open this URL unless you can verify that it is legitimate.";

    }

    else if (
        analysis.score >= 40
    ) {

        level = "MEDIUM RISK";

        resultClass = "warning";

        recommendation =
            "Be careful. Verify the website domain before continuing.";

    }

    else {

        level = "LOW RISK";

        resultClass = "safe";

        recommendation =
            "No major phishing indicators were detected by this basic analysis.";

    }


    let warningHTML = "";


    if (
        analysis.warnings.length === 0
    ) {

        warningHTML = `

            <p class="no-warning">

                ✓ No suspicious indicators found.

            </p>

        `;

    }

    else {

        warningHTML = `

            <ul class="warning-list">

                ${analysis.warnings.map(
                    function(item) {

                        return `

                            <li>
                                ⚠️
                                ${escapeHTML(item)}
                            </li>

                        `;

                    }
                ).join("")}

            </ul>

        `;

    }


    result.innerHTML = `

        <div class="result-box ${resultClass}">

            <div class="risk-header">

                <div>

                    <span class="result-label">
                        Risk Level
                    </span>

                    <h3>
                        ${level}
                    </h3>

                </div>

                <div class="risk-score">

                    ${analysis.score}

                    <small>/100</small>

                </div>

            </div>


            <div class="score-bar">

                <div
                    class="score-fill"
                    style="width:${analysis.score}%">
                </div>

            </div>


            <div class="analysis-details">

                <p>

                    <strong>Domain:</strong>

                    ${escapeHTML(
                        url.hostname
                    )}

                </p>


                <p>

                    <strong>Protocol:</strong>

                    ${url.protocol
                        .replace(":", "")
                        .toUpperCase()}

                </p>

            </div>


            <div class="warnings">

                <h4>
                    Security Indicators
                </h4>

                ${warningHTML}

            </div>


            <div class="recommendation">

                <strong>
                    Recommendation
                </strong>

                <p>
                    ${recommendation}
                </p>

            </div>

        </div>

    `;

}


/* =========================
   QR SCANNER
========================= */

function scanQR() {

    const input =
        document.getElementById("qrInput");

    const result =
        document.getElementById("qrResult");

    const canvas =
        document.getElementById("qrCanvas");

    const context =
        canvas.getContext("2d");


    if (!input.files.length) {

        return;

    }


    const file =
        input.files[0];


    if (!file.type.startsWith("image/")) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>
                    ❌ Invalid File
                </h3>

                <p>
                    Please select an image file.
                </p>

            </div>

        `;

        return;

    }


    const image =
        new Image();


    image.onload =
        function() {

            canvas.width =
                image.width;

            canvas.height =
                image.height;


            context.drawImage(
                image,
                0,
                0,
                canvas.width,
                canvas.height
            );


            const imageData =
                context.getImageData(
                    0,
                    0,
                    canvas.width,
                    canvas.height
                );


            if (
                typeof jsQR ===
                "undefined"
            ) {

                result.innerHTML = `

                    <div class="result-box danger">

                        <h3>
                            ❌ QR Scanner Error
                        </h3>

                        <p>
                            QR scanning library
                            could not be loaded.
                        </p>

                    </div>

                `;

                return;

            }


            const code =
                jsQR(
                    imageData.data,
                    imageData.width,
                    imageData.height
                );


            if (!code) {

                result.innerHTML = `

                    <div class="result-box warning">

                        <h3>
                            ⚠️ QR Code Not Detected
                        </h3>

                        <p>
                            Make sure the image contains
                            a clear and visible QR code.
                        </p>

                    </div>

                `;

                return;

            }


            analyzeQRData(
                code.data
            );

        };


    image.onerror =
        function() {

            result.innerHTML = `

                <div class="result-box danger">

                    <h3>
                        ❌ Image Error
                    </h3>

                    <p>
                        Could not read the selected image.
                    </p>

                </div>

            `;

        };


    image.src =
        URL.createObjectURL(file);

}


/* =========================
   ANALYZE QR DATA
========================= */

function analyzeQRData(data) {

    const result =
        document.getElementById("qrResult");


    const cleanData =
        data.trim();


    let isURL = false;

    let url = null;


    try {

        let testURL =
            cleanData;


        if (
            testURL.startsWith("www.")
        ) {

            testURL =
                "https://" + testURL;

        }


        url =
            new URL(testURL);

        isURL = true;

    }

    catch (error) {

        isURL = false;

    }


    /* =========================
       NON URL QR
    ========================= */

    if (!isURL) {

        result.innerHTML = `

            <div class="result-box safe">

                <div class="risk-header">

                    <div>

                        <span class="result-label">
                            QR Content
                        </span>

                        <h3>
                            DATA DETECTED
                        </h3>

                    </div>

                    <div class="risk-score">
                        —
                    </div>

                </div>


                <div class="analysis-details">

                    <p>
                        <strong>Type:</strong>
                        Text / Data
                    </p>

                    <p>
                        <strong>Content:</strong>
                        ${escapeHTML(cleanData)}
                    </p>

                </div>


                <div class="recommendation">

                    <strong>
                        Recommendation
                    </strong>

                    <p>
                        QR content was decoded successfully.
                        Verify the information before using it.
                    </p>

                </div>

            </div>

        `;

        return;

    }


    /* =========================
       URL QR
    ========================= */

    const analysis =
        analyzeURLValue(
            url.href
        );


    let level;
    let resultClass;
    let recommendation;


    if (
        analysis.score >= 70
    ) {

        level = "HIGH RISK";

        resultClass = "danger";

        recommendation =
            "Do not open this QR destination. Verify the URL independently.";

    }

    else if (
        analysis.score >= 40
    ) {

        level = "MEDIUM RISK";

        resultClass = "warning";

        recommendation =
            "Verify the destination before opening it.";

    }

    else {

        level = "LOW RISK";

        resultClass = "safe";

        recommendation =
            "No major phishing indicators were detected.";

    }


    let warningHTML = "";


    if (
        analysis.warnings.length === 0
    ) {

        warningHTML = `

            <p class="no-warning">

                ✓ No suspicious indicators found.

            </p>

        `;

    }

    else {

        warningHTML = `

            <ul class="warning-list">

                ${analysis.warnings.map(
                    function(item) {

                        return `

                            <li>
                                ⚠️
                                ${escapeHTML(item)}
                            </li>

                        `;

                    }
                ).join("")}

            </ul>

        `;

    }


    result.innerHTML = `

        <div class="result-box ${resultClass}">

            <div class="risk-header">

                <div>

                    <span class="result-label">
                        QR URL Risk
                    </span>

                    <h3>
                        ${level}
                    </h3>

                </div>


                <div class="risk-score">

                    ${analysis.score}

                    <small>/100</small>

                </div>

            </div>


            <div class="score-bar">

                <div
                    class="score-fill"
                    style="width:${analysis.score}%">
                </div>

            </div>


            <div class="analysis-details">

                <p>

                    <strong>Decoded URL:</strong>

                    ${escapeHTML(url.href)}

                </p>


                <p>

                    <strong>Domain:</strong>

                    ${escapeHTML(
                        url.hostname
                    )}

                </p>

            </div>


            <div class="warnings">

                <h4>
                    Security Indicators
                </h4>

                ${warningHTML}

            </div>


            <div class="recommendation">

                <strong>
                    Recommendation
                </strong>

                <p>
                    ${recommendation}
                </p>

            </div>

        </div>

    `;

}


/* =========================
   EMAIL
========================= */

function analyzeEmail() {

    const sender =
        document.getElementById("emailSender")
        .value.trim();

    const subject =
        document.getElementById("emailSubject")
        .value.trim();

    const body =
        document.getElementById("emailBody")
        .value.trim();

    const result =
        document.getElementById("emailResult");


    if (!sender && !subject && !body) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>
                    ⚠️ Email Required
                </h3>

                <p>
                    Please enter email information.
                </p>

            </div>

        `;

        return;

    }


    let score = 0;

    let warnings = [];


    const fullText =
        (
            sender +
            " " +
            subject +
            " " +
            body
        ).toLowerCase();


    const urgencyWords = [

        "urgent",
        "immediately",
        "action required",
        "act now",
        "within 24 hours",
        "account will be closed",
        "final warning",
        "last warning",
        "important notice"

    ];


    const foundUrgency =
        findMatches(
            fullText,
            urgencyWords
        );


    if (
        foundUrgency.length > 0
    ) {

        score += Math.min(
            foundUrgency.length * 7,
            20
        );

        warnings.push(
            "Urgency or pressure language detected: " +
            foundUrgency.join(", ")
        );

    }


    const credentialWords = [

        "password",
        "otp",
        "one time password",
        "verification code",
        "pin",
        "login",
        "username",
        "credential",
        "security code",
        "confirm your identity"

    ];


    const foundCredentials =
        findMatches(
            fullText,
            credentialWords
        );


    if (
        foundCredentials.length > 0
    ) {

        score += Math.min(
            foundCredentials.length * 8,
            25
        );

        warnings.push(
            "Credential or verification information requested: " +
            foundCredentials.join(", ")
        );

    }


    const financialWords = [

        "bank",
        "payment",
        "refund",
        "invoice",
        "credit card",
        "debit card",
        "transaction",
        "wallet",
        "upi",
        "money",
        "billing"

    ];


    const foundFinancial =
        findMatches(
            fullText,
            financialWords
        );


    if (
        foundFinancial.length > 0
    ) {

        score += Math.min(
            foundFinancial.length * 5,
            20
        );

        warnings.push(
            "Financial or payment-related content detected: " +
            foundFinancial.join(", ")
        );

    }


    const phishingPhrases = [

        "click here",
        "verify your account",
        "confirm your account",
        "claim your reward",
        "you have won",
        "your account has been suspended",
        "your account will be suspended",
        "update your account",
        "verify immediately",
        "click the link"

    ];


    const foundPhrases =
        findMatches(
            fullText,
            phishingPhrases
        );


    if (
        foundPhrases.length > 0
    ) {

        score += Math.min(
            foundPhrases.length * 8,
            25
        );

        warnings.push(
            "Common phishing phrases detected: " +
            foundPhrases.join(", ")
        );

    }


    const linkPattern =
        /(https?:\/\/[^\s]+)/gi;

    const links =
        body.match(linkPattern) || [];


    if (
        links.length > 0
    ) {

        score += Math.min(
            links.length * 5,
            15
        );

        warnings.push(
            links.length +
            " clickable URL(s) detected in the email."
        );

    }


    if (sender) {

        const freeEmailDomains = [

            "gmail.com",
            "outlook.com",
            "hotmail.com",
            "yahoo.com"

        ];


        const senderParts =
            sender.toLowerCase().split("@");


        if (
            senderParts.length === 2 &&
            freeEmailDomains.includes(
                senderParts[1]
            )
        ) {

            score += 5;

            warnings.push(
                "Sender uses a common free email provider."
            );

        }

    }


    score =
        Math.min(score, 100);


    let level;
    let resultClass;
    let recommendation;


    if (score >= 70) {

        level = "HIGH RISK";

        resultClass = "danger";

        recommendation =
            "Do not click links or provide passwords, OTPs, payment information, or other sensitive data.";

    }

    else if (score >= 40) {

        level = "MEDIUM RISK";

        resultClass = "warning";

        recommendation =
            "Verify the sender independently and avoid clicking suspicious links.";

    }

    else {

        level = "LOW RISK";

        resultClass = "safe";

        recommendation =
            "No major phishing indicators were detected by this basic analysis.";

    }


    let warningHTML = "";


    if (warnings.length === 0) {

        warningHTML = `

            <p class="no-warning">
                ✓ No major suspicious indicators found.
            </p>

        `;

    }

    else {

        warningHTML = `

            <ul class="warning-list">

                ${warnings.map(
                    function(item) {

                        return `
                            <li>
                                ⚠️ ${escapeHTML(item)}
                            </li>
                        `;

                    }
                ).join("")}

            </ul>

        `;

    }


    result.innerHTML = `

        <div class="result-box ${resultClass}">

            <div class="risk-header">

                <div>

                    <span class="result-label">
                        Email Risk Level
                    </span>

                    <h3>
                        ${level}
                    </h3>

                </div>

                <div class="risk-score">

                    ${score}
                    <small>/100</small>

                </div>

            </div>


            <div class="score-bar">

                <div
                    class="score-fill"
                    style="width:${score}%">
                </div>

            </div>


            <div class="analysis-details">

                <p>
                    <strong>Sender:</strong>
                    ${escapeHTML(sender || "Not provided")}
                </p>

                <p>
                    <strong>Subject:</strong>
                    ${escapeHTML(subject || "Not provided")}
                </p>

                <p>
                    <strong>Links Found:</strong>
                    ${links.length}
                </p>

            </div>


            <div class="warnings">

                <h4>
                    Security Indicators
                </h4>

                ${warningHTML}

            </div>


            <div class="recommendation">

                <strong>
                    Recommendation
                </strong>

                <p>
                    ${recommendation}
                </p>

            </div>

        </div>

    `;

}


/* =========================
   HELPERS
========================= */

function findMatches(text, words) {

    return words.filter(
        function(word) {

            return text.includes(
                word.toLowerCase()
            );

        }
    );

}


function escapeHTML(text) {

    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


/* =========================
   CLOSE TOOL
========================= */

function closeTool() {

    document.getElementById(
        "toolModal"
    ).style.display = "none";

}


/* =========================
   GUIDELINES
========================= */

function openGuidelines() {

    document.getElementById(
        "guidelinesModal"
    ).style.display = "flex";

}


function closeGuidelines() {

    document.getElementById(
        "guidelinesModal"
    ).style.display = "none";

}


/* =========================
   DASHBOARD
========================= */

function openDashboard() {

    document.getElementById(
        "dashboardModal"
    ).style.display = "flex";

}


function closeDashboard() {

    document.getElementById(
        "dashboardModal"
    ).style.display = "none";

}


/* =========================
   BACKDROP
========================= */

window.addEventListener(
    "click",
    function(event) {

        const toolModal =
            document.getElementById(
                "toolModal"
            );

        const guidelinesModal =
            document.getElementById(
                "guidelinesModal"
            );

        const dashboardModal =
            document.getElementById(
                "dashboardModal"
            );


        if (
            event.target === toolModal
        ) {

            closeTool();

        }


        if (
            event.target === guidelinesModal
        ) {

            closeGuidelines();

        }


        if (
            event.target === dashboardModal
        ) {

            closeDashboard();

        }

    }
);
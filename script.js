/* =========================================================
   CYBERGUARD
   STEP 9.3
   CLEAN FRONTEND SCRIPT
   ========================================================= */


/* =========================================================
   CONFIG
   ========================================================= */

// After deploying the backend, replace the URL below with your Render service URL.
const CYBERGUARD_API = (window.CYBERGUARD_API_URL || "https://cyberguard-api-x8vn.onrender.com").replace(/\/$/, "");


/* =========================================================
   GLOBAL HELPERS
   ========================================================= */

function escapeHTML(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function findMatches(text, keywords) {
    const lower = String(text || "").toLowerCase();

    return keywords.filter(keyword =>
        lower.includes(keyword.toLowerCase())
    );
}


function getRiskClass(risk) {
    const value = String(risk || "").toUpperCase();

    if (value === "HIGH") {
        return "danger";
    }

    if (value === "SUSPICIOUS" || value === "MEDIUM") {
        return "warning";
    }

    return "safe";
}


function getRiskEmoji(risk) {
    const value = String(risk || "").toUpperCase();

    if (value === "HIGH") {
        return "🔴";
    }

    if (value === "SUSPICIOUS") {
        return "🟡";
    }

    return "🟢";
}


/* =========================================================
   EVENT HISTORY
   ========================================================= */

let cyberGuardEvents = [];

function saveCyberGuardEvent(event) {
    cyberGuardEvents.unshift({
        ...event,
        timestamp: new Date().toISOString(),
    });

    if (cyberGuardEvents.length > 100) {
        cyberGuardEvents = cyberGuardEvents.slice(0, 100);
    }

    try {
        localStorage.setItem("cyberguard_events", JSON.stringify(cyberGuardEvents));
    } catch (_e) {
        // localStorage may be unavailable
    }
}

function loadCyberGuardEvents() {
    try {
        const stored = localStorage.getItem("cyberguard_events");

        if (stored) {
            cyberGuardEvents = JSON.parse(stored);
        }
    } catch (_e) {
        cyberGuardEvents = [];
    }
}

loadCyberGuardEvents();


/* =========================================================
   API HELPERS
   ========================================================= */

function renderApiError(resultBox, message) {
    resultBox.innerHTML = `
        <div class="result-box danger">
            <h3>⚠️ Analysis Failed</h3>
            <p>${escapeHTML(message || "An unexpected error occurred.")}</p>
            <p style="margin-top:10px;font-size:13px;color:#777;">
                Make sure the CyberGuard backend is running at ${CYBERGUARD_API}
            </p>
        </div>`;
}

async function safeFetch(url, options) {
    const response = await fetch(url, options);

    if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(`HTTP ${response.status}: ${text.slice(0, 200)}`);
    }

    return response.json();
}


/* =========================================================
   OPEN TOOL
   ========================================================= */

function openTool(type) {

    const modal = document.getElementById("toolModal");
    const content = document.getElementById("toolContent");

    if (!modal || !content) {
        return;
    }

    modal.style.display = "flex";


    /* =====================================================
       URL
       ===================================================== */

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
                    autocomplete="off"
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


    /* =====================================================
       EMAIL
       ===================================================== */

    if (type === "email") {

        content.innerHTML = `

            <h2>✉️ Email Phishing Analysis</h2>

            <p>
                Analyze an email for phishing,
                scam and social-engineering indicators.
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


    /* =====================================================
       QR
       ===================================================== */

    if (type === "qr") {

        content.innerHTML = `

            <h2>▦ QR Code Security Scanner</h2>

            <p>
                Upload a QR image and CyberGuard
                will detect and analyze its content.
            </p>

            <div class="qr-upload-box" id="qrDropZone">

                <label class="upload-label">

                    📷 Select QR Image

                    <input
                        type="file"
                        id="qrInput"
                        accept="image/*"
                        hidden
                    >

                </label>

                <p style="margin-top:10px;font-size:12px;color:#999;">
                    or drag &amp; drop a QR image here
                </p>

            </div>

            <div id="qrResult"></div>

        `;

        setTimeout(setupQRDropZone, 50);
        return;
    }


    /* =====================================================
       SOCIAL
       ===================================================== */

    if (type === "social") {

        content.innerHTML = `

            <h2>👥 Social Media Impersonation</h2>

            <p>
                Check a social media username for
                suspicious impersonation indicators.
            </p>

            <div class="email-form">

                <label>Platform</label>

                <select id="socialPlatform">

                    <option value="Instagram">Instagram</option>
                    <option value="Facebook">Facebook</option>
                    <option value="X">X / Twitter</option>
                    <option value="YouTube">YouTube</option>
                    <option value="Telegram">Telegram</option>
                    <option value="LinkedIn">LinkedIn</option>

                </select>

                <label>Username / ID</label>

                <input
                    type="text"
                    id="socialUsername"
                    placeholder="@username"
                >

                <label>Profile Name (Optional)</label>

                <input
                    type="text"
                    id="socialDisplayName"
                    placeholder="Profile name"
                >

                <button
                    class="analyze-btn"
                    onclick="analyzeSocial()">

                    Analyze Profile

                </button>

            </div>

            <div id="socialResult"></div>

        `;

        return;
    }


    /* =====================================================
       IMAGE
       ===================================================== */

    if (type === "image") {

        content.innerHTML = `

            <h2>🖼️ Image Security Analysis</h2>

            <p>
                Inspect image metadata and technical
                characteristics.
            </p>

            <div class="qr-upload-box">

                <label class="upload-label">

                    🖼️ Select Image

                    <input
                        type="file"
                        id="imageInput"
                        accept="image/*"
                        onchange="analyzeImage(event)"
                        hidden
                    >

                </label>

            </div>

            <div id="imageResult"></div>

        `;

        return;
    }


    /* =====================================================
       VIDEO
       ===================================================== */

    if (type === "video") {

        content.innerHTML = `

            <h2>🎥 Video Security Analysis</h2>

            <p>
                Inspect video properties and technical
                characteristics.
            </p>

            <div class="qr-upload-box">

                <label class="upload-label">

                    🎥 Select Video

                    <input
                        type="file"
                        id="videoInput"
                        accept="video/*"
                        onchange="analyzeVideo(event)"
                        hidden
                    >

                </label>

            </div>

            <div id="videoResult"></div>

        `;

        return;
    }
}


/* =========================================================
   URL ANALYZER
   FASTAPI BACKEND
   ========================================================= */

async function analyzeURL() {

    const input = document.getElementById("urlInput");
    const resultBox = document.getElementById("urlResult");

    if (!input || !resultBox) {
        return;
    }

    const value = input.value.trim();

    if (!value) {

        resultBox.innerHTML = `

            <div class="result-box danger">

                <h3>⚠️ URL Required</h3>

                <p>
                    Please enter a URL first.
                </p>

            </div>

        `;

        return;
    }


    resultBox.innerHTML = `

        <div class="dashboard-placeholder">

            🔍 Analyzing URL with CyberGuard AI Backend...

        </div>

    `;


    try {

        const data =
            await safeFetch(`${CYBERGUARD_API}/api/analyze-url`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: value }),
            });

        if (!data.success) {

            renderApiError(resultBox, data.message || "URL analysis failed.");
            return;
        }


        const score = Number(data.score || 0);

        const risk = String(
            data.risk || "LOW"
        ).toUpperCase();

        const indicators =
            Array.isArray(data.indicators)
                ? data.indicators
                : [];

        const riskClass = getRiskClass(risk);


        let indicatorsHTML = "";


        if (indicators.length > 0) {

            indicatorsHTML = `

                <div class="warnings">

                    <h4>
                        ⚠️ Detected Indicators
                    </h4>

                    <ul class="warning-list">

                        ${indicators.map(
                            item => `
                                <li>
                                    ${escapeHTML(item)}
                                </li>
                            `
                        ).join("")}

                    </ul>

                </div>

            `;

        } else {

            indicatorsHTML = `

                <div class="analysis-details">

                    <h4>
                        ✅ No Major Indicators
                    </h4>

                    <p>
                        No major suspicious indicators
                        were detected.
                    </p>

                </div>

            `;

        }


        resultBox.innerHTML = `

            <div class="result-box ${riskClass}">

                <div class="risk-header">

                    <div>

                        <strong>
                            CyberGuard Analysis
                        </strong>

                        <div>
                            ⚡ FastAPI Backend
                        </div>

                    </div>

                    <div class="risk-score">

                        ${score}

                    </div>

                </div>


                <div class="score-bar">

                    <div
                        class="score-fill"
                        style="width:${score}%">
                    </div>

                </div>


                <div class="analysis-details">

                    <h4>
                        🛡️ Risk Level
                    </h4>

                    <p>
                        <strong>
                            ${escapeHTML(risk)}
                        </strong>
                    </p>

                </div>


                <div class="analysis-details">

                    <h4>
                        🔗 URL
                    </h4>

                    <p class="break-text">

                        ${escapeHTML(
                            data.url || value
                        )}

                    </p>

                </div>


                <div class="analysis-details">

                    <h4>
                        🌐 Hostname
                    </h4>

                    <p>

                        ${escapeHTML(
                            data.hostname || "Unknown"
                        )}

                    </p>

                </div>


                ${indicatorsHTML}


                <div class="recommendation">

                    <strong>
                        🛡️ Recommendation
                    </strong>

                    <p>

                        ${escapeHTML(
                            data.recommendation || ""
                        )}

                    </p>

                </div>

            </div>

        `;


        saveCyberGuardEvent({

            type: "URL",

            input: data.hostname ||
                   data.url ||
                   value,

            score: score,

            risk: risk,

            source: "FastAPI Backend"

        });

    }

    catch (error) {

        console.error(
            "CyberGuard URL Error:", error
        );

        renderApiError(resultBox, "Could not connect to the CyberGuard backend.");

    }
}


/* =========================================================
   EMAIL ANALYZER
   ========================================================= */

async function analyzeEmail() {

    const sender =
        document.getElementById("emailSender");

    const subject =
        document.getElementById("emailSubject");

    const body =
        document.getElementById("emailBody");

    const result =
        document.getElementById("emailResult");


    if (!sender || !subject || !body || !result) {
        return;
    }


    const senderValue =
        sender.value.trim();

    const subjectValue =
        subject.value.trim();

    const bodyValue =
        body.value.trim();


    if (
        !senderValue &&
        !subjectValue &&
        !bodyValue
    ) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>⚠️ Email Required</h3>

                <p>
                    Please enter email information.
                </p>

            </div>

        `;

        return;
    }


    result.innerHTML = `

        <div class="dashboard-placeholder">

            🧠 CyberGuard Email Engine
            is analyzing...

        </div>

    `;


    try {

        const data =
            await safeFetch(`${CYBERGUARD_API}/api/analyze-email`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sender: senderValue,
                    subject: subjectValue,
                    body: bodyValue,
                }),
            });

        if (!data.success) {

            renderApiError(result, data.message || "Email analysis failed.");
            return;
        }


        const score =
            Number(data.score || 0);

        const risk =
            String(
                data.risk || "LOW"
            ).toUpperCase();

        const indicators =
            Array.isArray(data.indicators)
                ? data.indicators
                : [];


        const riskClass =
            getRiskClass(risk);


        let indicatorsHTML = "";


        if (indicators.length > 0) {

            indicatorsHTML = `

                <div class="warnings">

                    <h4>
                        ⚠️ Detected Indicators
                    </h4>

                    <ul class="warning-list">

                        ${indicators.map(
                            item => `
                                <li>
                                    ${escapeHTML(item)}
                                </li>
                            `
                        ).join("")}

                    </ul>

                </div>

            `;

        }
        else {

            indicatorsHTML = `

                <div class="analysis-details">

                    <h4>
                        ✅ No Major Indicators
                    </h4>

                    <p>
                        No major phishing indicators
                        were detected.
                    </p>

                </div>

            `;

        }


        result.innerHTML = `

            <div class="result-box ${riskClass}">

                <div class="risk-header">

                    <div>

                        <strong>
                            Email Security Analysis
                        </strong>

                        <div>
                            ⚡ CyberGuard FastAPI
                        </div>

                    </div>

                    <div class="risk-score">

                        ${score}

                    </div>

                </div>


                <div class="score-bar">

                    <div
                        class="score-fill"
                        style="width:${score}%">
                    </div>

                </div>


                <div class="analysis-details">

                    <h4>
                        🛡️ Risk Level
                    </h4>

                    <p>

                        <strong>
                            ${escapeHTML(risk)}
                        </strong>

                    </p>

                </div>


                <div class="analysis-details">

                    <h4>
                        ✉️ Sender
                    </h4>

                    <p>

                        ${escapeHTML(
                            data.sender ||
                            senderValue
                        )}

                    </p>

                </div>


                <div class="analysis-details">

                    <h4>
                        📌 Subject
                    </h4>

                    <p>

                        ${escapeHTML(
                            data.subject ||
                            subjectValue ||
                            "No subject"
                        )}

                    </p>

                </div>


                ${indicatorsHTML}


                <div class="recommendation">

                    <strong>
                        🛡️ Recommendation
                    </strong>

                    <p>

                        ${escapeHTML(
                            data.recommendation || ""
                        )}

                    </p>

                </div>

            </div>

        `;


        saveCyberGuardEvent({

            type: "EMAIL",

            input:
                senderValue ||
                "Email Analysis",

            score: score,

            risk: risk,

            source:
                "FastAPI Email Engine"

        });

    }

    catch (error) {

        console.error(
            "CyberGuard Email Error:", error
        );

        renderApiError(result, "Could not connect to the CyberGuard backend.");

    }
}


/* =========================================================
   QR SCANNER — jsQR decode + backend analysis
   ========================================================= */

function setupQRDropZone() {
    const dropZone = document.getElementById("qrDropZone");
    const fileInput = document.getElementById("qrInput");

    if (!dropZone || !fileInput) {
        return;
    }

    const result = document.getElementById("qrResult");

    dropZone.addEventListener("dragover", function(e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.style.borderColor = "#222";
        dropZone.style.background = "#e0e0e0";
    });

    dropZone.addEventListener("dragleave", function(e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.style.borderColor = "#bbb";
        dropZone.style.background = "#f2f2f2";
    });

    dropZone.addEventListener("drop", function(e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.style.borderColor = "#bbb";
        dropZone.style.background = "#f2f2f2";

        const files = e.dataTransfer.files;

        if (files.length > 0) {
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(files[0]);
            fileInput.files = dataTransfer.files;
            scanQR({ target: fileInput });
        }
    });

    fileInput.addEventListener("change", function() {
        if (fileInput.files.length > 0) {
            scanQR({ target: fileInput });
        }
    });
}

function scanQR(event) {

    const file =
        event?.target?.files?.[0];

    const result =
        document.getElementById("qrResult");

    if (!file || !result) {
        return;
    }

    if (typeof jsQR === "undefined") {

        result.innerHTML = `
            <div class="result-box danger">
                <h3>❌ QR Library Not Loaded</h3>
                <p>jsQR library could not be loaded. Check your internet connection and reload the page.</p>
            </div>`;

        return;
    }

    if (!file.type.startsWith("image/")) {

        result.innerHTML = `
            <div class="result-box danger">
                <h3>⚠️ Invalid File</h3>
                <p>Please select an image file (PNG, JPG, GIF, WebP, etc.).</p>
            </div>`;

        return;
    }

    result.innerHTML = `
        <div class="dashboard-placeholder">
            🔍 Decoding QR Code...
        </div>`;

    const reader = new FileReader();

    reader.onerror = function() {

        result.innerHTML = `
            <div class="result-box danger">
                <h3>⚠️ File Read Error</h3>
                <p>Could not read the selected file. Please try again.</p>
            </div>`;

    };

    reader.onload = function(e) {

        const image = new Image();

        image.onerror = function() {

            result.innerHTML = `
                <div class="result-box danger">
                    <h3>⚠️ Image Could Not Be Loaded</h3>
                    <p>The selected file is not a valid image or is corrupted. Please try another file.</p>
                </div>`;

        };

        image.onload = function() {

            if (image.width === 0 || image.height === 0) {

                result.innerHTML = `
                    <div class="result-box danger">
                        <h3>⚠️ Invalid Image</h3>
                        <p>The image has zero dimensions and cannot be processed.</p>
                    </div>`;

                return;
            }

            decodeQRFromImage(image);

        };

        image.src = e.target.result;

    };

    reader.readAsDataURL(file);
}

function decodeQRFromImage(image) {
    const result = document.getElementById("qrResult");
    if (!result) {
        return;
    }

    // Scale up small images so jsQR has enough pixels to detect the pattern
    const minDimension = Math.min(image.width, image.height);
    const scale = minDimension < 300 ? Math.ceil(300 / minDimension) : 1;
    const scaledWidth = image.width * scale;
    const scaledHeight = image.height * scale;

    const canvas  = document.createElement("canvas");
    const context = canvas.getContext("2d");
    canvas.width  = scaledWidth;
    canvas.height = scaledHeight;
    context.imageSmoothingEnabled = false;
    context.drawImage(image, 0, 0, scaledWidth, scaledHeight);

    try {
        const imageData = context.getImageData(0, 0, scaledWidth, scaledHeight);

        let code = jsQR(imageData.data, imageData.width, imageData.height);

        if (!code) {
            code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
        }

        if (!code) {

            result.innerHTML = `
                <div class="result-box danger">
                    <h3>❌ QR Code Not Detected</h3>
                    <p>No QR code was found in this image. Try:</p>
                    <ul class="warning-list">
                        <li>Using a clearer, higher-resolution image</li>
                        <li>Making sure the QR code is fully visible (not cropped or blurry)</li>
                        <li>Taking a photo of the QR code instead of a screenshot</li>
                        <li>Ensuring good lighting and no glare</li>
                    </ul>
                </div>`;

            return;
        }

        analyzeQRContent(code.data);

    } catch (err) {
        console.error("Canvas/QR decode error:", err);

        result.innerHTML = `
            <div class="result-box danger">
                <h3>⚠️ Processing Error</h3>
                <p>Could not process the image. Try a different file format (PNG or JPG recommended).</p>
            </div>`;
    }
}


/* =========================================================
   QR CONTENT ANALYSIS — backend is the source of truth
   ========================================================= */

async function analyzeQRContent(value) {
    const result = document.getElementById("qrResult");
    if (!result) return;

    const qrValue = String(value || "").trim();
    if (!qrValue) {
        result.innerHTML = `<div class="result-box danger"><h3>QR content is empty</h3></div>`;
        return;
    }

    result.innerHTML = `<div class="dashboard-placeholder">Analyzing QR content…</div>`;

    try {
        const data = await safeFetch(`${CYBERGUARD_API}/api/analyze-qr`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content: qrValue }),
        });

        if (!data.success) {
            renderApiError(result, data.message || data.indicators?.[0] || "QR analysis failed.");
            return;
        }

        const score = Math.max(0, Math.min(100, Number(data.score) || 0));
        const risk = String(data.risk || "LOW").toUpperCase();
        const riskClass = getRiskClass(risk);
        const indicators = Array.isArray(data.indicators) ? data.indicators : [];
        const indicatorMarkup = indicators.length
            ? `<div class="warnings"><h4>Detected Indicators</h4><ul class="warning-list">${indicators.map(item => `<li>${escapeHTML(item)}</li>`).join("")}</ul></div>`
            : `<div class="analysis-details"><p>No major suspicious indicators were detected. This is not a guarantee of safety.</p></div>`;

        result.innerHTML = `
            <div class="result-box ${riskClass}">
                <div class="risk-header">
                    <div><strong>QR Security Analysis</strong><div>${escapeHTML(data.analysis_engine || "CyberGuard backend")}</div></div>
                    <div class="risk-score">${score}</div>
                </div>
                <div class="score-bar"><div class="score-fill" style="width:${score}%"></div></div>
                <div class="analysis-details"><h4>Risk Level</h4><p><strong>${escapeHTML(risk)}</strong></p></div>
                <div class="analysis-details"><h4>Content Type</h4><p>${escapeHTML(data.content_type || "Unknown")}</p></div>
                <div class="analysis-details"><h4>Decoded Content</h4><p class="break-text">${escapeHTML(data.decoded_content || qrValue)}</p></div>
                ${indicatorMarkup}
                <div class="recommendation"><strong>Recommendation</strong><p>${escapeHTML(data.recommendation || "Verify the QR destination independently before using it.")}</p></div>
            </div>`;

        // Keep only a generic label in browser history; never persist decoded QR content.
        saveCyberGuardEvent({
            type: "QR",
            input: data.content_type || "QR code",
            score,
            risk,
            source: data.analysis_engine || "CyberGuard backend",
        });
    } catch (error) {
        console.error("CyberGuard QR backend error:", error);
        renderApiError(result, "Could not connect to the CyberGuard backend. Check that it is running and that the API URL is correct.");
    }
}


/* =========================================================
   SOCIAL MEDIA ANALYZER
   ========================================================= */

function analyzeSocial() {

    const platform =
        document.getElementById("socialPlatform");

    const username =
        document.getElementById("socialUsername");

    const displayName =
        document.getElementById("socialDisplayName");

    const result =
        document.getElementById("socialResult");


    if (!platform || !username || !result) {
        return;
    }


    const platformValue =
        platform.value;

    const usernameValue =
        username.value.trim();

    const displayValue =
        displayName
            ? displayName.value.trim()
            : "";


    if (!usernameValue) {

        result.innerHTML = `

            <div class="result-box danger">

                <h3>
                    ⚠️ Username Required
                </h3>

                <p>
                    Enter a social media username.
                </p>

            </div>

        `;

        return;
    }


    let score = 0;
    const warnings = [];


    const suspiciousTerms = [
        "official",
        "support",
        "admin",
        "help",
        "customer",
        "security",
        "verify",
        "real",
        "original"
    ];


    const found =
        findMatches(
            usernameValue,
            suspiciousTerms
        );


    if (found.length > 0) {

        score += Math.min(
            found.length * 8,
            30
        );

        warnings.push(
            "Username contains identity/authority-related terms."
        );

    }


    if (
        /[0-9]{3,}/.test(usernameValue)
    ) {

        score += 10;

        warnings.push(
            "Username contains a large numeric sequence."
        );

    }


    if (
        usernameValue.length > 25
    ) {

        score += 10;

        warnings.push(
            "Username is unusually long."
        );

    }


    if (
        displayValue &&
        usernameValue
            .replace(/[@_.0-9]/g, "")
            .toLowerCase() ===
        displayValue
            .replace(/\s/g, "")
            .toLowerCase()
    ) {

        score += 10;

    }


    score = Math.min(score, 100);


    let risk = "LOW";


    if (score >= 70) {
        risk = "HIGH";
    }
    else if (score >= 40) {
        risk = "SUSPICIOUS";
    }


    const riskClass =
        getRiskClass(risk);


    let warningHTML = "";


    if (warnings.length > 0) {

        warningHTML = `

            <div class="warnings">

                <h4>
                    ⚠️ Indicators
                </h4>

                <ul class="warning-list">

                    ${warnings.map(
                        item => `
                            <li>
                                ${escapeHTML(item)}
                            </li>
                        `
                    ).join("")}

                </ul>

            </div>

        `;

    }


    result.innerHTML = `

        <div class="result-box ${riskClass}">

            <div class="risk-header">

                <div>

                    <strong>
                        Social Media Analysis
                    </strong>

                    <div>
                        👥 ${escapeHTML(platformValue)}
                    </div>

                </div>

                <div class="risk-score">
                    ${score}
                </div>

            </div>


            <div class="score-bar">

                <div
                    class="score-fill"
                    style="width:${score}%">
                </div>

            </div>


            <div class="analysis-details">

                <h4>
                    Username
                </h4>

                <p>
                    ${escapeHTML(usernameValue)}
                </p>

            </div>


            <div class="analysis-details">

                <h4>
                    Risk Level
                </h4>

                <p>
                    <strong>
                        ${risk}
                    </strong>
                </p>

            </div>


            ${warningHTML}


            <div class="recommendation">

                <strong>
                    🛡️ Important
                </strong>

                <p>
                    This is a heuristic check only.
                    Verify the account through the
                    platform's official verification
                    mechanisms before trusting it.
                </p>

            </div>

        </div>

    `;


    saveCyberGuardEvent({

        type: "SOCIAL",

        input: `${platformValue} profile`,

        score: score,

        risk: risk,

        source: "Client Heuristic"

    });
}


/* =========================================================
   IMAGE ANALYSIS
   ========================================================= */

async function analyzeImage(event) {
    const file = event?.target?.files?.[0];
    const result = document.getElementById("imageResult");
    if (!file || !result) return;
    if (file.size > 15 * 1024 * 1024) { result.innerHTML = '<div class="result-box warning">Image must be 15 MB or smaller.</div>'; return; }
    const preview = URL.createObjectURL(file);
    result.innerHTML = `<div class="result-box"><p><strong>Selected image</strong></p><img src="${preview}" alt="Selected image preview" style="display:block;max-width:100%;max-height:320px;object-fit:contain;border-radius:12px;margin:12px auto"><div class="dashboard-placeholder">Connecting to AI image review…</div></div>`;
    try {
      const form = new FormData(); form.append("file", file);
      const response = await fetch(`${CYBERGUARD_API}/api/analyze-image-ai`, {method:"POST", body:form});
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Image AI review failed.");
      const items = Array.isArray(data.observations) ? data.observations : [];
      result.innerHTML = `<div class="result-box"><span class="result-label">AI-ASSISTED REVIEW</span><h3 style="margin-top:12px">${escapeHTML(data.assessment || "Inconclusive")}</h3><div class="analysis-details"><h4>Image description</h4><p>${escapeHTML(data.image_description || "Not available")}</p></div><div class="analysis-details"><h4>Observations</h4>${items.length ? `<ul class="warning-list">${items.map(x=>`<li>${escapeHTML(x)}</li>`).join("")}</ul>` : '<p>No specific observations returned.</p>'}</div><div class="recommendation">${escapeHTML(data.recommendation || "Verify important media using trusted original sources.")}</div><p class="recommendation">${escapeHTML(data.limitations || "Visual AI review is not definitive forensic proof.")}</p></div>`;
    } catch (err) { result.innerHTML = `<div class="result-box warning"><h3>AI image review unavailable</h3><p>${escapeHTML(err.message || "Could not contact the AI service.")}</p><p>Add GEMINI_API_KEY to Render environment variables, then redeploy.</p></div>`; }
}

async function analyzeVideo(event) {
    const file = event?.target?.files?.[0];
    const result = document.getElementById("videoResult");
    if (!file || !result) return;
    if (file.size > 15 * 1024 * 1024) { result.innerHTML = '<div class="result-box warning">Video must be 15 MB or smaller for AI review.</div>'; return; }
    const preview = URL.createObjectURL(file);
    result.innerHTML = `<div class="result-box"><video controls preload="metadata" src="${preview}" style="display:block;width:100%;max-height:320px;border-radius:12px;margin-bottom:12px"></video><div class="dashboard-placeholder">Sending video for AI-assisted review…</div></div>`;
    try {
      const form = new FormData(); form.append("file", file);
      const response = await fetch(`${CYBERGUARD_API}/api/analyze-video-ai`, {method:"POST", body:form});
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Video AI review failed.");
      const items = Array.isArray(data.observations) ? data.observations : [];
      result.innerHTML = `<div class="result-box"><span class="result-label">AI-ASSISTED VIDEO REVIEW</span><h3 style="margin-top:12px">${escapeHTML(data.assessment || "Inconclusive")}</h3><div class="analysis-details"><h4>Summary</h4><p>${escapeHTML(data.summary || "Not available")}</p></div><div class="analysis-details"><h4>Observations</h4>${items.length ? `<ul class="warning-list">${items.map(x=>`<li>${escapeHTML(x)}</li>`).join("")}</ul>` : '<p>No specific observations returned.</p>'}</div><div class="recommendation">${escapeHTML(data.recommendation || "Verify important media using trusted original sources.")}</div><p class="recommendation">${escapeHTML(data.limitations || "AI visual review cannot conclusively prove a video is a deepfake.")}</p></div>`;
    } catch (err) { result.innerHTML = `<div class="result-box warning"><h3>AI video review unavailable</h3><p>${escapeHTML(err.message || "Could not contact the AI service.")}</p><p>Add GEMINI_API_KEY to Render environment variables, then redeploy.</p></div>`; }
}

/* =========================================================
   FORMAT VIDEO DURATION
   ========================================================= */

function formatDuration(seconds) {

    if (!Number.isFinite(seconds)) {
        return "Unknown";
    }


    const total =
        Math.floor(seconds);

    const hours =
        Math.floor(total / 3600);

    const minutes =
        Math.floor((total % 3600) / 60);

    const secs =
        total % 60;


    if (hours > 0) {

        return `${hours}h ${minutes}m ${secs}s`;

    }


    return `${minutes}m ${secs}s`;
}


/* =========================================================
   CYBERGUARD HISTORY
   ========================================================= */

function getCyberGuardEvents() {

    try {

        return JSON.parse(
            localStorage.getItem(
                "cyberguard_events"
            ) || "[]"
        );

    }
    catch (error) {

        console.error(
            "Could not read CyberGuard history:",
            error
        );

        return [];

    }
}


/* =========================================================
   DASHBOARD
   ========================================================= */

function openDashboard() {

    const modal =
        document.getElementById(
            "dashboardModal"
        );

    if (!modal) {
        return;
    }


    modal.style.display = "flex";


    renderDashboard();
}


/* =========================================================
   RENDER DASHBOARD
   ========================================================= */

function renderDashboard() {

    const box =
        document.querySelector(
            "#dashboardModal .dashboard-placeholder"
        );


    if (!box) {
        return;
    }


    const events =
        getCyberGuardEvents();


    const total =
        events.length;


    const safe =
        events.filter(
            item =>
                String(item.risk).toUpperCase() === "LOW"
        ).length;


    const suspicious =
        events.filter(
            item =>
                String(item.risk).toUpperCase() ===
                "SUSPICIOUS"
        ).length;


    const high =
        events.filter(
            item =>
                String(item.risk).toUpperCase() ===
                "HIGH"
        ).length;


    const average =
        total
            ? Math.round(
                events.reduce(
                    (sum, item) =>
                        sum +
                        Number(item.score || 0),
                    0
                ) / total
            )
            : 0;


    const categories = {};


    events.forEach(item => {

        const type =
            item.type || "UNKNOWN";

        categories[type] =
            (categories[type] || 0) + 1;

    });


    const latest =
        events.slice(0, 10);


    let latestHTML = "";


    if (latest.length === 0) {

        latestHTML = `

            <p>
                No security events yet.
            </p>

        `;

    }
    else {

        latestHTML = latest.map(item => `

            <div
                style="
                    padding:10px 0;
                    border-bottom:1px solid #ddd;
                "
            >

                <strong>
                    ${escapeHTML(item.type)}
                </strong>

                —
                ${escapeHTML(item.risk)}

                —
                Score:
                ${Number(item.score || 0)}

                <br>

                <small>
                    ${escapeHTML(item.input)}
                </small>

            </div>

        `).join("");

    }


    const categoryHTML =
        Object.keys(categories).length
            ? Object.entries(categories)
                .map(
                    ([key, value]) => `
                        <li>
                            <strong>
                                ${escapeHTML(key)}
                            </strong>
                            : ${value}
                        </li>
                    `
                )
                .join("")
            : "<li>No data</li>";


    box.innerHTML = `

        <div style="text-align:left;">

            <div
                style="
                    display:grid;
                    grid-template-columns:
                        repeat(
                            auto-fit,
                            minmax(140px,1fr)
                        );
                    gap:12px;
                    margin-bottom:20px;
                "
            >

                <div class="analysis-details">
                    <h4>Total Scans</h4>
                    <p><strong>${total}</strong></p>
                </div>

                <div class="analysis-details">
                    <h4>Low Risk</h4>
                    <p><strong>${safe}</strong></p>
                </div>

                <div class="analysis-details">
                    <h4>Suspicious</h4>
                    <p><strong>${suspicious}</strong></p>
                </div>

                <div class="analysis-details">
                    <h4>High Risk</h4>
                    <p><strong>${high}</strong></p>
                </div>

                <div class="analysis-details">
                    <h4>Average Score</h4>
                    <p><strong>${average}</strong></p>
                </div>

            </div>


            <div class="analysis-details">

                <h3>
                    📂 Analysis Categories
                </h3>

                <ul>
                    ${categoryHTML}
                </ul>

            </div>


            <div class="analysis-details">

                <h3>
                    🕘 Recent Security Events
                </h3>

                ${latestHTML}

            </div>


            <button
                class="analyze-btn"
                onclick="clearCyberGuardHistory()"
                style="margin-top:15px;"
            >

                🗑️ Clear History

            </button>

        </div>

    `;
}


/* =========================================================
   CLEAR HISTORY
   ========================================================= */

function clearCyberGuardHistory() {

    const confirmed =
        confirm(
            "Clear all CyberGuard analysis history?"
        );


    if (!confirmed) {
        return;
    }


    localStorage.removeItem(
        "cyberguard_events"
    );


    renderDashboard();

}


/* =========================================================
   CLOSE TOOL
   ========================================================= */

function closeTool() {

    const modal =
        document.getElementById(
            "toolModal"
        );

    if (modal) {
        modal.style.display = "none";
    }

    // Reset QR file input so the same file can be re-selected
    const qrInput =
        document.getElementById("qrInput");

    if (qrInput) {
        qrInput.value = "";
    }

}


/* =========================================================
   GUIDELINES
   ========================================================= */

function openGuidelines() {

    const modal =
        document.getElementById(
            "guidelinesModal"
        );

    if (modal) {
        modal.style.display = "flex";
    }

}


function closeGuidelines() {

    const modal =
        document.getElementById(
            "guidelinesModal"
        );

    if (modal) {
        modal.style.display = "none";
    }

}


/* =========================================================
   CLOSE DASHBOARD
   ========================================================= */

function closeDashboard() {

    const modal =
        document.getElementById(
            "dashboardModal"
        );

    if (modal) {
        modal.style.display = "none";
    }

}


/* =========================================================
   BACKDROP CLICK
   ========================================================= */

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
            toolModal &&
            event.target === toolModal
        ) {

            closeTool();

        }


        if (
            guidelinesModal &&
            event.target === guidelinesModal
        ) {

            closeGuidelines();

        }


        if (
            dashboardModal &&
            event.target === dashboardModal
        ) {

            closeDashboard();

        }

    }
);


/* =========================================================
   ENTER KEY SUPPORT
   ========================================================= */

document.addEventListener(
    "keydown",
    function(event) {

        if (
            event.key === "Enter" &&
            document.activeElement?.id === "urlInput"
        ) {

            analyzeURL();

        }

    }
);

// Accessibility and resilience: ensure security cards remain operable by mouse and keyboard.
document.addEventListener("keydown", function(event) {
  const card = event.target.closest && event.target.closest(".tool-card[tabindex]");
  if (card && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); card.click(); }
});


function scanURL() {
    const input = document.getElementById("urlInput");
    const result = document.getElementById("result");
    const url = input.value.trim();

    if (!url) {
        alert("Please enter a website URL!");
        return;
    }

    let parsed;

    try {
        const normalized = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(url)
            ? url
            : "https://" + url;

        parsed = new URL(normalized);

        if (!["http:", "https:"].includes(parsed.protocol)) {
            throw new Error("Unsupported protocol");
        }

        if (!parsed.hostname || !parsed.hostname.includes(".")) {
            throw new Error("Invalid hostname");
        }
    } catch (error) {
        alert("Please enter a valid website URL!");
        return;
    }

    let score = 0;
    let findings = [];

    const hostname = parsed.hostname.toLowerCase();
    const fullURL = url.toLowerCase();

    // 1. Check HTTPS
    if (parsed.protocol !== "https:") {
        score += 15;
        findings.push("⚠️ Website does not use HTTPS.");
    }

    // 2. Check IP address
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

    if (isIP) {
        score += 30;
        findings.push("⚠️ Website uses an IP address instead of a domain.");
    }

    // 3. Check suspicious keywords
    const keywords = [
        "login", "verify", "update", "secure",
        "account", "banking", "password",
        "signin", "free", "gift", "wallet",
        "confirm", "payment"
    ];

    const matchedWords = keywords.filter(word =>
        fullURL.includes(word)
    );

    if (matchedWords.length > 0) {
        score += Math.min(matchedWords.length * 5, 20);

        findings.push(
            "⚠️ Suspicious keywords found: " +
            matchedWords.join(", ")
        );
    }

    // 4. Check @ symbol / credentials
    if (parsed.username || parsed.password) {
        score += 25;
        findings.push("⚠️ URL contains embedded login credentials.");
    }

    // 5. Check URL length
    if (url.length > 75) {
        score += 10;
        findings.push("⚠️ Unusually long URL.");
    }

    // 6. Check URL shorteners
    const shorteners = [
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly", "shorturl.at"
    ];

    if (shorteners.includes(hostname)) {
        score += 15;
        findings.push("⚠️ URL uses a shortening service.");
    }

    // 7. Check multiple subdomains
    const parts = hostname.split(".");

    if (parts.length > 3) {
        score += 10;
        findings.push("⚠️ Multiple subdomains detected.");
    }

    // 8. Check multiple hyphens
    if ((hostname.match(/-/g) || []).length >= 2) {
        score += 10;
        findings.push("⚠️ Multiple hyphens in domain name.");
    }

    // 9. Check unusual port
    if (parsed.port && !["80", "443"].includes(parsed.port)) {
        score += 15;
        findings.push("⚠️ Unusual port number detected.");
    }

    score = Math.min(score, 100);

    // Display results
    document.getElementById("score").textContent = score + "%";
    document.getElementById("progressBar").style.width = score + "%";

    const verdict = document.getElementById("verdict");
    const progressBar = document.getElementById("progressBar");

    if (score >= 50) {
        verdict.textContent = "🔴 HIGH RISK - Suspicious URL";
        verdict.style.color = "#ff5b65";
        progressBar.style.background = "#ff5b65";
    } else if (score >= 25) {
        verdict.textContent = "🟠 MEDIUM RISK - Be Careful";
        verdict.style.color = "#ffb84d";
        progressBar.style.background = "#ffb84d";
    } else {
        verdict.textContent = "🟢 LOW RISK - No Major Indicators";
        verdict.style.color = "#46e5a2";
        progressBar.style.background = "#46e5a2";
    }

    // Display detected indicators safely
    const findingsList = document.getElementById("findings");
    findingsList.innerHTML = "";

    if (findings.length === 0) {
        findingsList.innerHTML =
            "<li>✅ No suspicious indicators detected.</li>";
    } else {
        findings.forEach(item => {
            const li = document.createElement("li");
            li.textContent = item;
            findingsList.appendChild(li);
        });
    }

    result.classList.remove("hidden");

    result.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}

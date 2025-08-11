const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const app = express();
const port = 3001;

function bytesToMB(bytes) {
    return +(bytes / (1024 * 1024)).toFixed(2);
}

function parseResourceSummary(audit) {
    const summary = {};
    audit.details.items.forEach(item => {
        summary[item.resourceType] = {
            transfer: item.transferSize || 0,
            decoded: item.size || item.transferSize || 0
        };
    });
    return summary;
}

function extractMetrics(reportJson, deviceLabel) {
    const audits = reportJson.audits;
    const perfScore = reportJson.categories.performance.score * 100;

    return {
        [`Performance Score (${deviceLabel})`]: perfScore,
        [`First Contentful Paint (${deviceLabel})`]: audits["first-contentful-paint"]?.displayValue || "Error",
        [`Speed Index (${deviceLabel})`]: audits["speed-index"]?.displayValue || "Error",
        [`Time to Interactive (${deviceLabel})`]: audits["interactive"]?.displayValue || "Error",
        [`LCP Lighthouse (${deviceLabel})`]: audits["largest-contentful-paint"]?.displayValue || "Error",
        [`CLS Lighthouse (${deviceLabel})`]: audits["cumulative-layout-shift"]?.displayValue || "Error"
    };
}

function generateCommand(url, outputFile, isDesktop = false) {
    const preset = isDesktop ? "--preset=desktop" : "";
    return `npx lighthouse ${url} --output=json --output-path=${outputFile} --chrome-flags="--headless --no-sandbox --disable-gpu --disable-dev-shm-usage" ${preset}`;
}

app.get("/metrics", async (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: "URL is required" });

    const ts = Date.now();
    const mobileFile = `lh-mobile-${ts}.json`;
    const desktopFile = `lh-desktop-${ts}.json`;

    const cmdMobile = generateCommand(url, mobileFile, false);
    const cmdDesktop = generateCommand(url, desktopFile, true);

    exec(cmdMobile, (err1) => {
        if (err1) {
            console.error("Mobile Lighthouse error:", err1.message);
            return res.status(500).json({ error: "Lighthouse (mobile) failed" });
        }

        exec(cmdDesktop, (err2) => {
            if (err2) {
                console.error("Desktop Lighthouse error:", err2.message);
                fs.unlinkSync(mobileFile);
                return res.status(500).json({ error: "Lighthouse (desktop) failed" });
            }

            try {
                const mobileData = JSON.parse(fs.readFileSync(mobileFile, "utf8"));
                const desktopData = JSON.parse(fs.readFileSync(desktopFile, "utf8"));
                fs.unlinkSync(mobileFile);
                fs.unlinkSync(desktopFile);

                const metricsMobile = extractMetrics(mobileData, "Mobile");
                const metricsDesktop = extractMetrics(desktopData, "Desktop");

                const audits = mobileData.audits;
                const summary = parseResourceSummary(audits["resource-summary"]);

                const sizes = {
                    html: summary.document || { transfer: 0, decoded: 0 },
                    css: summary.stylesheet || { transfer: 0, decoded: 0 },
                    js: summary.script || { transfer: 0, decoded: 0 },
                    images: summary.image || { transfer: 0, decoded: 0 },
                    other: summary.other || { transfer: 0, decoded: 0 }
                };

                const output = {
                    ...metricsMobile,
                    ...metricsDesktop,
                    "Server Response Time": +(audits["server-response-time"]?.numericValue || 0 / 1000).toFixed(1),
                    "All Content Loaded Time": +(audits["dom-size"]?.numericValue || 0 / 1000).toFixed(1),
                    "Scripts Complete Time": +(audits["mainthread-work-breakdown"]?.numericValue || 0 / 1000).toFixed(1),

                    // Transfer sizes
                    "HTML Size (MB)": bytesToMB(sizes.html.transfer),
                    "CSS Size (MB)": bytesToMB(sizes.css.transfer),
                    "JS Size (MB)": bytesToMB(sizes.js.transfer),
                    "Image Size (MB)": bytesToMB(sizes.images.transfer),
                    "Other Size (MB)": bytesToMB(sizes.other.transfer),
                    "Total Page Size (MB)": bytesToMB(
                        sizes.html.transfer + sizes.css.transfer + sizes.js.transfer + sizes.images.transfer + sizes.other.transfer
                    ),

                    // Decoded sizes
                    "HTML Decoded Size (MB)": bytesToMB(sizes.html.decoded),
                    "CSS Decoded Size (MB)": bytesToMB(sizes.css.decoded),
                    "JS Decoded Size (MB)": bytesToMB(sizes.js.decoded),
                    "Image Decoded Size (MB)": bytesToMB(sizes.images.decoded),
                    "Other Decoded Size (MB)": bytesToMB(sizes.other.decoded)
                };

                res.json(output);
            } catch (e) {
                console.error("Parsing error:", e);
                return res.status(500).json({ error: "Failed to parse Lighthouse data" });
            }
        });
    });
});

app.listen(port, () => {
    console.log(`✅ Lighthouse server running at http://localhost:${port}`);
});

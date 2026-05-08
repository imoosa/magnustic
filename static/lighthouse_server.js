const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const app = express();
const port = 3001;

const TEMP_DIR = os.tmpdir();

function bytesToMB(bytes) {
    return +(bytes / (1024 * 1024)).toFixed(2);
}

function parseResourceSummary(audit) {
    const summary = {};
    if (audit?.details?.items) {
        audit.details.items.forEach(item => {
            summary[item.resourceType] = {
                transfer: item.transferSize || 0,
                decoded: item.size || item.transferSize || 0
            };
        });
    }
    return summary;
}

function extractMetrics(reportJson, deviceLabel) {
    const audits = reportJson.audits || {};
    const perfScore = reportJson.categories?.performance?.score;

    return {
        [`Performance Score (${deviceLabel})`]: perfScore ? Math.round(perfScore * 100) : "N/A",
        [`First Contentful Paint (${deviceLabel})`]: audits["first-contentful-paint"]?.displayValue || "N/A",
        [`Speed Index (${deviceLabel})`]: audits["speed-index"]?.displayValue || "N/A",
        [`Time to Interactive (${deviceLabel})`]: audits["interactive"]?.displayValue || "N/A",
        [`LCP Lighthouse (${deviceLabel})`]: audits["largest-contentful-paint"]?.displayValue || "N/A",
        [`CLS Lighthouse (${deviceLabel})`]: audits["cumulative-layout-shift"]?.displayValue || "N/A"
    };
}

function generateCommand(url, outputFile, isDesktop = false) {
    const preset = isDesktop ? "--preset=desktop" : "";
    
    // Aggressive skipping of heavy audits
    const skipAudits = [
        "screenshot-thumbnails",
        "final-screenshot",
        "full-page-screenshot",
        "unused-css-rules",
        "unused-javascript",
        "modern-image-formats",
        "uses-optimized-images",
        "uses-text-compression",
        "uses-responsive-images",
        "offscreen-images",
        "render-blocking-resources",
        "uses-webp-images",
        "efficient-animated-content",
        "duplicated-javascript",
        "legacy-javascript"
    ].join(",");

    // Fix 1: Single --chrome-flags block (duplicate flags = last one wins, drops all others)
    // Fix 2: Removed --metrics-recording-only (suppresses rendering pipeline, causes NO_FCP)
    // Fix 3: Use --headless=old instead of --headless=new (better Windows paint compatibility)
    // Fix 4: Increased timeouts for slower/heavier sites
    const chromeFlags = [
        "--headless=old",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-extensions",
        "--disable-software-rasterizer",
        "--disable-setuid-sandbox",
        "--ignore-certificate-errors",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--disable-translate",
        "--hide-scrollbars",
        "--mute-audio",
        "--no-first-run",
        "--disable-breakpad",
        "--disable-crash-reporter",
        "--disable-notifications",
        "--no-default-browser-check"
    ].join(" ");

    return `lighthouse ${url} \
        --output=json \
        --output-path=${outputFile} \
        --chrome-flags="${chromeFlags}" \
        ${preset} \
        --only-categories=performance \
        --throttling-method=provided \
        --screenEmulation.disabled=true \
        --max-wait-for-load=45000 \
        --max-wait-for-fcp=15000 \
        --disable-full-page-screenshot \
        --skip-audits=${skipAudits} \
        --quiet`;
}

app.get("/metrics", async (req, res) => {
    const startTime = Date.now();
    let url = req.query.url;
    
    if (!url) return res.status(400).json({ error: "URL is required" });

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        url = "https://" + url;
    }

    console.log(`Testing: ${url}`);

    const ts = Date.now();
    const mobileFile = path.join(TEMP_DIR, `lh-mobile-${ts}.json`);
    const desktopFile = path.join(TEMP_DIR, `lh-desktop-${ts}.json`);

    // Helper to run single lighthouse test
    const runSingleTest = (cmd, type, outputFile) => {
        return new Promise((resolve, reject) => {
            console.log(`Starting ${type} test...`);
            const testStart = Date.now();
            
            exec(cmd, { timeout: 60000 }, (error, stdout, stderr) => {
                const duration = ((Date.now() - testStart) / 1000).toFixed(2);
                
                if (error) {
                    console.error(`${type} failed after ${duration}s:`, error.message);
                    reject({ type, error: error.message });
                } else {
                    console.log(`${type} completed in ${duration}s`);
                    resolve(outputFile);
                }
            });
        });
    };

    try {
        // Run tests SEQUENTIALLY to avoid Chrome resource contention
        // This prevents Chrome from competing for CPU/memory which can slow both down
        await runSingleTest(generateCommand(url, mobileFile, false), "mobile", mobileFile);
        await runSingleTest(generateCommand(url, desktopFile, true), "desktop", desktopFile);

        // Parse results
        if (!fs.existsSync(mobileFile) || !fs.existsSync(desktopFile)) {
            throw new Error("Lighthouse output files not found");
        }

        const mobileData = JSON.parse(fs.readFileSync(mobileFile, "utf8"));
        const desktopData = JSON.parse(fs.readFileSync(desktopFile, "utf8"));

        // Clean up temp files
        try {
            if (fs.existsSync(mobileFile)) fs.unlinkSync(mobileFile);
            if (fs.existsSync(desktopFile)) fs.unlinkSync(desktopFile);
        } catch (unlinkError) {
            console.warn("Error deleting temp files:", unlinkError);
        }

        const metricsMobile = extractMetrics(mobileData, "Mobile");
        const metricsDesktop = extractMetrics(desktopData, "Desktop");

        const audits = mobileData.audits || {};
        const summary = parseResourceSummary(audits["resource-summary"]);

        const sizes = {
            html: summary.document || { transfer: 0, decoded: 0 },
            css: summary.stylesheet || { transfer: 0, decoded: 0 },
            js: summary.script || { transfer: 0, decoded: 0 },
            images: summary.image || { transfer: 0, decoded: 0 },
            other: summary.other || { transfer: 0, decoded: 0 }
        };

        const serverResponseMs = audits["server-response-time"]?.numericValue || 0;
        const domSizeVal = audits["dom-size"]?.numericValue || 0;
        const mainThreadVal = audits["mainthread-work-breakdown"]?.numericValue || 0;

        const output = {
            ...metricsMobile,
            ...metricsDesktop,
            "Server Response Time (s)": +(serverResponseMs / 1000).toFixed(3),
            "DOM Elements": Math.round(domSizeVal),
            "Main Thread Work (s)": +(mainThreadVal / 1000).toFixed(3),

            // Transfer sizes
            "HTML Size (MB)": bytesToMB(sizes.html.transfer),
            "CSS Size (MB)": bytesToMB(sizes.css.transfer),
            "JS Size (MB)": bytesToMB(sizes.js.transfer),
            "Image Size (MB)": bytesToMB(sizes.images.transfer),
            "Other Size (MB)": bytesToMB(sizes.other.transfer),
            "Total Page Size (MB)": bytesToMB(
                sizes.html.transfer + sizes.css.transfer +
                sizes.js.transfer + sizes.images.transfer + sizes.other.transfer
            ),

            // Decoded sizes
            "HTML Decoded Size (MB)": bytesToMB(sizes.html.decoded),
            "CSS Decoded Size (MB)": bytesToMB(sizes.css.decoded),
            "JS Decoded Size (MB)": bytesToMB(sizes.js.decoded),
            "Image Decoded Size (MB)": bytesToMB(sizes.images.decoded),
            "Other Decoded Size (MB)": bytesToMB(sizes.other.decoded),
            
            // Timing info
            "Total Test Time (s)": ((Date.now() - startTime) / 1000).toFixed(2)
        };

        console.log(`✅ Total time: ${output["Total Test Time (s)"]}s`);
        res.json(output);

    } catch (error) {
        console.error("Test failed:", error);
        
        // Clean up temp files if they exist
        try {
            if (fs.existsSync(mobileFile)) fs.unlinkSync(mobileFile);
            if (fs.existsSync(desktopFile)) fs.unlinkSync(desktopFile);
        } catch (e) {
            // Ignore cleanup errors
        }
        
        res.status(500).json({ 
            error: `Lighthouse test failed: ${error.error || error.message}`,
            totalTime: ((Date.now() - startTime) / 1000).toFixed(2) + "s"
        });
    }
});

app.listen(port, () => {
    console.log(`⚡ Fast Lighthouse server running at http://localhost:${port}`);
    console.log(`Example: http://localhost:${port}/metrics?url=example.com`);
});
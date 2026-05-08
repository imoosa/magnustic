// screenshot_server.js  —  OPTIMIZED
const express = require("express");
const { mkdirSync, existsSync } = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");

const app = express();
const PORT = 3002;
const screenshotDir = path.join(__dirname, "screenshots");

// Create screenshots directory on startup (not on every request)
if (!existsSync(screenshotDir)) {
    mkdirSync(screenshotDir, { recursive: true });
}

// Serve screenshots as static files
app.use("/screenshots", express.static(screenshotDir));

// ─── Device configs ───────────────────────────────────────────────────────────
const DEVICES = [
    { name: "desktop", width: 1920, height: 1080 },
    { name: "tablet",  width: 768,  height: 1024 },
    { name: "mobile",  width: 375,  height: 667  }
];

// ─── Browser pool ─────────────────────────────────────────────────────────────
// Reuse a single browser instance across requests instead of launching a new
// one every time. This removes ~3–5s of Chrome startup time per request.
let browserInstance = null;

async function getBrowser() {
    if (browserInstance) {
        try {
            // Verify the existing browser is still alive
            await browserInstance.version();
            return browserInstance;
        } catch (_) {
            // Browser crashed — will relaunch below
            browserInstance = null;
        }
    }

    console.log("Launching Puppeteer browser...");
    browserInstance = await puppeteer.launch({
        headless: "new",
        args: [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",       // prevents crashes in low-memory envs
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-default-apps",
            "--mute-audio"
        ]
    });

    // If the browser crashes, clear the instance so it relaunches next time
    browserInstance.on("disconnected", () => {
        console.warn("Browser disconnected — will relaunch on next request");
        browserInstance = null;
    });

    return browserInstance;
}

// ─── Screenshot helper ────────────────────────────────────────────────────────
/**
 * Takes a screenshot for a single device viewport.
 *
 * KEY CHANGES vs original:
 *  1. waitUntil changed from "networkidle2" → "domcontentloaded"
 *     networkidle2 waits until there are ≤2 network connections for 500ms.
 *     On slow/complex sites this alone can take 30–60s.
 *     domcontentloaded fires as soon as the HTML is parsed — much faster.
 *     We add a short 800ms settle delay after for visual completeness.
 *
 *  2. timeout changed from 0 (infinite) → 20000ms (20s hard cap)
 *     timeout:0 means a broken URL could hang forever, blocking all requests.
 *
 *  3. Pages reuse the shared browser instead of launching a new one each time.
 *     All 3 device screenshots still run via Promise.all (same as original).
 */
async function takeScreenshot(browser, url, device) {
    const page = await browser.newPage();
    try {
        await page.setViewport({ width: device.width, height: device.height });

        // CHANGED: domcontentloaded is much faster than networkidle2
        await page.goto(url, {
            waitUntil: "domcontentloaded",
            timeout: 20000           // 20s max — was 0 (infinite) in original
        });

        // Short settle time so CSS/fonts render before screenshot
        await new Promise(resolve => setTimeout(resolve, 800));

        await page.evaluate(() => window.scrollTo(0, 0));

        const fileName = `${device.name}-${Date.now()}.png`;
        const filePath = path.join(screenshotDir, fileName);

        await page.screenshot({ path: filePath, fullPage: false });

        return `/screenshots/${fileName}`;

    } catch (err) {
        console.error(`Screenshot failed for ${device.name}:`, err.message);
        return null;  // Return null instead of crashing — handled gracefully below
    } finally {
        // Always close the page even if an error occurred
        await page.close().catch(() => {});
    }
}

// ─── Route ────────────────────────────────────────────────────────────────────
app.get("/screenshot", async (req, res) => {
    const url = req.query.url;
    if (!url) {
        return res.status(400).json({ error: "URL is required" });
    }

    console.log(`[${new Date().toISOString()}] Taking screenshots for: ${url}`);
    const t0 = Date.now();

    try {
        const browser = await getBrowser();

        // ── All 3 devices run in TRUE PARALLEL ──────────────────────────────
        // Original code also used Promise.all here — kept the same.
        // The difference: pages now reuse the shared browser (no relaunch cost)
        // and waitUntil is "domcontentloaded" instead of "networkidle2".
        const results = await Promise.all(
            DEVICES.map(device => takeScreenshot(browser, url, device))
        );

        console.log(`Screenshots done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

        // Build response — map results back to device names
        const screenshots = {};
        const baseUrl = "https://seoapp.magnustic.com";

        DEVICES.forEach((device, i) => {
            const filePath = results[i];
            // Only include screenshot if it was captured successfully
            screenshots[device.name] = filePath ? baseUrl + filePath : "";
        });

        return res.json({ screenshots });

    } catch (err) {
        console.error("Screenshot route error:", err.stack || err.message);
        return res.status(500).json({ error: "Failed to capture screenshots: " + err.message });
    }
});

// ─── Cleanup on shutdown ──────────────────────────────────────────────────────
async function shutdown() {
    if (browserInstance) {
        console.log("Closing browser...");
        await browserInstance.close().catch(() => {});
    }
    process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT",  shutdown);

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`✅ Screenshot server running at http://localhost:${PORT}`);

    // Warm up the browser on startup so the first request isn't slow
    getBrowser().then(() => {
        console.log("✅ Browser pre-launched and ready");
    }).catch(err => {
        console.error("Browser pre-launch failed:", err.message);
    });
});

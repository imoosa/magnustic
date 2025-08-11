// screenshot_server.js
const express = require("express");
const { mkdirSync, existsSync } = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");

const app = express();
const PORT = 3002;

// Serve the screenshots folder as static
app.use("/screenshots", express.static(path.join(__dirname, "screenshots")));

// Screenshot route
app.get("/screenshot", async (req, res) => {
    const url = req.query.url;
    if (!url) {
        return res.status(400).json({ error: "URL is required" });
    }

    const devices = [
        { name: "desktop", width: 1920, height: 1080 },
        { name: "tablet", width: 768, height: 1024 },
        { name: "mobile", width: 375, height: 667 }
    ];

    const screenshots = {};

    try {
        // Create screenshots folder if not exists
        const screenshotDir = path.join(__dirname, "screenshots");
        if (!existsSync(screenshotDir)) {
            mkdirSync(screenshotDir);
        }

        // Launch Puppeteer
        const browser = await puppeteer.launch({
            headless: "new",
            args: ["--no-sandbox", "--disable-setuid-sandbox"]
        });

        const page = await browser.newPage();

        for (const device of devices) {
            await page.setViewport({ width: device.width, height: device.height });
            await page.goto(url, { waitUntil: "networkidle2", timeout: 60000 });

            const fileName = `${device.name}-${Date.now()}.png`;
            const filePath = path.join(screenshotDir, fileName);
            await page.evaluate(() => window.scrollTo(0, 0)); // Scroll to top
            await new Promise(resolve => setTimeout(resolve, 1000));
            await page.screenshot({ path: filePath, fullPage: false }); // Capture viewport only


            // Add the path to the response object
            screenshots[device.name] = `/screenshots/${fileName}`;
        }

        await browser.close();
        return res.json({ screenshots });

    } catch (err) {
        console.error("❌ Screenshot capture failed:", err.stack || err);
        return res.status(500).json({ error: "Failed to capture screenshots" });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`✅ Screenshot server running at http://localhost:${PORT}`);
});

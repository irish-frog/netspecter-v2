const { chromium } = require("playwright");
const fs = require("fs");

const site = process.env.NS_SITE.replace(/\/$/, "");
const out = process.env.NS_OUT;
const user = process.env.NS_USER;
const pass = process.env.NS_PASS;

const pages = {
  "dashboard": "/",
  "map": "/map",
  "devices": "/devices",
  "traffic": "/traffic",
  "history": "/history",
  "application-activity": "/applications",
  "blocked-dns": "/blocked",
  "blocked-services": "/blocked-services",
  "ids-alerts": "/ids-alerts",
  "incidents": "/incidents",
  "anomalies": "/anomalies",
  "adguard": "/adguard",
  "unifi": "/unifi",
  "telegram": "/telegram",
  "telemetry": "/telemetry",
  "speed-tests": "/speed-tests",
  "monitor": "/monitor",
  "exports": "/exports",
  "settings": "/settings",
  "health": "/health",
  "backups": "/vault",
  "logs": "/system"
};

(async () => {
  fs.mkdirSync(out, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1600, height: 1000 },
    ignoreHTTPSErrors: true
  });
  const page = await context.newPage();

  await page.goto(site, { waitUntil: "domcontentloaded" });

  const userField = page.locator(
    'input[name="username"], input[name="email"], input[type="email"], input[type="text"]'
  ).first();

  await userField.fill(user);
  await page.locator('input[type="password"]').first().fill(pass);
  await page.locator('button[type="submit"], input[type="submit"]').first().click();

  await page.waitForTimeout(2000);

  for (const [name, path] of Object.entries(pages)) {
    console.log(`Capturing ${name}...`);
    await page.goto(`${site}${path}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(3000);
    await page.screenshot({ path: `${out}\\${name}.png`, fullPage: true });
  }

  await browser.close();
})();

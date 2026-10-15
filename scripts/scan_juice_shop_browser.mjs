import fs from 'node:fs';
import process from 'node:process';
import path from 'node:path';

const base = process.argv[2] || 'http://127.0.0.1:3000';
const output = process.argv[3] || 'reports/juice-shop-browser.json';
const result = { schema_version: '1.0', target: base, status: 'blocked', checks: [], coverage_gaps: [] };
try {
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const response = await page.goto(base, { waitUntil: 'domcontentloaded', timeout: 15000 });
  result.status = 'completed';
  result.checks.push({ name: 'home_page_load', http_status: response?.status() ?? null, title: await page.title() });
  const marker = `security-review-${Date.now()}`;
  await page.goto(`${base}/#/search?q=${encodeURIComponent(marker)}`, { waitUntil: 'domcontentloaded', timeout: 15000 });
  const body = await page.locator('body').innerText();
  result.checks.push({ name: 'search_dom_marker', marker_ref: marker, reflected_in_dom: body.includes(marker) });
  await browser.close();
} catch (error) {
  result.status = 'blocked';
  result.coverage_gaps.push(`Browser check unavailable: ${error?.message || String(error)}`);
}
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({ status: result.status, output }));

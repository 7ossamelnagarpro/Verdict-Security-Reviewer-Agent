#!/usr/bin/env node
// Bounded, same-origin, non-mutating browser crawl. It records coverage and
// server errors; it does not submit forms or click application controls.
import process from 'node:process';

function option(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const baseUrl = option('--base-url', '');
const maxPages = Math.min(20, Math.max(1, Number(option('--max-pages', '12')) || 12));
const output = { schema_version: '1.0', source: 'playwright-browser-runtime', target: baseUrl,
  status: 'blocked', pages_visited: 0, discovered_links: 0, results: [], coverage_gaps: [] };
try {
  const { chromium } = await import('playwright');
  const origin = new URL(baseUrl);
  const rawSeeds = JSON.parse(option('--seed-paths-json', '[]'));
  if (!Array.isArray(rawSeeds) || rawSeeds.length > 20 || rawSeeds.some(path =>
    typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') ||
    path.includes('\\') || path.includes('#') || path.length > 500 || /[\x00-\x1f]/.test(path))) {
    throw new Error('Invalid bounded same-origin browser seed paths');
  }
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: false });
  await context.route('**/*', route => {
    const request = route.request();
    const url = new URL(request.url());
    if ((url.protocol === 'http:' || url.protocol === 'https:') &&
        (url.origin !== origin.origin || request.method() !== 'GET')) return route.abort();
    return route.continue();
  });
  const page = await context.newPage();
  const queue = [new URL(origin).toString(), ...rawSeeds.map(path => new URL(path, origin).toString())];
  const seen = new Set();
  const responseHandler = response => {
    if (response.status() >= 500) {
      output.results.push({ rule_id: 'browser.endpoint-server-error', title: 'Browser-discovered endpoint returned a server error',
        path: new URL(response.url()).pathname || '/', vulnerable: true, severity: 'medium', confidence: 'medium',
        evidence: { status: response.status(), method: response.request().method(), browser_observed: true } });
    }
  };
  page.on('response', responseHandler);
  while (queue.length && seen.size < maxPages) {
    const target = queue.shift();
    const url = new URL(target);
    if (url.origin !== origin.origin || seen.has(url.pathname + url.search)) continue;
    seen.add(url.pathname + url.search);
    try {
      await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 10000 });
      const links = await page.locator('a[href]').evaluateAll(nodes => nodes.map(n => n.href));
      for (const href of links) {
        try {
          const next = new URL(href);
          if (next.origin === origin.origin && !seen.has(next.pathname + next.search) && queue.length < maxPages * 2) queue.push(next.toString());
        } catch {}
      }
    } catch (error) {
      output.coverage_gaps.push(`Could not visit ${url.pathname}: ${String(error).slice(0, 240)}`);
    }
  }
  output.status = 'completed';
  output.pages_visited = seen.size;
  output.discovered_links = queue.length + seen.size;
  output.coverage_gaps.push('Browser crawl is same-origin and GET-only; forms, clicks, OAuth/MFA and destructive workflows were not submitted.');
  await browser.close();
} catch (error) {
  output.coverage_gaps.push('Install the optional Playwright package and browser before enabling browser DAST.');
  output.coverage_gaps.push(String(error).slice(0, 500));
}
console.log(JSON.stringify(output));

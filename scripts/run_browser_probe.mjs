#!/usr/bin/env node
// Bounded, same-origin, single-endpoint browser probe for the Penetration Agent.
//
// Unlike run_browser_dast.mjs (a whole-site crawl), this visits exactly ONE path as exactly ONE
// account, after an optional login that reuses the SAME account schema (login_path/encoding/
// username_field/password_field/session/token_path) as scanners/runtime_workflows.py's Transport —
// no separate credential or login convention is invented here. The browser then renders the page for
// real, which plain HTTP cannot: it also observes any same-origin GET XHR/fetch calls the page itself
// makes while loading (useful when an SPA fetches protected data client-side after the initial document
// loads). Only GET navigation/requests are ever allowed through the page; the login call is the one
// deliberate, declared exception, exactly as in the existing crawler.
import process from 'node:process';

function option(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const baseUrl = option('--base-url', '');
const targetPath = option('--target-path', '/');
const accountJson = option('--account-json', 'null');
const timeoutMs = Math.min(20000, Math.max(1000, Number(option('--timeout-ms', '10000')) || 10000));
const output = { schema_version: '1.0', source: 'playwright-browser-probe', target: baseUrl,
  target_path: targetPath, status: 'blocked', actor: 'anonymous', document_status: null,
  observed_statuses: [], coverage_gaps: [] };

function badPath(value) {
  return typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') ||
    value.includes('\\') || value.includes('#') || value.length > 500 || /[\x00-\x1f]/.test(value);
}

try {
  const { chromium } = await import('playwright');
  const origin = new URL(baseUrl);
  if (badPath(targetPath)) throw new Error('Invalid bounded same-origin target path');
  const account = JSON.parse(accountJson);
  if (account !== null && (typeof account !== 'object' || badPath(account.login_path || '') ||
      !['json', 'form'].includes(account.encoding) || !['bearer', 'cookie'].includes(account.session))) {
    throw new Error('Invalid or unrecognized account definition');
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: false });

  if (account) {
    output.actor = account.id || 'account';
    const username = process.env[`SECURITY_TEST_WF_${(account.id || '').toUpperCase()}_USERNAME`];
    const password = process.env[`SECURITY_TEST_WF_${(account.id || '').toUpperCase()}_PASSWORD`];
    if (!username || !password) throw new Error('Test account credentials are not set in the environment');
    const body = { [account.username_field]: username, [account.password_field]: password };
    // context.request is a separate API client; it is NOT subject to the page's GET-only route
    // filter below, exactly as the login step is the declared exception in the HTTP-only executor.
    const response = await context.request.post(new URL(account.login_path, origin).toString(),
      account.encoding === 'json' ? { data: body } : { form: body });
    if (!response.ok()) throw new Error(`Login failed with HTTP ${response.status()}`);
    if (account.session === 'bearer') {
      const data = await response.json().catch(() => ({}));
      const token = (account.token_path || 'access_token').split('.').reduce((acc, key) => (acc ?? {})[key], data);
      if (!token) throw new Error('Login response did not contain the expected token field');
      await context.setExtraHTTPHeaders({ Authorization: `Bearer ${token}` });
    }
    // session === "cookie": context.request already stored any Set-Cookie in the shared cookie jar.
  }

  await context.route('**/*', route => {
    const request = route.request();
    const url = new URL(request.url());
    if ((url.protocol === 'http:' || url.protocol === 'https:') &&
        (url.origin !== origin.origin || request.method() !== 'GET')) return route.abort();
    return route.continue();
  });
  const page = await context.newPage();
  page.on('response', response => {
    try {
      const url = new URL(response.url());
      if (url.origin !== origin.origin) return;
      output.observed_statuses.push({ path: url.pathname, status: response.status(),
        is_document: response.request().resourceType() === 'document' });
    } catch {}
  });
  const navigation = await page.goto(new URL(targetPath, origin).toString(),
    { waitUntil: 'networkidle', timeout: timeoutMs });
  output.document_status = navigation ? navigation.status() : null;
  await page.waitForTimeout(250);  // let any just-started same-origin fetch/XHR resolve and get recorded
  output.status = 'completed';
  await browser.close();
} catch (error) {
  output.status = 'blocked';
  output.coverage_gaps.push(String(error).slice(0, 500));
}
process.stdout.write(JSON.stringify(output) + '\n');

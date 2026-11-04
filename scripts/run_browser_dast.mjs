#!/usr/bin/env node
// Bounded same-origin crawl with optional verified test-account sessions.
import process from 'node:process';

function option(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

function localPath(path) {
  return typeof path === 'string' && path.startsWith('/') && !path.startsWith('//') &&
    !path.includes('\\') && !path.includes('#') && path.length <= 500 && !/[\x00-\x20]/.test(path);
}

function field(value, path) {
  return path.split('.').reduce((current, part) => current?.[part], value);
}

function validAccount(a) {
  return a && /^[a-z][a-z0-9_]{0,31}$/.test(a.id || '') &&
    localPath(a.login_path) && localPath(a.verify_path) &&
    ['json', 'form'].includes(a.encoding) && ['bearer', 'cookie'].includes(a.session) &&
    [a.username_field, a.password_field, a.identity_path].every(
      value => typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/.test(value)) &&
    (a.session !== 'bearer' || /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/.test(a.token_path || ''));
}

const baseUrl = option('--base-url', '');
const maxPages = Math.min(20, Math.max(1, Number(option('--max-pages', '12')) || 12));
const output = { schema_version: '1.0', source: 'playwright-browser-runtime', target: baseUrl,
  status: 'blocked', pages_visited: 0, discovered_links: 0, results: [], accounts: [],
  observed_requests: [], observed_forms: [], blocked_write_requests: 0, coverage_gaps: [] };

try {
  const { chromium } = await import('playwright');
  const origin = new URL(baseUrl);
  const seeds = JSON.parse(option('--seed-paths-json', '[]'));
  const accounts = JSON.parse(option('--accounts-json', '[]'));
  if (!Array.isArray(seeds) || seeds.length > 20 || seeds.some(path => !localPath(path)) ||
      !Array.isArray(accounts) || accounts.length > 8 || accounts.some(a => !validAccount(a)) ||
      new Set(accounts.map(a => a.id)).size !== accounts.length) {
    throw new Error('InvalidBrowserConfiguration');
  }
  const browser = await chromium.launch({ headless: true });
  const requestKeys = new Set();
  const formKeys = new Set();
  try {
    for (const account of [null, ...accounts]) {
      const actor = account?.id || 'anonymous';
      const context = await browser.newContext({ ignoreHTTPSErrors: false });
      try {
        await context.route('**/*', route => {
          const request = route.request();
          let url;
          try { url = new URL(request.url()); } catch { return route.abort(); }
          if (url.origin === origin.origin && request.method() !== 'GET') output.blocked_write_requests += 1;
          if (!['http:', 'https:'].includes(url.protocol) ||
              url.origin !== origin.origin || request.method() !== 'GET') return route.abort();
          return route.continue();
        });
        if (account) {
          const prefix = `SECURITY_TEST_WF_${actor.toUpperCase()}_`;
          const username = process.env[`${prefix}USERNAME`];
          const password = process.env[`${prefix}PASSWORD`];
          if (!username || !password) throw new Error('credentials_missing');
          const credentials = { [account.username_field]: username, [account.password_field]: password };
          const login = await context.request.post(new URL(account.login_path, origin).toString(),
            account.encoding === 'form' ? { form: credentials, maxRedirects: 0, timeout: 5000 } :
              { data: credentials, maxRedirects: 0, timeout: 5000 });
          if (!login.ok()) throw new Error('login_rejected');
          let headers = {};
          if (account.session === 'bearer') {
            const token = field(await login.json(), account.token_path);
            if (typeof token !== 'string' || !token || token.length > 8192 || /[\x00-\x1f]/.test(token)) {
              throw new Error('invalid_token');
            }
            headers = { Authorization: `Bearer ${token}` };
          }
          const identity = await context.request.get(new URL(account.verify_path, origin).toString(),
            { headers, maxRedirects: 0, timeout: 5000 });
          if (identity.status() !== 200 || String(field(await identity.json(), account.identity_path)) !== username) {
            throw new Error('identity_mismatch');
          }
          if (account.session === 'bearer') await context.setExtraHTTPHeaders(headers);
          output.accounts.push({ actor, status: 'verified' });
        }

        const page = await context.newPage();
        const queue = [origin.toString(), ...seeds.map(path => new URL(path, origin).toString())];
        const seen = new Set();
        page.on('response', response => {
          const url = new URL(response.url());
          if (url.origin !== origin.origin) return;
          const resourceType = response.request().resourceType();
          if (['document', 'fetch', 'xhr'].includes(resourceType)) {
            const record = { actor, method: response.request().method(), path: url.pathname || '/',
              status: response.status(), resource_type: resourceType };
            const key = JSON.stringify(record);
            if (!requestKeys.has(key) && output.observed_requests.length < 160) {
              requestKeys.add(key);
              output.observed_requests.push(record);
            }
          }
          if (response.status() >= 500 && output.results.length < 80) {
            output.results.push({ rule_id: 'browser.endpoint-server-error', title: 'Browser-discovered endpoint returned a server error',
              path: url.pathname || '/', vulnerable: true, severity: 'medium', confidence: 'medium',
              evidence: { actor, status: response.status(), method: response.request().method(), browser_observed: true } });
          }
        });
        while (queue.length && seen.size < maxPages) {
          const target = queue.shift();
          const url = new URL(target);
          if (url.origin !== origin.origin || seen.has(url.pathname + url.search)) continue;
          seen.add(url.pathname + url.search);
          try {
            await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 10000 });
            await page.waitForTimeout(150);
            const forms = await page.locator('form').evaluateAll(nodes => nodes.map(form => ({
              action: form.action, method: form.method.toUpperCase(),
              fields: [...form.elements].filter(item => item.name).map(item =>
                ({ name: item.name.slice(0, 100), type: (item.type || '').slice(0, 40) })).slice(0, 20),
            })));
            for (const form of forms) {
              const action = new URL(form.action, origin);
              if (action.origin !== origin.origin) continue;
              const record = { actor, path: action.pathname || '/', method: form.method, fields: form.fields,
                status: 'proposal_requires_review' };
              const key = JSON.stringify(record);
              if (!formKeys.has(key) && output.observed_forms.length < 80) {
                formKeys.add(key);
                output.observed_forms.push(record);
              }
            }
            const links = await page.locator('a[href]').evaluateAll(nodes => nodes.map(node => node.href));
            for (const href of links) {
              try {
                const next = new URL(href);
                if (next.origin === origin.origin && !seen.has(next.pathname + next.search) && queue.length < maxPages * 2) {
                  queue.push(next.toString());
                }
              } catch {}
            }
          } catch {
            output.coverage_gaps.push(`Could not visit ${url.pathname} for ${actor}.`);
          }
        }
        output.pages_visited += seen.size;
        output.discovered_links += queue.length + seen.size;
      } catch {
        if (account) {
          output.accounts.push({ actor, status: 'blocked', reason: 'login_or_identity_failed' });
          output.coverage_gaps.push(`Authenticated browser crawl was unavailable for ${actor}.`);
        } else {
          output.coverage_gaps.push('Anonymous browser crawl could not start.');
        }
      } finally {
        await context.close();
      }
    }
    output.status = output.coverage_gaps.length ? 'partial' : 'completed';
  } finally {
    await browser.close();
  }
} catch (error) {
  output.coverage_gaps.push('Browser crawl could not start; check the Playwright package, browser and local runtime.');
  output.coverage_gaps.push(error?.name || 'BrowserStartupError');
}
console.log(JSON.stringify(output));

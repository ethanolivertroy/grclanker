#!/usr/bin/env node
// Checks the built site in dist/ for broken internal links and docs pages
// missing from the sidebar. `--external` also probes external links and
// reports (never fails on) the results.
//
// Usage: node scripts/check-links.mjs [--external] [distDir]

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const args = process.argv.slice(2);
const checkExternal = args.includes('--external');
const distDir = args.find((arg) => !arg.startsWith('--')) ?? 'dist';

const LINK_ATTRS = new Set(['href', 'src', 'srcset', 'poster']);
const SKIP_SCHEMES = /^(mailto|tel|javascript|data|blob):/i;
const EXTERNAL = /^(https?:)?\/\//i;
const ORIGIN = 'https://site.invalid';

// Generated FedRAMP detail pages are reached from their hub page, not the
// sidebar (see cli/scripts/sync-fedramp.ts).
const HUB_LINKED = [
  { prefix: '/docs/fedramp/ksi/', hub: '/docs/fedramp/ksis/' },
  { prefix: '/docs/fedramp/processes/', hub: '/docs/fedramp/processes/' },
];

const EXTERNAL_TIMEOUT_MS = 10000;
const EXTERNAL_CONCURRENCY = 8;
// Bot walls and rate limits, not proof that a page is gone.
const BLOCKED_STATUSES = new Set([401, 403, 429, 999]);

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

function decodeEntities(value) {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function parseTags(html) {
  const markup = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, '');
  const tagPattern = /<([a-zA-Z][\w-]*)((?:\s+[^\s"'>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*\/?>/g;
  const attrPattern = /([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  const tags = [];
  for (const [, name, rawAttrs] of markup.matchAll(tagPattern)) {
    const attrs = {};
    for (const [, key, dq, sq, bare] of rawAttrs.matchAll(attrPattern)) {
      attrs[key.toLowerCase()] = decodeEntities(dq ?? sq ?? bare ?? '');
    }
    tags.push({ name: name.toLowerCase(), attrs });
  }
  return tags;
}

function linksFrom(tags) {
  const links = [];
  for (const { name, attrs } of tags) {
    for (const [key, value] of Object.entries(attrs)) {
      if (!LINK_ATTRS.has(key)) continue;
      const refs = key === 'srcset'
        ? value.split(',').map((part) => part.trim().split(/\s+/)[0])
        : [value.trim()];
      for (const ref of refs) {
        if (ref) links.push({ ref, tag: name, rel: attrs.rel ?? '' });
      }
    }
  }
  return links;
}

function pageUrl(file) {
  const path = '/' + relative(distDir, file).split(sep).join('/');
  return path.endsWith('/index.html') ? path.slice(0, -'index.html'.length) : path;
}

// Mirrors Workers static assets `html_handling: auto-trailing-slash`, which
// serves /a/b from /a/b.html or /a/b/index.html. Anything else gets the
// `not_found_handling: 404-page` response, so a miss here is a broken link.
function resolveTarget(pathname, files) {
  const candidates = pathname.endsWith('/')
    ? [`${pathname}index.html`]
    : [pathname, `${pathname}.html`, `${pathname}/index.html`];
  return candidates.find((candidate) => files.has(candidate));
}

function canonicalPage(pathname, files) {
  const target = resolveTarget(pathname, files);
  return target?.endsWith('.html') ? pageUrl(join(distDir, target)) : undefined;
}

if (!existsSync(distDir)) {
  console.error(`check-links: ${distDir}/ not found; run \`npm run build\` first.`);
  process.exit(1);
}

const started = Date.now();
const allFiles = walk(distDir);
const files = new Set(allFiles.map((file) => '/' + relative(distDir, file).split(sep).join('/')));
const pages = new Map();
for (const file of allFiles.filter((path) => path.endsWith('.html'))) {
  const tags = parseTags(readFileSync(file, 'utf8'));
  const ids = new Set();
  for (const { name, attrs } of tags) {
    if (attrs.id) ids.add(attrs.id);
    if (name === 'a' && attrs.name) ids.add(attrs.name);
  }
  pages.set(pageUrl(file), { file: relative('.', file), tags, ids, links: linksFrom(tags) });
}

const problems = [];
const external = new Map();
const inbound = new Map();
let internalCount = 0;

for (const [url, page] of pages) {
  for (const { ref, rel } of page.links) {
    if (SKIP_SCHEMES.test(ref)) continue;
    if (EXTERNAL.test(ref)) {
      if (/\b(preconnect|dns-prefetch)\b/.test(rel)) continue;
      const target = new URL(ref, ORIGIN);
      target.hash = '';
      const href = target.href;
      if (!external.has(href)) external.set(href, new Set());
      external.get(href).add(page.file);
      continue;
    }
    internalCount += 1;
    const target = new URL(ref, ORIGIN + url);
    const pathname = decodeURIComponent(target.pathname);
    const fragment = decodeURIComponent(target.hash.slice(1));
    const resolved = resolveTarget(pathname, files);
    if (!resolved) {
      problems.push(`${page.file}: ${ref} (no built file)`);
      continue;
    }
    const targetUrl = canonicalPage(pathname, files);
    if (targetUrl && targetUrl !== url) {
      if (!inbound.has(targetUrl)) inbound.set(targetUrl, new Set());
      inbound.get(targetUrl).add(url);
    }
    if (fragment && fragment !== 'top' && targetUrl && !pages.get(targetUrl).ids.has(fragment)) {
      problems.push(`${page.file}: ${ref} (no id="${fragment}" on ${targetUrl})`);
    }
  }
}

const sidebar = new Set();
const docsIndexFile = join(distDir, 'docs', 'index.html');
const sidebarNav = existsSync(docsIndexFile)
  ? readFileSync(docsIndexFile, 'utf8').match(/<nav class="docs-sidebar-nav"[\s\S]*?<\/nav>/)?.[0]
  : undefined;
for (const { ref } of linksFrom(parseTags(sidebarNav ?? ''))) {
  sidebar.add(canonicalPage(new URL(ref, ORIGIN).pathname, files));
}
if (sidebar.size === 0) problems.push(`${docsIndexFile}: no docs sidebar links found`);

for (const url of pages.keys()) {
  if (!url.startsWith('/docs/') || sidebar.has(url)) continue;
  const hubRule = HUB_LINKED.find(({ prefix }) => url.startsWith(prefix));
  if (!hubRule) {
    problems.push(`${pages.get(url).file}: not in the docs sidebar (src/lib/docs.ts docsSections)`);
  } else if (!inbound.get(url)?.has(hubRule.hub)) {
    problems.push(`${pages.get(url).file}: not linked from its hub page ${hubRule.hub}`);
  }
}

console.log(
  `check-links: ${pages.size} pages, ${internalCount} internal links, ` +
  `${sidebar.size} sidebar entries, ${external.size} unique external URLs ` +
  `(${Date.now() - started}ms)`,
);

if (checkExternal) await reportExternal(external);

if (problems.length > 0) {
  console.error(`\ncheck-links: ${problems.length} problem(s):`);
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}
console.log('check-links: no broken internal links or orphaned docs pages');

async function probe(url) {
  for (const method of ['HEAD', 'GET']) {
    try {
      const res = await fetch(url, {
        method,
        redirect: 'follow',
        signal: AbortSignal.timeout(EXTERNAL_TIMEOUT_MS),
        headers: { 'user-agent': 'grclanker-link-check (+https://grclanker.com)' },
      });
      await res.body?.cancel();
      if (method === 'HEAD' && res.status >= 400) continue;
      return { status: res.status, finalUrl: res.url };
    } catch (error) {
      if (method === 'GET') return { error: error.cause?.code ?? error.name };
    }
  }
}

async function reportExternal(urls) {
  const queue = [...urls.keys()].sort();
  const results = new Map();
  const worker = async () => {
    while (queue.length > 0) {
      const url = queue.shift();
      results.set(url, await probe(url));
    }
  };
  await Promise.all(Array.from({ length: EXTERNAL_CONCURRENCY }, worker));

  const groups = { broken: [], blocked: [], redirected: [], ok: [] };
  for (const [url, result] of [...results].sort(([a], [b]) => a.localeCompare(b))) {
    const where = [...urls.get(url)].sort().join(', ');
    if (BLOCKED_STATUSES.has(result.status)) {
      groups.blocked.push(`${result.status} ${url}`);
    } else if (result.error || result.status >= 400) {
      groups.broken.push(`${result.error ?? result.status} ${url}\n      on ${where}`);
    } else if (result.finalUrl !== url) {
      groups.redirected.push(`${result.status} ${url} -> ${result.finalUrl}`);
    } else {
      groups.ok.push(url);
    }
  }
  console.log(
    `\ncheck-links --external: ${results.size} URLs, ${groups.ok.length} ok, ` +
    `${groups.redirected.length} redirected, ${groups.blocked.length} blocked or rate-limited, ` +
    `${groups.broken.length} broken or unreachable (reported, not failed)`,
  );
  for (const title of ['broken', 'blocked', 'redirected']) {
    if (groups[title].length === 0) continue;
    console.log(`\n  ${title}:`);
    for (const line of groups[title]) console.log(`    ${line}`);
  }
}

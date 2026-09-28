import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkSite, parseSrcset, parseTags, resolveTarget } from './check-links.mjs';

const script = join(dirname(fileURLToPath(import.meta.url)), 'check-links.mjs');
const fixtures = [];

after(() => {
  for (const dir of fixtures) rmSync(dir, { recursive: true, force: true });
});

const sidebar = `
  <nav class="docs-sidebar-nav">
    <a href="/docs">Overview</a>
    <a href="/docs/guide">Guide</a>
    <a href="/docs/hub">Hub</a>
  </nav>`;

function site(files) {
  const dir = mkdtempSync(join(tmpdir(), 'check-links-'));
  fixtures.push(dir);
  const all = {
    'docs/index.html': `<main id="main">${sidebar}</main>`,
    'docs/guide/index.html': `${sidebar}<h2 id="setup">Setup</h2>`,
    'docs/hub/index.html': `${sidebar}<a href="/docs/hub/detail/">Detail</a>`,
    'docs/hub/detail/index.html': sidebar,
    ...files,
  };
  for (const [path, contents] of Object.entries(all)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), contents);
  }
  return dir;
}

const hubs = [{ prefix: '/docs/hub/', hub: '/docs/hub/' }];

function problemsFor(files, options = {}) {
  return checkSite({ distDir: site(files), hubs, ...options }).problems;
}

test('resolveTarget mirrors the Workers auto-trailing-slash table', () => {
  const files = new Set(['/index.html', '/file.html', '/folder/index.html', '/install']);
  for (const path of ['/file', '/file.html', '/file/', '/file/index', '/file/index.html']) {
    assert.equal(resolveTarget(path, files), '/file.html', path);
  }
  for (const path of ['/folder', '/folder.html', '/folder/', '/folder/index', '/folder/index.html']) {
    assert.equal(resolveTarget(path, files), '/folder/index.html', path);
  }
  assert.equal(resolveTarget('/', files), '/index.html');
  assert.equal(resolveTarget('/install', files), '/install');
  for (const path of ['/missing', '/file/other', '/file.htm', '/install/', '/folder/file']) {
    assert.equal(resolveTarget(path, files), undefined, path);
  }
});

test('resolveTarget matches Workers when x.html and x/index.html both exist', () => {
  const files = new Set(['/dual.html', '/dual/index.html']);
  const expected = {
    '/dual': '/dual.html',
    '/dual.html': '/dual.html',
    '/dual/': '/dual/index.html',
    '/dual/index': '/dual/index.html',
    '/dual/index.html': '/dual/index.html',
  };
  for (const [path, target] of Object.entries(expected)) {
    assert.equal(resolveTarget(path, files), target, path);
  }
});

test('fragments on colliding pages are checked against the page Workers serves', () => {
  const problems = problemsFor({
    'dual.html': '<h2 id="standalone">Standalone</h2>',
    'dual/index.html': '<h2 id="folder">Folder</h2>',
    'page/index.html': `
      <a href="/dual#standalone">ok</a>
      <a href="/dual.html#standalone">ok</a>
      <a href="/dual/#folder">ok</a>
      <a href="/dual/index#folder">ok</a>
      <a href="/dual/index.html#folder">ok</a>
      <a href="/dual#folder">bad</a>
      <a href="/dual/#standalone">bad</a>`,
  });
  assert.equal(problems.length, 2);
  assert.match(problems[0], /\/dual#folder \(no id="folder" on \/dual\.html\)/);
  assert.match(problems[1], /\/dual\/#standalone \(no id="standalone" on \/dual\/index\.html\)/);
});

test('raw-text element bodies are ignored but their opening tags are checked', () => {
  const tags = parseTags(`
    <script src="/app.js">const link = '<a href="/in-script">';</script>
    <style media="screen">a { background: url(/in-style.png); }</style>
    <textarea><a href="/in-textarea"></a></textarea>
    <title><a href="/in-title"></a></title>
    <!-- <a href="/in-comment"></a> -->
    <template><a href="/in-template"></a></template>`);
  const refs = tags.flatMap(({ attrs }) => attrs.href ?? attrs.src ?? []);
  assert.deepEqual(refs, ['/app.js', '/in-template']);

  const problems = problemsFor({ 'page/index.html': '<script src="/missing.js"></script>' });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /\/missing\.js \(no built file\)/);
});

test('parseSrcset follows the HTML candidate rules', () => {
  assert.deepEqual(parseSrcset('/a.png 1x, /b.png 2x'), ['/a.png', '/b.png']);
  assert.deepEqual(parseSrcset('/images/with,comma.png 1x'), ['/images/with,comma.png']);
  assert.deepEqual(parseSrcset('data:image/png;base64,AAAA 1x, /b.png 2x'), ['data:image/png;base64,AAAA', '/b.png']);
  assert.deepEqual(parseSrcset('/a.png,, /b.png'), ['/a.png', '/b.png']);
  assert.deepEqual(parseSrcset('/a.png (w, h) 2x, /b.png'), ['/a.png', '/b.png']);
});

test('srcset URLs with commas and data URLs resolve', () => {
  const ok = problemsFor({
    'images/with,comma.png': '',
    'page/index.html': '<img srcset="/images/with,comma.png 1x, data:image/png;base64,AAAA 2x, /images/with%2Ccomma.png 3x">',
  });
  assert.deepEqual(ok, []);
  const bad = problemsFor({ 'page/index.html': '<img srcset="/images/with,comma.png 1x">' });
  assert.equal(bad.length, 1);
  assert.match(bad[0], /\/images\/with,comma\.png \(no built file\)/);
});

test('fragments are decoded and checked on the target page', () => {
  const problems = problemsFor({
    'page/index.html': `
      <h2 id="hello world">Hello</h2>
      <a href="#hello%20world">ok</a>
      <a href="/docs/guide#setup">ok</a>
      <a href="/docs/guide/#setup">ok</a>
      <a href="/docs/guide?tab=cli#setup">ok</a>
      <a href="#top">ok</a>
      <a href="/docs/guide#missing">bad</a>
      <a href="#nope">bad</a>`,
  });
  assert.equal(problems.length, 2);
  assert.match(problems[0], /\/docs\/guide#missing \(no id="missing" on \/docs\/guide\/index\.html\)/);
  assert.match(problems[1], /#nope \(no id="nope"/);
});

test('relative links, query strings, and public files resolve', () => {
  const problems = problemsFor({
    install: '#!/bin/sh',
    'og-card.jpg': '',
    'standalone.html': '<a href="docs/guide/">ok</a>',
    'page/index.html': `
      <a href="../docs/guide/">ok</a>
      <a href="/install">ok</a>
      <a href="/og-card.jpg?v=2">ok</a>
      <a href="/standalone/">ok</a>
      <a href="/docs/guide.html">ok</a>
      <a href="../missing/">bad</a>`,
  });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /\.\.\/missing\/ \(no built file\)/);
});

test('docs pages must be in the sidebar or linked from their hub', () => {
  const orphan = problemsFor({ 'docs/orphan/index.html': sidebar });
  assert.equal(orphan.length, 1);
  assert.match(orphan[0], /docs\/orphan\/index\.html: not in the docs sidebar/);

  const unlinked = problemsFor({ 'docs/hub/index.html': sidebar });
  assert.equal(unlinked.length, 1);
  assert.match(unlinked[0], /docs\/hub\/detail\/index\.html: not linked from its hub page \/docs\/hub\//);

  const noHubRule = checkSite({ distDir: site({}), hubs: [] }).problems;
  assert.equal(noHubRule.length, 1);
  assert.match(noHubRule[0], /docs\/hub\/detail\/index\.html: not in the docs sidebar/);
});

test('the CLI exits 1 on problems and 0 on a clean site', () => {
  const broken = site({ 'page/index.html': '<a href="/nowhere">x</a>' });
  const brokenRun = spawnSync(process.execPath, [script, broken], { encoding: 'utf8' });
  assert.equal(brokenRun.status, 1);
  assert.match(brokenRun.stderr, /\/nowhere \(no built file\)/);

  const minimal = mkdtempSync(join(tmpdir(), 'check-links-'));
  fixtures.push(minimal);
  mkdirSync(join(minimal, 'docs'));
  writeFileSync(join(minimal, 'docs', 'index.html'), '<nav class="docs-sidebar-nav"><a href="/docs/">Docs</a></nav>');
  const okRun = spawnSync(process.execPath, [script, minimal], { encoding: 'utf8' });
  assert.equal(okRun.status, 0, okRun.stderr);
  assert.match(okRun.stdout, /no broken internal links/);
});

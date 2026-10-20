import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

const home = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');
const about = readFileSync(new URL('../src/app/about/page.tsx', import.meta.url), 'utf8');
const rail = readFileSync(new URL('../src/components/hero-images.tsx', import.meta.url), 'utf8');
const install = readFileSync(new URL('../src/components/hero-install.tsx', import.meta.url), 'utf8');
const llms = readFileSync(new URL('../public/llms.txt', import.meta.url), 'utf8');

test('homepage workflow states match the shipped prompts', () => {
  assert.match(
    home,
    /satisfied, partially satisfied, not satisfied, or unable to assess/,
  );
  assert.match(home, /strong, mixed, at risk, or critical/);
  assert.match(
    home,
    /actively validated, previously validated but expired, in process, or not found/,
  );
  assert.doesNotMatch(home, /unverifiable/);
  assert.doesNotMatch(home, /partial, absent/);
});

test('runtime path lists count the durable runtime', () => {
  const lists = [...`${home}\n${about}`.matchAll(/Pi, Cursor Agent SDK,[^.']*?runtime\s+paths/g)].map((match) => match[0]);
  assert.equal(lists.length, 3);
  for (const list of lists) assert.match(list, /experimental durable runtime/);
  assert.match(home, /label: 'Four runtime paths'/);
});

test('the install command stays in the button name', () => {
  assert.match(install, /aria-label=\{`Copy install command: \$\{command\}`\}/);
});

test('llms.txt raw spec URLs use the published repository', () => {
  const urls = [...llms.matchAll(/https:\/\/raw\.githubusercontent\.com\/([^/]+\/[^/]+)\/main\/specs\/([^)\s]+\.spec\.md)/g)];
  assert.ok(urls.length >= 35);
  assert.deepEqual([...new Set(urls.map((match) => match[1]))], ['ethanolivertroy/grclanker']);
  assert.equal(urls.filter((match) => match[2] === 'veracode-sec-inspector.spec.md').length, 1);
  assert.equal(new Set(urls.map((match) => match[2])).size, urls.length);
  assert.match(llms, /except Vanta/);
});

test('pages reference image files that exist', () => {
  const sources = [home, about, rail];
  const paths = sources.flatMap((source) => [...source.matchAll(/['"](\/[^'"]+\.(?:webp|png|jpe?g))['"]/g)].map((match) => match[1]));
  assert.ok(paths.length >= 8);
  for (const path of paths) {
    assert.equal(existsSync(new URL(`../public${path}`, import.meta.url)), true, path);
  }
  assert.equal(existsSync(new URL('../public/hero/grclanker-terminal.png', import.meta.url)), false);
  assert.equal(existsSync(new URL('../public/hero/assembly.webp', import.meta.url)), false);
  assert.equal(existsSync(new URL('../public/hero/cockpit.webp', import.meta.url)), false);
});

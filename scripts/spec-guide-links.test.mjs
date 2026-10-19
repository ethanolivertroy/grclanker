import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { getSpecGuideSlug, loadSpecs, specGuideOverrides } from '../src/lib/specs.ts';

const DOCS_DIR = join('src', 'content', 'docs', 'docs');
const specs = loadSpecs();

function guideFile(slug) {
  const base = join(DOCS_DIR, getSpecGuideSlug(slug));
  return [`${base}.md`, `${base}.mdx`].find((file) => existsSync(file));
}

test('every spec page links to a guide that exists', () => {
  assert.ok(specs.length > 0);
  for (const { slug } of specs) {
    assert.ok(guideFile(slug), `${slug} has no guide at ${getSpecGuideSlug(slug)}`);
  }
});

test('every guide links back to its spec page', () => {
  for (const { slug } of specs) {
    const markdown = readFileSync(guideFile(slug), 'utf8');
    assert.ok(markdown.includes(`](/specs/${slug}/)`), `${getSpecGuideSlug(slug)} does not link to /specs/${slug}/`);
  }
});

test('no two specs share a guide, and each override replaces the default guide', () => {
  const guides = specs.map(({ slug }) => getSpecGuideSlug(slug));
  assert.equal(new Set(guides).size, guides.length);
  for (const [slug, guide] of Object.entries(specGuideOverrides)) {
    assert.ok(specs.some((spec) => spec.slug === slug), `override for unknown spec ${slug}`);
    assert.notEqual(guide, `integrations/${slug.replace(/-sec-inspector$/, '')}`);
  }
});

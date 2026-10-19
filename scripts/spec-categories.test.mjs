import assert from 'node:assert/strict';
import { test } from 'node:test';

import { categoryAliases, categoryLabels, getCategoryLabel, groupSpecsByCategory, loadSpecs } from '../src/lib/specs.ts';

const specs = loadSpecs();
const isGroup = (key) => Object.hasOwn(categoryLabels, key);

test('every spec category is a catalog group or maps to one', () => {
  assert.ok(specs.length > 0);
  const unmapped = specs.filter(({ category }) => !isGroup(category) && !Object.hasOwn(categoryAliases, category));
  assert.equal(
    unmapped.length,
    0,
    `Add each of these categories to categoryAliases in src/lib/specs.ts with the catalog group it belongs to: ${unmapped
      .map(({ slug, category }) => `"${category}" (${slug})`)
      .join(', ')}`,
  );
});

test('the catalog lists every spec exactly once', () => {
  const listed = Object.values(groupSpecsByCategory(specs)).flatMap((group) => group.specs.map((spec) => spec.slug));
  assert.deepEqual(listed.sort(), specs.map((spec) => spec.slug).sort());
});

test('each alias names a catalog group and is not one itself', () => {
  for (const [alias, key] of Object.entries(categoryAliases)) {
    assert.ok(isGroup(key), `${alias} maps to ${key}, which is not a catalog group`);
    assert.ok(!isGroup(alias), `${alias} is already a catalog group`);
  }
});

test('spec pages and search show a group label, not a category name', () => {
  const labels = new Set(Object.values(categoryLabels));
  for (const { slug, category } of specs) {
    assert.ok(labels.has(getCategoryLabel(category)), `${slug} shows "${getCategoryLabel(category)}"`);
  }
});

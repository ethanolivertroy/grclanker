import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { getCategoryLabel, groupSpecsByCategory, loadSpecCatalog, parseFrontmatter } from '../src/lib/specs.ts';

const fields = {
  slug: 'example', name: 'Example', vendor: 'Example', category: 'cloud',
  language: 'language-neutral', status: 'generated', version: '1.0',
  source_repo: 'https://github.com/example/project', last_updated: '2026-11-07',
};
const markdown = (values = fields) => ['---', ...Object.entries(values).map(([key, value]) => `${key}: ${JSON.stringify(value)}`), '---', '', 'Body.'].join('\n');

function directory(run) {
  const path = mkdtempSync(join(tmpdir(), 'grclanker-spec-metadata-'));
  try { run(path); } finally { rmSync(path, { recursive: true, force: true }); }
}

test('generated JSON-quoted frontmatter round-trips escapes and multiline strings', () => {
  const name = 'Example "quoted" name: backslash \\ and\nsecond line';
  const { meta, content } = parseFrontmatter(markdown({ ...fields, name }));
  assert.equal(meta.name, name);
  assert.equal(meta.category, 'cloud');
  assert.equal(getCategoryLabel(meta.category), 'Cloud Infrastructure');
  assert.equal(content, '\nBody.');
});

test('authored YAML quoting is decoded rather than stripped', () => {
  const source = markdown().replace('name: "Example"', "name: 'Owner''s Example'");
  assert.equal(parseFrontmatter(source.replaceAll('\n', '\r\n')).meta.name, "Owner's Example");
});

test('invalid metadata fails at the collection boundary', () => {
  const { vendor: _missing, ...missingVendor } = fields;
  assert.throws(() => parseFrontmatter(markdown(missingVendor)), /vendor/);
  assert.throws(() => parseFrontmatter(markdown({ ...fields, slug: 42 })), /slug/);
  assert.throws(() => parseFrontmatter(markdown({ ...fields, last_updated: '2026-02-30' })), /date/);
  assert.throws(() => parseFrontmatter(markdown({ ...fields, category: 'unmapped-new-category' })), /Unknown spec category/);
  assert.throws(() => parseFrontmatter(markdown({ ...fields, source_repo: 'javascript:alert(1)' })), /HTTP/);
  assert.throws(() => parseFrontmatter(markdown().replace('---\n\nBody.', 'name: "duplicate"\n---\nBody.')), /Invalid spec YAML/);
  assert.throws(() => groupSpecsByCategory([{ ...fields, category: 'unmapped-new-category' }]), /Unknown spec category/);
});

test('collection errors identify malformed files, mismatched routes, and duplicate slugs', () => {
  directory((path) => {
    writeFileSync(join(path, 'example.spec.md'), markdown());
    writeFileSync(join(path, 'wrong.spec.md'), markdown({ ...fields, slug: 'other' }));
    assert.throws(() => loadSpecCatalog(path), /wrong.spec.md: filename does not match spec slug other/);
    writeFileSync(join(path, 'wrong.spec.md'), markdown());
    assert.throws(() => loadSpecCatalog(path), /duplicate spec slug example/);
    writeFileSync(join(path, 'wrong.spec.md'), 'no metadata');
    assert.throws(() => loadSpecCatalog(path), /wrong.spec.md: Invalid spec frontmatter/);
  });
});

test('validated catalog exposes the same sorted metadata and indexed documents', () => {
  directory((path) => {
    writeFileSync(join(path, 'zeta.spec.md'), markdown({ ...fields, slug: 'zeta', name: 'Zeta' }));
    writeFileSync(join(path, 'alpha.spec.md'), markdown({ ...fields, slug: 'alpha', name: 'Alpha' }));
    const catalog = loadSpecCatalog(path);
    assert.deepEqual(catalog.metadata.map((meta) => meta.slug), ['alpha', 'zeta']);
    assert.equal(catalog.bySlug.get('alpha'), catalog.specs[0]);
    assert.equal(catalog.bySlug.get('zeta').content, '\nBody.');
  });
});

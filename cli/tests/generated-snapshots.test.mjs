import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { writeGeneratedFiles } from '../scripts/sync-fedramp.ts';
import { writeIntegrationSpecSnapshot } from '../scripts/generate-integration-specs.mjs';

async function directory(run) {
  const path = mkdtempSync(join(tmpdir(), 'grclanker-generated-snapshot-'));
  try { await run(path); } finally { rmSync(path, { recursive: true, force: true }); }
}

const currentFiles = [{ path: 'fedramp/index.md', content: 'new index' }, { path: 'fedramp/processes/current.md', content: 'current process' }];

test('FedRAMP generation keeps the previous snapshot if staging or publication fails', async () => {
  await directory(async (path) => {
    const target = join(path, 'fedramp');
    mkdirSync(target);
    writeFileSync(join(target, 'index.md'), 'old index');
    writeFileSync(join(target, 'old.md'), 'old process');
    const conflicts = [{ path: 'fedramp/a.md', content: 'first' }, { path: 'fedramp/a.md/conflict.md', content: 'cannot write' }];
    await assert.rejects(writeGeneratedFiles(target, conflicts));
    assert.equal(readFileSync(join(target, 'index.md'), 'utf8'), 'old index');
    await assert.rejects(writeGeneratedFiles(target, currentFiles, { beforePublish: () => { throw new Error('publication failed'); } }), /publication failed/);
    assert.deepEqual(readdirSync(target).sort(), ['index.md', 'old.md']);
    await assert.rejects(writeGeneratedFiles(target, currentFiles, { beforeInstall: () => { throw new Error('installation failed'); } }), /installation failed/);
    assert.equal(readFileSync(join(target, 'index.md'), 'utf8'), 'old index');
    await assert.rejects(writeGeneratedFiles(target, [{ path: 'fedramp/../../outside.md', content: 'escape' }]), /Invalid generated/);
    await assert.rejects(writeGeneratedFiles(target, []), /empty/);
    await writeGeneratedFiles(target, currentFiles);
    assert.equal(readFileSync(join(target, 'index.md'), 'utf8'), 'new index');
    assert.deepEqual(readdirSync(target).sort(), ['index.md', 'processes']);
    assert.equal(readFileSync(join(target, 'processes/current.md'), 'utf8'), 'current process');
  });
});

test('integration contracts, llms catalog, and stale removal commit or roll back together', async () => {
  await directory(async (path) => {
    const specsDir = join(path, 'specs');
    mkdirSync(specsDir);
    const current = join(specsDir, 'current.spec.md');
    const stale = join(specsDir, 'stale.spec.md');
    const manual = join(specsDir, 'manual.spec.md');
    const llms = join(path, 'llms.txt');
    const journalPath = join(path, '.cache/specs-transaction.json');
    writeFileSync(current, '<!-- generated integration spec -->\nold contract');
    writeFileSync(stale, '<!-- generated integration spec -->\nstale contract');
    writeFileSync(manual, '# Handwritten spec');
    writeFileSync(llms, 'old catalog');
    const outputs = new Map([[current, '<!-- generated integration spec -->\nnew contract'], [llms, 'new catalog']]);
    await assert.rejects(writeIntegrationSpecSnapshot(outputs, {
      specsDir, journalPath, beforeCommit: (index) => { if (index === 2) throw new Error('last replacement failed'); },
    }), /last replacement failed/);
    assert.match(readFileSync(current, 'utf8'), /old contract/);
    assert.equal(readFileSync(llms, 'utf8'), 'old catalog');
    assert.match(readFileSync(stale, 'utf8'), /stale contract/);
    await writeIntegrationSpecSnapshot(outputs, { specsDir, journalPath });
    assert.match(readFileSync(current, 'utf8'), /new contract/);
    assert.equal(readFileSync(llms, 'utf8'), 'new catalog');
    assert.deepEqual(readdirSync(specsDir).sort(), ['current.spec.md', 'manual.spec.md']);
    assert.equal(readFileSync(manual, 'utf8'), '# Handwritten spec');
  });
});

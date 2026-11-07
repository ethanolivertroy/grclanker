import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseToolManifest } from './lib/tool-manifest.mjs';

const tool = { name: 'example_check_access', label: 'Example', description: 'Check access', group: 'Example', kind: 'domain', effect: 'read', parameters: { type: 'object' } };
const manifest = { schemaVersion: 1, toolPrefixes: ['example_'], tools: [tool], environmentVariables: ['EXAMPLE_API_KEY'] };

test('manifest reader accepts neutral domain and compute descriptors', () => {
  const input = { ...manifest, tools: [tool, { ...tool, name: 'read', kind: 'compute' }] };
  assert.deepEqual(parseToolManifest(input), input);
});

test('manifest reader rejects incompatible, incomplete, or ambiguous inventories', () => {
  assert.throws(() => parseToolManifest({ ...manifest, schemaVersion: 2 }), /schemaVersion/);
  assert.throws(() => parseToolManifest({ ...manifest, toolPrefixes: ['other_'] }), /prefix/);
  assert.throws(() => parseToolManifest({ ...manifest, tools: [tool, tool] }), /Duplicate/);
  assert.throws(() => parseToolManifest({ ...manifest, tools: [{ ...tool, effect: 'guess' }] }), /definition/);
  assert.throws(() => parseToolManifest({ ...manifest, tools: [{ ...tool, parameters: {} }] }), /definition/);
  assert.throws(() => parseToolManifest({ ...manifest, environmentVariables: ['EXAMPLE_API_KEY', 'EXAMPLE_API_KEY'] }), /environmentVariables/);
});

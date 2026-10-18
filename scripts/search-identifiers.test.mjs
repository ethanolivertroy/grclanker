import assert from 'node:assert/strict';
import { test } from 'node:test';

import { identifierContents } from '../src/lib/search-identifiers.mjs';

const tools = new Set(['zscaler_check_access', 'zscaler_export_audit_bundle']);

test('each section lists the identifiers it mentions once, in the order they first appear', () => {
  const contents = [
    { heading: 'zia', content: 'Set `ZIA_CLOUD` and `ZIA_API_KEY`. `ZIA_CLOUD` names the ZIA cloud.' },
    { heading: 'zia', content: 'Then run zscaler_check_access.' },
    { heading: 'framework-mappings', content: 'ZS-07 maps to AC-2, ac-2.13, AC.L2-3.1.1, SRG-APP-000148, and V-256374.' },
    { heading: 'live-smoke', content: 'Needs ZIA_CLOUD.' },
  ];
  assert.deepEqual(identifierContents(contents, tools), [
    { heading: 'zia', content: '`ZIA_CLOUD` `ZIA_API_KEY` `zscaler_check_access`' },
    { heading: 'framework-mappings', content: '`ZS-07` `AC-2` `ac-2.13` `AC.L2-3.1.1` `SRG-APP-000148` `V-256374`' },
    { heading: 'live-smoke', content: '`ZIA_CLOUD`' },
  ]);
});

test('snake case names count only when they name a tool', () => {
  const contents = [{ heading: 'run-it', content: 'Pass output_dir to zscaler_export_audit_bundle, or set stale_host_days.' }];
  assert.deepEqual(identifierContents(contents, tools), [{ heading: 'run-it', content: '`zscaler_export_audit_bundle`' }]);
});

test('prose without identifiers leaves no text behind', () => {
  const contents = [
    { heading: undefined, content: 'Read-only Zscaler inspection, pre-2024 tenants included.' },
    { heading: 'limits', content: 'Large tenants take longer to read.' },
  ];
  assert.deepEqual(identifierContents(contents, tools), []);
});

test('long lists split into blocks of at most perBlock identifiers under the same heading', () => {
  const contents = [{ heading: 'control-coverage', content: 'ZS-01, ZS-02, ZS-03, ZS-04, and ZS-05.' }];
  assert.deepEqual(identifierContents(contents, tools, 2), [
    { heading: 'control-coverage', content: '`ZS-01` `ZS-02`' },
    { heading: 'control-coverage', content: '`ZS-03` `ZS-04`' },
    { heading: 'control-coverage', content: '`ZS-05`' },
  ]);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildDocsSections, getDocMetadataTitle } from '../src/lib/docs.ts';

const page = (id, title) => ({ id, data: { title } });

test('FedRAMP processes and KSI domains sit under their hubs, sorted by title', () => {
  const sections = buildDocsSections([
    page('fedramp/processes/vulnerability-detection-and-response', 'Vulnerability Detection and Response'),
    page('fedramp/processes/agency-use', 'Agency Use of FedRAMP Certified Cloud Services'),
    page('fedramp/ksi/change-management', 'Change Management'),
  ]);
  const fedramp = sections.find((section) => section.title === 'FedRAMP');
  assert.deepEqual(fedramp.items, [
    { label: 'Official Sources', slug: 'fedramp' },
    {
      label: 'Processes',
      slug: 'fedramp/processes',
      items: [
        { label: 'Agency Use of FedRAMP Certified Cloud Services', slug: 'fedramp/processes/agency-use' },
        { label: 'Vulnerability Detection and Response', slug: 'fedramp/processes/vulnerability-detection-and-response' },
      ],
    },
    {
      label: 'KSI Domains',
      slug: 'fedramp/ksis',
      items: [{ label: 'Change Management', slug: 'fedramp/ksi/change-management' }],
    },
  ]);
});

test('integration guides form the last section, sorted by title', () => {
  const sections = buildDocsSections([page('integrations/okta', 'Okta'), page('integrations/box', 'Box')]);
  assert.deepEqual(sections.at(-1), {
    title: 'Integrations',
    items: [
      { label: 'Box', slug: 'integrations/box' },
      { label: 'Okta', slug: 'integrations/okta' },
    ],
  });
});

test('a hub with no pages under it stays a plain link', () => {
  const sections = buildDocsSections([]);
  assert.equal(sections.at(-1).title, 'FedRAMP');
  assert.deepEqual(
    sections
      .flatMap((section) => section.items)
      .filter((item) => 'items' in item || 'childPrefix' in item || 'childKind' in item),
    [],
  );
});

test('FedRAMP process and KSI pages say what they are in the browser tab title', () => {
  assert.equal(
    getDocMetadataTitle('fedramp/ksi/incident-response', 'Incident Response'),
    'Incident Response: FedRAMP KSI Domain: grclanker docs',
  );
  assert.equal(
    getDocMetadataTitle('fedramp/processes/agency-use', 'Agency Use of FedRAMP Certified Cloud Services'),
    'Agency Use of FedRAMP Certified Cloud Services: FedRAMP Process: grclanker docs',
  );
  assert.equal(getDocMetadataTitle('fedramp/ksis', 'FedRAMP KSI Domains'), 'FedRAMP KSI Domains: grclanker docs');
  assert.equal(getDocMetadataTitle('integrations/okta', 'Okta'), 'Okta: grclanker docs');
  assert.equal(getDocMetadataTitle('', 'grclanker Docs'), 'grclanker Docs');
});

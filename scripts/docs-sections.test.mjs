import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildDocsSections } from '../src/lib/docs.ts';

const page = (id, title) => ({ id, data: { title } });

test('FedRAMP processes and KSI domains sit under their hubs without the generated suffix', () => {
  const sections = buildDocsSections([
    page('fedramp/processes/vulnerability-detection-and-response', 'Vulnerability Detection and Response: FedRAMP Process'),
    page('fedramp/processes/agency-use', 'Agency Use of FedRAMP Certified Cloud Services: FedRAMP Process'),
    page('fedramp/ksi/change-management', 'Change Management: FedRAMP KSI Domain'),
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
    sections.flatMap((section) => section.items).filter((item) => 'items' in item || 'childPrefix' in item),
    [],
  );
});

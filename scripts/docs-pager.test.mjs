import assert from 'node:assert/strict';
import { test } from 'node:test';

import { getPagerLinks } from '../src/lib/docs-pager.ts';

const separator = (name) => ({ type: 'separator', name });
const page = (name, url) => ({ type: 'page', name, url });

const tree = {
  name: 'Docs',
  children: [
    separator('Getting Started'),
    page('Overview', '/docs/'),
    page("What's New", '/docs/changelog/'),
    page('Installation', '/docs/getting-started/installation/'),
    page('Flue Runtime', '/docs/getting-started/flue-runtime/'),
    separator('Workflows'),
    page('Investigate', '/docs/workflows/investigate/'),
    separator('FedRAMP'),
    {
      type: 'folder',
      name: 'Processes',
      index: page('Processes', '/docs/fedramp/processes'),
      children: [page('Agency Use', '/docs/fedramp/processes/agency-use')],
    },
    { ...page('GitHub', 'https://github.com/ethanolivertroy/grclanker'), external: true },
  ],
};

const names = ({ previous, next }) => [previous?.name, next?.name];

test('each link is described by its sidebar section', () => {
  assert.deepEqual(getPagerLinks(tree, '/docs/getting-started/flue-runtime/'), {
    previous: { name: 'Installation', url: '/docs/getting-started/installation/', description: 'Getting Started' },
    next: { name: 'Investigate', url: '/docs/workflows/investigate/', description: 'Workflows' },
  });
});

test("the reading path skips What's New, which still links to its neighbors", () => {
  assert.deepEqual(names(getPagerLinks(tree, '/docs/')), [undefined, 'Installation']);
  assert.deepEqual(names(getPagerLinks(tree, '/docs/getting-started/installation/')), ['Overview', 'Flue Runtime']);
  assert.deepEqual(names(getPagerLinks(tree, '/docs/changelog/')), ['Overview', 'Installation']);
});

test('folders list their index page before their children, and external links are skipped', () => {
  assert.deepEqual(names(getPagerLinks(tree, '/docs/workflows/investigate/')), ['Flue Runtime', 'Processes']);
  assert.deepEqual(names(getPagerLinks(tree, '/docs/fedramp/processes/')), ['Investigate', 'Agency Use']);
  assert.deepEqual(names(getPagerLinks(tree, '/docs/fedramp/processes/agency-use/')), ['Processes', undefined]);
});

test('a page missing from the sidebar gets no links', () => {
  assert.deepEqual(getPagerLinks(tree, '/docs/fedramp/ksi/change-management/'), {});
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createElement } from 'react';

import { headingText } from '../src/lib/heading-text.mjs';

test('a plain heading keeps its text', () => {
  assert.equal(headingText('Setup and authentication'), 'Setup and authentication');
});

test('inline code, links, and emphasis contribute their text', () => {
  const Link = ({ children }) => children;
  const children = [
    'Run ',
    createElement('code', { key: 'code' }, 'aws_check_access'),
    ' before ',
    createElement(Link, { key: 'link', href: '/docs/workflows/audit/' }, createElement('em', null, 'the audit')),
  ];
  assert.equal(headingText(children), 'Run aws_check_access before the audit');
});

test('line-break hints inside code add no text', () => {
  const code = createElement('code', null, 'okta_', createElement('wbr'), 'assess_', createElement('span', { 'data-nowrap': '' }, 'auth'));
  assert.equal(headingText(['Using ', code]), 'Using okta_assess_auth');
});

test('numbers count, empty children do not, and whitespace collapses', () => {
  assert.equal(headingText(['  Step ', 2, null, undefined, false, true, [' of\n', ['  ', 3]], ' ']), 'Step 2 of 3');
});

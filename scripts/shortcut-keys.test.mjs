import assert from 'node:assert/strict';
import { test } from 'node:test';

import { shortcutHandler } from '../src/lib/shortcut-keys.mjs';

// The Fumadocs search provider's default hotkey.
const searchHotKey = [{ key: (event) => event.metaKey || event.ctrlKey }, { key: 'k' }];

function setup({ helpOpen = false, searchOpen = false } = {}) {
  const help = {
    open: helpOpen,
    close() {
      this.open = false;
    },
    showModal() {
      this.open = true;
    },
  };
  const calls = [];
  const handle = shortcutHandler({
    help,
    searchOpen,
    searchHotKey,
    openSearch: () => calls.push('search'),
    copyRawUrl: () => calls.push('copy'),
    goHome: () => calls.push('home'),
  });
  function press(key, init = {}) {
    const event = {
      key,
      target: null,
      metaKey: false,
      ctrlKey: false,
      altKey: false,
      defaultPrevented: false,
      preventDefault() {
        this.defaultPrevented = true;
      },
      ...init,
    };
    handle(event);
    return event;
  }
  return { help, calls, press };
}

test('the search hotkey closes the help dialog and opens search', () => {
  for (const modifier of ['metaKey', 'ctrlKey']) {
    const { help, calls, press } = setup({ helpOpen: true });
    const event = press('k', { [modifier]: true });
    assert.equal(help.open, false, modifier);
    assert.deepEqual(calls, ['search'], modifier);
    assert.equal(event.defaultPrevented, true, modifier);
  }
});

test('the search hotkey is left to the provider when the help dialog is closed', () => {
  const { calls, press } = setup();
  const event = press('k', { metaKey: true });
  assert.deepEqual(calls, []);
  assert.equal(event.defaultPrevented, false);
});

test('only ? and the search hotkey act while the help dialog is open', () => {
  const { help, calls, press } = setup({ helpOpen: true });
  for (const [key, init] of [['/'], ['c'], ['h'], ['k'], ['c', { metaKey: true }], ['?', { ctrlKey: true }]]) {
    press(key, init);
  }
  assert.equal(help.open, true);
  assert.deepEqual(calls, []);
  assert.equal(press('?').defaultPrevented, true);
  assert.equal(help.open, false);
});

test('single keys open search, open help, copy the raw URL, and go home', () => {
  const { help, calls, press } = setup();
  assert.equal(press('/').defaultPrevented, true);
  press('c');
  press('h');
  assert.deepEqual(calls, ['search', 'copy', 'home']);
  assert.equal(press('?').defaultPrevented, true);
  assert.equal(help.open, true);
});

test('shortcuts are ignored while typing, with modifiers, once handled, or with search open', () => {
  const { calls, press } = setup();
  for (const tagName of ['INPUT', 'TEXTAREA', 'SELECT']) press('/', { target: { tagName } });
  press('h', { target: { tagName: 'DIV', isContentEditable: true } });
  press('c', { metaKey: true });
  press('h', { altKey: true });
  press('/', { defaultPrevented: true });
  assert.deepEqual(calls, []);

  const searching = setup({ searchOpen: true });
  searching.press('?');
  searching.press('h');
  assert.equal(searching.help.open, false);
  assert.deepEqual(searching.calls, []);
});

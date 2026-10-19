import assert from 'node:assert/strict';
import { test } from 'node:test';

import { leaveOutFarLabels } from '../src/lib/spec-table-labels.mjs';

const VIEWPORT = 800;

// Runs the script from its source text, as the page does, against tables whose
// wrappers sit at the given [top, bottom] offsets from the top of the page.
function run(offsets, { phone = true } = {}) {
  let scrollY = 0;
  const tables = offsets.map(([top, bottom]) => {
    const table = {
      attributes: new Map(),
      setAttribute(name, value) {
        this.attributes.set(name, value);
      },
      removeAttribute(name) {
        this.attributes.delete(name);
      },
    };
    table.parentElement = { getBoundingClientRect: () => ({ top: top - scrollY, bottom: bottom - scrollY }) };
    return table;
  });
  let observer = null;
  class IntersectionObserver {
    constructor(callback, options) {
      this.callback = callback;
      this.options = options;
      this.targets = [];
      this.connected = true;
      observer = this;
    }
    observe(target) {
      this.targets.push(target);
    }
    disconnect() {
      this.connected = false;
    }
  }
  const listeners = new Map();
  const globals = {
    document: {
      querySelectorAll(selector) {
        assert.equal(selector, '.spec-reader .docs-table-scroll > table');
        return tables;
      },
    },
    innerHeight: VIEWPORT,
    IntersectionObserver,
    matchMedia(query) {
      assert.equal(query, 'screen and (max-width: 720px)');
      return { matches: phone };
    },
    addEventListener: (type, listener, options) => listeners.set(type, { listener, options }),
    removeEventListener(type, listener) {
      if (listeners.get(type)?.listener === listener) listeners.delete(type);
    },
  };
  new Function(...Object.keys(globals), `(${leaveOutFarLabels.toString()})()`)(...Object.values(globals));
  return {
    tables,
    observer,
    listeners,
    labels: () => tables.map((table) => table.attributes.get('data-labels') ?? null),
    // Moves the page under the viewport, as a reflow would, without a scroll event.
    shift(y) {
      scrollY = y;
    },
    scrollTo(y) {
      scrollY = y;
      listeners.get('scroll')?.listener();
    },
  };
}

test('tables more than three viewport heights above or below the viewport leave out their labels', () => {
  const { tables, observer, labels } = run([
    [100, 900],
    [3200, 4000],
    [3201, 4000],
    [-3000, -2400],
    [-3000, -2401],
  ]);
  assert.deepEqual(labels(), [null, null, 'lazy', null, 'lazy']);
  assert.deepEqual(observer.targets, [tables[2].parentElement, tables[4].parentElement]);
  assert.equal(observer.options.rootMargin, '300% 0px');
});

test('a screen wider than a phone keeps every label', () => {
  const { observer, listeners, labels } = run([[5000, 6000]], { phone: false });
  assert.deepEqual(labels(), [null]);
  assert.equal(observer, null);
  assert.equal(listeners.size, 0);
});

test('a scroll gives a table its labels back once it comes within reach', () => {
  const { listeners, labels, scrollTo } = run([
    [5000, 6000],
    [9000, 9500],
  ]);
  assert.equal(listeners.get('scroll').options.passive, true);
  scrollTo(1799);
  assert.deepEqual(labels(), ['lazy', 'lazy']);
  scrollTo(1800);
  assert.deepEqual(labels(), [null, 'lazy']);
});

test('the observer catches a table brought within reach without a scroll, then stops watching', () => {
  const { observer, listeners, labels, shift } = run([[5000, 6000]]);
  observer.callback([]);
  assert.deepEqual(labels(), ['lazy']);
  shift(2000);
  observer.callback([]);
  assert.deepEqual(labels(), [null]);
  assert.equal(observer.connected, false);
  assert.equal(listeners.has('scroll'), false);
});

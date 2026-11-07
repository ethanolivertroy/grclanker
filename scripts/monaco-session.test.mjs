import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createMonacoSession } from '../src/lib/monaco-session.mjs';

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function controller() {
  const options = [];
  let disposed = 0;
  return { options, get disposed() { return disposed; }, setOptions: (value) => options.push(value), focus() {}, layout() {}, dispose() { disposed++; } };
}

test('wrap changes while loading reach the editor before it becomes ready', async () => {
  const pending = deferred();
  const editor = controller();
  let ready = 0;
  const session = createMonacoSession({
    mount: () => pending.promise, options: { wrap: true, map: false },
    onReady() { ready++; assert.deepEqual(editor.options.at(-1), { wrap: false, map: true }); },
    onError: (error) => { throw error; },
  });
  await Promise.resolve();
  session.updateOptions({ wrap: false, map: true });
  pending.resolve(editor);
  await session.ready;
  assert.equal(ready, 1);
  session.updateOptions({ wrap: true, map: false });
  assert.deepEqual(editor.options.at(-1), { wrap: true, map: false });
  session.dispose();
  assert.equal(editor.disposed, 1);
});

test('a view disposed during loading cannot publish a late editor or failure', async () => {
  for (const fails of [false, true]) {
    const pending = deferred();
    const editor = controller();
    let notifications = 0;
    let signal;
    const session = createMonacoSession({
      mount: (lifetime) => { signal = lifetime; return pending.promise; },
      options: { wrap: true, map: false },
      onReady: () => notifications++, onError: () => notifications++,
    });
    await Promise.resolve();
    session.dispose();
    assert.equal(signal.aborted, true);
    if (fails) pending.reject(new Error('Late failure'));
    else pending.resolve(editor);
    await session.ready;
    assert.equal(notifications, 0);
    assert.equal(editor.disposed, fails ? 0 : 1);
    assert.equal(editor.options.length, 0);
  }
});

test('initialization errors report failure once and clean up a partially configured controller', async () => {
  let errors = 0;
  const editor = controller();
  editor.setOptions = () => { throw new Error('Options rejected'); };
  const session = createMonacoSession({
    mount: async () => editor, options: { wrap: true, map: false },
    onReady: () => assert.fail('must not report ready'),
    onError: (error) => { errors++; assert.match(error.message, /Options rejected/); },
  });
  await session.ready;
  assert.equal(errors, 1);
  assert.equal(editor.disposed, 1);
  session.dispose();
  assert.equal(editor.disposed, 1);
});

'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { useSearchContext } from 'fumadocs-ui/contexts/search';
import { shortcutHandler } from '../lib/shortcut-keys.mjs';

const BANNER =
  '%c  ┌─────────────────────────┐\n' +
  '  │  (@>@)  GRCLANKER       │\n' +
  '  │  /(   )\\  v0.1.4        │\n' +
  '  │   `---´                 │\n' +
  '  │  Put a clanker on it.   │\n' +
  '  │ethanolivertroy/grclanker│\n' +
  '  └─────────────────────────┘';

const SHORTCUTS = [
  { label: 'Search site', keys: <><kbd>/</kbd> or <kbd>Cmd+K</kbd></> },
  { label: 'Close overlay', keys: <kbd>Esc</kbd> },
  { label: 'Navigate results', keys: <><kbd>&uarr;</kbd> <kbd>&darr;</kbd></> },
  { label: 'Open selected', keys: <kbd>Enter</kbd> },
  { label: 'Copy raw URL', keys: <><kbd>c</kbd> <span className="text-subtext0 text-xs">(spec pages)</span></> },
  { label: 'Go home', keys: <kbd>h</kbd> },
  { label: 'This help', keys: <kbd>?</kbd> },
];

/** Site-wide keyboard shortcuts, the help dialog that lists them, and the copy toast. */
export function KeyboardShortcuts() {
  const router = useRouter();
  const { open: searchOpen, setOpenSearch, hotKey } = useSearchContext();
  const helpRef = useRef<HTMLDialogElement>(null);
  const [toast, setToast] = useState({ text: '', visible: false });

  useEffect(() => {
    console.log(BANNER, 'color: #8caaee; font-family: monospace;');
  }, []);

  useEffect(() => {
    let hideTimer: ReturnType<typeof setTimeout> | undefined;

    async function copyRawUrl() {
      const url = document.getElementById('spec-page-data')?.getAttribute('data-raw-url');
      if (!url) return;
      let text = 'URL copied to clipboard';
      try {
        await navigator.clipboard.writeText(url);
      } catch {
        text = 'Clipboard access failed';
      }
      setToast({ text, visible: true });
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => setToast((current) => ({ ...current, visible: false })), 1500);
    }

    const onKeyDown = shortcutHandler({
      help: helpRef.current,
      searchOpen,
      searchHotKey: hotKey,
      openSearch: () => setOpenSearch(true),
      copyRawUrl,
      goHome: () => router.push('/'),
    });
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      clearTimeout(hideTimer);
    };
  }, [hotKey, router, searchOpen, setOpenSearch]);

  return (
    <>
      <dialog
        ref={helpRef}
        className="overlay-dialog"
        aria-label="Keyboard shortcuts"
        onClick={(event) => {
          if (event.target === event.currentTarget) event.currentTarget.close();
        }}
      >
        <div className="viewscreen rounded-lg p-6 hud-corners">
          <div className="flex items-center justify-between mb-4">
            <span className="hud-label">Keyboard Shortcuts</span>
            <div className="flex items-center gap-3">
              <span className="text-xs text-subtext0">
                Press <kbd>?</kbd> or <kbd>Esc</kbd> to close
              </span>
              <button
                type="button"
                className="overlay-close"
                aria-label="Close keyboard shortcuts"
                onClick={() => helpRef.current?.close()}
              >
                Close
              </button>
            </div>
          </div>
          <dl className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
            {SHORTCUTS.map((shortcut) => (
              <div key={shortcut.label} className="flex items-center justify-between gap-3">
                <dt className="text-subtext1">{shortcut.label}</dt>
                <dd>{shortcut.keys}</dd>
              </div>
            ))}
          </dl>
        </div>
      </dialog>
      <div className={toast.visible ? 'toast show' : 'toast'} role="status" aria-live="polite">
        {toast.text}
      </div>
    </>
  );
}

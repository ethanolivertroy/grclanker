'use client';

import { useEffect, useRef, useState } from 'react';
import { mountMonacoViewer } from '../lib/monaco-viewer';
import { createMonacoSession } from '../lib/monaco-session.mjs';
import { useCopy } from '../lib/use-copy';

type EditorStatus = 'idle' | 'loading' | 'ready' | 'unavailable';

const loadLabels: Record<EditorStatus, string> = {
  idle: 'EDITOR',
  loading: 'LOADING',
  ready: 'READY',
  unavailable: 'UNAVAILABLE',
};

const skeletonWidths = ['w-3/4', 'w-1/2', 'w-5/6', 'w-2/3', 'w-4/5', 'w-1/3', 'w-3/4', 'w-1/2'];

/**
 * Shows the raw markdown in a plain `<pre>` and swaps in a read-only Monaco
 * editor: automatically on desktop, on request on phones.
 */
export function MonacoViewer({ content }: { content: string }) {
  const [status, setStatus] = useState<EditorStatus>('idle');
  const [requested, setRequested] = useState(false);
  const [wrap, setWrap] = useState(true);
  const [map, setMap] = useState(false);
  const { copied, copy } = useCopy('Spec markdown copied to clipboard');
  const containerRef = useRef<HTMLDivElement>(null);
  const fallbackRef = useRef<HTMLPreElement>(null);
  const loadButtonRef = useRef<HTMLButtonElement>(null);
  const sessionRef = useRef<ReturnType<typeof createMonacoSession> | null>(null);
  const focusAfterLoad = useRef(false);

  useEffect(() => {
    if (window.matchMedia('(min-width: 768px)').matches) setRequested(true);
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (!requested || !container) return;
    setStatus('loading');
    const session = createMonacoSession({
      options: { wrap, map },
      mount: (signal) => mountMonacoViewer({ container, source: content, signal }),
      onReady() {
        focusAfterLoad.current = fallbackRef.current?.contains(document.activeElement) ?? false;
        setStatus('ready');
      },
      onError: () => setStatus('unavailable'),
    });
    sessionRef.current = session;
    return () => {
      session.dispose();
      sessionRef.current = null;
    };
    // Options are synchronized separately, including changes during loading.
  }, [content, requested]);

  useEffect(() => {
    sessionRef.current?.updateOptions({ wrap, map });
  }, [wrap, map]);

  useEffect(() => {
    if (status !== 'ready') return;
    sessionRef.current?.layout();
    if (focusAfterLoad.current) sessionRef.current?.focus();
  }, [status]);

  function requestEditor() {
    if (document.activeElement === loadButtonRef.current) fallbackRef.current?.focus({ preventScroll: true });
    setRequested(true);
  }

  return (
    <>
      <div className="editor-toolbar">
        <div className="toolbar-actions">
          <button
            type="button"
            className={copied ? 'toolbar-btn copied' : 'toolbar-btn'}
            title="Copy markdown"
            onClick={() => copy(content)}
          >
            {copied ? 'COPIED' : 'COPY'}
          </button>
          <button
            type="button"
            className={wrap ? 'toolbar-btn active' : 'toolbar-btn'}
            title="Toggle word wrap"
            aria-pressed={wrap}
            onClick={() => setWrap((value) => !value)}
          >
            WRAP
          </button>
          <button
            ref={loadButtonRef}
            type="button"
            className={status === 'ready' ? 'toolbar-btn' : 'toolbar-btn active'}
            title="Load enhanced editor"
            disabled={status !== 'idle'}
            onClick={requestEditor}
          >
            {loadLabels[status]}
          </button>
          <button
            type="button"
            className={map ? 'toolbar-btn active' : 'toolbar-btn'}
            title="Toggle minimap"
            aria-pressed={map}
            disabled={status !== 'ready'}
            onClick={() => setMap((value) => !value)}
          >
            MAP
          </button>
        </div>
      </div>

      <div className="fallback-notice" hidden={status === 'ready'}>
        Mobile stays in plain markdown first. Load the editor only when you need line numbers or the minimap.
      </div>

      <div className="monaco-skeleton" hidden={status !== 'loading'}>
        {skeletonWidths.map((width, index) => (
          <div key={index} className={`skeleton-line ${width}`} />
        ))}
      </div>

      <div ref={containerRef} id="monaco-container" hidden={status !== 'ready'} />

      <pre
        ref={fallbackRef}
        hidden={status === 'ready'}
        className={wrap ? 'fallback-pre fallback-pre-wrap' : 'fallback-pre fallback-pre-nowrap'}
        role="region"
        aria-label="Raw markdown"
        tabIndex={0}
      >
        {content}
      </pre>
    </>
  );
}

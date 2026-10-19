'use client';

import { useEffect, useRef, useState } from 'react';
import { mountMonacoViewer, type MonacoViewerController } from '../lib/monaco-viewer';
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
  const [wrap, setWrap] = useState(true);
  const [map, setMap] = useState(false);
  const { copied, copy } = useCopy('Spec markdown copied to clipboard');
  const containerRef = useRef<HTMLDivElement>(null);
  const skeletonRef = useRef<HTMLDivElement>(null);
  const fallbackRef = useRef<HTMLPreElement>(null);
  const loadButtonRef = useRef<HTMLButtonElement>(null);
  const controllerRef = useRef<MonacoViewerController | null>(null);
  const mountedRef = useRef(false);

  async function loadEditor() {
    const container = containerRef.current;
    const skeleton = skeletonRef.current;
    const fallbackPre = fallbackRef.current;
    if (!container || !skeleton || !fallbackPre) return;

    setStatus('loading');
    // The button disables itself, so keep keyboard focus on the content.
    if (document.activeElement === loadButtonRef.current) fallbackPre.focus({ preventScroll: true });
    try {
      const controller = await mountMonacoViewer({ container, skeleton, fallbackPre, source: content, initialWrap: wrap });
      if (!mountedRef.current) {
        controller.dispose();
        return;
      }
      controllerRef.current = controller;
      setStatus('ready');
    } catch {
      if (mountedRef.current) setStatus('unavailable');
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    const timer = window.matchMedia('(min-width: 768px)').matches ? window.setTimeout(loadEditor, 0) : undefined;
    return () => {
      mountedRef.current = false;
      window.clearTimeout(timer);
      controllerRef.current?.dispose();
      controllerRef.current = null;
    };
    // Reads `content` once; the spec page keys this component by slug.
  }, []);

  function toggleWrap() {
    setWrap(!wrap);
    controllerRef.current?.setWrap(!wrap);
  }

  function toggleMap() {
    setMap(!map);
    controllerRef.current?.setMap(!map);
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
            onClick={toggleWrap}
          >
            WRAP
          </button>
          <button
            ref={loadButtonRef}
            type="button"
            className={status === 'ready' ? 'toolbar-btn' : 'toolbar-btn active'}
            title="Load enhanced editor"
            disabled={status !== 'idle'}
            onClick={loadEditor}
          >
            {loadLabels[status]}
          </button>
          <button
            type="button"
            className={map ? 'toolbar-btn active' : 'toolbar-btn'}
            title="Toggle minimap"
            aria-pressed={map}
            disabled={status !== 'ready'}
            onClick={toggleMap}
          >
            MAP
          </button>
        </div>
      </div>

      <div className="fallback-notice" hidden={status === 'ready'}>
        Mobile stays in plain markdown first. Load the editor only when you need line numbers or the minimap.
      </div>

      <div ref={skeletonRef} className="monaco-skeleton" hidden={status !== 'loading'}>
        {skeletonWidths.map((width, index) => (
          <div key={index} className={`skeleton-line ${width}`} />
        ))}
      </div>

      {/* mountMonacoViewer reveals this container and hides the fallback once the editor is ready. */}
      <div ref={containerRef} id="monaco-container" style={{ display: 'none' }} />

      <pre
        ref={fallbackRef}
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

'use client';

import { useState, type KeyboardEvent, type ReactNode } from 'react';
import { MonacoViewer } from './monaco-viewer';

const views = [
  { id: 'document', label: 'Document' },
  { id: 'source', label: 'Markdown source' },
] as const;

type View = (typeof views)[number]['id'];

type Source = { status: 'idle' | 'loading' | 'failed' } | { status: 'ready'; content: string };

function keyTarget(key: string, current: number) {
  const last = views.length - 1;
  switch (key) {
    case 'ArrowLeft':
      return current === 0 ? last : current - 1;
    case 'ArrowRight':
      return current === last ? 0 : current + 1;
    case 'Home':
      return 0;
    case 'End':
      return last;
    default:
      return null;
  }
}

function SourceView({ source, retry }: { source: Source; retry: () => void }) {
  switch (source.status) {
    case 'idle':
    case 'loading':
      return (
        <p role="status" className="spec-source-status">
          Loading the markdown…
        </p>
      );
    case 'failed':
      return (
        <p role="status" className="spec-source-status">
          The markdown didn’t load.
          <button type="button" className="spec-action-btn" onClick={retry}>
            Try again
          </button>
        </p>
      );
    case 'ready':
      return (
        <div className="viewscreen rounded-lg scanlines relative min-w-0 overflow-hidden">
          <div className="relative z-10">
            <MonacoViewer content={source.content} />
          </div>
        </div>
      );
    default: {
      const unhandled: never = source;
      return unhandled;
    }
  }
}

/**
 * Switches a spec page between its rendered document and its markdown. The
 * markdown, and the Monaco editor that shows it on desktop, load the first
 * time a reader opens that view.
 */
export function SpecViews({ sourceUrl, children }: { sourceUrl: string; children: ReactNode }) {
  const [view, setView] = useState<View>('document');
  const [source, setSource] = useState<Source>({ status: 'idle' });

  async function loadSource() {
    setSource({ status: 'loading' });
    try {
      const response = await fetch(sourceUrl);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setSource({ status: 'ready', content: await response.text() });
    } catch {
      setSource({ status: 'failed' });
    }
  }

  function select(next: View) {
    setView(next);
    if (next === 'source' && source.status === 'idle') loadSource();
  }

  function moveFocus(event: KeyboardEvent<HTMLDivElement>) {
    const next = keyTarget(event.key, views.findIndex(({ id }) => id === view));
    if (next === null) return;
    event.preventDefault();
    select(views[next].id);
    document.getElementById(`spec-tab-${views[next].id}`)?.focus();
  }

  return (
    <>
      <div role="tablist" aria-label="Spec view" className="spec-tabs" onKeyDown={moveFocus}>
        {views.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            role="tab"
            id={`spec-tab-${id}`}
            aria-selected={view === id}
            aria-controls={`spec-panel-${id}`}
            tabIndex={view === id ? 0 : -1}
            className="spec-tab"
            onClick={() => select(id)}
          >
            {label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id="spec-panel-document" aria-labelledby="spec-tab-document" hidden={view !== 'document'}>
        {children}
      </div>

      <div role="tabpanel" id="spec-panel-source" aria-labelledby="spec-tab-source" hidden={view !== 'source'}>
        {source.status !== 'idle' && <SourceView source={source} retry={loadSource} />}
      </div>
    </>
  );
}

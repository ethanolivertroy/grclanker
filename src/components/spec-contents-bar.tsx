'use client';

import type { TOCItemType } from 'fumadocs-core/toc';
import { useEffect, useId, useRef, useState, type FocusEvent, type MouseEvent, type RefObject } from 'react';
import { ChevronDownIcon } from './icons';
import { useDocumentView } from './spec-views';

// A jump to a section leaves its heading 1rem under the bar (the scroll margin
// on `.docs-prose [id]`), so the reading line sits a little lower than that.
const READING_LINE_GAP = 24;

const RING_RADIUS = 7.5;
const RING_LENGTH = 2 * Math.PI * RING_RADIUS;

/**
 * The index of the last section whose heading has reached the reading line
 * under the bar, or -1 above the first. The last sections of a spec can be
 * too short to scroll up to the line, so at the bottom of the page the one a
 * link jumped to, or else the last one on screen, is current. Follows the
 * page only while the bar shows, so not from 1024px, where the rail beside
 * the document marks the section.
 */
function useCurrentSection(items: TOCItemType[], barRef: RefObject<HTMLElement | null>) {
  const [current, setCurrent] = useState(-1);

  useEffect(() => {
    const headings = items.map((item) => document.getElementById(item.url.slice(1)));
    const top = (index: number) => headings[index]?.getBoundingClientRect().top ?? Infinity;
    let frame = 0;
    let shown: number | undefined;

    // Headings run down the page in order, so bisection finds the last one to
    // pass a test in a few position reads a frame.
    function lastWhere(test: (top: number) => boolean) {
      let low = 0;
      let high = headings.length - 1;
      while (low <= high) {
        const mid = (low + high) >> 1;
        if (test(top(mid))) low = mid + 1;
        else high = mid - 1;
      }
      return high;
    }

    function update() {
      frame = 0;
      const bar = barRef.current;
      if (!bar) return;
      const line = bar.getBoundingClientRect().bottom + READING_LINE_GAP;
      let index = lastWhere((t) => t <= line);
      if (scrollY + innerHeight >= document.documentElement.scrollHeight - 1) {
        const target = items.findIndex((item) => item.url === location.hash);
        index = target > index && top(target) < innerHeight ? target : lastWhere((t) => t < innerHeight);
      }
      if (index === shown) return;
      shown = index;
      setCurrent(index);
    }

    function schedule() {
      frame ||= requestAnimationFrame(update);
    }

    function follow(shows: boolean) {
      if (shows) {
        addEventListener('scroll', schedule, { passive: true });
        addEventListener('resize', schedule);
        addEventListener('hashchange', schedule);
        schedule();
      } else {
        removeEventListener('scroll', schedule);
        removeEventListener('resize', schedule);
        removeEventListener('hashchange', schedule);
        cancelAnimationFrame(frame);
        frame = 0;
      }
    }

    const visibility = new ResizeObserver(([entry]) => follow(entry.contentRect.height > 0));
    if (barRef.current) visibility.observe(barRef.current);
    return () => {
      visibility.disconnect();
      follow(false);
    };
  }, [items, barRef]);

  return current;
}

function ProgressRing({ value }: { value: number }) {
  return (
    <svg className="spec-contents-ring" width="18" height="18" viewBox="0 0 18 18" fill="none" strokeWidth="1.5" aria-hidden="true">
      <circle cx="9" cy="9" r={RING_RADIUS} stroke="currentColor" strokeOpacity="0.25" />
      <circle
        cx="9"
        cy="9"
        r={RING_RADIUS}
        stroke="currentColor"
        strokeDasharray={RING_LENGTH}
        strokeDashoffset={RING_LENGTH * (1 - value)}
        strokeLinecap="round"
        transform="rotate(-90 9 9)"
      />
    </svg>
  );
}

/**
 * Below 1024px, a bar under the site header names the section in view and
 * opens the list of sections, so a reader deep in a spec that runs hundreds
 * of screens can change sections without going back to the top. Shown with
 * the document, not the markdown source.
 */
export function SpecContentsBar({ items }: { items: TOCItemType[] }) {
  return useDocumentView() ? <ContentsBar items={items} /> : null;
}

function ContentsBar({ items }: { items: TOCItemType[] }) {
  const barRef = useRef<HTMLElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const [open, setOpen] = useState(false);
  const current = useCurrentSection(items, barRef);
  const section = items[current];

  useEffect(() => {
    if (!open) return;
    const panel = panelRef.current;
    const active = panel?.querySelector<HTMLElement>('[aria-current]');
    if (panel && active) panel.scrollTop = active.offsetTop - panel.clientHeight / 2;

    function closeOnOutsidePointer(event: PointerEvent) {
      if (!barRef.current?.contains(event.target as Node)) setOpen(false);
    }

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key !== 'Escape') return;
      setOpen(false);
      buttonRef.current?.focus();
    }

    document.addEventListener('pointerdown', closeOnOutsidePointer);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOnOutsidePointer);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [open]);

  function closeOnFocusLeaving(event: FocusEvent<HTMLElement>) {
    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setOpen(false);
  }

  function closeOnSection(event: MouseEvent<HTMLDivElement>) {
    if ((event.target as Element).closest('a')) setOpen(false);
  }

  return (
    <nav ref={barRef} className="spec-contents-bar" aria-label="On this page" onBlur={closeOnFocusLeaving}>
      <button
        ref={buttonRef}
        type="button"
        className="spec-contents-trigger"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen(!open)}
      >
        <ProgressRing value={(current + 1) / items.length} />
        <span className="spec-contents-label">
          {section ? (
            <>
              <span className="sr-only">On this page: </span>
              {section.title}
            </>
          ) : (
            'On this page'
          )}
        </span>
        <ChevronDownIcon className="spec-contents-chevron" />
      </button>
      <div ref={panelRef} id={panelId} className="spec-contents-panel" hidden={!open} onClick={closeOnSection}>
        <ul className="spec-toc-list">
          {items.map((item, index) => (
            <li key={item.url}>
              {/* Marked with aria-current alone: Fumadocs CSS matches :has([data-active=true]),
                  so each data-active change makes Chrome recheck the :has() rules on <html>. */}
              <a
                href={item.url}
                className="spec-toc-link"
                data-depth={item.depth}
                aria-current={index === current ? 'location' : undefined}
              >
                {item.title}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
}

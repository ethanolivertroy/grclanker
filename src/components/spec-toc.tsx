'use client';

import { useRef } from 'react';
import { AnchorProvider, ScrollProvider, TOCItem, type TOCItemType } from 'fumadocs-core/toc';

/** The spec's sections beside the document on wide screens, marking the one in view. */
export function SpecToc({ items }: { items: TOCItemType[] }) {
  const navRef = useRef<HTMLElement>(null);

  return (
    <AnchorProvider toc={items} single>
      <nav ref={navRef} className="spec-toc-rail" aria-label="On this page">
        <p className="spec-toc-title">On this page</p>
        <ScrollProvider containerRef={navRef}>
          <ul className="spec-toc-list">
            {items.map((item) => (
              <li key={item.url}>
                <TOCItem href={item.url} className="spec-toc-link" data-depth={item.depth}>
                  {item.title}
                </TOCItem>
              </li>
            ))}
          </ul>
        </ScrollProvider>
      </nav>
    </AnchorProvider>
  );
}

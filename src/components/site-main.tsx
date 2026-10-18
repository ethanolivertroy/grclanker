'use client';

import { useSelectedLayoutSegment } from 'next/navigation';
import type { ReactNode } from 'react';

/**
 * The page's main landmark, which "Skip to content" targets. Docs pages put
 * theirs around the article instead (DocsPageContainer), so that the skip link
 * and landmark navigation land past the docs sidebar.
 */
export function SiteMain({ children }: { children: ReactNode }) {
  const segment = useSelectedLayoutSegment();
  if (segment === 'docs') return <div className="flex-1">{children}</div>;
  return (
    <main id="main-content" className="flex-1">
      {children}
    </main>
  );
}

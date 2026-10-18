'use client';

import { useSelectedLayoutSegment } from 'next/navigation';

/**
 * On docs pages the main landmark starts with the docs sidebar, so the link
 * skips to the article (DocsPageContainer) instead.
 */
export function SkipLink() {
  const target = useSelectedLayoutSegment() === 'docs' ? '#nd-page' : '#main-content';
  return (
    <a href={target} className="skip-link">
      Skip to content
    </a>
  );
}

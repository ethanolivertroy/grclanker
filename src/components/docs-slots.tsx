'use client';

import type { ComponentProps } from 'react';

/** The site header already carries the brand, so the docs sidebar shows no title. */
export function NoNavTitle() {
  return null;
}

/**
 * Fumadocs' page container with this site's spacing. Its `<main>` is the docs
 * page's only one (see SiteMain), and the skip link's target.
 */
export function DocsPageContainer({ className, ...props }: ComponentProps<'article'>) {
  return (
    <main id="main-content" className="grid justify-items-center [grid-area:main]" data-layout-main="">
      <article
        id="nd-page"
        data-layout-content=""
        {...props}
        className={[
          'w-full min-w-0 max-w-[52rem] px-4 pt-5 pb-8 sm:px-6 md:py-10 xl:px-8',
          className,
        ]
          .filter(Boolean)
          .join(' ')}
      />
    </main>
  );
}

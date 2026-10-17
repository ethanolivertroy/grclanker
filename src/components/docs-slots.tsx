'use client';

import type { ComponentProps } from 'react';

/** The site header already carries the brand, so the docs sidebar shows no title. */
export function NoNavTitle() {
  return null;
}

/**
 * Fumadocs' page container renders a `<main>`; the root layout already has
 * one, so this keeps the same grid placement on a plain `<div>`.
 */
export function DocsPageContainer({ className, ...props }: ComponentProps<'article'>) {
  return (
    <div className="grid justify-items-center [grid-area:main]" data-layout-main="">
      <article
        id="nd-page"
        data-layout-content=""
        {...props}
        className={[
          'w-full min-w-0 max-w-[52rem] px-4 py-8 sm:px-6 md:py-10 xl:px-8',
          className,
        ]
          .filter(Boolean)
          .join(' ')}
      />
    </div>
  );
}

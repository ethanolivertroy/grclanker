'use client';

import type { ComponentProps } from 'react';

type CropSource = { media: string; srcSet: string };

/**
 * An above-the-fold image rendered from a Client Component. React adds a
 * preload hint for an image rendered in a Server Component to the page's
 * prefetch data, so every page whose links prefetch this one would download
 * the image without showing it. Server rendering still preloads it on its own
 * page, unless `sources` wraps it in a <picture>, whose source the browser
 * picks as it parses the page.
 */
export function HeroImage({ sources, ...props }: ComponentProps<'img'> & { sources?: CropSource[] }) {
  const image = <img {...props} />;
  if (!sources) return image;
  return (
    <picture>
      {sources.map((source) => (
        <source key={source.media} media={source.media} srcSet={source.srcSet} />
      ))}
      {image}
    </picture>
  );
}

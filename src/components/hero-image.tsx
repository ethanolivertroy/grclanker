'use client';

import type { ComponentProps } from 'react';

/**
 * An above-the-fold image rendered from a Client Component. React adds a
 * preload hint for an image rendered in a Server Component to the page's
 * prefetch data, so every page whose links prefetch this one would download
 * the image without showing it. Server rendering still preloads it on its own
 * page.
 */
export function HeroImage(props: ComponentProps<'img'>) {
  return <img {...props} />;
}

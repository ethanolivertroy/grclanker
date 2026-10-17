import type { Metadata } from 'next';
import { defaultDescription, ogImage, siteName, siteUrl } from './site';

interface PageMetadataOptions {
  title: string;
  description?: string;
  /** Site path with a trailing slash, or null for pages without a canonical URL (404). */
  path: string | null;
}

// Next merges metadata one top-level key at a time, so every page repeats the
// full Open Graph and Twitter objects instead of inheriting the image.
export function pageMetadata({ title, description = defaultDescription, path }: PageMetadataOptions): Metadata {
  const url = path === null ? undefined : new URL(path, siteUrl).href;
  return {
    metadataBase: new URL(siteUrl),
    title: { absolute: title },
    description,
    alternates: url ? { canonical: url } : undefined,
    icons: { icon: { url: '/favicon.svg', type: 'image/svg+xml' } },
    openGraph: {
      title,
      description,
      type: 'website',
      url,
      siteName,
      images: [ogImage],
    },
    twitter: {
      card: 'summary_large_image',
      title,
      description,
      images: [{ url: ogImage.url, alt: ogImage.alt }],
    },
  };
}

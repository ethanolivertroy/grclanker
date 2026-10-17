export const siteUrl = 'https://grclanker.com';
export const siteName = 'grclanker';
export const githubUrl = 'https://github.com/ethanolivertroy/grclanker';

export const defaultDescription =
  'CMVP certificates, KEV feeds, EPSS scores, framework mappings. One terminal session. Keep prompts on your machine with a local model, or choose a hosted one.';

export const ogImage = {
  url: `${siteUrl}/og-card.jpg`,
  width: 1376,
  height: 768,
  alt: 'Spacecraft cockpit whose central radar screen reads GRCLANKER, AI GRC CLI',
  type: 'image/jpeg',
};

export const primaryLinks = [
  { href: '/', label: 'CLI' },
  { href: '/docs/', label: 'Docs' },
  { href: '/specs/', label: 'Specs' },
  { href: '/about/', label: 'About' },
];

export const footerImages = [
  '/footer/closeup.webp',
  '/footer/skyline.webp',
  '/footer/standby.webp',
  '/footer/walkaway.webp',
];

/** Pathname without a trailing slash, so server and client renders agree. */
export function normalizePathname(pathname: string) {
  return pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
}

export function isActivePath(href: string, pathname: string) {
  const current = normalizePathname(pathname);
  const target = normalizePathname(href);
  return target === '/' ? current === '/' : current === target || current.startsWith(`${target}/`);
}

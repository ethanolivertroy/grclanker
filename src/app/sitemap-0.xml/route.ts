import { absoluteUrl, getSitemapPaths, xmlResponse } from '../../lib/sitemap';

export const revalidate = false;

export function GET() {
  const urls = getSitemapPaths()
    .map((path) => `<url><loc>${absoluteUrl(path)}</loc></url>`)
    .join('');
  return xmlResponse(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`);
}

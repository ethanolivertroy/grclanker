import { absoluteUrl, xmlResponse } from '../../lib/sitemap';

export const revalidate = false;

export function GET() {
  return xmlResponse(
    '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' +
      `<sitemap><loc>${absoluteUrl('/sitemap-0.xml')}</loc></sitemap>` +
      '</sitemapindex>',
  );
}

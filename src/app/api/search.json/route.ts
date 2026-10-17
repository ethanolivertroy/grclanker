import { createSearchAPI } from 'fumadocs-core/search/server';
import { getDocHref } from '../../../lib/docs';
import { getDocSlug, source } from '../../../lib/source';

export const revalidate = false;

// Titles, descriptions, and headings only: body text would make the static
// index the browser downloads several times larger.
export const { staticGET: GET } = createSearchAPI('advanced', {
  indexes: source.getPages().map((page) => {
    const url = getDocHref(getDocSlug(page));
    return {
      id: url,
      title: page.data.title,
      description: page.data.description,
      url,
      structuredData: { headings: page.data.structuredData.headings, contents: [] },
    };
  }),
});

import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DocsPage } from 'fumadocs-ui/layouts/docs/page';
import { TOC, TOCProvider } from 'fumadocs-ui/layouts/docs/page/slots/toc';
import { AgentCommandsSection } from '../../../components/agent-commands-section';
import { DocsContentsBar } from '../../../components/docs-contents-bar';
import { getDocsFooterItems } from '../../../components/docs-footer';
import { getDocsRoutesToc } from '../../../components/docs-routes';
import { DocsPageContainer } from '../../../components/docs-slots';
import { mdxComponents } from '../../../components/mdx';
import { getDocHref } from '../../../lib/docs';
import { pageMetadata } from '../../../lib/metadata';
import { getDocSlug, source } from '../../../lib/source';

interface PageProps {
  params: Promise<{ slug?: string[] }>;
}

async function getPageOrNotFound(props: PageProps) {
  const { slug } = await props.params;
  const page = source.getPage(slug);
  if (!page) notFound();
  return page;
}

export default async function Page(props: PageProps) {
  const page = await getPageOrNotFound(props);
  const slug = getDocSlug(page);
  const Content = page.data.body;
  // The landing page's route map comes before any of its own headings.
  const toc = slug === '' ? [...getDocsRoutesToc(), ...page.data.toc] : page.data.toc;

  return (
    <DocsPage
      toc={toc}
      breadcrumb={{ enabled: false }}
      // The bar carries the docs menu, so pages without headings need it too.
      tableOfContentPopover={{ enabled: true }}
      slots={{
        container: DocsPageContainer,
        toc: { provider: TOCProvider, main: TOC, popover: DocsContentsBar },
      }}
      footer={{ items: getDocsFooterItems(slug) }}
    >
      <h1 className="docs-article-title">{page.data.title}</h1>
      <div className="docs-prose">
        <Content components={mdxComponents} />
      </div>
      {slug === 'specs/using-specs-as-inputs' && (
        <div className="mt-8">
          <AgentCommandsSection />
        </div>
      )}
    </DocsPage>
  );
}

export function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: PageProps): Promise<Metadata> {
  const page = await getPageOrNotFound(props);
  const slug = getDocSlug(page);
  return pageMetadata({
    title: slug === '' ? page.data.title : `${page.data.title}: grclanker docs`,
    description: page.data.description,
    path: getDocHref(slug),
  });
}

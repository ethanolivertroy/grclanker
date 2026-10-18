import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DocsPage } from 'fumadocs-ui/layouts/docs/page';
import { AgentCommandsSection } from '../../../components/agent-commands-section';
import { getDocsFooterItems } from '../../../components/docs-footer';
import { DocsMobileNav } from '../../../components/docs-mobile-nav';
import { DocsPageContainer } from '../../../components/docs-slots';
import { mdxComponents } from '../../../components/mdx';
import { getDocHref } from '../../../lib/docs';
import { pageMetadata } from '../../../lib/metadata';
import { getDocSlug, getDocsSections, source } from '../../../lib/source';

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

  return (
    <DocsPage
      toc={page.data.toc}
      breadcrumb={{ enabled: false }}
      slots={{ container: DocsPageContainer }}
      footer={{ items: getDocsFooterItems(slug) }}
    >
      <DocsMobileNav sections={getDocsSections()} currentSlug={slug} />
      {slug === '' && (
        <section className="page-image-break docs-index-break" aria-label="Docs ambient frame">
          <img src="/footer/skyline.webp" alt="" className="page-image-break-image" loading="eager" />
          <div className="page-image-break-overlay">
            <span className="page-image-break-pill">
              241 domain tools // 35 vendor integrations // three runtime paths
            </span>
          </div>
        </section>
      )}
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

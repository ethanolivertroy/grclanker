import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { SpecUrlCopyButton } from '../../../components/spec-copy';
import { SpecContentsBar } from '../../../components/spec-contents-bar';
import { SpecDocument, specSections } from '../../../components/spec-document';
import { SpecViewState, SpecViews } from '../../../components/spec-views';
import { pageMetadata } from '../../../lib/metadata';
import { githubUrl } from '../../../lib/site';
import { source } from '../../../lib/source';
import { RAW_BASE, getCategoryLabel, getSpec, getSpecGuideSlug, loadSpecs } from '../../../lib/specs';

interface PageProps {
  params: Promise<{ slug: string }>;
}

const pillClass =
  'inline-flex items-center rounded-full border px-2.5 py-1 text-[0.6875rem] font-mono uppercase tracking-[0.12em]';
const neutralPillClass = `${pillClass} border-surface0 bg-crust/70 text-subtext0`;
const textLinkClass = 'text-blue underline! underline-offset-2 hover:text-lavender';

async function getSpecOrNotFound(props: PageProps) {
  const { slug } = await props.params;
  const spec = getSpec(slug);
  if (!spec) notFound();
  return spec;
}

export function generateStaticParams() {
  return loadSpecs().map((spec) => ({ slug: spec.slug }));
}

export async function generateMetadata(props: PageProps): Promise<Metadata> {
  const { meta } = await getSpecOrNotFound(props);
  return pageMetadata({
    title: `${meta.name}: grclanker`,
    description: `Compliance automation spec for ${meta.vendor}. ${meta.name}.`,
    path: `/specs/${meta.slug}/`,
  });
}

export default async function SpecPage(props: PageProps) {
  const { meta, content } = await getSpecOrNotFound(props);
  const rawUrl = `${RAW_BASE}/${meta.slug}.spec.md`;
  const toc = await specSections(content);
  const guide = source.getPage(getSpecGuideSlug(meta.slug).split('/'));

  return (
    <SpecViewState key={meta.slug}>
      {toc.length > 0 && <SpecContentsBar items={toc} />}

      <div className="max-w-content mx-auto px-4 py-6 sm:px-6 sm:py-8">
        {/* Read by the "c" keyboard shortcut. */}
        <div id="spec-page-data" data-raw-url={rawUrl} className="hidden" />

        <div className="viewscreen rounded-lg mb-6 overflow-hidden">
          <div className="px-4 py-5 sm:px-6 sm:py-6 flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <p className="text-[0.6875rem] font-mono uppercase tracking-[0.18em] text-subtext1 mb-2">{meta.slug}.spec.md</p>
              <h1 className="font-bold text-2xl md:text-3xl text-text leading-tight">{meta.name}</h1>
              <div className="mt-3 flex flex-wrap gap-2">
                <span className={`${pillClass} border-blue/20 bg-blue/[0.06] text-blue`}>{meta.vendor}</span>
                <span className={`${pillClass} border-teal/20 bg-teal/[0.06] text-teal`}>
                  {getCategoryLabel(meta.category)}
                </span>
                <span className={neutralPillClass}>{meta.language}</span>
                <span className={neutralPillClass}>v{meta.version}</span>
                <span className={neutralPillClass}>{meta.last_updated}</span>
              </div>
              {meta.contributor && (
                <p className="mt-3 text-xs text-subtext0">
                  Community spec contributed by{' '}
                  {meta.contributor_url ? (
                    <a href={meta.contributor_url} target="_blank" rel="noopener" className={textLinkClass}>
                      @{meta.contributor}
                    </a>
                  ) : (
                    <span className="text-subtext1">@{meta.contributor}</span>
                  )}
                  {meta.source_pr && (
                    <>
                      {' '}
                      via{' '}
                      <a href={meta.source_pr} target="_blank" rel="noopener" className={textLinkClass}>
                        PR #{meta.source_pr.split('/').pop()}
                      </a>
                    </>
                  )}
                </p>
              )}
              {guide && (
                <p className="mt-3 text-sm text-subtext0">
                  Set up and run it with the{' '}
                  {/* Prefetching would download the guide on every visit to the spec. */}
                  <Link href={guide.url} prefetch={false} className={textLinkClass}>
                    {guide.data.title} guide
                  </Link>
                  .
                </p>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2 lg:max-w-[18rem] lg:justify-end">
              <SpecUrlCopyButton
                url={rawUrl}
                label="Copy URL"
                detail={`of the raw ${meta.name} spec`}
                className="copy-btn spec-action-btn spec-action-btn-primary"
              />
              <a href={rawUrl} download className="spec-action-btn">
                Download
              </a>
              <a href={`${githubUrl}/blob/main/specs/${meta.slug}.spec.md`} target="_blank" rel="noopener" className="spec-action-btn">
                GitHub
              </a>
              <a
                href={`${githubUrl}/edit/main/specs/${meta.slug}.spec.md`}
                target="_blank"
                rel="noopener"
                className="spec-action-link"
              >
                Suggest edit
              </a>
            </div>
          </div>
        </div>

        <SpecViews sourceUrl={`/specs/${meta.slug}/source.md`}>
          <SpecDocument content={content} toc={toc} />
        </SpecViews>
      </div>
    </SpecViewState>
  );
}

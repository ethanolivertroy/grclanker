import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { MonacoViewer } from '../../../components/monaco-viewer';
import { SpecUrlCopyButton } from '../../../components/spec-copy';
import { pageMetadata } from '../../../lib/metadata';
import { githubUrl } from '../../../lib/site';
import { RAW_BASE, categoryLabels, getSpec, loadSpecs } from '../../../lib/specs';

interface PageProps {
  params: Promise<{ slug: string }>;
}

const pillClass =
  'inline-flex items-center rounded-full border px-2.5 py-1 text-[0.6875rem] font-mono uppercase tracking-[0.12em]';
const neutralPillClass = `${pillClass} border-surface0 bg-crust/70 text-subtext0`;
const externalLinkClass = 'text-blue hover:text-lavender';

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

  return (
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
                {categoryLabels[meta.category] || meta.category}
              </span>
              <span className={neutralPillClass}>{meta.language}</span>
              <span className={neutralPillClass}>v{meta.version}</span>
              <span className={neutralPillClass}>{meta.last_updated}</span>
            </div>
            {meta.contributor && (
              <p className="mt-3 text-xs text-subtext0">
                Community spec contributed by{' '}
                {meta.contributor_url ? (
                  <a href={meta.contributor_url} target="_blank" rel="noopener" className={externalLinkClass}>
                    @{meta.contributor}
                  </a>
                ) : (
                  <span className="text-subtext1">@{meta.contributor}</span>
                )}
                {meta.source_pr && (
                  <>
                    {' '}
                    via{' '}
                    <a href={meta.source_pr} target="_blank" rel="noopener" className={externalLinkClass}>
                      PR #{meta.source_pr.split('/').pop()}
                    </a>
                  </>
                )}
              </p>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 lg:max-w-[18rem] lg:justify-end">
            <SpecUrlCopyButton
              url={rawUrl}
              label="COPY URL"
              specName={meta.name}
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

      <div className="viewscreen rounded-lg scanlines relative min-w-0 overflow-hidden">
        <div className="relative z-10">
          <MonacoViewer key={meta.slug} content={content.trim()} />
        </div>
      </div>
    </div>
  );
}

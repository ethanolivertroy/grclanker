import Link from 'next/link';
import { HeroImage } from '../../components/hero-image';
import { SpecCatalogSection } from '../../components/spec-catalog-section';
import { SpecCommandHero } from '../../components/spec-copy';
import { pageMetadata } from '../../lib/metadata';
import { RAW_BASE, loadSpecs } from '../../lib/specs';

export const metadata = pageMetadata({
  title: 'Specs: grclanker',
  description:
    'Browse 35 repository specs for shipped grclanker integrations and compute backends, or reuse a raw spec with any agent.',
  path: '/specs/',
});

export default function SpecsPage() {
  const specs = loadSpecs();
  const generatedSpecCount = specs.filter((spec) => spec.status === 'generated').length;

  return (
    <>
      <section className="relative overflow-hidden border-b border-surface0/60">
        <div className="absolute inset-0 w-full h-full">
          <HeroImage
            src="/hero/holographic.webp"
            alt="Spec catalog cockpit display"
            className="w-full h-full object-cover object-center"
            loading="eager"
          />
        </div>
        <div className="absolute inset-0 bg-gradient-to-b from-base/55 via-base/78 to-base pointer-events-none" />

        <div className="relative z-10 max-w-content mx-auto px-6 pt-14 pb-14 md:pt-18 md:pb-18">
          <div className="max-w-3xl mx-auto text-center">
            <h1 className="font-bold text-3xl sm:text-4xl md:text-5xl text-text leading-tight hero-text-shadow">
              {specs.length} specs. Each one backed by shipped tools.
            </h1>
            <p className="mx-auto mt-4 max-w-2xl text-base text-subtext1 leading-relaxed italic">
              One per vendor integration except Vanta, plus the compute backends. Inspect what shipped, or reuse the raw
              build plan with any agent.
            </p>
          </div>

          <div className="mt-8 max-w-3xl mx-auto">
            <SpecCommandHero command={`curl -O ${RAW_BASE}/aws-sec-inspector.spec.md`} />
          </div>
        </div>
      </section>

      <div className="max-w-content mx-auto px-6 py-8 md:py-10">
        <SpecCatalogSection specs={specs} />

        <section className="page-image-break mb-8" aria-label="Specs ambient frame">
          <img src="/footer/closeup.webp" alt="" className="page-image-break-image" loading="lazy" />
          <div className="page-image-break-overlay">
            <span className="page-image-break-pill">Raw markdown in // agent output out</span>
          </div>
        </section>

        <section className="viewscreen rounded-xl scanlines relative overflow-hidden">
          <div className="relative z-10 p-5 md:p-6 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
            <div className="max-w-2xl">
              <h2 className="font-semibold text-sm tracking-widest uppercase text-blue mb-2">Use With Any Agent</h2>
              <p className="text-subtext1 text-sm leading-relaxed italic">
                Each spec now has a native grclanker tool family, and {generatedSpecCount} of them are generated from it.
                The raw files remain portable inputs for extensions, independent implementations, and review.
              </p>
            </div>
            <Link
              href="/docs/specs/using-specs-as-inputs/"
              className="spec-action-btn spec-action-btn-primary self-start md:self-auto"
            >
              Open docs
            </Link>
          </div>
        </section>
      </div>
    </>
  );
}

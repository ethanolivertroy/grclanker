import Link from 'next/link';
import { HeroImage } from '../../components/hero-image';
import { pageMetadata } from '../../lib/metadata';
import { githubUrl } from '../../lib/site';

export const metadata = pageMetadata({
  title: 'About: grclanker',
  description:
    'What grclanker ships today: an open source compliance agent with 241 domain tools, 35 vendor integrations, and Pi, Cursor Agent SDK, Flue, and experimental durable runtime paths.',
  path: '/about/',
});

export default function AboutPage() {
  return (
    <>
      <section className="relative overflow-hidden">
        <div className="hero-backdrop absolute inset-0 w-full h-full">
          <HeroImage
            src="/about-clanker.webp"
            alt="A clanker robot working at a compliance workstation"
            className="w-full h-full object-cover object-center"
            loading="eager"
          />
        </div>
        <div className="absolute inset-0 bg-gradient-to-b from-base/30 via-base/60 to-base pointer-events-none" />
        <div className="relative z-10 max-w-content mx-auto px-6 pt-24 pb-16 text-center">
          <h1 className="font-bold text-3xl md:text-4xl text-text hero-text-shadow">What is grclanker</h1>
        </div>
      </section>

      <div className="max-w-content mx-auto px-6 pb-12">
        <div className="about-intro-grid">
          <div className="about-copy-stack">
            <div className="viewscreen rounded-lg p-6 md:p-8 scanlines relative -mt-8">
              <div className="relative z-10 space-y-5 text-subtext1 leading-relaxed">
                <div className="flex flex-wrap gap-4 justify-center md:justify-start">
                  <img
                    src="/badges/audited-by-clanker.webp"
                    alt="Audited by Clanker badge"
                    className="h-24 w-24 rounded-full"
                    loading="lazy"
                  />
                  <img src="/badges/spec-driven.webp" alt="Spec Driven badge" className="h-24 w-24 rounded-full" loading="lazy" />
                </div>

                <div className="text-sm text-subtext0 space-y-1.5 font-mono">
                  <p>
                    Built by <a href="https://ethantroy.dev">Ethan Troy</a>
                  </p>
                  <p>
                    <a href="https://ethantroy.dev">ethantroy.dev</a>
                  </p>
                  <p>
                    <a href={githubUrl}>GitHub</a>
                  </p>
                </div>

                <div className="hud-divider !my-7" />

                <p>
                  <strong className="text-text">grclanker</strong> is an open source compliance agent with 241 domain tools.
                  It ships 35 vendor integrations with native checks, assessments, or evidence exports, and every one except
                  Vanta has a repository spec. CMVP, KEV, EPSS, FedRAMP, SCF, and OSCAL tools round out the current surface.
                  The v0.1.3 release bundle carries the full set.
                </p>

                <p>
                  The same prompts, personas, and domain tools run in the Pi terminal CLI, the Cursor Agent SDK project, and
                  the Flue Framework adapter. The Pi path supports local-first models or an explicitly configured hosted
                  provider. The experimental, opt-in durable runtime runs the agent with only the domain tools, and it can
                  resume a run that crashed or was stopped.
                </p>

                <p>
                  The project exists because compliance evidence is scattered across vendor dashboards, government feeds,
                  and spreadsheets. grclanker gathers that evidence, maps it to controls, and packages the result for
                  review.
                </p>

                <p>
                  grclanker is licensed under the{' '}
                  <a href={`${githubUrl}/blob/main/LICENSE`} className="text-blue underline! underline-offset-2">
                    Apache License 2.0
                  </a>
                  , with a{' '}
                  <a href={`${githubUrl}/blob/main/NOTICE`} className="text-blue underline! underline-offset-2">
                    NOTICE
                  </a>{' '}
                  file.
                </p>

                <p>
                  Shared hardening scrubs credential-shaped error text, marks incomplete collections, and reports
                  pagination stops. Evidence exporters allocate a new bundle path on each rerun instead of overwriting a
                  prior export. Runtime adapters validate tool schemas, classify read effects, and put approval gates
                  around writer tools where the host supports them.
                </p>

                <p>
                  Every raw spec remains an agent-agnostic build plan with APIs, authentication, control mappings,
                  architecture, and test guidance. Browse them at{' '}
                  <Link href="/specs/" className="text-blue underline! underline-offset-2">
                    /specs
                  </Link>
                  .
                </p>
              </div>
            </div>
          </div>

          <aside className="about-robot-column" aria-label="grclanker field unit">
            <div className="about-robot-card">
              <div className="about-robot-meta">
                <span className="hud-label">Field Unit</span>
                <span className="about-robot-status">
                  <span className="led led-live" /> Local-first CLI
                </span>
              </div>
              <div className="about-robot-figure">
                <img
                  src="/about/grclanker-robot-v1.webp"
                  width={896}
                  height={1200}
                  alt="Full-body illustration of the grclanker robot"
                  className="about-robot-image"
                  loading="lazy"
                />
              </div>
            </div>
          </aside>
        </div>

        <section className="page-image-break mt-8" aria-label="About ambient frame">
          <img src="/footer/standby.webp" alt="" className="page-image-break-image" loading="lazy" />
          <div className="page-image-break-overlay">
            <span className="page-image-break-pill">Open source // local-first // experimental by design</span>
          </div>
        </section>
      </div>
    </>
  );
}

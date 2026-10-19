import Link from 'next/link';
import { HeroImage } from '../components/hero-image';
import { HeroBrandRail, HeroImageBreak } from '../components/hero-images';
import { HeroInstall } from '../components/hero-install';
import { pageMetadata } from '../lib/metadata';
import { githubUrl } from '../lib/site';
import { loadSpecs } from '../lib/specs';

export const metadata = pageMetadata({
  title: 'grclanker: Put a Clanker on Your Compliance',
  description:
    '241 domain tools across 35 vendor integrations and CMVP, KEV, EPSS, FedRAMP, SCF, and OSCAL, with Pi, Cursor Agent SDK, and Flue runtime paths.',
  path: '/',
});

const terminalExamples = [
  {
    command: 'grclanker flue run --message "What is the CMVP certificate for BoringCrypto?"',
    description: 'Resolve the exact validation record and answer with the cert, standard, and status.',
  },
  {
    command: 'grclanker investigate "CVE-2024-3094"',
    description:
      'Start the investigation workflow with its subject filled in to trace KEV status, EPSS likelihood, and ransomware linkage.',
  },
  {
    command: 'grclanker tools aws_check_access',
    description: 'List every bundled tool, or show one tool’s group, description, and parameters before you run it.',
  },
];

const workflowCards = [
  {
    command: '/investigate',
    color: 'text-sapphire',
    description: 'Trace crypto status, KEVs, EPSS, and ransomware linkage for a module, vendor, product, or CVE.',
  },
  {
    command: '/audit',
    color: 'text-yellow',
    description:
      'Map gathered evidence to the requested framework and classify each control as satisfied, partially satisfied, not satisfied, or unable to assess.',
  },
  {
    command: '/assess',
    color: 'text-peach',
    description: 'Classify the subject as strong, mixed, at risk, or critical, then name the top risks and the next actions.',
  },
  {
    command: '/validate',
    color: 'text-green',
    description:
      'Answer the narrow FIPS question: actively validated, previously validated but expired, in process, or not found.',
  },
];

function releaseFacts(integrationSpecCount: number) {
  return [
    {
      label: '241 domain tools',
      detail:
        'Native checks, assessments, and evidence exports cover 35 vendor integrations, plus CMVP, KEV, EPSS, FedRAMP, SCF, and OSCAL tools. The v0.1.2 release bundle carries all of them.',
    },
    {
      label: 'Three runtime paths',
      detail:
        'Use the Pi terminal CLI, run the same agent from source with the Cursor Agent SDK, or use the bundled Flue runner and official Flue CLI.',
    },
    {
      label: 'Hardened evidence',
      detail:
        'Runtime adapters classify read effects, approval-gate writers, and redact credential-shaped arguments. Integration exports document sensitive-data handling and partial collection.',
    },
    {
      label: `${integrationSpecCount} integration specs`,
      detail:
        'Every shipped vendor integration except Vanta has a repository spec that remains a reusable design record and build input.',
    },
  ];
}

const whatsNewCards = [
  {
    label: 'October 2026 FedRAMP rules',
    color: 'text-sapphire',
    detail:
      'The FedRAMP docs are regenerated from Consolidated Rules 2026.10.13.01. FRC-CSX-MOT is gone, leaving 245 requirements.',
  },
  {
    label: 'Fuller FedRAMP lookups',
    color: 'text-yellow',
    detail:
      'fedramp_get_requirement shows notification forms, mapped Rev5 controls, and the full update history. fedramp_search_frmr matches control IDs such as ra-5.',
  },
  {
    label: 'Trust-center headers',
    color: 'text-peach',
    detail:
      'The ADS bundle and site scaffolds list the FRC-CSO-JSN hosting requirements: a JSON content type, nosniff, and CORS.',
  },
  {
    label: 'sandbox-runtime 0.0.78',
    color: 'text-green',
    detail:
      'Backend grep and find keep working with the placeholder files it mounts, and env exec and env smoke-test exit when done.',
  },
  {
    label: 'Agent SDK on BDK 0.2.26',
    color: 'text-mauve',
    detail:
      'The Cursor Agent SDK project moves up from 0.2.21 and still serves all 241 tools: 199 read-only and 42 approval-gated writers.',
  },
  {
    label: 'New docs site',
    color: 'text-blue',
    detail:
      'grclanker.com runs on Next.js with Fumadocs at the same URLs. Search covers docs, specs, and pages, and wide tables stack into cards on phones.',
  },
];

export default function HomePage() {
  const specs = loadSpecs();
  const integrationSpecCount = specs.filter((spec) => spec.vendor !== 'grclanker').length;

  return (
    <>
      <section className="relative overflow-hidden border-b border-surface0/60">
        <div className="hero-backdrop absolute inset-0 w-full h-full">
          <HeroImage
            src="/hero/command-center.webp"
            alt="Clanker command center"
            className="w-full h-full object-cover object-center"
            loading="eager"
          />
        </div>
        <div className="absolute inset-0 bg-gradient-to-b from-base/65 via-base/84 to-base pointer-events-none" />

        <div className="relative z-10 max-w-content mx-auto px-6 pt-14 pb-18 md:pt-20 md:pb-24">
          <section className="hero-stack">
            <div className="max-w-4xl text-center hero-copy-block">
              <h1 className="font-bold text-4xl sm:text-5xl lg:text-6xl text-text leading-tight hero-text-shadow">
                Your compliance evidence is scattered.
                <br />
                Put a clanker on it.
              </h1>
              <p className="mx-auto mt-5 max-w-2xl text-base md:text-lg text-subtext1 leading-relaxed italic hero-copy-lede">
                241 domain tools. 35 vendor integrations. Pi, Cursor Agent SDK, and Flue runtime paths.
              </p>
            </div>

            <div className="hero-install-panel">
              <HeroInstall />

              <div className="hero-action-row">
                <Link href="/docs/getting-started/installation/" className="hero-primary-link">
                  Get Started
                </Link>
                <a href={githubUrl} target="_blank" rel="noopener" className="hero-secondary-link">
                  GitHub
                </a>
              </div>

              <p className="hero-support-copy">
                The curl installer ships the v0.1.2 release bundle with all 241 domain tools and its own Node.js runtime.
                To run unreleased changes,{' '}
                <Link href="/docs/getting-started/installation/#install-from-source">build from source</Link> (Node 22.19
                or newer).
              </p>
              <p className="hero-support-copy">
                Need just the skills?{' '}
                <Link href="/docs/getting-started/installation/#skills-only">Install the skills-only bundle</Link>.
              </p>
            </div>
          </section>
        </div>
      </section>

      <section className="hero-preview-section">
        <div className="max-w-content mx-auto px-6">
          <div className="hero-preview-shell">
            <HeroImage
              src="/hero/grclanker-terminal.webp"
              width={1750}
              height={1316}
              alt="grclanker CLI start screen from the v0.1.2 release bundle: 248 tools and 2 agents, the investigate, audit, assess, and validate workflows, and 241 domain tools ready"
              className="hero-preview-image"
              loading="eager"
            />
          </div>
        </div>
      </section>

      <div className="max-w-content mx-auto px-6 pt-5 pb-8 md:pt-7 md:pb-10 space-y-8">
        <HeroBrandRail />

        <section className="viewscreen rounded-xl scanlines relative overflow-hidden hero-briefing">
          <div className="relative z-10 p-5 md:p-6">
            <div className="hero-briefing-top">
              <div>
                <h2 className="font-semibold text-sm tracking-widest uppercase text-blue">What You Ask → What It Does</h2>
                <p className="text-subtext0 text-sm mt-1 italic">Shipped in v0.1.2, not a roadmap.</p>
              </div>
              <div className="hero-briefing-version">v0.1.2 // released</div>
            </div>

            <div className="hero-briefing-grid">
              <div className="hero-briefing-main">
                <div className="hero-summary-list">
                  {terminalExamples.map((item) => (
                    <div key={item.command} className="hero-summary-item">
                      <div className="hero-summary-command">{item.command}</div>
                      <div className="hero-summary-copy">{item.description}</div>
                    </div>
                  ))}
                </div>
              </div>

              <aside className="hero-briefing-side" aria-label="Release details">
                <p className="hero-briefing-kicker">Local-first when you want it. Hosted when you choose it.</p>

                <div className="hero-fact-list">
                  {releaseFacts(integrationSpecCount).map((item) => (
                    <div key={item.label} className="hero-fact-row">
                      <div className="hero-fact-label">{item.label}</div>
                      <div className="hero-fact-body">{item.detail}</div>
                    </div>
                  ))}
                </div>
              </aside>
            </div>
          </div>
        </section>

        <section className="viewscreen rounded-xl scanlines relative overflow-hidden" aria-labelledby="whats-new-heading">
          <div className="relative z-10 p-5 md:p-6">
            <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
              <div>
                <h2 id="whats-new-heading" className="font-semibold text-sm tracking-widest uppercase text-blue">
                  What's New in v0.1.2
                </h2>
                <p className="text-subtext0 text-sm mt-1 italic">
                  Updates the FedRAMP tools to the October 2026 Consolidated Rules and moves the sandbox-runtime backend to
                  0.0.78. The tool surface is unchanged, and the changelog has upgrade notes.
                </p>
              </div>
              <Link href="/docs/changelog/" className="spec-action-btn spec-action-btn-primary self-start md:self-auto">
                Full changelog
              </Link>
            </div>

            <div className="workflow-grid">
              {whatsNewCards.map((item) => (
                <div key={item.label} className="workflow-row">
                  <div className={`font-mono text-sm ${item.color}`}>{item.label}</div>
                  <div className="text-subtext0 text-sm mt-2 leading-relaxed">{item.detail}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <HeroImageBreak />

        <section className="viewscreen rounded-xl scanlines relative overflow-hidden">
          <div className="relative z-10 p-5 md:p-6">
            <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
              <div>
                <h2 className="font-semibold text-sm tracking-widest uppercase text-blue">Workflow Deck</h2>
                <p className="text-subtext0 text-sm mt-1 italic">Four structured workflows. Pick one, stay on it.</p>
              </div>
              <div className="text-[0.6875rem] font-mono uppercase tracking-[0.16em] text-subtext0">
                /investigate /audit /assess /validate
              </div>
            </div>

            <div className="workflow-grid">
              {workflowCards.map((item) => (
                <div key={item.command} className="workflow-row">
                  <div className={item.color}>{item.command}</div>
                  <div className="text-subtext0 text-sm mt-2 leading-relaxed">{item.description}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </>
  );
}

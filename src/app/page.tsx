import Link from 'next/link';
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
      'Map gathered evidence against the requested framework and classify what is satisfied, partial, absent, or unverifiable.',
  },
  {
    command: '/assess',
    color: 'text-peach',
    description: 'Produce an evidence-backed posture readout with top risks, confidence notes, and remediation order.',
  },
  {
    command: '/validate',
    color: 'text-green',
    description: 'Answer the narrow FIPS question cleanly: active, historical, in process, or absent.',
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

function whatsNew(specCount: number, generatedSpecCount: number) {
  return [
    {
      label: '8 to 241 tools',
      color: 'text-sapphire',
      detail: '35 vendor integrations plus FedRAMP, SCF, and OSCAL tools, each integration with its own docs guide.',
    },
    {
      label: 'Ask from the shell',
      color: 'text-yellow',
      detail:
        'grclanker "<prompt>" and grclanker investigate <subject> pass your question straight in, with an optional --compute backend for that run.',
    },
    {
      label: 'Two more runtimes',
      color: 'text-peach',
      detail:
        'The Cursor Agent SDK serves all 241 tools with 42 approval-gated writers, and grclanker flue run drives the same agent under Flue.',
    },
    {
      label: 'Remote compute',
      color: 'text-green',
      detail: 'Modal, RunPod Pod, and RunPod Serverless join host, sandbox-runtime, Docker, and Parallels VM backends.',
    },
    {
      label: 'Specs from code',
      color: 'text-mauve',
      detail: `${specCount} repository specs, ${generatedSpecCount} of them generated from the tool registry. CI fails when a generated spec drifts.`,
    },
    {
      label: 'Hardened evidence',
      color: 'text-blue',
      detail:
        'Credential scrubbing in errors and exports, no credentials on cross-origin pagination links, and exports that allocate a new bundle on rerun.',
    },
    {
      label: 'Verifiable releases',
      color: 'text-sky',
      detail:
        'Reproducible bundles for six platforms with SHA256SUMS and GitHub build provenance attestations, plus CI on every pull request.',
    },
    {
      label: 'Apache-2.0',
      color: 'text-lavender',
      detail: 'grclanker is licensed under the Apache License 2.0, with a NOTICE file.',
    },
  ];
}

export default function HomePage() {
  const specs = loadSpecs();
  const integrationSpecCount = specs.filter((spec) => spec.vendor !== 'grclanker').length;
  const generatedSpecCount = specs.filter((spec) => spec.status === 'generated').length;

  return (
    <>
      <section className="relative overflow-hidden border-b border-surface0/60">
        <div className="absolute inset-0 w-full h-full">
          <img
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
            <img
              src="/hero/grclanker-terminal.png"
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
                  What's New in v0.1.0
                </h2>
                <p className="text-subtext0 text-sm mt-1 italic">
                  The first full release since v0.0.1. The one-line installer now ships v0.1.2, which adds the October 2026
                  FedRAMP rules and sandbox-runtime fixes.
                </p>
              </div>
              <Link href="/docs/changelog/" className="spec-action-btn spec-action-btn-primary self-start md:self-auto">
                Full changelog
              </Link>
            </div>

            <div className="workflow-grid">
              {whatsNew(specs.length, generatedSpecCount).map((item) => (
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

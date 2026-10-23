import Link from 'next/link';
import { HeroImage } from '../components/hero-image';
import { HeroBrandRail, HeroImageBreak } from '../components/hero-images';
import { HeroInstall } from '../components/hero-install';
import { pageMetadata } from '../lib/metadata';
import { imageSrcSet } from '../lib/responsive-images.mjs';
import { githubUrl } from '../lib/site';
import { loadSpecs } from '../lib/specs';

export const metadata = pageMetadata({
  title: 'grclanker: Put a Clanker on Your Compliance',
  description:
    '241 domain tools across 35 vendor integrations and CMVP, KEV, EPSS, FedRAMP, SCF, and OSCAL, with Pi, Cursor Agent SDK, Flue, and experimental durable runtime paths.',
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
        'Native checks, assessments, and evidence exports cover 35 vendor integrations, plus CMVP, KEV, EPSS, FedRAMP, SCF, and OSCAL tools. The v0.1.4 release bundle carries all of them.',
    },
    {
      label: 'Four runtime paths',
      detail:
        'Use the Pi terminal CLI, run the same agent from source with the Cursor Agent SDK, use the bundled Flue runner and official Flue CLI, or opt in to the experimental durable runtime, which can resume a crashed or stopped run.',
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
    label: 'Retries, then fails closed',
    color: 'text-sapphire',
    detail:
      '32 integrations and the KEV, EPSS, CMVP, SCF, and FedRAMP tools retry rate limits, server errors, and timeouts. A read that still fails is reported as unread, so no check passes on partial data.',
  },
  {
    label: 'Rejected credentials named',
    color: 'text-yellow',
    detail:
      'When a vendor refuses the credentials themselves, 29 access checks now report failed instead of a permission gap, and the next step names the variable or setting to fix.',
  },
  {
    label: 'Smoother first run',
    color: 'text-peach',
    detail:
      'grclanker --version prints the version, grclanker --session <id> reopens a session, and a first launch without a terminal exits with a message instead of a stack trace.',
  },
  {
    label: 'Failed upgrades roll back',
    color: 'text-green',
    detail:
      'Both installers put the previous install back when extraction fails, and the skills installers keep the installed skill when a download is cut off or wrong.',
  },
  {
    label: 'Bundles tested on their own OS',
    color: 'text-mauve',
    detail:
      'Each of the six release bundles is installed and run on a native macOS, Linux, or Windows runner, and a release gate refuses to publish unless every check passes.',
  },
  {
    label: 'Tools match their docs',
    color: 'text-blue',
    detail:
      'kevs_search puts an exact CVE ID first, AWS lists the S3 IAM actions a policy needs, and Zendesk ZD-05, LaunchDarkly, and SCF now do what their docs say.',
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
            sources={[
              { media: '(max-width: 479px)', srcSet: '/hero/command-center-crop-880.webp' },
              { media: '(max-width: 767px)', srcSet: '/hero/command-center-crop-1500.webp' },
            ]}
            alt="Clanker command center"
            className="w-full h-full object-cover object-center"
            loading="eager"
            fetchPriority="high"
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
                241 domain tools. 35 vendor integrations. Pi, Cursor Agent SDK, Flue, and experimental durable runtime
                paths.
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
                The curl installer ships the v0.1.4 release bundle with all 241 domain tools and its own Node.js runtime.
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
            {/* The shell is at most 54rem wide, inside a 1px border. Low priority
                leaves the bandwidth to the hero picture, the largest paint. */}
            <HeroImage
              src="/hero/grclanker-terminal.webp"
              srcSet={imageSrcSet('/hero/grclanker-terminal.webp')}
              sizes="(min-width: 912px) 862px, calc(100vw - 50px)"
              width={1750}
              height={1316}
              alt="grclanker CLI start screen from the v0.1.4 release bundle: 248 tools and 2 agents, the investigate, audit, assess, and validate workflows, and 241 domain tools ready"
              className="hero-preview-image"
              loading="eager"
              fetchPriority="low"
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
                <p className="text-subtext0 text-sm mt-1 italic">Shipped in v0.1.4, not a roadmap.</p>
              </div>
              <div className="hero-briefing-version">v0.1.4 // released</div>
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
                  What's New in v0.1.4
                </h2>
                <p className="text-subtext0 text-sm mt-1 italic">
                  Retries rate limits and brief outages, names rejected credentials in 29 access checks, and rolls back a
                  failed install.
                  The tool surface is unchanged, and the changelog has upgrade notes for the results that change.
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

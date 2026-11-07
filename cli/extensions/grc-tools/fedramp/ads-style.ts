export function buildAdsSiteCss(): string {
  return `:root {
  color-scheme: dark;
  --bg: oklch(0.2 0.022 255);
  --bg-elevated: oklch(0.25 0.026 255);
  --bg-panel: color-mix(in oklch, var(--bg-elevated) 86%, oklch(0.58 0.06 140) 14%);
  --ink: oklch(0.92 0.018 250);
  --muted: oklch(0.78 0.018 250);
  --line: oklch(0.42 0.03 246 / 0.48);
  --accent: oklch(0.8 0.12 145);
  --accent-soft: oklch(0.68 0.07 150);
  --warning: oklch(0.82 0.1 80);
  --shadow: 0 24px 80px oklch(0.06 0.02 250 / 0.42);
  --serif: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
  --sans: "Aptos", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
}

* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at top, oklch(0.36 0.05 150 / 0.18), transparent 0 38rem),
    linear-gradient(180deg, color-mix(in oklch, var(--bg) 84%, oklch(0.28 0.03 150) 16%), var(--bg));
  color: var(--ink);
  font-family: var(--sans);
  line-height: 1.6;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    linear-gradient(var(--line) 1px, transparent 1px),
    linear-gradient(90deg, var(--line) 1px, transparent 1px);
  background-size: 2.75rem 2.75rem;
  mask-image: linear-gradient(180deg, oklch(0 0 0 / 0.3), transparent 85%);
  opacity: 0.28;
}

a { color: inherit; }

.site-shell {
  width: min(76rem, calc(100vw - 2rem));
  margin: 0 auto;
  padding: 1.25rem 0 3rem;
}

.topbar,
.panel,
.footer-panel {
  border: 1px solid var(--line);
  background: color-mix(in oklch, var(--bg-panel) 88%, black 12%);
  box-shadow: var(--shadow);
}

.topbar {
  display: grid;
  gap: 1rem;
  padding: 1rem 1.1rem;
  border-radius: 1.4rem;
  backdrop-filter: blur(12px);
}

.brand-row {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  align-items: start;
}

.brand-meta {
  display: grid;
  gap: 0.28rem;
}

.eyebrow {
  text-transform: uppercase;
  letter-spacing: 0.18em;
  font-size: 0.72rem;
  color: var(--accent);
}

.brand-title {
  margin: 0;
  font-family: var(--serif);
  font-size: clamp(2rem, 5vw, 3.6rem);
  line-height: 0.94;
}

.brand-copy {
  max-width: 40rem;
  margin: 0;
  color: var(--muted);
}

.meta-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 0.65rem;
}

.meta-pill,
.site-nav-link,
.action-link {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  min-height: 2.6rem;
  padding: 0.55rem 0.95rem;
  border-radius: 999px;
  border: 1px solid var(--line);
  text-decoration: none;
}

.meta-pill {
  color: var(--muted);
  background: color-mix(in oklch, var(--bg-elevated) 72%, black 28%);
}

.site-nav {
  display: flex;
  flex-wrap: wrap;
  gap: 0.7rem;
}

.site-nav-link {
  color: var(--muted);
  background: transparent;
}

.site-nav-link.is-active,
.action-link.primary {
  color: oklch(0.16 0.015 250);
  background: linear-gradient(135deg, var(--accent), color-mix(in oklch, var(--accent) 66%, white 34%));
  border-color: transparent;
}

.action-link.secondary {
  color: var(--ink);
  background: color-mix(in oklch, var(--bg-elevated) 72%, black 28%);
}

.hero-grid,
.content-grid {
  display: grid;
  gap: 1rem;
  margin-top: 1rem;
}

.hero-grid {
  grid-template-columns: minmax(0, 1.7fr) minmax(18rem, 1fr);
}

.panel {
  border-radius: 1.5rem;
  padding: 1.25rem;
}

.lede {
  margin: 0;
  color: var(--muted);
}

.action-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-top: 1.2rem;
}

.stats-grid {
  display: grid;
  gap: 0.8rem;
}

.stat {
  padding-bottom: 0.8rem;
  border-bottom: 1px solid color-mix(in oklch, var(--line) 78%, transparent 22%);
}

.stat:last-child { border-bottom: 0; padding-bottom: 0; }

.stat-label {
  display: block;
  font-size: 0.8rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--accent-soft);
}

.stat-value {
  margin-top: 0.2rem;
  font-size: 1rem;
}

.section-grid {
  display: grid;
  gap: 1rem;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  margin-top: 1rem;
}

.section-grid > section,
.section-grid > aside {
  grid-column: span 6;
}

.section-kicker {
  display: inline-block;
  color: var(--accent-soft);
  text-transform: uppercase;
  letter-spacing: 0.14em;
  font-size: 0.78rem;
}

.section-title {
  margin: 0.3rem 0 0.7rem;
  font-family: var(--serif);
  font-size: clamp(1.5rem, 3vw, 2.15rem);
  line-height: 1;
}

.section-copy,
.footer-copy,
.artifact-list p,
.rollout-list p,
.empty-copy,
.provenance,
.history-table td,
.history-table th {
  color: var(--muted);
}

.artifact-list,
.rollout-list,
.endpoint-list,
.checklist,
.footer-links {
  list-style: none;
  margin: 0;
  padding: 0;
}

.artifact-list,
.endpoint-list,
.checklist {
  display: grid;
  gap: 0.75rem;
}

.artifact-list li,
.endpoint-list li,
.rollout-list li,
.checklist li {
  padding: 0.9rem 1rem;
  border-radius: 1.1rem;
  border: 1px solid color-mix(in oklch, var(--line) 76%, transparent 24%);
  background: color-mix(in oklch, var(--bg-elevated) 78%, black 22%);
}

.artifact-list h3,
.rollout-list h3,
.endpoint-list h3 {
  margin: 0 0 0.3rem;
  font-size: 1rem;
}

.artifact-meta,
.tiny-note {
  font-size: 0.9rem;
}

.rollout-list { display: grid; gap: 0.75rem; }
.rollout-list ul { margin: 0.7rem 0 0; padding-left: 1.15rem; color: var(--muted); }

.provenance {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid color-mix(in oklch, var(--line) 78%, transparent 22%);
  font-size: 0.93rem;
}

.history-table {
  width: 100%;
  border-collapse: collapse;
  overflow: hidden;
  border-radius: 1rem;
}

.history-table th,
.history-table td {
  padding: 0.9rem 0.8rem;
  border-bottom: 1px solid color-mix(in oklch, var(--line) 78%, transparent 22%);
  text-align: left;
}

.history-table thead th {
  color: var(--ink);
  text-transform: uppercase;
  font-size: 0.8rem;
  letter-spacing: 0.12em;
}

.footer-panel {
  margin-top: 1rem;
  border-radius: 1.4rem;
  padding: 1rem 1.1rem 1.2rem;
}

.footer-links {
  display: flex;
  flex-wrap: wrap;
  gap: 0.7rem;
  margin-top: 0.9rem;
}

.footer-links a { color: var(--muted); text-decoration: none; }

.mono-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  min-height: 2rem;
  padding: 0.4rem 0.7rem;
  border-radius: 999px;
  background: color-mix(in oklch, var(--bg-elevated) 76%, black 24%);
  border: 1px solid color-mix(in oklch, var(--line) 76%, transparent 24%);
  color: var(--muted);
  font-size: 0.9rem;
}

.mono-chip strong {
  color: var(--ink);
  font-weight: 600;
}

@media (max-width: 860px) {
  .hero-grid,
  .section-grid {
    grid-template-columns: 1fr;
  }

  .section-grid > section,
  .section-grid > aside {
    grid-column: auto;
  }

  .brand-row {
    flex-direction: column;
  }
}

@media (max-width: 640px) {
  .site-shell {
    width: min(100vw - 1rem, 76rem);
    padding-top: 0.75rem;
    padding-bottom: 2rem;
  }

  .panel,
  .topbar,
  .footer-panel {
    border-radius: 1.1rem;
    padding: 1rem;
  }

  .action-link,
  .site-nav-link,
  .meta-pill {
    width: 100%;
    justify-content: center;
  }

  .footer-links {
    display: grid;
  }
}
`;
}

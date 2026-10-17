import { RAW_BASE } from '../lib/specs';
import { CommandLine } from './command-line';

const sampleSpec = `${RAW_BASE}/aws-sec-inspector.spec.md`;
const prompt = `"Read ${sampleSpec}, inspect the shipped AWS tools, and propose an extension"`;
const shortPrompt = '"Read ...spec.md and propose an extension"';

const groups = [
  {
    title: 'Terminal Agents',
    open: true,
    items: [
      { label: 'Claude Code', command: `claude ${prompt}`, preview: `claude ${shortPrompt}` },
      { label: 'Codex CLI', command: `codex ${prompt}`, preview: `codex ${shortPrompt}` },
      { label: 'Gemini CLI', command: `gemini ${prompt}`, preview: `gemini ${shortPrompt}` },
      { label: 'OpenCode', command: `opencode run ${prompt}`, preview: `opencode run ${shortPrompt}` },
      { label: 'Droid', command: `droid exec ${prompt}`, preview: `droid exec ${shortPrompt}` },
      { label: 'Pi', command: `pi ${prompt}`, preview: `pi ${shortPrompt}` },
      { label: 'Goose', command: `goose run -t ${prompt}`, preview: `goose run -t ${shortPrompt}` },
      { label: 'Amp', command: `amp -x ${prompt}`, preview: `amp -x ${shortPrompt}` },
      { label: 'Crush', command: `crush run ${prompt}`, preview: `crush run ${shortPrompt}` },
    ],
  },
  {
    title: 'IDE Agents',
    open: false,
    items: [
      {
        label: 'Cursor / Windsurf',
        command: '@aws-sec-inspector.spec.md Compare this spec with the shipped AWS tools and propose an extension',
        preview: '@aws-sec-inspector.spec.md Propose an extension',
      },
      {
        label: 'GitHub Copilot',
        command: '@workspace #file:aws-sec-inspector.spec.md compare this spec with the shipped AWS tools',
        preview: '@workspace #file:aws-sec-inspector.spec.md compare coverage',
      },
      {
        label: 'Cline / Roo Code',
        command: `Compare this spec with the shipped AWS tools: ${sampleSpec}`,
        preview: 'Paste the raw URL into the chat',
      },
    ],
  },
  {
    title: 'Any Chat Interface',
    open: false,
    items: [
      {
        label: 'Claude.ai / ChatGPT / Gemini',
        command: `Here is a shipped compliance integration spec: ${sampleSpec}. Review its coverage and propose the next extension.`,
        preview: 'Review this shipped spec and propose an extension.',
      },
    ],
  },
  {
    title: 'Programmatic',
    open: false,
    items: [
      {
        label: 'Pipe to any LLM',
        command: `curl -s ${sampleSpec} | your-agent "Review this shipped spec and propose an extension"`,
        preview: 'curl -s ...spec.md | your-agent "Review this"',
      },
      {
        label: 'Clone all specs',
        command: 'git clone https://github.com/ethanolivertroy/grclanker.git',
        preview: 'git clone https://github.com/ethanolivertroy/grclanker.git',
      },
    ],
  },
];

export function AgentCommandsSection() {
  return (
    <section className="mb-8" data-agent-commands>
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-widest text-blue">
        Review or Extend With Any Agent
      </h2>
      <p className="mb-5 text-sm italic text-subtext0">
        The native tool family already ships. Use the spec to inspect coverage or plan the next change.
      </p>
      {groups.map((group) => (
        <details key={group.title} className="agent-group mb-3" open={group.open}>
          <summary className="agent-group-toggle">{group.title}</summary>
          <div className="agent-group-content">
            {group.items.map((item) => (
              <CommandLine key={item.label} {...item} />
            ))}
          </div>
        </details>
      ))}
    </section>
  );
}

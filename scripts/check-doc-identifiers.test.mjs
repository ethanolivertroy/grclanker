import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  checkDocs,
  findEnvNames,
  findToolNames,
  readCodeIdentifiers,
  shellCommands,
  toolNamePattern,
} from './check-doc-identifiers.mjs';

const script = join(dirname(fileURLToPath(import.meta.url)), 'check-doc-identifiers.mjs');
const repoDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = [];

after(() => {
  for (const dir of fixtures) rmSync(dir, { recursive: true, force: true });
});

const catalog = `const DOMAIN_GROUPS: Array<[prefix: string, label: string]> = [
  ["demo_", "Demo"],
  ["demo_ops_", "Demo Operator"],
];
`;

const extension = `pi.registerTool({ name: "demo_check_access", label: "Check" });
pi.registerTool({ name: \`demo_assess_posture\` });
registerAssessment(pi, "demo_assess_identity");
pi.registerTool({ name: 'demo_ops_review_tokens' });
const config = { region: "demo_region" };
const token = process.env.DEMO_API_TOKEN ?? process.env["DEMO_TOKEN"];
`;

function repo(files = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'check-doc-identifiers-'));
  fixtures.push(dir);
  const all = {
    'cli/pi/tool-catalog.ts': catalog,
    'cli/extensions/demo.ts': extension,
    'cli/scripts/demo-live-smoke.mjs': 'const regions = process.env.DEMO_SMOKE_REGIONS;\n',
    'cli/tests/demo.test.mjs': 'const ghost = "demo_assess_ghost";\nprocess.env.DEMO_TEST_ONLY = "1";\n',
    'cli/dist/extensions/demo.js': 'const stale = "demo_assess_stale";\nprocess.env.DEMO_DIST_ONLY;\n',
    'public/install': 'INSTALL_DIR="${GRCLANKER_INSTALL_DIR:-$HOME/.local/share/grclanker}"\n',
    'public/llms.txt': 'DEMO_LLMS_ONLY\n',
    'README.md': '# Demo\n\nRun `demo_check_access` first.\n',
    'src/content/docs/docs/index.mdx': '---\ntitle: Demo\n---\n',
    ...files,
  };
  for (const [path, contents] of Object.entries(all)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), contents);
  }
  return dir;
}

const pattern = toolNamePattern(['demo_', 'demo_ops_'], ['check', 'assess', 'review', 'recent']);
const toolNames = (markdown) => findToolNames(markdown, pattern).map(({ name }) => name);
const envNames = (markdown) => findEnvNames(markdown).map(({ name }) => name);

test('tool names come from string literals in cli/extensions and verbs from registered names', () => {
  const code = readCodeIdentifiers(repo());
  assert.deepEqual([...code.toolNames].sort(), [
    'demo_assess_identity',
    'demo_assess_posture',
    'demo_check_access',
    'demo_ops_review_tokens',
    'demo_region',
  ]);
  assert.deepEqual(findToolNames('`demo_check_access` `demo_assess_x` `demo_ops_review_y` `demo_region_x`', code.toolPattern).map(({ name }) => name), [
    'demo_check_access',
    'demo_assess_x',
    'demo_ops_review_y',
  ]);
});

test('environment variable names come from the code under cli/ and the installers, never tests or builds', () => {
  const { envNames: names } = readCodeIdentifiers(repo());
  for (const name of ['DEMO_API_TOKEN', 'DEMO_TOKEN', 'DEMO_SMOKE_REGIONS', 'GRCLANKER_INSTALL_DIR']) {
    assert.ok(names.has(name), name);
  }
  for (const name of ['DEMO_TEST_ONLY', 'DEMO_DIST_ONLY', 'DEMO_LLMS_ONLY']) assert.ok(!names.has(name), name);
});

test('a tool catalog without DOMAIN_GROUPS fails instead of checking nothing', () => {
  assert.throws(() => readCodeIdentifiers(repo({ 'cli/pi/tool-catalog.ts': 'export const GROUPS = [];\n' })), /DOMAIN_GROUPS/);
  assert.throws(() => readCodeIdentifiers(repo({ 'cli/extensions/demo.ts': 'const x = 1;\n' })), /registered tool names/);
});

test('a tool name is a prefix and a verb, with or without more words', () => {
  assert.deepEqual(toolNames('Run `demo_check_access`, then demo_assess_identity and demo_recent.'), [
    'demo_check_access',
    'demo_assess_identity',
    'demo_recent',
  ]);
  assert.deepEqual(toolNames('{"tool":"demo_ops_review_tokens"} [link](/docs/tools/catalog/#demo_assess_x)'), [
    'demo_ops_review_tokens',
    'demo_assess_x',
  ]);
});

test('globs, placeholders, file names, and other snake_case words are not tool names', () => {
  assert.deepEqual(
    toolNames(
      '`demo_assess_*` `demo_ops_*` `<slug>_check_access` `demo_check_access.json` `my_demo_check_access` ' +
        '`demo-check_access` `demo_check-access` `demo_sub_type` `demo_checks_x` `DEMO_CHECK_ACCESS` `demo_assessment`',
    ),
    [],
  );
});

test('tool names report the line they are on', () => {
  assert.deepEqual(findToolNames('intro\n\nuse demo_check_access\r\nand demo_assess_x', pattern), [
    { name: 'demo_check_access', line: 3 },
    { name: 'demo_assess_x', line: 4 },
  ]);
});

test('shell lines split into commands with quotes, substitutions, and comments kept apart', () => {
  assert.deepEqual(shellCommands('export A_B="$(gcloud auth print-access-token)" C=\'x y\' # export D_E=1'), [
    ['export', 'A_B="$(gcloud auth print-access-token)"', "C='x y'"],
  ]);
  assert.deepEqual(shellCommands('curl -fsSL https://x.test/#install | A_B="$HOME/x" bash && echo "a|b"; ls'), [
    ['curl', '-fsSL', 'https://x.test/#install'],
    ['A_B="$HOME/x"', 'bash'],
    ['echo', '"a|b"'],
    ['ls'],
  ]);
  assert.deepEqual(shellCommands('export KEY="-----BEGIN KEY-----\\n..." OTHER=1'), [
    ['export', 'KEY="-----BEGIN KEY-----\\n..."', 'OTHER=1'],
  ]);
});

test('shell blocks check exported variables and variables set for grclanker commands', () => {
  const markdown = [
    '```bash',
    'export DEMO_API_TOKEN="$(demo auth print-token)" DEMO_REGION=us   # or DEMO_COMMENTED',
    'export DEMO_SECRET',
    'DEMO_URL=https://demo.example DEMO_KEY=... \\',
    '  npm --prefix cli run test:demo:live',
    'curl -fsSL https://grclanker.com/install | GRCLANKER_INSTALL_DIR="$HOME/opt/grclanker" bash',
    'env DEMO_ENV_PREFIX=1 ./node_modules/.bin/grclanker',
    '$ export DEMO_PROMPTED=1',
    '```',
  ].join('\n');
  assert.deepEqual(envNames(markdown), [
    'DEMO_API_TOKEN',
    'DEMO_REGION',
    'DEMO_SECRET',
    'DEMO_URL',
    'DEMO_KEY',
    'GRCLANKER_INSTALL_DIR',
    'DEMO_ENV_PREFIX',
    'DEMO_PROMPTED',
  ]);
});

test('shell variables, other programs, comments, and heredocs are not checked', () => {
  const markdown = [
    '```bash',
    'OLLAMA_CONTEXT_LENGTH=128000 ollama serve',
    'LOCAL_ONLY=$(date)',
    'IFS= read -rs DEMO_READ',
    'echo "$DEMO_REFERENCED" ${DEMO_BRACED}',
    'modal setup   # or: export MODAL_TOKEN_ID=... MODAL_TOKEN_SECRET=...',
    'export PATH="$HOME/bin:$PATH"',
    'cat > .env <<\'EOF\'',
    'export DEMO_HEREDOC=1',
    'DEMO_IN_FILE=1 grclanker',
    'EOF',
    '```',
  ].join('\n');
  assert.deepEqual(envNames(markdown), []);
});

test('PowerShell blocks check $env: assignments', () => {
  const markdown = [
    '```powershell',
    "$env:GRCLANKER_VERSION = '0.1.3'",
    "if ($env:DEMO_COMPARED -eq 'x') { }",
    "# $env:DEMO_COMMENTED = 'x'",
    '```',
  ].join('\n');
  assert.deepEqual(envNames(markdown), ['GRCLANKER_VERSION']);
});

test('other code blocks and prose are not checked for environment variables', () => {
  const markdown = [
    'There is no `AWS_EXTERNAL_ID` environment variable.',
    '- `OKTA_CLIENT_SECRET=SSWS rejected` renders `OKTA_CLIENT_SECRET=[REDACTED] rejected`.',
    'Set `DEMO_INLINE=1` to skip the download.',
    '```text',
    'export DEMO_TEXT=1',
    '```',
    '````markdown',
    '```bash',
    'export DEMO_NESTED=1',
    '```',
    '````',
    '```sql',
    'GRANT ROLE SNOWFLAKE_AUDITOR TO USER GRCLANKER_SVC;',
    '```',
  ].join('\n');
  assert.deepEqual(envNames(markdown), []);
});

test('tables check the Variable and Environment variable columns only', () => {
  const markdown = [
    '| Variable | Purpose |',
    '| --- | --- |',
    '| `DEMO_ONE`, `DEMO_TWO`, or `$DEMO_THREE` | Also reads `NODE_EXTRA_CA_CERTS`. |',
    '| `DEMO_VERIFY_TLS=false` | Lab only. |',
    '',
    'Prose between tables names `DEMO_PROSE`.',
    '',
    '| Setting | Tool argument | **Environment variable** | Default |',
    '|:---|:---:|---:|---|',
    '| Region | `demo_region` | `DEMO_REGION` or none | `US_DEFAULT` |',
    '| Pipe | `a\\|b` | `DEMO_AFTER_PIPE` | |',
    '',
    '| Name | Value |',
    '| --- | --- |',
    '| `DEMO_NAME_COLUMN` | `DEMO_VALUE` |',
    '',
    '| Variable | Purpose |',
    '| --- | --- |',
    '| `demo_lowercase` and `DEMO ONE` | spans that are not one variable name |',
  ].join('\n');
  assert.deepEqual(findEnvNames(markdown), [
    { name: 'DEMO_ONE', line: 3 },
    { name: 'DEMO_TWO', line: 3 },
    { name: 'DEMO_THREE', line: 3 },
    { name: 'DEMO_VERIFY_TLS', line: 4 },
    { name: 'DEMO_REGION', line: 10 },
    { name: 'DEMO_AFTER_PIPE', line: 11 },
  ]);
});

test('a continued command reports the line it starts on', () => {
  const markdown = ['# Live smoke', '', '```bash', 'DEMO_URL=... \\', '  DEMO_KEY=... \\', '  npm run smoke', '```'].join('\n');
  assert.deepEqual(findEnvNames(markdown), [
    { name: 'DEMO_URL', line: 4 },
    { name: 'DEMO_KEY', line: 4 },
  ]);
});

test('checkDocs reports names the code does not define with their file and line', () => {
  const dir = repo({
    'src/content/docs/docs/integrations/demo.md': [
      '# Demo',
      '',
      'Run `demo_check_access`, then `demo_assess_ghost`.',
      '',
      '| Variable | Purpose |',
      '| --- | --- |',
      '| `DEMO_API_TOKEN` | API token. |',
      '| `DEMO_TEST_ONLY` | Only a test sets it. |',
      '',
      '```bash',
      'export DEMO_TOKEN=... DEMO_SMOKE_REGIONS=us DEMO_TYPO=1',
      '```',
    ].join('\n'),
  });
  const { problems, stats } = checkDocs({ repoDir: dir });
  assert.deepEqual(problems, [
    'src/content/docs/docs/integrations/demo.md:3: no tool named `demo_assess_ghost` in cli/extensions',
    'src/content/docs/docs/integrations/demo.md:8: environment variable `DEMO_TEST_ONLY` is not in cli/ or the public/install* installers',
    'src/content/docs/docs/integrations/demo.md:11: environment variable `DEMO_TYPO` is not in cli/ or the public/install* installers',
  ]);
  assert.deepEqual(stats, { files: 3, tools: 2, env: 5 });
});

test('the script exits non-zero and lists each problem', () => {
  const dir = repo({ 'README.md': 'Run `demo_check_acces`.\n' });
  const result = spawnSync(process.execPath, [script, dir], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /README\.md:1: no tool named `demo_check_acces` in cli\/extensions/);

  const clean = spawnSync(process.execPath, [script, repo()], { encoding: 'utf8' });
  assert.equal(clean.status, 0, clean.stderr);
  assert.match(clean.stdout, /2 files, 1 tool names, 0 environment variables/);
});

test('the docs and README name only tools and environment variables the code defines', () => {
  const { problems, stats } = checkDocs({ repoDir });
  assert.deepEqual(problems, []);
  assert.ok(stats.tools > 200, `only ${stats.tools} tool names found in the docs`);
  assert.ok(stats.env > 200, `only ${stats.env} environment variables found in the docs`);
});

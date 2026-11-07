#!/usr/bin/env node
// Checks that the docs and the README name only tools and environment
// variables that the code defines.
//
// Tool names and environment variables come from the checked-in neutral catalog.
// The shared generator validates that catalog against registered implementations.
// Globs and file names such as aws_check_access.json are not tool references.
//
// An environment variable is checked only where a page sets or lists one:
// `export` lines, assignments in front of a grclanker, npm, npx, node, bash,
// or sh command, and `$env:` assignments in shell code blocks, plus the
// Variable or Environment variable column of a table. Prose that only
// mentions a name, such as a redaction example or "there is no X variable",
// is not checked. The name must appear in the code under cli/ (tests
// excluded) or in the public/install* installers.
//
// Usage: node scripts/check-doc-identifiers.mjs [repoDir]

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readToolManifest, TOOL_MANIFEST_PATH } from './lib/tool-manifest.mjs';

const DOCS_DIR = 'src/content/docs/docs';
const README = 'README.md';
const SKIPPED_DIRS = new Set(['node_modules', 'dist', 'tests']);
const ENV_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;

const FENCE = /^\s*(`{3,}|~{3,})(.*)$/;
const SHELL_LANGS = new Set(['bash', 'sh', 'shell', 'zsh', 'console']);
const POWERSHELL_LANGS = new Set(['powershell', 'pwsh', 'ps1']);
// Variables set in front of these commands reach grclanker, its npm scripts,
// or the installer. Others, like `OLLAMA_CONTEXT_LENGTH=... ollama serve`,
// configure someone else's program.
const OWN_COMMANDS = new Set(['grclanker', 'npm', 'npx', 'node', 'bash', 'sh']);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const HEREDOC = /<<-?\s*(['"]?)(\w+)\1/;
const POWERSHELL_ASSIGNMENT = /\$env:(\w+)\s*=(?!=)/gi;

const TABLE_ROW = /^\s*\|/;
const TABLE_DELIMITER = /^\s*\|?[\s|:-]*-[\s|:-]*$/;
const VARIABLE_HEADERS = new Set([
  'variable',
  'variables',
  'environment variable',
  'environment variables',
  'env var',
  'env vars',
]);
const VARIABLE_SPAN = /^\$?([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)(?:=.*)?$/;

function walk(dir, keep) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      return entry.name.startsWith('.') || SKIPPED_DIRS.has(entry.name) ? [] : walk(path, keep);
    }
    return keep(entry.name) ? [path] : [];
  });
}

export function docFiles(repoDir) {
  return [join(repoDir, README), ...walk(join(repoDir, DOCS_DIR), (name) => /\.mdx?$/.test(name))];
}

function longestPrefix(word, prefixes) {
  let match;
  for (const prefix of prefixes) {
    if (word.length > prefix.length && word.startsWith(prefix) && (!match || prefix.length > match.length)) {
      match = prefix;
    }
  }
  return match;
}

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const alternatives = (words) => [...words].sort((a, b) => b.length - a.length).map(escapeRegExp).join('|');

export function toolNamePattern(prefixes, verbs) {
  return new RegExp(
    `(?<![\\w-])(?:${alternatives(prefixes)})(?:${alternatives(verbs)})(?:_[a-z0-9]+)*(?![\\w*-]|\\.[A-Za-z])`,
    'g',
  );
}

export function readCodeIdentifiers(repoDir) {
  const manifest = readToolManifest(repoDir);
  const tools = manifest.tools.filter((tool) => tool.kind === 'domain');
  const toolNames = new Set(tools.map((tool) => tool.name));
  const prefixes = manifest.toolPrefixes;
  const verbs = new Set(tools.map((tool) => tool.name.slice(longestPrefix(tool.name, prefixes).length).split('_')[0]));
  return { toolNames, envNames: new Set(manifest.environmentVariables), toolPattern: toolNamePattern(prefixes, verbs) };
}

export function findToolNames(markdown, toolPattern) {
  return markdown
    .split(/\r?\n/)
    .flatMap((text, index) => [...text.matchAll(toolPattern)].map(([name]) => ({ name, line: index + 1 })));
}

// Splits a shell line into simple commands of words, keeping quoted text and
// $(...) inside the word, and dropping a trailing comment.
export function shellCommands(line) {
  const commands = [[]];
  let word = null;
  let quote = null;
  let depth = 0;
  const end = () => {
    if (word !== null) commands.at(-1).push(word);
    word = null;
  };
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (quote) {
      word += char;
      if (char === '\\' && quote === '"') word += line[++i] ?? '';
      else if (char === quote) quote = null;
    } else if (depth > 0) {
      word += char;
      if (char === '(') depth++;
      else if (char === ')') depth--;
    } else if (char === '\\') {
      word = (word ?? '') + char + (line[++i] ?? '');
    } else if (char === '"' || char === "'") {
      word = (word ?? '') + char;
      quote = char;
    } else if (char === '$' && line[i + 1] === '(') {
      word = (word ?? '') + '$(';
      depth = 1;
      i++;
    } else if (char === '#' && word === null) {
      break;
    } else if (/\s/.test(char)) {
      end();
    } else if ('|&;()'.includes(char)) {
      end();
      commands.push([]);
    } else {
      word = (word ?? '') + char;
    }
  }
  end();
  return commands.filter((words) => words.length > 0);
}

function commandEnvNames(words) {
  if (words[0] === 'export') {
    return words.slice(1).filter((word) => !word.startsWith('-')).map((word) => word.split('=')[0]).filter((name) => ENV_NAME.test(name));
  }
  let i = 0;
  if (words[0] === 'env') {
    i = 1;
    while (words[i]?.startsWith('-')) i++;
  }
  const names = [];
  for (; i < words.length && ASSIGNMENT.test(words[i]); i++) names.push(words[i].slice(0, words[i].indexOf('=')));
  const command = words[i]?.split('/').pop();
  return OWN_COMMANDS.has(command) ? names.filter((name) => ENV_NAME.test(name)) : [];
}

function shellEnvNames(lines) {
  const found = [];
  let heredoc = null;
  for (let i = 0; i < lines.length; i++) {
    const { line } = lines[i];
    let { text } = lines[i];
    if (heredoc) {
      if (text.trim() === heredoc) heredoc = null;
      continue;
    }
    while (text.endsWith('\\') && i + 1 < lines.length) text = `${text.slice(0, -1)} ${lines[++i].text}`;
    text = text.replace(/^\s*\$\s+/, '');
    heredoc = text.match(HEREDOC)?.[2] ?? null;
    for (const words of shellCommands(text)) {
      for (const name of commandEnvNames(words)) found.push({ name, line });
    }
  }
  return found;
}

function powershellEnvNames(lines) {
  return lines.flatMap(({ text, line }) =>
    [...text.replace(/#.*$/, '').matchAll(POWERSHELL_ASSIGNMENT)]
      .map(([, name]) => ({ name, line }))
      .filter(({ name }) => ENV_NAME.test(name)),
  );
}

function tableCells(row) {
  return row
    .trim()
    .replace(/^\|/, '')
    .replace(/(?<!\\)\|$/, '')
    .split(/(?<!\\)\|/)
    .map((cell) => cell.trim());
}

export function findEnvNames(markdown) {
  const lines = markdown.split(/\r?\n/);
  const found = [];
  let fence = null;
  let columns = null;
  const closeFence = () => {
    if (SHELL_LANGS.has(fence.lang)) found.push(...shellEnvNames(fence.lines));
    else if (POWERSHELL_LANGS.has(fence.lang)) found.push(...powershellEnvNames(fence.lines));
    fence = null;
  };

  for (let index = 0; index < lines.length; index++) {
    const text = lines[index];
    const marker = text.match(FENCE);
    if (fence) {
      if (marker && marker[1][0] === fence.char && marker[1].length >= fence.length && !marker[2].trim()) closeFence();
      else fence.lines.push({ text, line: index + 1 });
      continue;
    }
    if (marker) {
      const lang = marker[2].trim().split(/\s/)[0].toLowerCase();
      fence = { char: marker[1][0], length: marker[1].length, lang, lines: [] };
      columns = null;
      continue;
    }
    if (TABLE_ROW.test(text) && TABLE_DELIMITER.test(lines[index + 1] ?? '')) {
      columns = tableCells(text).flatMap((cell, column) =>
        VARIABLE_HEADERS.has(cell.replace(/[`*]/g, '').trim().toLowerCase()) ? [column] : [],
      );
      index++;
      continue;
    }
    if (columns && TABLE_ROW.test(text)) {
      const cells = tableCells(text);
      for (const column of columns) {
        for (const [, span] of (cells[column] ?? '').matchAll(/`([^`]+)`/g)) {
          const name = span.trim().match(VARIABLE_SPAN)?.[1];
          if (name) found.push({ name, line: index + 1 });
        }
      }
      continue;
    }
    columns = null;
  }
  if (fence) closeFence();
  return found;
}

export function checkDocs({ repoDir, files = docFiles(repoDir) }) {
  const code = readCodeIdentifiers(repoDir);
  const problems = [];
  const tools = new Set();
  const env = new Set();
  for (const file of files) {
    const markdown = readFileSync(file, 'utf8');
    const where = relative(repoDir, file);
    for (const { name, line } of findToolNames(markdown, code.toolPattern)) {
      tools.add(name);
      if (!code.toolNames.has(name)) problems.push(`${where}:${line}: no tool named \`${name}\` in ${TOOL_MANIFEST_PATH}`);
    }
    for (const { name, line } of findEnvNames(markdown)) {
      env.add(name);
      if (!code.envNames.has(name)) {
        problems.push(`${where}:${line}: environment variable \`${name}\` is not in ${TOOL_MANIFEST_PATH}`);
      }
    }
  }
  return { problems, stats: { files: files.length, tools: tools.size, env: env.size } };
}

function main() {
  const repoDir = resolve(process.argv[2] ?? fileURLToPath(new URL('..', import.meta.url)));
  const started = Date.now();
  let result;
  try {
    result = checkDocs({ repoDir });
  } catch (error) {
    console.error(`check-doc-identifiers: ${error.message}`);
    process.exit(1);
  }
  const { problems, stats } = result;
  console.log(
    `check-doc-identifiers: ${stats.files} files, ${stats.tools} tool names, ` +
    `${stats.env} environment variables (${Date.now() - started}ms)`,
  );
  if (problems.length > 0) {
    console.error(`\ncheck-doc-identifiers: ${problems.length} problem(s):`);
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }
  console.log('check-doc-identifiers: every tool name the docs mention and every environment variable they set or list is defined in the code');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}

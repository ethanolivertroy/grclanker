#!/usr/bin/env node
// Checks that the docs and the README name only tools and environment
// variables that the code defines.
//
// A tool name is a word that joins a DOMAIN_GROUPS prefix from
// cli/pi/tool-catalog.ts to a verb that a registered tool name uses, such as
// `aws_check_access` or `kevs_recent`. It must appear as a string literal in
// cli/extensions. Globs like `aws_assess_*` and file names like
// `aws_check_access.json` are not tool names.
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

const DOCS_DIR = 'src/content/docs/docs';
const README = 'README.md';
const TOOL_CATALOG = 'cli/pi/tool-catalog.ts';
const TOOL_SOURCES = 'cli/extensions';
const CODE_DIR = 'cli';
const INSTALLER_DIR = 'public';

const CODE_FILE = /\.[cm]?[jt]s$/;
const SKIPPED_DIRS = new Set(['node_modules', 'dist', 'tests']);
const SNAKE_LITERAL = /(["'`])([a-z][a-z0-9_]*)\1/g;
const TOOL_NAME_PROPERTY = /\bname:\s*(["'`])([a-z][a-z0-9_]*)\1/g;
const ENV_WORD = /\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g;
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

const codeFiles = (dir) => walk(dir, (name) => CODE_FILE.test(name) && !name.includes('.test.'));

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
  const catalog = readFileSync(join(repoDir, TOOL_CATALOG), 'utf8');
  const groups = catalog.match(/\bDOMAIN_GROUPS\b[^=]*=\s*\[([\s\S]*?)\n\];/);
  const prefixes = groups ? [...groups[1].matchAll(/\[\s*["']([a-z0-9_]+_)["']\s*,/g)].map(([, prefix]) => prefix) : [];
  if (prefixes.length === 0) throw new Error(`no DOMAIN_GROUPS prefixes found in ${TOOL_CATALOG}`);

  const toolNames = new Set();
  const verbs = new Set();
  for (const file of codeFiles(join(repoDir, TOOL_SOURCES))) {
    const source = readFileSync(file, 'utf8');
    for (const [, , literal] of source.matchAll(SNAKE_LITERAL)) {
      if (longestPrefix(literal, prefixes)) toolNames.add(literal);
    }
    for (const [, , name] of source.matchAll(TOOL_NAME_PROPERTY)) {
      const prefix = longestPrefix(name, prefixes);
      if (prefix) verbs.add(name.slice(prefix.length).split('_')[0]);
    }
  }
  verbs.delete('');
  if (verbs.size === 0) throw new Error(`no registered tool names found in ${TOOL_SOURCES}`);

  const installers = walk(join(repoDir, INSTALLER_DIR), (name) => name.startsWith('install'));
  const envNames = new Set();
  for (const file of [...codeFiles(join(repoDir, CODE_DIR)), ...installers]) {
    for (const [name] of readFileSync(file, 'utf8').matchAll(ENV_WORD)) envNames.add(name);
  }

  return { toolNames, envNames, toolPattern: toolNamePattern(prefixes, verbs) };
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
      if (!code.toolNames.has(name)) problems.push(`${where}:${line}: no tool named \`${name}\` in ${TOOL_SOURCES}`);
    }
    for (const { name, line } of findEnvNames(markdown)) {
      env.add(name);
      if (!code.envNames.has(name)) {
        problems.push(`${where}:${line}: environment variable \`${name}\` is not in ${CODE_DIR}/ or the ${INSTALLER_DIR}/install* installers`);
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

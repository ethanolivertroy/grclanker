import type { RehypeCodeOptions } from 'fumadocs-core/mdx-plugins';
import codeBreaks from './code-breaks.mjs';
import hangingIndents from './hanging-indents.mjs';
import tableLabels from './table-labels.mjs';

// Shared by the docs, which fumadocs-mdx compiles, and the spec pages, which
// render their markdown in a Server Component, so code and tables look the same in both.
export const rehypeCodeOptions: RehypeCodeOptions = {
  themes: { dark: 'catppuccin-frappe' },
  defaultColor: 'dark',
  icon: false,
};

/** Run after code highlighting. */
export const siteRehypePlugins = [tableLabels, codeBreaks, hangingIndents];

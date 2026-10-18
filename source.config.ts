import { defineConfig } from 'fumadocs-mdx/config';
import remarkSmartypants from 'remark-smartypants';
import codeBreaks from './src/lib/code-breaks.mjs';
import hangingIndents from './src/lib/hanging-indents.mjs';
import tableLabels from './src/lib/table-labels.mjs';

export default defineConfig({
  mdxOptions: {
    remarkPlugins: [remarkSmartypants],
    rehypePlugins: (plugins) => [...plugins, tableLabels, codeBreaks, hangingIndents],
    rehypeCodeOptions: {
      themes: { dark: 'catppuccin-frappe' },
      defaultColor: 'dark',
      icon: false,
    },
  },
});

import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';
import { satteri } from '@astrojs/markdown-satteri';
import tableLabels from './src/lib/table-labels.mjs';

export default defineConfig({
  site: 'https://grclanker.com',
  output: 'static',
  integrations: [sitemap()],
  markdown: {
    processor: satteri({ hastPlugins: [tableLabels] }),
    shikiConfig: {
      theme: 'catppuccin-frappe',
    },
  },

  vite: {
    plugins: [tailwindcss()],
  },
});
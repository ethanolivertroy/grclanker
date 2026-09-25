import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://www.grclanker.com',
  output: 'static',
  markdown: {
    shikiConfig: {
      theme: 'catppuccin-frappe',
    },
  },

  vite: {
    plugins: [tailwindcss()],
  },
});
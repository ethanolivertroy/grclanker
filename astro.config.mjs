import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://www.grclanker.com',
  markdown: {
    shikiConfig: {
      theme: 'catppuccin-frappe',
    },
  },
  vite: {
    plugins: [tailwindcss()],
  },
});

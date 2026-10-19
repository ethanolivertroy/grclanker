import { defineConfig } from 'fumadocs-mdx/config';
import remarkSmartypants from 'remark-smartypants';
import { rehypeCodeOptions, siteRehypePlugins } from './src/lib/markdown-options';

export default defineConfig({
  mdxOptions: {
    remarkPlugins: [remarkSmartypants],
    rehypePlugins: (plugins) => [...plugins, ...siteRehypePlugins],
    rehypeCodeOptions,
  },
});

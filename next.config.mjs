import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
const config = {
  output: 'export',
  trailingSlash: true,
  reactStrictMode: true,
  // AGENTS.md is a curated contributor guide; keep `next dev` from adding its block.
  agentRules: false,
};

export default withMDX(config);

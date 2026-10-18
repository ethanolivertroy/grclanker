import Link from 'next/link';
import type { ComponentProps } from 'react';
import type { MDXComponents } from 'mdx/types';
import { CodeBlock } from './code-block';
import { DocsRoutes } from './docs-routes';

function MdxLink({ href = '', ...props }: ComponentProps<'a'>) {
  if (href.startsWith('/')) return <Link href={href} {...props} />;
  return <a href={href} {...props} />;
}

// The docs layout clips horizontal overflow, so a table that still cannot fit
// the column scrolls inside its own box instead of losing its right edge.
function MdxTable(props: ComponentProps<'table'>) {
  return (
    <div className="docs-table-scroll">
      <table {...props} />
    </div>
  );
}

export const mdxComponents: MDXComponents = {
  a: MdxLink,
  pre: CodeBlock,
  table: MdxTable,
  DocsRoutes,
};

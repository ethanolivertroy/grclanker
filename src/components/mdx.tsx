import Link from 'next/link';
import type { ComponentProps } from 'react';
import type { MDXComponents } from 'mdx/types';
import { CodeBlock } from './code-block';

function MdxLink({ href = '', ...props }: ComponentProps<'a'>) {
  if (href.startsWith('/')) return <Link href={href} {...props} />;
  return <a href={href} {...props} />;
}

export const mdxComponents: MDXComponents = {
  a: MdxLink,
  pre: CodeBlock,
};

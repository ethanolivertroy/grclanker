import { createMarkdownRenderer, type MarkdownRendererOptions } from 'fumadocs-core/content/md';
import { getTableOfContents } from 'fumadocs-core/content/toc';
import { rehypeCode, remarkGfm, remarkHeading } from 'fumadocs-core/mdx-plugins';
import type { TOCItemType } from 'fumadocs-core/toc';
import type { ComponentProps, CSSProperties } from 'react';
import { rehypeCodeOptions, siteRehypePlugins } from '../lib/markdown-options';
import { githubUrl } from '../lib/site';
import remarkSpecSource from '../lib/spec-markdown.mjs';
import staticTables, { STATIC_TABLE } from '../lib/static-tables.mjs';
import { mdxComponents } from './mdx';
import { SpecTableLabels } from './spec-table-labels';
import { SpecToc } from './spec-toc';

// The table of contents comes from a second pass over the markdown, so both
// passes run the same plugins before heading ids are assigned.
const remarkPlugins: NonNullable<MarkdownRendererOptions['remarkPlugins']> = [
  remarkGfm,
  [remarkSpecSource, { linkBase: `${githubUrl}/blob/main/specs/` }],
];

const { MarkdownServer } = createMarkdownRenderer({
  remarkPlugins: [...remarkPlugins, remarkHeading],
  rehypePlugins: [[rehypeCode, rehypeCodeOptions], ...siteRehypePlugins, staticTables],
});

type StaticTableProps = { html: string; narrow: number; wide: number };

function StaticTable({ html, narrow, wide }: StaticTableProps) {
  const heights = { '--table-narrow-height': `${narrow}px`, '--table-wide-height': `${wide}px` } as CSSProperties;
  // SpecTableLabels marks far tables before hydration.
  return <div className="docs-table-scroll" style={heights} suppressHydrationWarning dangerouslySetInnerHTML={{ __html: html }} />;
}

type MarkdownComponents = NonNullable<ComponentProps<typeof MarkdownServer>['components']>;

// fumadocs looks components up by any tag name, but its type lists only HTML tags.
const components = { ...mdxComponents, [STATIC_TABLE]: StaticTable } as MarkdownComponents;

/** The sections a spec lists in its contents bar and beside its document. */
export async function specSections(content: string): Promise<TOCItemType[]> {
  return (await getTableOfContents(content, remarkPlugins)).filter((item) => item.depth <= 3);
}

/** A spec's markdown set like a docs page, with its sections listed alongside. */
export function SpecDocument({ content, toc }: { content: string; toc: TOCItemType[] }) {
  return (
    <div className="spec-reader">
      <div className="spec-reader-columns">
        <article className="docs-prose min-w-0">
          <MarkdownServer components={components}>{content}</MarkdownServer>
        </article>
        {toc.length > 0 && <SpecToc items={toc} />}
      </div>
      <SpecTableLabels />
    </div>
  );
}

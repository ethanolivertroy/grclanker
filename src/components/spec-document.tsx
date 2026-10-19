import { createMarkdownRenderer, type MarkdownRendererOptions } from 'fumadocs-core/content/md';
import { getTableOfContents } from 'fumadocs-core/content/toc';
import { rehypeCode, remarkGfm, remarkHeading } from 'fumadocs-core/mdx-plugins';
import type { CSSProperties } from 'react';
import { rehypeCodeOptions, siteRehypePlugins } from '../lib/markdown-options';
import { githubUrl } from '../lib/site';
import remarkSpecSource from '../lib/spec-markdown.mjs';
import staticTables, { STATIC_TABLE } from '../lib/static-tables.mjs';
import { mdxComponents } from './mdx';
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
  return <div className="docs-table-scroll" style={heights} dangerouslySetInnerHTML={{ __html: html }} />;
}

const components = { ...mdxComponents, [STATIC_TABLE]: StaticTable };

/** A spec's markdown set like a docs page, with its sections listed alongside. */
export async function SpecDocument({ content }: { content: string }) {
  const toc = (await getTableOfContents(content, remarkPlugins)).filter((item) => item.depth <= 3);

  return (
    <div className="spec-reader">
      {toc.length > 0 && (
        <nav className="spec-toc-inline" aria-label="On this page">
          <details>
            <summary>On this page</summary>
            <ul className="spec-toc-list">
              {toc.map((item) => (
                <li key={item.url}>
                  <a href={item.url} className="spec-toc-link" data-depth={item.depth}>
                    {item.title}
                  </a>
                </li>
              ))}
            </ul>
          </details>
        </nav>
      )}
      <div className="spec-reader-columns">
        <article className="docs-prose min-w-0">
          <MarkdownServer components={components}>{content}</MarkdownServer>
        </article>
        {toc.length > 0 && <SpecToc items={toc} />}
      </div>
    </div>
  );
}

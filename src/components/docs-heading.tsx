import type { ComponentProps } from 'react';
import { headingText } from '../lib/heading-text.mjs';
import { LinkIcon } from './icons';

type DocsHeadingProps = ComponentProps<'h2'> & { as: 'h2' | 'h3' | 'h4' };

// The link follows the heading instead of sitting inside it, so a screen
// reader's list of headings doesn't read each heading twice.
export function DocsHeading({ as: Heading, id, children, ...props }: DocsHeadingProps) {
  if (!id) return <Heading {...props}>{children}</Heading>;
  return (
    <div className={`docs-heading docs-heading-${Heading}`}>
      <Heading id={id} {...props}>
        {children}
      </Heading>
      <a href={`#${id}`} className="docs-heading-anchor" aria-label={`Section titled “${headingText(children)}”`}>
        <LinkIcon />
      </a>
    </div>
  );
}

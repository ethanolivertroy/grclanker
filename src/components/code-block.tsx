'use client';

import { useRef, type ComponentProps } from 'react';
import { useCopy } from '../lib/use-copy';
import { CheckIcon, CopyIcon } from './icons';

export function CodeBlock({ children, ...props }: ComponentProps<'pre'>) {
  const ref = useRef<HTMLPreElement>(null);
  const { copied, copy } = useCopy('Code copied to clipboard', 1800);

  return (
    // Docs code wraps instead of scrolling, so the tabindex Shiki gives every
    // block would only add a Tab stop before the Copy button.
    <pre ref={ref} {...props} tabIndex={undefined}>
      {children}
      <button
        type="button"
        className="copy-code"
        aria-label="Copy code"
        onClick={() => {
          const pre = ref.current;
          if (!pre) return;
          copy(pre.querySelector('code')?.textContent ?? pre.textContent ?? '');
        }}
      >
        {copied ? <CheckIcon /> : <CopyIcon />}
      </button>
    </pre>
  );
}

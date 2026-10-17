'use client';

import { useCopy } from '../lib/use-copy';
import { CheckIcon, CopyIcon } from './icons';

export function SpecUrlCopyButton({
  url,
  label,
  specName,
  className,
}: {
  url: string;
  label: string;
  specName: string;
  className: string;
}) {
  const { copied, copy } = useCopy('Raw spec URL copied to clipboard');
  return (
    <button
      type="button"
      className={copied ? `${className} copied` : className}
      aria-label={`Copy raw URL for ${specName}`}
      onClick={() => copy(url)}
    >
      {copied ? 'COPIED' : label}
    </button>
  );
}

export function SpecCommandHero({ command }: { command: string }) {
  const { copied, copy } = useCopy('Command copied to clipboard');
  return (
    <div className="cmd-hero">
      <code>{command}</code>
      <button type="button" className="cmd-hero-copy" aria-label="Copy raw spec command" onClick={() => copy(command)}>
        {copied ? <CheckIcon size={16} /> : <CopyIcon size={16} />}
      </button>
    </div>
  );
}

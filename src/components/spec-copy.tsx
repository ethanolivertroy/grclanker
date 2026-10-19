'use client';

import { useCopy } from '../lib/use-copy';
import { CheckIcon, CopyIcon } from './icons';

/** The button's name is its visible label and then `detail`, so saying the label still finds it by voice. */
export function SpecUrlCopyButton({
  url,
  label,
  detail,
  className,
}: {
  url: string;
  label: string;
  detail: string;
  className: string;
}) {
  const { copied, copy } = useCopy('Raw spec URL copied to clipboard');
  return (
    <button
      type="button"
      className={copied ? `${className} copied` : className}
      aria-label={`${label} ${detail}`}
      onClick={() => copy(url)}
    >
      {copied ? 'Copied' : label}
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

'use client';

import { useCopy } from '../lib/use-copy';
import { CheckIcon, CopyIcon } from './icons';

export function CommandLine({ label, command, preview }: { label: string; command: string; preview: string }) {
  const { copied, copy } = useCopy('Command copied to clipboard');
  return (
    <div className="cmd-line">
      <span className="cmd-label">{label}</span>
      <code>{preview}</code>
      <button
        type="button"
        className="cmd-copy"
        aria-label={`Copy command for ${label}`}
        onClick={() => copy(command)}
      >
        {copied ? <CheckIcon /> : <CopyIcon />}
      </button>
    </div>
  );
}

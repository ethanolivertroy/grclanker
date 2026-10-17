'use client';

import { useRef, useState, type KeyboardEvent } from 'react';
import { useCopy } from '../lib/use-copy';
import { CheckIcon, CopyIcon } from './icons';

const installCommands = [
  { label: 'curl', command: 'curl -fsSL https://grclanker.com/install | bash' },
  {
    label: 'source',
    command:
      'git clone https://github.com/ethanolivertroy/grclanker.git && cd grclanker/cli && npm ci && npm run build && npm link',
  },
];

export function HeroInstall() {
  const [active, setActive] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const { copied, copy } = useCopy('Install command copied to clipboard', 1600);
  const { command } = installCommands[active];

  function selectTab(index: number) {
    setActive(index);
    tabs.current[index]?.focus();
  }

  function onTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = installCommands.length - 1;
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        selectTab(index === last ? 0 : index + 1);
        break;
      case 'ArrowLeft':
      case 'ArrowUp':
        selectTab(index === 0 ? last : index - 1);
        break;
      case 'Home':
        selectTab(0);
        break;
      case 'End':
        selectTab(last);
        break;
      default:
        return;
    }
    event.preventDefault();
  }

  return (
    <div className="hero-install-shell">
      <div className="hero-install-toggle-row" role="tablist" aria-label="Install methods">
        {installCommands.map((entry, index) => (
          <button
            key={entry.label}
            ref={(node) => {
              tabs.current[index] = node;
            }}
            type="button"
            role="tab"
            className={index === active ? 'hero-install-toggle is-active' : 'hero-install-toggle'}
            aria-selected={index === active}
            tabIndex={index === active ? 0 : -1}
            onClick={() => setActive(index)}
            onKeyDown={(event) => onTabKeyDown(event, index)}
          >
            {entry.label}
          </button>
        ))}
      </div>
      <button type="button" className="hero-install-command" aria-label="Copy install command" onClick={() => copy(command)}>
        <span className="hero-install-command-text">{command}</span>
        {copied ? <CheckIcon className="hero-install-icon" /> : <CopyIcon className="hero-install-icon" />}
      </button>
    </div>
  );
}

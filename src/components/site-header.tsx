'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { useSearchContext } from 'fumadocs-ui/contexts/search';
import { githubUrl, isActivePath, primaryLinks } from '../lib/site';
import { GitHubIcon, RobotLogo, SearchIcon } from './icons';
import { preloadSiteSearchDialog } from './site-search';

export function SiteHeader() {
  const pathname = usePathname();
  const { setOpenSearch } = useSearchContext();
  const [menuOpen, setMenuOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (menuOpen) panelRef.current?.querySelector('a')?.focus();
  }, [menuOpen]);

  function toggleMenu() {
    setMenuOpen((open) => !open);
  }

  function onPanelKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key !== 'Escape') return;
    setMenuOpen(false);
    toggleRef.current?.focus();
  }

  return (
    <nav className="border-b border-surface0/60 bg-mantle sticky top-0 z-50" aria-label="Main navigation">
      <div className="max-w-content mx-auto px-4 sm:px-6">
        <div className="site-nav-row flex min-h-[4.25rem] items-center justify-between gap-4 py-2">
          <div className="site-nav-brand flex items-center gap-2.5 min-w-0">
            <Link href="/" className="site-nav-logo flex items-center gap-2 text-text hover:text-blue transition-colors group">
              <RobotLogo />
              <span className="led led-live" />
              <span className="font-bold nav-wordmark">GRCLANKER</span>
            </Link>
            <a href="https://hackidle.com" className="text-overlay1 hover:text-blue text-[0.8125rem] transition-colors hidden md:inline">
              by hackIDLE
            </a>
          </div>
          <div className="hidden md:flex items-center gap-4 md:gap-6 text-sm">
            <button
              type="button"
              onClick={() => setOpenSearch(true)}
              onPointerEnter={preloadSiteSearchDialog}
              onFocus={preloadSiteSearchDialog}
              className="nav-action-btn nav-search-btn"
              aria-label="Search site (press / or Cmd+K)"
            >
              Search <kbd className="hidden md:inline">/</kbd>
            </button>
            {primaryLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className={isActivePath(link.href, pathname) ? 'nav-link is-active' : 'nav-link'}
              >
                {link.label}
              </Link>
            ))}
            <a
              href={githubUrl}
              target="_blank"
              rel="noopener"
              className="text-subtext0 hover:text-blue transition-colors"
              aria-label="GitHub repository"
            >
              <GitHubIcon size={20} />
            </a>
          </div>
          <div className="site-nav-mobile-actions flex md:hidden items-center gap-2">
            <button
              type="button"
              onClick={() => setOpenSearch(true)}
              onPointerEnter={preloadSiteSearchDialog}
              onFocus={preloadSiteSearchDialog}
              className="nav-icon-btn"
              aria-label="Search site"
            >
              <SearchIcon size={18} />
            </button>
            <a href={githubUrl} target="_blank" rel="noopener" className="nav-icon-btn" aria-label="GitHub repository">
              <GitHubIcon size={18} />
            </a>
            <button
              ref={toggleRef}
              type="button"
              className="nav-action-btn"
              aria-expanded={menuOpen}
              aria-controls="mobile-nav-panel"
              onClick={toggleMenu}
            >
              Menu
            </button>
          </div>
        </div>
        <div
          ref={panelRef}
          id="mobile-nav-panel"
          className={menuOpen ? 'site-mobile-nav-panel md:hidden' : 'site-mobile-nav-panel md:hidden hidden'}
          aria-label="Mobile navigation"
          onKeyDown={onPanelKeyDown}
        >
          <div className="site-mobile-nav-links">
            {primaryLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="site-mobile-nav-link"
                onClick={() => setMenuOpen(false)}
              >
                {link.label}
              </Link>
            ))}
          </div>
        </div>
      </div>
    </nav>
  );
}

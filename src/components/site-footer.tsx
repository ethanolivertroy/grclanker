'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { footerImages, githubUrl, normalizePathname } from '../lib/site';

function footerImageFor(pathname: string) {
  const sum = Array.from(normalizePathname(pathname)).reduce((total, char) => total + char.charCodeAt(0), 0);
  return footerImages[sum % footerImages.length];
}

export function SiteFooter() {
  const pathname = usePathname();

  return (
    <footer className="border-t border-surface0/60 bg-mantle/80">
      <div className="footer-image-strip" aria-hidden="true">
        <img src={footerImageFor(pathname)} alt="" className="footer-image-strip-media" loading="lazy" />
        <div className="footer-image-strip-overlay" />
      </div>
      <div className="site-footer-shell max-w-content mx-auto px-6 py-4 text-xs text-subtext0">
        <div className="site-footer-meta flex flex-wrap gap-x-3">
          <span>
            Built by <a href="https://ethantroy.dev" className="hover:text-blue">Ethan Troy</a>
          </span>
          <span>
            Licensed <a href={`${githubUrl}/blob/main/LICENSE`} className="hover:text-blue">Apache-2.0</a>
          </span>
        </div>
        <div className="site-footer-links">
          <Link href="/" className="site-footer-link hover:text-blue">CLI</Link>
          <Link href="/docs/" className="site-footer-link hover:text-blue">Docs</Link>
          <Link href="/specs/" className="site-footer-link hover:text-blue">Specs</Link>
          <Link href="/about/" className="site-footer-link hover:text-blue">About</Link>
          <a href={githubUrl} target="_blank" rel="noopener" className="site-footer-link site-footer-link-wide hover:text-blue">
            GitHub
          </a>
        </div>
        <span className="site-footer-status">
          <span className="led led-live" />
          <span className="italic">SYS NOMINAL</span>
        </span>
      </div>
    </footer>
  );
}

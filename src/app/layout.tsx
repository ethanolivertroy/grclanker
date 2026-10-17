import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import { RootProvider } from 'fumadocs-ui/provider/next';
import { KeyboardShortcuts } from '../components/keyboard-shortcuts';
import { SiteFooter } from '../components/site-footer';
import { SiteHeader } from '../components/site-header';
import { SiteSearchDialog } from '../components/site-search';
import { pageMetadata } from '../lib/metadata';
import { siteName } from '../lib/site';
import '../styles/global.css';

export const metadata: Metadata = pageMetadata({ title: siteName, path: null });

export const viewport: Viewport = {
  themeColor: '#303446',
  colorScheme: 'dark',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="font-sans antialiased">
        <RootProvider
          theme={{ enabled: false }}
          search={{ SearchDialog: SiteSearchDialog }}
        >
          <a href="#main-content" className="skip-link">
            Skip to content
          </a>
          <div id="app-shell" className="flex min-h-screen flex-col">
            <SiteHeader />
            <main id="main-content" className="flex-1">
              {children}
            </main>
            <SiteFooter />
          </div>
          <div id="site-announcer" className="sr-only" aria-live="polite" aria-atomic="true" />
          <KeyboardShortcuts />
        </RootProvider>
      </body>
    </html>
  );
}

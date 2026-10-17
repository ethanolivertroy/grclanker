import Link from 'next/link';
import { pageMetadata } from '../lib/metadata';

export const metadata = pageMetadata({
  title: 'Signal Lost: grclanker',
  description: 'This page does not exist. Head back to the grclanker homepage, docs, or spec catalog.',
  path: null,
});

export default function NotFound() {
  return (
    <section className="relative overflow-hidden">
      <div className="absolute inset-0 w-full h-full">
        <img src="/404-cockpit.webp" alt="" className="w-full h-full object-cover object-center" loading="eager" />
      </div>
      <div className="absolute inset-0 bg-gradient-to-b from-base/30 via-base/50 to-base pointer-events-none" />
      <div className="relative z-10 max-w-content mx-auto px-6 py-32 text-center">
        <p className="hud-label mb-4 text-red/70">Signal Lost</p>
        <h1 className="font-bold text-6xl text-text mb-4">404</h1>
        <p className="text-subtext0 mb-8">This sector is uncharted. The page you're looking for doesn't exist.</p>
        <Link
          href="/"
          className="inline-block text-sm bg-blue/10 hover:bg-blue/15 text-blue px-6 py-2.5 rounded-md border border-blue/20 transition-colors"
        >
          Return to cockpit
        </Link>
      </div>
    </section>
  );
}

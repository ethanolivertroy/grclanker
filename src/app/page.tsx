import Link from 'next/link';
import { pageMetadata } from '../lib/metadata';

export const metadata = pageMetadata({
  title: 'grclanker: Put a Clanker on Your Compliance',
  description:
    '241 domain tools across 35 vendor integrations and CMVP, KEV, EPSS, FedRAMP, SCF, and OSCAL, with Pi, Cursor Agent SDK, and Flue runtime paths.',
  path: '/',
});

export default function HomePage() {
  return (
    <section className="mx-auto max-w-content px-4 py-16 sm:px-6">
      <h1 className="text-lg font-bold text-text">grclanker</h1>
      <p className="mt-4 text-subtext0">Put a clanker on your compliance.</p>
      <p className="mt-6 flex gap-6">
        <Link href="/docs/">Docs</Link>
        <Link href="/specs/">Specs</Link>
        <Link href="/about/">About</Link>
      </p>
    </section>
  );
}

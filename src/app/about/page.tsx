import { pageMetadata } from '../../lib/metadata';

export const metadata = pageMetadata({
  title: 'About: grclanker',
  description:
    'What grclanker ships today: an open source compliance agent with 241 domain tools, 35 vendor integrations, and Pi, Cursor Agent SDK, and Flue runtime paths.',
  path: '/about/',
});

export default function AboutPage() {
  return (
    <section className="mx-auto max-w-content px-4 py-16 sm:px-6">
      <h1 className="text-lg font-bold text-text">About grclanker</h1>
    </section>
  );
}

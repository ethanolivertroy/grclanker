'use client';

import { useEffect, useState } from 'react';
import { IMAGE_BREAK_SIZES, imageSrcSet } from '../lib/responsive-images.mjs';

const brandFrames = [
  { eyebrow: 'Specs in', title: 'Use each integration spec to review coverage or plan an extension.' },
  { eyebrow: 'Terminal-first', title: 'Evidence gathering stays in your terminal.' },
  { eyebrow: 'Local-first', title: 'Run a local model and prompts stay on your machine. Or choose a hosted provider.' },
];

const railImages = [
  '/hero/rail/assembly.webp',
  '/hero/rail/holographic.webp',
  '/hero/rail/about.webp',
  '/mid-break.webp',
  '/footer/closeup.webp',
  '/footer/skyline.webp',
];

const breakImages = ['/mid-break.webp', '/footer/walkaway.webp', '/footer/standby.webp', '/hero/command-center.webp'];

// In the three-column rail a card is about 300px wide but at least 11rem tall,
// so covering it takes about 415px of picture width. Narrower screens stack the
// cards across the content column.
const railSizes = '(min-width: 900px) 415px, calc(100vw - 48px)';

function shuffle<T>(items: readonly T[]) {
  const next = items.slice();
  for (let index = next.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(Math.random() * (index + 1));
    [next[index], next[swapIndex]] = [next[swapIndex], next[index]];
  }
  return next;
}

// Both components prerender the first images and pick new ones after hydration,
// so the static HTML stays deterministic.

export function HeroBrandRail() {
  const [images, setImages] = useState(railImages);

  useEffect(() => setImages(shuffle(railImages)), []);

  return (
    <section className="hero-brand-rail" aria-label="Clanker brand frames">
      {brandFrames.map((frame, index) => (
        <article key={frame.eyebrow} className="hero-brand-card">
          <img
            src={images[index]}
            srcSet={imageSrcSet(images[index], 1000)}
            sizes={railSizes}
            alt=""
            className="hero-brand-image"
            loading="lazy"
          />
          <div className="hero-brand-overlay">
            <span className="hero-brand-eyebrow">{frame.eyebrow}</span>
            <p className="hero-brand-title">{frame.title}</p>
          </div>
        </article>
      ))}
    </section>
  );
}

export function HeroImageBreak() {
  const [image, setImage] = useState(breakImages[0]);

  useEffect(() => setImage(breakImages[Math.floor(Math.random() * breakImages.length)]), []);

  return (
    <section className="hero-image-break" aria-label="Clanker ambient frame">
      <img
        src={image}
        srcSet={imageSrcSet(image, 1600)}
        sizes={IMAGE_BREAK_SIZES}
        alt=""
        className="hero-image-break-image"
        loading="lazy"
      />
      <div className="hero-image-break-overlay">
        <span className="hero-image-break-pill">Evidence first // controls mapped // build from specs</span>
      </div>
    </section>
  );
}

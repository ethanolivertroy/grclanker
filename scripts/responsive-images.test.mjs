import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { IMAGE_COPIES, copyPath, imageSrcSet } from '../src/lib/responsive-images.mjs';

// Pixel width from a WebP header, in its lossy, lossless, or extended format.
function webpWidth(path) {
  const bytes = readFileSync(new URL(`../public${path}`, import.meta.url));
  const format = bytes.toString('ascii', 12, 16);
  if (format === 'VP8X') return 1 + bytes.readUIntLE(24, 3);
  if (format === 'VP8L') return 1 + (bytes.readUInt16LE(21) & 0x3fff);
  if (format === 'VP8 ') return bytes.readUInt16LE(26) & 0x3fff;
  throw new Error(`${path} is not a WebP file`);
}

test('each image and copy is as wide as its srcset says', () => {
  for (const [src, { width, copies }] of Object.entries(IMAGE_COPIES)) {
    assert.equal(webpWidth(src), width, src);
    assert.deepEqual(copies, [...copies].sort((a, b) => a - b), src);
    for (const copyWidth of copies) {
      assert.ok(copyWidth < width, src);
      assert.equal(webpWidth(copyPath(src, copyWidth)), copyWidth, copyPath(src, copyWidth));
    }
  }
});

test('srcsets run narrowest first and drop copies wider than the slot', () => {
  assert.equal(
    imageSrcSet('/mid-break.webp'),
    '/mid-break-480.webp 480w, /mid-break-640.webp 640w, /mid-break-1000.webp 1000w, /mid-break.webp 1600w',
  );
  assert.equal(imageSrcSet('/footer/walkaway.webp', 1600), '/footer/walkaway-1000.webp 1000w, /footer/walkaway-1600.webp 1600w');
  assert.equal(imageSrcSet('/footer/walkaway.webp', 800), '/footer/walkaway-1000.webp 1000w');
  assert.equal(imageSrcSet('/favicon.svg'), undefined);
});

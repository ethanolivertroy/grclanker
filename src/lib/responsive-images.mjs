// Smaller copies of the site's large images, keyed by the original's path.
// Each copy sits beside its original as `<name>-<width>.webp` (WebP quality
// 75), so regenerate the copies whenever an original changes. Pictures shown
// in an image break get a 1000px copy rather than 960px, since a break can be
// 976px wide.
export const IMAGE_COPIES = {
  '/about-clanker.webp': { width: 2752, copies: [960, 1600] },
  '/footer/closeup.webp': { width: 3168, copies: [480, 640, 1000, 1600] },
  '/footer/skyline.webp': { width: 3168, copies: [480, 640, 960, 1600] },
  '/footer/standby.webp': { width: 3168, copies: [1000, 1600] },
  '/footer/walkaway.webp': { width: 3168, copies: [1000, 1600] },
  '/hero/command-center.webp': { width: 3168, copies: [1000, 1600] },
  '/hero/grclanker-terminal.webp': { width: 1750, copies: [640, 960] },
  '/hero/holographic.webp': { width: 3168, copies: [1600] },
  '/hero/rail/about.webp': { width: 800, copies: [480, 640] },
  '/hero/rail/assembly.webp': { width: 800, copies: [480, 640] },
  '/hero/rail/holographic.webp': { width: 800, copies: [480, 640] },
  '/mid-break.webp': { width: 1600, copies: [480, 640, 1000] },
};

// `sizes` for an image break, which spans the content column (976px at most)
// and on phones keeps its picture at least 434px wide by its minimum height.
export const IMAGE_BREAK_SIZES = '(min-width: 1024px) 976px, (min-width: 482px) calc(100vw - 48px), 434px';

/**
 * @param {string} src
 * @param {number} width
 */
export function copyPath(src, width) {
  return src.replace(/\.webp$/, `-${width}.webp`);
}

/**
 * The `srcset` for an image and its copies, or undefined for an image without
 * copies. Candidates wider than `maxWidth` are left out, all but the narrowest,
 * for slots that never show more pixels than that.
 *
 * @param {string} src
 * @param {number} [maxWidth]
 * @returns {string | undefined}
 */
export function imageSrcSet(src, maxWidth = Infinity) {
  const image = IMAGE_COPIES[/** @type {keyof typeof IMAGE_COPIES} */ (src)];
  if (!image) return undefined;
  return [...image.copies, image.width]
    .filter((width, index) => index === 0 || width <= maxWidth)
    .map((width) => `${width === image.width ? src : copyPath(src, width)} ${width}w`)
    .join(', ');
}

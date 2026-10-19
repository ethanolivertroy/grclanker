// Estimated heights of a spec table in each of its layouts, for the space an
// offscreen table holds before it first renders (content-visibility in
// global.css). The lengths mirror the table rules there. Prose advances were
// measured in 15px Noto Sans; Apple and Android system fonts run a little
// narrower, so their tables come out slightly shorter than estimated.

const CODE_CHAR = 0.875 * 15 * 0.6;
const LABEL_CHAR = 12 * 0.66;
const LINE = 24;
const LABEL_LINE = 16.8;

function proseAdvance(char) {
  if (char === ' ') return 3.8;
  if (/\p{Ll}/u.test(char)) return 7.4;
  if (/\p{Lu}/u.test(char)) return 9.5;
  if (/\p{N}/u.test(char)) return 8.6;
  return 5.5;
}

// Characters Chrome breaks a line after, besides spaces and <wbr>.
const BREAK_AFTER = new Set(['-', '?', '\u2013', '\u2014', '\u2026']);

// Content widths the estimates assume: a 390px phone for the stacked layout up
// to 720px, which overestimates wider windows, and the docs column from 1024px.
const NARROW_WIDTH = 358;
const WIDE_WIDTH = 728;

function childElements(node, tagName) {
  return node.children.filter((child) => child.type === 'element' && child.tagName === tagName);
}

function textContent(node) {
  if (node.type === 'text') return node.value;
  return node.children ? node.children.map(textContent).join('') : '';
}

// A cell as the lines its <br>s force, each a list of the unbreakable runs a
// line can wrap between, with the width of any space before each run.
function measureCell(cell) {
  const lines = [[]];
  let run = { width: 0, space: 0 };
  const endRun = (space) => {
    if (run.width > 0) {
      lines.at(-1).push(run);
      run = { width: 0, space };
    } else {
      run.space = Math.max(run.space, space);
    }
  };
  const walk = (node, code, nowrap) => {
    if (node.type === 'text') {
      const value = node.value.replace(/[ \t\n\r]+/g, ' ');
      for (let index = 0; index < value.length; index += 1) {
        const char = value[index];
        const advance = code ? CODE_CHAR : proseAdvance(char);
        if (char === ' ' && !nowrap) {
          endRun(advance);
        } else {
          run.width += advance;
          if (BREAK_AFTER.has(char) && !nowrap && /\S/.test(value[index + 1] ?? '')) endRun(0);
        }
      }
    } else if (node.tagName === 'br') {
      endRun(0);
      lines.push([]);
      run.space = 0;
    } else if (node.tagName === 'wbr') {
      endRun(0);
    } else if (node.type === 'element') {
      node.children.forEach((child) => walk(child, code || node.tagName === 'code', nowrap || 'dataNowrap' in node.properties));
    }
  };
  walk(cell, false, false);
  endRun(0);
  return lines;
}

const longestRun = (lines) => Math.max(0, ...lines.flat().map((run) => run.width));
const widestLine = (lines) => Math.max(0, ...lines.map((runs) => runs.reduce((sum, run, index) => sum + run.width + (index ? run.space : 0), 0)));

// Lines a cell fills at a width: greedily, as browsers fill them, with a run
// longer than a whole line broken wherever it overflows.
function lineCount(lines, width) {
  let count = 0;
  for (const runs of lines) {
    let x = 0;
    count += 1;
    for (const run of runs) {
      if (x > 0 && x + run.space + run.width > width) {
        count += 1;
        x = run.width;
      } else {
        x += (x > 0 ? run.space : 0) + run.width;
      }
      if (x > width) {
        const overflow = Math.ceil(x / width) - 1;
        count += overflow;
        x -= overflow * width;
      }
    }
  }
  return count;
}

const labelLines = (label, width) => lineCount([label.split(' ').map((word, index) => ({ width: word.length * LABEL_CHAR, space: index ? LABEL_CHAR : 0 }))], width);

// Up to 720px every row is a block of cells, each a label line over its text.
function stackedHeight(table, width) {
  let height = 1;
  for (const cells of table.rows) {
    height += 29.8;
    cells.forEach((cell, index) => {
      const label = table.labels[index] ? labelLines(table.labels[index], width) * LABEL_LINE + 2.4 : 0;
      height += (index ? 9.6 : 0) + label + lineCount(cell, width / table.scale) * LINE * table.scale;
    });
  }
  return height;
}

// Wider, a table of sentences gives each cell a row, its label in a 10rem column.
function labeledRowsHeight(table, width) {
  let height = 1;
  for (const cells of table.rows) {
    height += 29.8;
    cells.forEach((cell, index) => {
      const label = labelLines(table.labels[index] ?? '', 160) * LABEL_LINE;
      height += 8 + Math.max(label, lineCount(cell, (width - 180) / table.scale) * LINE * table.scale);
    });
  }
  return height;
}

// Other tables keep their columns, sized by the browser's automatic table
// layout: each column gets at least its longest unbreakable run, and the width
// left over goes to each in proportion to how much more its longest line needs.
function columnsHeight({ labels, rows, scale }, width) {
  const gutter = labels.length >= 7 ? 8 : labels.length >= 4 ? 10 : 16;
  const padding = (index) => (index > 0 ? gutter : 0) + (index < labels.length - 1 ? gutter : 0);
  const columns = labels.map((label, index) => {
    const cells = rows.map((cells) => cells[index]).filter(Boolean);
    const words = label.split(' ').map((word) => word.length * LABEL_CHAR);
    return {
      min: Math.max(...words, ...cells.map((cell) => longestRun(cell) * scale)) + padding(index),
      max: Math.max(label.length * LABEL_CHAR, ...cells.map((cell) => widestLine(cell) * scale)) + padding(index),
    };
  });
  const least = columns.reduce((sum, column) => sum + column.min, 0);
  const most = columns.reduce((sum, column) => sum + column.max, 0);
  const widths = columns.map(({ min, max }, index) => {
    const share = least >= width ? min : most <= width ? (max * width) / most : min + ((max - min) * (width - least)) / (most - least);
    return Math.max(1, share - padding(index));
  });
  let height = 11.4 + LABEL_LINE * Math.max(...labels.map((label, index) => labelLines(label, widths[index])));
  for (const cells of rows) {
    height += 26.6 + LINE * scale * Math.max(...cells.map((cell, index) => lineCount(cell, widths[index] / scale)));
  }
  return height;
}

/** Estimated heights in px of a table (hast) in each of its layouts. */
export function estimateTableHeights(node) {
  const headerRow = childElements(node, 'thead').flatMap((head) => childElements(head, 'tr'))[0];
  const labels = headerRow ? childElements(headerRow, 'th').map((cell) => textContent(cell).replace(/\s+/g, ' ').trim()) : [];
  const rows = childElements(node, 'tbody')
    .flatMap((body) => childElements(body, 'tr'))
    .map((row) => childElements(row, 'td').map(measureCell));
  // Tables of seven or more columns are set at 14px.
  const table = { labels, rows, scale: labels.length >= 7 ? 14 / 15 : 1 };
  const wide = node.properties.dataLayout === 'stacked' ? labeledRowsHeight : columnsHeight;
  return {
    narrow: Math.round(stackedHeight(table, NARROW_WIDTH)),
    wide: Math.round(wide(table, WIDE_WIDTH)),
  };
}

/**
 * Catppuccin Frappé theme for Monaco Editor.
 * Maps all editor chrome and markdown token colors to the Frappé palette.
 * Text colors keep 4.5:1 against editor.background and the current-line
 * highlight (WCAG 1.4.3); sliders, guides, and borders keep 3:1 (WCAG 1.4.11).
 * Selection fills stay dark so every token keeps 4.5:1 on them; the selection
 * outline in global.css carries the 3:1 visibility against the editor.
 */
export const catppuccinFrappe = {
  base: 'vs-dark' as const,
  inherit: false,
  rules: [
    // Markdown headings
    { token: 'keyword.md', foreground: '8caaee' },           // heading markers (#, ##, etc.)
    { token: 'markup.heading', foreground: '8caaee' },
    { token: 'markup.heading.markdown', foreground: '8caaee' },

    // Bold & italic
    { token: 'markup.bold', foreground: 'ef9f76', fontStyle: 'bold' },
    { token: 'strong', foreground: 'ef9f76', fontStyle: 'bold' },
    { token: 'markup.italic', foreground: 'ca9ee6', fontStyle: 'italic' },
    { token: 'emphasis', foreground: 'ca9ee6', fontStyle: 'italic' },

    // Inline code & code blocks
    { token: 'variable.source', foreground: 'a6d189' },
    { token: 'markup.inline', foreground: 'a6d189' },
    { token: 'string.md', foreground: 'a6d189' },

    // Links
    { token: 'string.link.md', foreground: '8caaee' },
    { token: 'markup.underline.link', foreground: '8caaee' },
    { token: 'type.identifier.md', foreground: '85c1dc' },   // link title text → sapphire

    // Lists
    { token: 'variable.md', foreground: 'ef9f76' },          // list markers (-, *, 1.)
    { token: 'punctuation.md', foreground: '949cbb' },

    // Blockquotes
    { token: 'comment.md', foreground: '949cbb' },            // blockquote markers
    { token: 'comment', foreground: '949cbb' },

    // Horizontal rules
    { token: 'keyword.table.header.md', foreground: '8caaee' },
    { token: 'keyword.table.left', foreground: '949cbb' },
    { token: 'keyword.table.middle', foreground: '949cbb' },
    { token: 'keyword.table.right', foreground: '949cbb' },

    // Default text
    { token: '', foreground: 'c6d0f5' },
    { token: 'source', foreground: 'c6d0f5' },

    // Numbers (in tables, etc.)
    { token: 'number', foreground: 'ef9f76' },

    // Strings
    { token: 'string', foreground: 'a6d189' },

    // Keywords
    { token: 'keyword', foreground: 'ca9ee6' },

    // Types
    { token: 'type', foreground: 'e5c890' },
  ],
  colors: {
    // Editor
    'editor.background': '#292c3c',
    'editor.foreground': '#c6d0f5',
    'editorCursor.foreground': '#f2d5cf',
    'editor.selectionBackground': '#232634',
    'editor.inactiveSelectionBackground': '#232634',
    'editor.selectionHighlightBackground': '#41455980',
    'editor.lineHighlightBackground': '#30344660',
    'editor.lineHighlightBorder': '#30344600',
    'editor.findMatchBackground': '#8caaee40',
    'editor.findMatchHighlightBackground': '#8caaee20',
    'editor.wordHighlightBackground': '#41455960',

    // Line numbers
    'editorLineNumber.foreground': '#949cbb',
    'editorLineNumber.activeForeground': '#c6d0f5',

    // Gutter
    'editorGutter.background': '#292c3c',
    'editorGutter.modifiedBackground': '#8caaee',
    'editorGutter.addedBackground': '#a6d189',
    'editorGutter.deletedBackground': '#e78284',

    // Scrollbar
    'scrollbar.shadow': '#23263400',
    'scrollbarSlider.background': '#737994',
    'scrollbarSlider.hoverBackground': '#838ba7',
    'scrollbarSlider.activeBackground': '#949cbb',

    // Minimap
    'minimap.background': '#292c3c',
    'minimapSlider.background': '#949cbbb3',
    'minimapSlider.hoverBackground': '#949cbbcc',
    'minimapSlider.activeBackground': '#a5adcecc',

    // Widget (find/replace, etc.)
    'editorWidget.background': '#292c3c',
    'editorWidget.border': '#414559',
    'editorWidget.foreground': '#c6d0f5',
    'input.background': '#303446',
    'input.border': '#838ba7',
    'input.foreground': '#c6d0f5',
    'input.placeholderForeground': '#949cbb',
    'inputOption.activeBorder': '#8caaee',
    'inputOption.activeBackground': '#8caaee30',

    // Bracket matching
    'editorBracketMatch.background': '#41455980',
    'editorBracketMatch.border': '#838ba7',

    // Indent guides
    'editorIndentGuide.background': '#737994',
    'editorIndentGuide.activeBackground': '#838ba7',

    // Folding
    'editorCodeLens.foreground': '#949cbb',
    'editor.foldBackground': '#41455930',

    // Ruler
    'editorRuler.foreground': '#414559',

    // Overview ruler (right edge)
    'editorOverviewRuler.border': '#41455900',
    'editorOverviewRuler.findMatchForeground': '#8caaee80',
  },
};

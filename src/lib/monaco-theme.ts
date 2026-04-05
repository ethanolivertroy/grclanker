/**
 * Catppuccin Frappé theme for Monaco Editor.
 * Maps all editor chrome and markdown token colors to the Frappé palette.
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
    { token: 'punctuation.md', foreground: '626880' },

    // Blockquotes
    { token: 'comment.md', foreground: '737994' },            // blockquote markers
    { token: 'comment', foreground: '737994' },

    // Horizontal rules
    { token: 'keyword.table.header.md', foreground: '8caaee' },
    { token: 'keyword.table.left', foreground: '626880' },
    { token: 'keyword.table.middle', foreground: '626880' },
    { token: 'keyword.table.right', foreground: '626880' },

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
    'editor.selectionBackground': '#414559',
    'editor.selectionHighlightBackground': '#41455980',
    'editor.lineHighlightBackground': '#30344660',
    'editor.lineHighlightBorder': '#30344600',
    'editor.findMatchBackground': '#8caaee40',
    'editor.findMatchHighlightBackground': '#8caaee20',
    'editor.wordHighlightBackground': '#41455960',

    // Line numbers
    'editorLineNumber.foreground': '#626880',
    'editorLineNumber.activeForeground': '#c6d0f5',

    // Gutter
    'editorGutter.background': '#292c3c',
    'editorGutter.modifiedBackground': '#8caaee',
    'editorGutter.addedBackground': '#a6d189',
    'editorGutter.deletedBackground': '#e78284',

    // Scrollbar
    'scrollbar.shadow': '#23263400',
    'scrollbarSlider.background': '#41455960',
    'scrollbarSlider.hoverBackground': '#51576d80',
    'scrollbarSlider.activeBackground': '#62688080',

    // Minimap
    'minimap.background': '#292c3c',
    'minimapSlider.background': '#41455940',
    'minimapSlider.hoverBackground': '#41455960',
    'minimapSlider.activeBackground': '#41455980',

    // Widget (find/replace, etc.)
    'editorWidget.background': '#292c3c',
    'editorWidget.border': '#414559',
    'editorWidget.foreground': '#c6d0f5',
    'input.background': '#303446',
    'input.border': '#414559',
    'input.foreground': '#c6d0f5',
    'input.placeholderForeground': '#737994',
    'inputOption.activeBorder': '#8caaee',
    'inputOption.activeBackground': '#8caaee30',

    // Bracket matching
    'editorBracketMatch.background': '#41455980',
    'editorBracketMatch.border': '#626880',

    // Indent guides
    'editorIndentGuide.background': '#41455940',
    'editorIndentGuide.activeBackground': '#41455980',

    // Folding
    'editorCodeLens.foreground': '#737994',
    'editor.foldBackground': '#41455930',

    // Ruler
    'editorRuler.foreground': '#414559',

    // Overview ruler (right edge)
    'editorOverviewRuler.border': '#41455900',
    'editorOverviewRuler.findMatchForeground': '#8caaee80',
  },
};

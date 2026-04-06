export function quoteForBash(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

export function joinBashArgs(args: string[]): string {
  return args.map((value) => quoteForBash(value)).join(" ");
}

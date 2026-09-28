const FIXED_NOW = "2026-09-21T12:00:00.000Z";
const NativeDate = Date;

class FixedDate extends NativeDate {
  constructor(...args) {
    super(...(args.length === 0 ? [FIXED_NOW] : args));
  }

  static now() {
    return new NativeDate(FIXED_NOW).getTime();
  }
}

globalThis.Date = FixedDate;

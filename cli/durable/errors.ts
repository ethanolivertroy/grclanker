/** A problem the user can fix (arguments, configuration, or session state); printed without a stack. */
export class DurableUserError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DurableUserError";
  }
}

/** Bad command-line arguments; the CLI follows the message with a pointer to `--help`. */
export class DurableUsageError extends DurableUserError {
  constructor(message: string) {
    super(message);
    this.name = "DurableUsageError";
  }
}

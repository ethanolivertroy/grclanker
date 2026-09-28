export const CLI_HELP = `
grclanker

Usage:
  grclanker                     Interactive GRC CLI
  grclanker setup               Configure local-first or hosted model access
  grclanker setup --compute <k> Save <kind> as the preferred compute backend
  grclanker env list            List every compute backend, bucket, and readiness
  grclanker env doctor          Check compute backend availability
  grclanker env smoke-test      Validate the selected backend end-to-end
  grclanker env exec -- <cmd>   Run a shell command on the selected backend
  grclanker tools               List bundled GRC and compute tools
  grclanker flue run -m <text>  Run the same GRC agent under the Flue Framework runtime
  grclanker "<prompt>"          Send a literal free-form prompt to the GRC agent
  grclanker investigate         Trace crypto status, KEVs, and exploitability
  grclanker investigate <subject> [--compute <kind>]
  grclanker audit               Map evidence against a requested framework
  grclanker audit <subject> [--compute <kind>]
  grclanker assess              Produce a posture readout and remediation order
  grclanker assess <subject> [--compute <kind>]
  grclanker validate            Answer a narrow FIPS validation question
  grclanker validate <subject> [--compute <kind>]

Install:
  curl -fsSL https://grclanker.com/install | bash
  powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install.ps1 | iex"

Recommended next step after install:
  grclanker setup

Options:
  --help, -h                    Show this help
  --compute <kind>              Override the compute backend for this invocation
  --                            Treat all following text literally (including --compute)
`;

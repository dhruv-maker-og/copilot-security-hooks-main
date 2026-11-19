# Copilot Security Hooks

This private `security-hooks-marketplace` distributes the MIT-licensed
`sensitive-data-guard` plugin in `plugins/sensitive-data-guard`.

## Installation

Install the marketplace only from the trusted private repository
`dhpaliwa_poles/copilot-security-hooks`. Enterprise administrators should enable
`sensitive-data-guard@security-hooks-marketplace`. All execution hosts and
intended users need authenticated read access, including any required SSO
authorization.

Use a reviewed release for rollout. Keep the marketplace and plugin manifest
versions aligned, tag and validate the reviewed commit, and configure enterprise
rollout against that release.

The execution host needs Python 3.6 or later on `PATH` (`python` on Windows,
`python3` on macOS and Linux). The hook uses only the Python standard library.
Hook commands resolve scripts from `${PLUGIN_ROOT}`, not from the workspace.

## Behavior and verification

The plugin scans prompts, slash-command prompt files, and structured tool input
for supported PII and secret patterns. On `UserPromptSubmit`, a sensitive prompt
or an already-quarantined session produces a Copilot `decision: "block"` with a
fixed reason. The hook exits successfully without returning a replacement
prompt. Fresh clean prompts return `{}`. The legacy Local prompt-blocking
contract is not supported.

The separate transformed-prompt hook still redacts matches, and the tool hook
still denies sensitive tool inputs and tool use in quarantined sessions. A
clean follow-up does not clear quarantine. The plugin stores the taint flag
under a hashed session identifier, without storing raw prompts, and removes
the state when the supported session-end hook runs.

Run the repository tests with:

```sh
python -B -m unittest discover -s tests -v
```

This is pattern-based protection, not comprehensive data-loss prevention.
Hook execution and enforcement depend on the client. Before rollout, verify
with synthetic data in a fresh session in the target Copilot harness. Check
sanitized hook and model-request diagnostics for a block event such as
`policy_blocked`, no accepted `user.message`, no assistant turn or active
context entry, and zero model requests for the blocked submission. Repository
tests and the absence of a visible UI response do not prove live enforcement.

# agent-runtime-validator

> [!WARNING]
> **Proof-of-concept / test project — NOT for production use.**
> This is an unvalidated experimental tool. The probe implementations have not
> been audited, coverage of the underlying runbook is partial (several probes
> are manual/SKIP by design), and the probe mechanics (shell-out heuristics)
> can produce both false passes and false fails. Do not rely on it as a
> security gate for any real system without your own review and testing.

Harness-agnostic validation gate for hardened agent runtime images.
Rust implementation of the 26-probe verification runbook from
`~/reports/runner-research/agent-vm-package/implement/verification-runbook.md`.

The agent harness (OpenCode, Claude Code, Codex CLI, Hermes, …) is untrusted
middleware. Every load-bearing control lives below it — OS user model,
filesystem mounts, egress gateway, DNS path, systemd scopes, audit pipeline,
image signing. This tool proves those controls hold, on the image, before any
session is allowed to use it. Any FAIL exits 1 and blocks the image.

## Build

NixOS host (rustup's bundled lld wrapper is broken against current store paths):

```
nix shell nixpkgs#cargo nixpkgs#rustc --command cargo build --release
```

Produces `target/release/agent-runtime-validator` (~900 KB, no runtime deps
beyond coreutils/curl/dig present on the image).

## Usage

```
arv init [PATH]          starter config (TOML, mirrors all probes)
arv check-config [PATH]  parse + validate config
arv validate --config PATH [--json] [--digest D] [--operator NAME]
                [--only SECTION] [--admin] [--destructive]
```

- Probe IDs map to the source runbook (1–26) plus added confinement probes
  (27 non-root/no-caps, 28 bubblewrap sandbox, 29 Landlock LSM, 30 filesystem
  jail, 31 seccomp filter, 32 systemd unit restrictions, 33 MAC profile,
  34 no_new_privs).

- Probe IDs match the runbook 1:1, so the emitted report drops directly into
  the sign-off record (image digest + results + date + operator).
- `--json` emits a machine-readable report with config SHA-256 binding.
- SKIP is deliberately not PASS: the summary forces sign-off to account for
  every skipped probe (unconfigured collectors, admin-only tamper tests, …).
- `--destructive` enables resource probes that allocate/load (fallocate quota
  test, wall-clock kill test).
- Run as the `agent` user for the normal gate; admin-only probes stay SKIP
  unless run as root with `--admin`.

## Status

MVP validated on a non-hardened host: the engine correctly PASSes on hosts
that fail the model is not expected — on this dev box FAILs (direct DNS
reachable, secret-pattern env vars present, ~/.ssh present) are the tool
working as designed. Wire the config to a real agent VM image for the first
real gate run.

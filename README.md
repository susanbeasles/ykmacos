# ykmacos

Native macOS YubiKey/SEP UX bridge. Executable: `yk`.

## Current implementation

This foundation preview contains typed provider contracts, backup-coverage records, a provisioning transition model, runtime diagnostics, and Swift unit tests. It does not configure hardware, discover signing identities, store credentials, or implement cryptography yet.

Build on macOS 27+ with Swift 6:

```sh
./scripts/check
.build/debug/yk --help
.build/debug/yk doctor --json
```

`doctor` returns exit code 2 until native readiness probes exist. No command changes hardware or host configuration. Unsupported commands fail explicitly.

See [V1 decisions](docs/v1-decisions.md), [provisioning contract](docs/provisioning.md), and [Mac validation](docs/mac-validation.md).

## Discovery preview update

Native source now queries public identity references from file-based and Data Protection Keychains and lists CryptoTokenKit tokens. Authentication UI is disabled. This native code has not been compiled or hardware-tested in the Linux creation environment. Signing eligibility and device provisioning remain pending. Run the Mac validation procedure before relying on its inventory.

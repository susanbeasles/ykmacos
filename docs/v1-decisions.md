# V1 implementation decisions

V1 is the local macOS 27+ Swift YubiKey/SEP bridge, with modular YubiKey 5 support first. The full agreed product plan remains the implementation target; this initial source is a foundation preview.

- Administrative credentials and irreplaceable encrypted data require independently retained, verified recovery material.
- Never remove fallback account authentication automatically. Track actual tested backup coverage for each account/resource. Backup devices generate independent signing keys.
- Replaceable developer API credentials may use nonrecoverable SEP-bound encrypted storage, optionally with an additional YubiKey encryption layer requiring both. Provider account recovery must remain independently accessible.
- Release only a requested secret. Child-process environment delivery is an explicit exposure mode.
- Provisioning is journaled and resumable: stage encrypted old/proposed records, verify recovery, apply one mutation, verify hardware, commit. No rejected-PIN retries or interrupted-state guessing.
- Lifecycle covers add, test, rotate, replace, retire and lost devices. Unknown affected recovery coverage blocks destructive changes.
- Sealed policy verification binds immutable plans to exact inputs, digests and resource identity. Path substitution and concurrent changes must be checked before commit.
- Local state and SEP do not establish protection against hostile root/kernel. Add narrowly privileged helpers only for demonstrated enforcement needs.
- Established maintained authenticated encryption formats are preferred. Hardware recipient compatibility, format limits, metadata coverage and tamper behavior are shipping gates.
- Inputs and diagnostics exclude secrets. Updates require authenticated manifests and rotation/rollback policy. Uninstall preserves security material. Managed configuration is recorded precisely.
- Local operations remain offline-capable. Recovery rehearsals and coverage reporting belong in initial relevant phases.

## V2 boundary

The self-hosted remote broker is V2: upstream credentials remain remote; developers authorize narrowly scoped operations; executors return results without credentials. Short-lived hardware-authorized tunnels control reachability while broker policy independently controls operations.

Adaptive audiovisual or behavioral recovery is future research, outside V1/V2 release requirements.

# Provisioning contract

The journal stores only identifiers, stage and verification status. Credential values belong in independently encrypted records. This version implements transitions only; durable encrypted persistence and hardware execution are pending.

Sequence: planned → recovery staged → independent recovery verified → applying → hardware verified → committed.

Persist the applying stage durably before a hardware change. Perform exactly one explicit mutation. Retain old and proposed encrypted records until reconciliation completes. An interrupted applying or hardware-verified stage requires explicit reconciliation. A rejected credential stops the workflow; no automatic retry or credential guessing is permitted.

The recovery verification event is an internal boundary: production orchestration may invoke it only after actual export decryption and independent-retention checks. A boolean is not evidence of recovery by itself.

Before destructive lifecycle operations, verify every affected resource's tested recovery coverage. The current coverage record is a contract, not a complete resource dependency graph or destructive-operation executor.

Next implementation: transactional durable journal; bounded parser and schema validation; device/resource identity binding; encrypted recovery staging; fault injection at every persistence/hardware boundary; explicit reconciliation workflow.

# Recovery inventory and device removal planning

The inventory contains public labels and declarations, never PINs, passwords, API keys, recovery codes, or encrypted secret payloads. Keep it owned by your user with mode 0600. Commands require an absolute path, reject symlinks, and limit input to 64 KiB. Creation does not overwrite files.

```sh
cd ~/code/ykmacos &&
test -f Package.swift &&
.build/debug/yk recovery init --inventory "$PWD/recovery.inventory.json" --json
```

Edit the created inventory to include every managed resource. This example describes the schema; use your actual coverage and mark a route `tested` only after rehearsing recovery independently. Each backup ID identifies a distinct physical device, not a copy of the primary device's private key.

```json
{
  "schemaVersion": 1,
  "resources": [
    {
      "id": "personal-github",
      "kind": "account",
      "primaryDeviceID": "key-primary",
      "backups": [
        {
          "id": "key-backup",
          "status": "registered",
          "independentOfPrimary": true,
          "independentOfMac": true
        }
      ],
      "alternatives": [
        {
          "id": "offline-account-recovery",
          "status": "unknown",
          "independentOfPrimary": true,
          "independentOfMac": true
        }
      ]
    }
  ]
}
```

Kinds: `account`, `administrativeCredential`, `encryptedData`, `replaceableAPIKey`. Statuses: `unknown`, `configured`, `registered`, `tested`, `revoked`. Route IDs must be distinct within a resource and cannot equal its primary device ID. Resource IDs must be unique.

For accounts, alternatives mean independently retained and tested account recovery. For administrative credentials or irreplaceable encrypted data, they mean independently retained recovery material that has actually been recovered and verified. For replaceable API keys, they mean independently accessible provider account access to revoke and reissue credentials; an export is not mandatory.

```sh
cd ~/code/ykmacos &&
test -f Package.swift &&
.build/debug/yk recovery report --inventory "$PWD/recovery.inventory.json" --json &&
.build/debug/yk recovery plan --inventory "$PWD/recovery.inventory.json" --remove-device key-primary --json
```

Reports exit 2 when coverage needs attention or the inventory is empty; `&&` intentionally stops at unresolved coverage. Run `plan` separately if you want the removal analysis despite report blockers. Unknown device selections fail. Removal plans exclude the selected device from remaining coverage and require a remaining tested backup when removing a primary.

These commands assess user declarations. They do not prove recovery, enroll devices, change authentication, or grant authority. `destructiveChangeAuthorized` and `recoveryCryptographicallyVerified` remain false even when declarations satisfy coverage rules. Existing fallback authentication is never removed. Future executors must verify sealed operation plans and actual recovery evidence independently.

This phase adds offline coverage reporting and preflight planning. Encrypted recovery storage, rehearsal execution, and hardware lifecycle mutation remain pending.

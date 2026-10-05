# Identity possession diagnostic

`yk identities test --certificate SHA256 --token TOKEN --team TEAM --json` authorizes one diagnostic signing call. macOS may prompt for a PIN and the token may require touch. The application never receives or stores the PIN. macOS/token UI controls authentication and may allow manual re-entry; the application never retries signing or switches algorithms after failure.

The command blocks incomplete inventory, ambiguous exact selection, and failed certificate checks. It reacquires only the selected private-key reference by token ID and its public-key application label through the data-protection keychain with an authentication context, then revalidates its certificate bytes, token association, Team ID, chain and validity. It signs a closed, domain-separated JSON challenge with a new 256-bit system-generated nonce. No user-controlled payload or file can be supplied. The message binds the exact certificate digest, token ID and Team ID. The returned signature is verified against the certificate public key and is not exported.

The command changes no keys, PINs, certificates or enrollment records. Authentication may change token session state or retry counters, so a report marks `changed` conservatively after a signing attempt, and `retrySafe` becomes false. Cancellation, rejected authentication, disconnection and verification failure stop the command. Review token state before manually trying again; do not guess credentials.

Success proves that this invocation could use the selected key. It does not prove hardware-generated origin, attest the YubiKey, force a touch when token policy allows caching, enroll the signer, or establish fresh revocation status. It is not a codesign application-signing test.

Native validation requires a Mac and connected token. Validate success, cancellation and disconnection. Credential rejection and retry-counter tests must use disposable hardware. Unit tests verify challenge input binding and validation; they do not verify native authentication behavior.

Implementation uses Apple's [SecKeyCreateSignature](https://developer.apple.com/documentation/security/seckeycreatesignature(_:_:_:_:)) and corresponding public-key verification API.

# Native validation gates

No native or hardware tests have been run for this preview. The creation environment is Linux without Swift.

1. Run scripts/check with Swift 6 on macOS 27+.
2. Confirm doctor reports native probes pending and performs no mutations.
3. Implement and test token-aware public identity discovery, including the existing personal/employer identities. Never infer failure from security find-identity alone.
4. Validate effective production entitlements and SEP/Keychain access; investigate -34018 without software fallback.
5. Validate USB YubiKey 5 model, firmware and capability discovery without changing credentials.
6. Use disposable keys for credential rotation, reset, wrong-PIN, removal and interruption tests. Never use the working personal device for destructive tests.
7. Test recovery on another Mac without the original SEP; verify off-machine retention separately from decryptability.

Native discovery, enrollment, signing, secure persistence, recovery exports, and toolchain installation remain release gates.

## Public identity queries added in discovery preview

```sh
.build/debug/yk identities list --json
.build/debug/yk tokens list --json
```

Both file-Keychain search-list and Data Protection Keychain queries suppress authentication UI. Token metadata is association evidence, not proof of generated origin. Records remain separate by discovery source. The inventory is explicitly not a signing eligibility verdict; purpose, trust, validity, Team ID and matching-key checks remain pending.

Compare output with the known personal and employer identities without importing certificates or generating keys. An empty/incomplete inventory must never trigger repair. Token identifiers and certificate subjects can identify the user/device: review before sharing this inventory. Generic diagnostic exports must redact them.

Sources: [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains), [SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)), [SecKeyCopyAttributes](https://developer.apple.com/documentation/security/seckeycopyattributes(_:)).

## Consolidated identity inventory (schema 2)

`source` becomes a sorted `sources` array. Records are consolidated only when certificate digest, token association, subject and origin evidence agree. A token-associated record is never merged with a record lacking token association. Conflicting evidence stays separate. `observationCount` reports raw discovery results; `identities.count` reports consolidated records. Certificate identifiers are SHA-256 DER digests, not the SHA-1 selectors used by codesign.

Expected on the previously inspected Mac: the two personal token identities each retain both query sources; repeated unassociated certificate records collapse. No hardware-origin or signing eligibility conclusion is added.

## Certificate evidence (schema 3)

Identity records include certificate validity, subject OU values, recognized Developer ID purpose marker, public-key comparison, and local macOS code-signing trust. Trust evaluation disables network fetching to preserve offline operation. Failure may mean the local chain is unavailable; do not automatically import or regenerate anything.

OU is reported as subjectOrganizationalUnits, not an independently authenticated Team ID. Purpose OIDs are evidence, not proof of Apple issuance. A locally trusted certificate is not automatically Apple anchored. Apple anchor verification remains a mandatory enrollment gate. No signer is enrolled and eligibilityVerified remains false.

Compare the personal Developer ID evidence with expected OU 2VB7966G7R. Date fields use Foundation Codable dates (seconds since 2001-01-01 UTC). Public-key matching exports only public representations, not private keys. If the token cannot expose a public representation without approval, report unknown and stop eligibility rather than signing a probe.

References: [Apple Certificate OIDs](https://developer.apple.com/documentation/security/certificate-oids), [Developer ID CPS](https://images.apple.com/certificateauthority/pdf/Apple_Developer_ID_CPS_v2.1.pdf).

## Subject OU correction

OU extraction now reads the normalized DER subject Name using attribute OID 2.5.4.11. It does not parse the common name or localized certificate display labels. The reader is bounded, rejects indefinite/truncated encodings, and preserves duplicate OU values so ambiguity cannot silently disappear. Unsupported or malformed subject encoding leaves OU verification unavailable, never inferred from the certificate's display name.

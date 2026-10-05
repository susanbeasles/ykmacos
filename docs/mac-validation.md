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

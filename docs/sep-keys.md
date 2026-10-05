# Secure Enclave keys and certificate requests

This phase creates an independent persistent P-256 key inside the Mac's Secure Enclave and builds a PKCS #10 CSR signed by that key. There is no private-key export, software fallback, certificate issuance, certificate import, or new operational authority.

## Explicit access policy

Creation requires `--access user-presence`. Private-key use requires user presence under macOS authentication policy, which can permit Touch ID or password authentication. This is not a biometric-only promise and does not promise a new prompt for every call. The key is device-bound and cannot be recovered on another Mac. Keep independently accessible signing and account recovery paths. Do not use it as the sole means to recover administrative credentials or irreplaceable data.

The key lives in the Data Protection Keychain with `WhenUnlockedThisDeviceOnly` accessibility and `privateKeyUsage` plus `userPresence` access control. Production signing and the provisioning profile must be present; the ordinary ad-hoc Swift debug executable is not an equivalent deployment.

## Create and inspect

`sep create --record PATH --access user-presence --json` creates two public files without overwriting either:

- `PATH`: durable planned record with a unique key tag, written before key creation.
- `PATH.created.json`: completion record containing the public EC point after the exact permanent key reference has been re-read.

One key creation request is made. The key is retained if record publication fails. No cleanup deletes it. On interruption, inspect the planned record before deciding whether to create another independent key. `sep inspect --record PATH --json` queries only that tag without signing or authentication UI. Inspection may fail when macOS refuses noninteractive key reference access; a failure is not proof that no key exists.

Public records contain no PIN or private key, but still require safe absolute paths and owner-only permissions. Record declarations are not sealed policy or hardware attestation. A successful lookup revalidates the native key's Secure Enclave token attributes and public bytes.

## CSR

`sep csr --record PATH.created.json --common-name NAME --output NEW_PATH --json` validates the exact key and prepares a bounded DER CertificationRequestInfo. It includes version 0, one UTF-8 Common Name, the P-256 SubjectPublicKeyInfo, and an empty attributes set. It makes one ECDSA SHA-256 signing request, verifies the signature against the same public key, and writes public PEM without overwriting a destination.

The Common Name is supplied explicitly. No SAN, email, organization, Team ID, certificate extensions, or application privileges are inferred. The CSR is a request, not a certificate. Apple portal acceptance and compatibility of a resulting certificate with the intended signing workflow remain release gates.

CSR publication failures retain the key and never retry signing automatically. User cancellation produces failure, not a replacement key or fallback credential.

## Native validation session

Run `scripts/check` first. Its CSR interoperability test creates disposable software fixtures in memory and asks OpenSSL to verify the actual generated PEM. Production key generation always requests the SEP token.

Use the packaging probe's optional new absolute output directory to test current signed code without replacing the installed, notarized older build:

```sh
cd ~/code/ykmacos &&
test -f Package.swift &&
/bin/sh scripts/probe-cli-packaging \
  "$HOME/Downloads/YKMacOS_Developer_ID.provisionprofile" \
  "$PWD/.build/sep-session-01" &&
"$PWD/.build/sep-session-01/ykmacos/Contents/MacOS/yk" sep create \
  --record "$PWD/sep-signer-01.intent.json" --access user-presence --json &&
"$PWD/.build/sep-session-01/ykmacos/Contents/MacOS/yk" sep inspect \
  --record "$PWD/sep-signer-01.intent.json.created.json" --json &&
"$PWD/.build/sep-session-01/ykmacos/Contents/MacOS/yk" sep csr \
  --record "$PWD/sep-signer-01.intent.json.created.json" \
  --common-name "Anthony Vespoli" \
  --output "$PWD/sep-signer-01.certSigningRequest" --json &&
/usr/bin/openssl req -in "$PWD/sep-signer-01.certSigningRequest" -verify -noout
```

This signs the new test package once using the existing YubiKey identity and may request its PIN/touch. The later SEP CSR signing may request macOS authentication. The package is not submitted for notarization by this command. Existing session or record paths cause failure rather than replacement; do not rerun the whole sequence after partial success. Inspect its records and resume only the unfinished operation.

References: [Apple Secure Enclave key protection](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [PKCS #10 RFC 2986](https://www.rfc-editor.org/rfc/rfc2986).

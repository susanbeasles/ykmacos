# Suffix-free CLI installation

The installer consumes an already signed, notarized `ykmacos` directory. It does not build or sign code, upload to Apple, access credentials, or execute the installed binary as root. The profile and bundle structure stay intact without an `.app` suffix.

## First install

```sh
cd ~/code/ykmacos &&
test -f Package.swift &&
sudo /bin/sh scripts/install-cli \
  "$PWD/.build/packaging-probes/run.5ExqH6/ykmacos" \
  66900e7a3b73c9d54c099879506a9794c3e87f5b2342a40f4a01a12adc9ce4b7
```

The two inputs are an absolute bundle path and the independently selected signer certificate SHA-256. The certificate pin is a signing identity pin; it does not prove the key was generated on a YubiKey.

The installer checks root-owned installation parents, rejects writable parents and parent ACLs, takes a cooperative installation lock, copies into a private staging directory, rejects symlinks and special files, verifies bundle identity and signature, compares the signing certificate pin, and assesses the protected copy with Gatekeeper. It removes copied ACLs and sets explicit root ownership and file modes, then verifies the signature again before publication.

Version directories use the executable SHA-256 under `/usr/local/libexec/ykmacos/`. The `/usr/local/bin/yk` symlink points to that version's `Contents/MacOS/yk`. Existing versions and commands are never overwritten. These checks do not defend against a hostile root or kernel.

## Verify as the normal user

```sh
cd ~/code/ykmacos &&
test -f Package.swift &&
/usr/local/bin/yk capabilities --json &&
/usr/local/bin/yk signers status \
  --certificate 66900e7a3b73c9d54c099879506a9794c3e87f5b2342a40f4a01a12adc9ce4b7 \
  --token com.apple.pivtoken:12B7702B3E72411DB46DCAA62BEB19CA \
  --team 2VB7966G7R \
  --receipt "$PWD/personal-signer.receipt.json" \
  --policy "$PWD/personal-signer.policy.json" \
  --policy-digest 7be0a4194e79c422705376ee2252c5bb4456e5d779bef4592a71dcdb1b831338 \
  --json
```

Expected status: `YK_POLICY_ANCHOR_VERIFIED`. This reads public acceptance metadata; it performs no token signing or PIN verification. A successful install does not establish working Keychain access through the symlink until this command succeeds on the Mac.

The accepted packaging probe predates the recovery coverage patch. Installing it installs those older bytes; it will not contain newer commands just because the source has changed. Each new release must be rebuilt, signed, and notarized before installation. This installer does not masquerade a newer unsigned build as the accepted version.

## Interruptions and retained evidence

Staging directories and extracted public certificates are retained and their path is printed. A failure before command publication leaves no new command on PATH; a publication failure may leave a verified version directory. Inspect retained state before retrying. The lock is normally removed on exit; a killed process can leave a lock requiring manual review. No automatic cleanup touches old versions or security material.

Upgrade selection, uninstall, authenticated release manifests, and offline stapled distribution packaging are subsequent workflows. This first installer deliberately refuses existing installations.

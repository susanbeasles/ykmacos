# Possession receipts

Add `--receipt /absolute/new/path.json` to `identities test` to retain public certificate DER, exact challenge bytes, signature and algorithm. No private key or PIN is stored. This is past possession evidence, not enrollment or policy authorization, and has no trusted timestamp or hardware-origin attestation.

The destination must be new, absolute, without symlink components, and in an existing user-owned directory not writable by group or others. Staging uses mode 0600 and descriptor-relative operations. The writer flushes content and publishes without overwrite, then flushes the directory. Interrupted publication can leave public staging files. Commit errors are uncertain: preserve outputs and never automatically repeat signing. This writer is not a sealed-policy store; preflight/commit directory identity is not yet bound.

`identities verify-receipt --receipt PATH --certificate SHA256 --token TOKEN --team TEAM --json` verifies the retained exact message, certificate digest, signature and current offline certificate checks without hardware. Valid receipts prove only a past signature. Token identifiers are signed claims, not independent attestation. Fresh revocation remains unknown. Changed domains, selections or extra signed-message fields reject.

The bounded reader refuses nonregular files, symlinks, foreign ownership, multiple hard links and broad permissions. Local files cannot protect against hostile root/kernel or malicious same-user processes. Native persistence and signature verification require Mac validation.

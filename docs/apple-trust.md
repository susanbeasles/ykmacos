# Developer ID chain verification

The read-only inventory evaluates Developer ID Application certificate chains using the public macOS code-signing policy, an explicitly supplied Apple Root CA, and only the bundled Developer ID G1/G2 intermediate certificates. Network certificate fetching is disabled. Exact SHA-256 digests of the evaluated intermediate and root constrain issuance; certificate display names are never anchors.

Sources: [Apple PKI](https://www.apple.com/certificateauthority/) and [Apple code-signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).

Bundled certificate SHA-256 values:

- `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024`
- `7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f`
- `f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a`

This check is evidence only. It does not enroll a signer, prove hardware-generated origin, test a private-key operation, or establish current revocation status. Offline cached revocation information may affect trust evaluation; fresh revocation remains unknown. The original Developer ID intermediate expires February 1, 2027; its expiration is enforced by trust evaluation. Other Apple certificate families are outside this gate. New roots or intermediates require review and a software update, and fail closed until supported.

# rinsign

`rinsign` is the native C signer for canonical RinOS v3 RIN and NDRV images.
It accepts an unsigned image with zeroed signature fields, verifies that the
PEM private key exactly matches the trusted PKCS#1 DER public key, writes the
v3 content hash, and appends the RDS1 RSA-PKCS1-SHA256 envelope atomically.

```text
rinsign INPUT -o OUTPUT --key PRIVATE.pem --public-key PUBLIC.der
```

The tool has no Python runtime dependency. Invalid input, a mismatched key, an
unsupported image, or a failed write is an error and never produces a final
output image.

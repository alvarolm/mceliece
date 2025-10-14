
>** EXPERIMENTAL - USE AT YOUR OWN RISK**
>
>This is an experimental implementation that has not been independently reviewed or audited. It should not be used in production environments. Use at your own peril.



# Classic McEliece

This is a Go implementation of the Classic McEliece post-quantum key encapsulation mechanism (KEM), extracted from the [katzenpost/circl](https://github.com/katzenpost/circl) library.

## About Classic McEliece

Classic McEliece is a code-based post-quantum cryptographic algorithm that was submitted to the NIST Post-Quantum Cryptography (PQC) competition. It provides IND-CCA2 secure key encapsulation and is designed to resist attacks from both classical and quantum computers.

The implementation is based on the specification described in:
- [Classic McEliece NIST Submission (October 2020)](https://classic.mceliece.org/nist/mceliece-20201010.pdf)

This code is translated from:
- The C reference implementation
- A Rust implementation by Bernhard Berg, Lukas Prokop, and Daniel Kales ([Colfenor/classic-mceliece-rust](https://github.com/Colfenor/classic-mceliece-rust))

## Supported Parameter Sets

The implementation includes all NIST Round 4 parameter sets:

| Parameter Set | Public Key Size | Private Key Size | Ciphertext Size | Security Level |
|--------------|-----------------|------------------|-----------------|----------------|
| mceliece348864 | 261,120 bytes | 6,492 bytes | 96 bytes | NIST Level 1 |
| mceliece348864f | 261,120 bytes | 6,492 bytes | 96 bytes | NIST Level 1 |
| mceliece460896 | 524,160 bytes | 13,608 bytes | 156 bytes | NIST Level 3 |
| mceliece460896f | 524,160 bytes | 13,608 bytes | 156 bytes | NIST Level 3 |
| mceliece6688128 | 1,044,992 bytes | 13,932 bytes | 208 bytes | NIST Level 5 |
| mceliece6688128f | 1,044,992 bytes | 13,932 bytes | 208 bytes | NIST Level 5 |
| mceliece6960119 | 1,047,319 bytes | 13,948 bytes | 194 bytes | NIST Level 5 |
| mceliece6960119f | 1,047,319 bytes | 13,948 bytes | 194 bytes | NIST Level 5 |
| mceliece8192128 | 1,357,824 bytes | 14,120 bytes | 208 bytes | NIST Level 5 |
| mceliece8192128f | 1,357,824 bytes | 14,120 bytes | 208 bytes | NIST Level 5 |

Parameter sets with the 'f' suffix use semi-systematic encoding.

## Features

- Full implementation of all Classic McEliece parameter sets
- Key generation with deterministic derivation from seed
- IND-CCA2 secure key encapsulation
- Support for deterministic encapsulation (useful for testing)
- PEM encoding/decoding support for keys
- Compressed private key marshaling (32-byte seed)

## Usage

```go
import (
    "github.com/alvarolm/mceliece/mceliece348864"
)

// Generate a key pair
scheme := mceliece348864.Scheme()
pk, sk, err := scheme.GenerateKeyPair()
if err != nil {
    panic(err)
}

// Encapsulate - generate shared secret and ciphertext
ciphertext, sharedSecret, err := scheme.Encapsulate(pk)
if err != nil {
    panic(err)
}

// Decapsulate - recover shared secret from ciphertext
recoveredSecret, err := scheme.Decapsulate(sk, ciphertext)
if err != nil {
    panic(err)
}

// sharedSecret and recoveredSecret should be equal
```

## Code Generation

This implementation uses Go templates to generate code for different parameter sets, reducing code duplication. The `gen.go` file contains the code generation logic.

To regenerate the code from templates:

```bash
go run gen.go
```

## Testing

Each parameter set includes:
- Unit tests for core functionality
- Known Answer Tests (KAT) for verification against reference vectors

Run tests with:

```bash
go test ./...
```

## Security Considerations

- This is a defensive cryptographic implementation intended for research and experimental use
- McEliece implementations have large key sizes compared to other PQC algorithms
- The algorithm is designed to be conservative and has a long history of cryptanalytic study
- All random number generation uses `crypto/rand` for cryptographically secure randomness

## Original Source

This code was extracted from [katzenpost/circl](https://github.com/katzenpost/circl), which is a fork of [Cloudflare's CIRCL library](https://github.com/cloudflare/circl).

## References

- [Classic McEliece Official Website](https://classic.mceliece.org/)
- [NIST PQC Competition](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CIRCL Library](https://github.com/katzenpost/circl)

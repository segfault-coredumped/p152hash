# p152hash - Sponge-Based Cryptographic Hash Function

### Overview
This project implements a cryptographic hash function using the sponge construction with a custom 48-byte permutation function (p152).

It demonstrates how modern hash functions can be built from permutation-based primitives
___

### Features
- Sponge construction
- Custom permutation function (p152)
- Bitwise padding scheme (10*1 rule)
- Byte-level state manipulation
- Configurable output length
___

### Build
`gcc p152hash.c -o p152hash`
___

### Concepts Demonstrated
- Cryptographic hash function design
- Sponge construction (Keccak-style design)
- Permutation-based cryptography
- Bitwise operations
- Memory-level programming in C
___

### Notes
This implementation is for education purposes and is not intended for production cryptographic use.
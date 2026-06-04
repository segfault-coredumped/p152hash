# p152hash - Sponge-Based Cryptographic Hash Function

## Overview
This project implements a cryptographic hash function using the sponge construction with a custom 48-byte permutation function (p152).

It demonstrates how modern hash functions can be built from permutation-based primitives.

## Features
- Sponge construction (rate/capacity design)
- Custom permutation function (p152)
- Bitwise padding scheme (10*1 rule)
- Byte-level state manipulation
- Configurable output length

## Concepts Used
- Cryptographic hash function design
- Sponge construction (Keccak-style architecture)
- Permutation-based cryptography
- Bitwise operations
- Low-level memory manipulation in C

## Build
```bash
gcc p152hash.c -o p152hash
```

## Notes
This implementation is for educational purposes and is not intended for production cryptographic use.

# Public Key Generation with verifiable randomness

Library associated with the protocol described in: eprint 2020/294: https://eprint.iacr.org/2020/294.pdf

The paper was accepted at Asiacrypt 2020.
Written by Olivier Blazy, Patrick Towa and Damien Vergnaud.

## Introduction

This code implements the protocol presented in annex B, page 54

It simulates the interaction between a user, and a server to generate a secret key known by the user, while ensuring the server that the public key uses the entropy provided.

## Rust
We work with a rust 2018, stable
The instantiation is done using the dalek library.

To test the library simply clone it, and run cargo test

## Todo
- [x] Discrete Logarithm example
- [ ] RSA example
- [ ] Move away from academic code

//! Public Key Generation with verifiable randomness
//!
//! Based on: https://eprint.iacr.org/2020/294
//! Published at AC2020, by Blazy, Towa, Vergnaud
//! Initial Version by: Olivier Blazy olivier@blazy.eu
//! # Examples
//!
//! ```
//! # // TODO (if you put code here it'll run as a test and also show up
//! # //     in the crate-level documentation!)
//! ```

extern crate curve25519_dalek;
extern crate rand_core;
extern crate rand_os;
extern crate sha3;

mod pkgvr;

pub use crate::pkgvr::*;

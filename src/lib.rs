// FROST Threshold Signature Scheme for Bitcoin Taproot
//
// This library implements the FROST protocol over secp256k1, specifically designed for Bitcoin Taproot integration.
//
// For more information about FROST, see: https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod errors;
pub mod dkg;
pub mod signing;
pub mod taproot;
pub mod crypto;

pub mod prelude {
    pub use crate::errors::*;
    pub use crate::dkg::*;
    pub use crate::signing::*;
    pub use crate::taproot::*;
    pub use crate::crypto::*;
}

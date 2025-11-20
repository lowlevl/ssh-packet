#![doc = include_str!("../README.md")]
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    clippy::todo,
    clippy::unwrap_used,
    clippy::unimplemented,
    clippy::undocumented_unsafe_blocks
)]
#![forbid(unsafe_code)]

/// Maximum size for a packet, coincidentally this is
/// the maximum size for a TCP packet.
pub const MAX_SIZE: usize = u16::MAX as usize;

/// Minimum size for a packet, coincidentally this is
/// the largest block cipher's block-size.
pub const MIN_SIZE: usize = 16;

mod binary;
pub use binary::{Error, Packet};

pub mod arch;
pub mod connect;
pub mod kex;
pub mod sig;
pub mod trans;
pub mod userauth;

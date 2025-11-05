//! Types defined in the SSH's **architecture** (`SSH-ARCH`) part of the protocol,
//! as defined in the [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251).

pub mod id;

mod bytes;
pub use bytes::Bytes;

mod ascii;
pub use ascii::{Ascii, AsciiError};

mod utf8;
pub use utf8::Utf8;

mod namelist;
pub use namelist::NameList;

mod mpint;
pub use mpint::MpInt;

mod bool;
pub use bool::Bool;

#[doc(inline)]
pub use ascii::ascii;

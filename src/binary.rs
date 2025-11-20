//! Structures definitions & traits to manipulate them.

use binrw::{
    BinRead, BinWrite,
    meta::{ReadEndian, WriteEndian},
};

/// A trait representing a _packet_ in the SSH protocol.
pub trait Packet:
    for<'r> BinRead<Args<'r> = ()> + ReadEndian + for<'w> BinWrite<Args<'w> = ()> + WriteEndian
{
    /// Convert from _binary wire format_.
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::read(&mut std::io::Cursor::new(bytes.as_ref())).map_err(Error)
    }

    /// Convert to _binary wire format_.
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        self.write(&mut buf).unwrap_or_else(|err| {
            panic!(
                "failed to serialize `{}`: {err}",
                std::any::type_name::<Self>()
            )
        });

        buf.into_inner()
    }
}

/// An error that can occur while converting from and to _binary wire format_.
#[derive(Debug)]
pub struct Error(binrw::Error);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

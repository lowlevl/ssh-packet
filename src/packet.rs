use binrw::{
    BinRead, BinWrite,
    meta::{ReadEndian, WriteEndian},
};

/// A packet _deserialization_ & _serialization_ helper.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-6>.
#[derive(Debug, Clone)]
pub struct Packet(pub Vec<u8>);

impl Packet {
    /// Maximum size for a SSH packet, coincidentally this is
    /// the maximum size for a TCP packet.
    pub const MAX_SIZE: usize = u16::MAX as usize;

    /// Minimum size for a SSH packet, coincidentally this is
    /// the largest block cipher's block-size.
    pub const MIN_SIZE: usize = 16;

    /// Try to deserialize the [`Packet`] into `T`.
    pub fn to<T: for<'a> BinRead<Args<'a> = ()> + ReadEndian>(&self) -> Result<T, binrw::Error> {
        T::read(&mut std::io::Cursor::new(&self.0))
    }
}

impl std::ops::Deref for Packet {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Allow types implementing [`BinWrite`] to be easily converted to a [`Packet`].
pub trait IntoPacket {
    /// Convert the current type to a [`Packet`].
    fn into_packet(self) -> Packet;
}

impl IntoPacket for Packet {
    fn into_packet(self) -> Packet {
        self
    }
}

impl<T: for<'a> BinWrite<Args<'a> = ()> + WriteEndian> IntoPacket for &T {
    fn into_packet(self) -> Packet {
        let mut buffer = std::io::Cursor::new(Vec::new());
        self.write(&mut buffer)
            .expect("failed to convert `impl BinWrite` type to Packet");

        Packet(buffer.into_inner())
    }
}

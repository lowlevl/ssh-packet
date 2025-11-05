use binrw::{
    meta::{ReadEndian, WriteEndian},
    BinRead, BinWrite,
};

mod cipher;
pub use cipher::{CipherCore, OpeningCipher, SealingCipher};

mod mac;
pub use mac::Mac;

/// Maximum size for a SSH packet, coincidentally this is
/// the maximum size for a TCP packet.
pub const PACKET_MAX_SIZE: usize = u16::MAX as usize;

/// Minimum size for a SSH packet, coincidentally this is
/// the largest block cipher's block-size.
pub const PACKET_MIN_SIZE: usize = 16;

/// A packet _deserialization_ & _serialization_ helper.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-6>.
#[derive(Debug, Clone)]
pub struct Packet(pub Vec<u8>);

impl Packet {
    /// Try to deserialize the [`Packet`] into `T`.
    pub fn to<T: for<'a> BinRead<Args<'a> = ()> + ReadEndian>(&self) -> Result<T, binrw::Error> {
        T::read(&mut std::io::Cursor::new(&self.0))
    }

    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    /// Read a [`Packet`] from the provided asynchronous `reader`.
    pub async fn from_reader<R, C>(reader: &mut R, cipher: &mut C, seq: u32) -> Result<Self, C::Err>
    where
        R: futures::io::AsyncRead + Unpin,
        C: OpeningCipher,
    {
        use futures::io::AsyncReadExt;

        let mut buf = vec![0; cipher.block_size()];
        reader.read_exact(&mut buf[..]).await?;

        if !cipher.mac().etm() {
            cipher.decrypt(&mut buf[..])?;
        }

        let len = u32::from_be_bytes(
            buf[..4]
                .try_into()
                .expect("buffer of size 4 is not of size 4"),
        );

        if len as usize > PACKET_MAX_SIZE {
            return Err(binrw::Error::Custom {
                pos: len as u64,
                err: Box::new(format!("packet size too large, {len} > {PACKET_MAX_SIZE}")),
            })?;
        }

        // Read the rest of the data from the reader
        buf.resize(std::mem::size_of_val(&len) + len as usize, 0);
        reader.read_exact(&mut buf[cipher.block_size()..]).await?;

        let mut mac = vec![0; cipher.mac().size()];
        reader.read_exact(&mut mac[..]).await?;

        if cipher.mac().etm() {
            cipher.open(&buf, mac, seq)?;
            cipher.decrypt(&mut buf[4..])?;
        } else {
            cipher.decrypt(&mut buf[cipher.block_size()..])?;
            cipher.open(&buf, mac, seq)?;
        }

        let (padlen, mut decrypted) =
            buf[4..].split_first().ok_or_else(|| binrw::Error::Custom {
                pos: 0x4,
                err: Box::new(format!("Packet size too small ({len})")),
            })?;

        if *padlen as usize > len as usize - 1 {
            return Err(binrw::Error::Custom {
                pos: 0x4,
                err: Box::new(format!("Padding size too large, {padlen} > {} - 1", len)),
            })?;
        }

        let mut payload = vec![0; len as usize - *padlen as usize - std::mem::size_of_val(padlen)];
        std::io::Read::read_exact(&mut decrypted, &mut payload[..])?;

        let payload = cipher.decompress(payload)?;

        Ok(Self(payload))
    }

    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    /// Write the [`Packet`] to the provided asynchronous `writer`.
    pub async fn to_writer<W, C>(
        &self,
        writer: &mut W,
        cipher: &mut C,
        seq: u32,
    ) -> Result<(), C::Err>
    where
        W: futures::io::AsyncWrite + Unpin,
        C: SealingCipher,
    {
        use futures::AsyncWriteExt;

        let compressed = cipher.compress(&self.0)?;

        let padding = cipher.padding(compressed.len());
        let buf = cipher.pad(compressed, padding)?;
        let mut buf = [(buf.len() as u32).to_be_bytes().to_vec(), buf].concat();

        let (buf, mac) = if cipher.mac().etm() {
            cipher.encrypt(&mut buf[4..])?;
            let mac = cipher.seal(&buf, seq)?;

            (buf, mac)
        } else {
            let mac = cipher.seal(&buf, seq)?;
            cipher.encrypt(&mut buf[..])?;

            (buf, mac)
        };

        writer.write_all(&buf).await?;
        writer.write_all(&mac).await?;

        Ok(())
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

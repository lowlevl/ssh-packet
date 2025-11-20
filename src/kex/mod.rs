//! Facilities to produce some of the _exchange hashes_.

use binrw::binwrite;

use super::{arch, trans};

mod lengthed;
pub use lengthed::Lengthed;

/// The exchange hash for ECDH, computed as the
/// hash of the concatenation of the following.
///
/// see <https://datatracker.ietf.org/doc/html/rfc5656#section-4>.
#[binwrite]
#[derive(Debug)]
#[bw(big)]
pub struct Ecdh<'b> {
    /// Client's identification string (`\r` and `\n` excluded).
    pub v_c: arch::Bytes<'b>,

    /// Server's identification string (`\r` and `\n` excluded).
    pub v_s: arch::Bytes<'b>,

    /// Payload of the client's `SSH_MSG_KEXINIT` message.
    pub i_c: Lengthed<&'b trans::KexInit<'b>>,

    /// Payload of the server's `SSH_MSG_KEXINIT` message.
    pub i_s: Lengthed<&'b trans::KexInit<'b>>,

    /// Server's public host key.
    pub k_s: arch::Bytes<'b>,

    /// Client's ephemeral public key octet string.
    pub q_c: arch::Bytes<'b>,

    /// Server's ephemeral public key octet string.
    pub q_s: arch::Bytes<'b>,

    /// Computed shared secret.
    pub k: arch::MpInt<'b>,
}

impl Ecdh<'_> {
    /// Produce the exchange hash with the specified digest algorithm.
    #[cfg(feature = "digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
    pub fn hash<D: digest::Digest>(&self) -> digest::Output<D> {
        use binrw::BinWrite;

        let mut buffer = Vec::new();
        self.write(&mut std::io::Cursor::new(&mut buffer))
            .expect("The binrw structure serialization failed");

        D::digest(&buffer)
    }
}

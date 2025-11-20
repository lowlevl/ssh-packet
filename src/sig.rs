//! Facilities to interact with some of the _signature algorithms_.

use binrw::binwrite;

use super::arch;

/// The data that gets _signed_ and _verified_ to prove the possession of the said private key in
/// the `publickey` authentication method, computed from the concatenation of the following.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-7>.
#[binwrite]
#[derive(Debug)]
#[bw(big)]
pub struct Publickey<'b> {
    /// The session identifier issued by the key-exchange.
    pub session_id: arch::Bytes<'b>,

    #[bw(calc = 50)]
    magic: u8,

    /// Username for the auth request.
    pub username: arch::Utf8<'b>,

    /// Service name to query.
    pub service_name: arch::Ascii<'b>,

    #[bw(calc = "publickey".into())]
    method: arch::Utf8<'b>,

    #[bw(calc = true.into())]
    signed: arch::Bool,

    /// Public key algorithm's name.
    pub algorithm: arch::Bytes<'b>,

    /// Public key blob.
    pub blob: arch::Bytes<'b>,
}

impl Publickey<'_> {
    /// Verify the structure against the provided `signature` with the `key`.
    #[cfg(feature = "signature")]
    #[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
    pub fn verify<S, K: signature::Verifier<S>>(
        &self,
        key: &K,
        signature: &S,
    ) -> signature::Result<()> {
        use binrw::BinWrite;

        let mut buffer = Vec::new();
        self.write(&mut std::io::Cursor::new(&mut buffer))
            .expect("The binrw structure serialization failed");

        K::verify(key, &buffer, signature)
    }

    /// Sign the structure with the provided `key` to produce the `signature`.
    #[cfg(feature = "signature")]
    #[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
    pub fn sign<S, K: signature::Signer<S>>(&self, key: &K) -> S {
        use binrw::BinWrite;

        let mut buffer = Vec::new();
        self.write(&mut std::io::Cursor::new(&mut buffer))
            .expect("The binrw structure serialization failed");

        K::sign(key, &buffer)
    }
}
